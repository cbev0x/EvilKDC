# EvilKDC

A rogue Key Distribution Center for the **Windows KDC Proxy (MS-KKDCP / KPSSVC)** attack surface.
EvilKDC stands up, in one terminal, everything needed to impersonate a domain controller to a KDC
Proxy and **capture Kerberos pre-authentication for offline cracking**: a scoped DNS responder, a
NetLogon CLDAP responder, and a KDC listener that elicits and records `PA-ENC-TIMESTAMP`.

> **Authorized testing only.** EvilKDC is for red-team engagements and research in environments you
> are explicitly permitted to test. It captures credential material. Read *Prerequisites* before
> running it, and scope the network step (see *Two-terminal workflow*). The network-takeover step is
> intentionally not built in.

---

## What the KDC Proxy is, and why it's an attack surface

The **KDC Proxy Service (KPSSVC)** implements MS-KKDCP, letting a client perform Kerberos (AS/TGS,
kpasswd) over **HTTPS** instead of raw TCP/UDP 88/464. Microsoft ships it for external-facing
scenarios such as Always On VPN device tunnel, RD Gateway, Azure-joined clients reaching their on-prem
realm, and SMB over QUIC. A corporate KDC Proxy is therefore usually **reachable from outside** at
`https://<host>/KdcProxy`, and by design it serves **unauthenticated** clients (the whole point is to
help a client that has no tickets yet obtain them).

Two properties make it useful to an attacker:

1. **The proxy locates the target realm's DC via `DsGetDcName` (DNS SRV + CLDAP) and relays to
   whatever it finds, without verifying the located host is a genuine DC.** If you can influence what
   the proxy resolves for a realm's DC, the proxy connects out to a host you control and forwards the
   victim's Kerberos there — EvilKDC is that host.
2. **Requests are attributed to the proxy's source IP** at the real DC, so activity is IP-laundered.

---

## The attack chain

```
1. A client sends Kerberos-over-HTTPS (an AS-REQ for REALM) to the KDC Proxy.

2. The proxy runs DsGetDcName(REALM) and resolves, via the poisoned DNS:
      SRV  _kerberos._tcp.dc._msdcs.REALM   ->  EvilKDC
      A    dc.REALM                          ->  EvilKDC

3. The proxy CLDAP-pings the located "DC"; EvilKDC returns a valid NetLogon reply.

4. The proxy relays the AS-REQ to EvilKDC on tcp/88.

5. EvilKDC elicits pre-auth, captures PA-ENC-TIMESTAMP, writes a $krb5pa$ line.

6. Crack offline with hashcat. No lockout: the real KDC never sees a guess.
```

The victim's authentication fails through EvilKDC, which holds no `krbtgt` key and issues no real TGT.
That failure is inherent — it is a detection signal (see *Detection & hardening*).

---

## Prerequisites, and the floor

EvilKDC is the *capture* half. For the proxy to send it a victim's AS-REQ, the KDC Proxy host must
resolve the target realm's DC to EvilKDC. Naming a throwaway realm only relays your own requests
(useless); capturing other principals requires influencing their realm's DC resolution as the proxy
sees it.

What that costs:

| Path to redirect the proxy's DC resolution | What it needs | Works? |
|---|---|---|
| Overwrite the DC-locator records in AD (SRV/A) | DNS-admin or delegated rights. Locator records are DC-owned (`SELF`-only write), and standard-user ADIDNS is locked across the whole chain | Blocked for normal users |
| Non-secure DNS dynamic update | Zone misconfig (`NonsecureAndSecure`) | Environment-specific (secure by default) |
| A-record-only spoof (e.g. mitm6 default) | Resolver or same-subnet position | Insufficient. `DsGetDcName` selects via **SRV**, so a truthful SRV points to the real DC |
| **Serve poisoned SRV *and* A as the proxy's resolver** | Resolver position, no AD rights | **Yes.** Full redirect, and the CLDAP check does not verify DC identity, so a mismatched domain GUID is accepted |

**The floor is network position over the proxy's name resolution — not any AD privilege.** The
DC-locator authorizes "this is the realm's KDC" on DNS plus an *unauthenticated* CLDAP response. Ways
to hold that position, lowest bar first:

- **Same-subnet, unauthenticated:** become the proxy's DNS via DHCPv6 (mitm6). No credentials.
- **DHCP-assigned DNS** you can influence, a compromised resolver, or admin on the proxy host.

There is no LLMNR/NBT-NS/mDNS fallback in the proxy's SRV-based locator, so you cannot Responder your
way in when DNS succeeds. You must *be* the resolver.

---

## Two-terminal workflow (by design)

The dangerous part, taking over the segment's DNS, is deliberately not built into EvilKDC. An unscoped
one-click DHCPv6 takeover can knock whole subnets offline. Keeping it separate forces it to be a
conscious, scoped step.

**Terminal 1: resolver position (scoped mitm6).** Only for the same-subnet path, and only scoped to
the target so unrelated machines are untouched:

```bash
# scope to the target realm AND the proxy host
sudo mitm6 -d corp.local -hw kdcproxy.corp.local -i eth0
```

mitm6 spoofs A/AAAA, not SRV, which alone is insufficient (see the table above). The proxy's resolver
must answer the poisoned SRV records too. The reliable setup is a resolver that serves the full
poisoned zone (EvilKDC's built-in DNS, reachable by the proxy). Confirm end to end with
`--check --proxy` before relying on it. If you already hold resolver position another way (DHCP scope,
compromised DNS, static config), skip mitm6.

**Terminal 2: EvilKDC.** Serves poisoned SRV+A scoped to the realm, answers CLDAP, captures:

```bash
sudo ./EvilKDC.py --domain corp.local --host dc.corp.local --bind 10.10.20.51
```

### Verify before relying on it

```bash
# local preflight: can EvilKDC bind 53/389/88, and does its DNS answer poisoned SRV+A?
sudo ./EvilKDC.py --domain corp.local --host dc.corp.local --bind 10.10.20.51 --check

# end-to-end: is the proxy actually resolving the realm to EvilKDC right now?
sudo ./EvilKDC.py --domain corp.local --bind 10.10.20.51 --check --proxy https://kdcproxy.corp.local/KdcProxy
```

`REDIRECT LIVE` means the proxy located EvilKDC as the DC, so you are in the path and captures will
land. `MISS` means the proxy is not resolving the realm to EvilKDC yet, so fix resolver position first.

---

## Options

```
--domain     target realm to impersonate the DC for (required)
--host       DC dns host to advertise (default dc.<domain>); must match what DNS resolves to EvilKDC
--bind       bind/advertise IP (use your in-path IP if multi-homed; default 0.0.0.0)
--downgrade  offer RC4 only in the pre-auth hint (captures hashcat mode 7500; a client may refuse)
--no-dns     do not run the built-in DNS server (use an external resolver you control)
--loot       file to append captured $krb5pa$ lines (default evilkdc_loot.txt)
--check      preflight: verify listeners + DNS; with --proxy, test whether the redirect is live
--proxy      KDC Proxy URL (used only by --check)
--forest / --nbdomain / --nbcomputer / --site   NetLogon response fields (sane defaults)
```

## Cracking

Captured lines are hashcat `$krb5pa$` format:

```bash
hashcat -m 19900 evilkdc_loot.txt wordlist.txt   # etype 18 / AES256  (default modern)
hashcat -m 19800 evilkdc_loot.txt wordlist.txt   # etype 17 / AES128
hashcat -m 7500  evilkdc_loot.txt wordlist.txt   # etype 23 / RC4     (with --downgrade)
```

Cracking is offline and lockout-free. The real KDC never sees a guess.

---

## Detection & hardening

**Detect**
- KDC Proxy host making outbound 88/464 connections to unexpected IPs (not the real DCs).
- Mass pre-auth failures for external / KKDCP clients (authentication fails through a rogue KDC).
- DHCPv6 `Advertise`/`Reply` from non-DHCP hosts, and new IPv6 DNS servers appearing on member hosts
  (the mitm6 signature).
- CLDAP NetLogon responses whose domain GUID does not match the real domain.

**Harden**
- Set `HttpsClientAuth = 1` under `HKLM\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings` to require
  client-certificate authentication at the service. The HTTP.sys "Negotiate Client Certificate"
  binding setting is request-not-require and is bypassable with an empty certificate, so do not rely
  on it.
- Restrict the KDC Proxy's reachability to its intended front-end only.
- Disable IPv6 if unused, or deploy RA-Guard / DHCPv6-Guard to close the mitm6 path.
- Protect DC-locator DNS integrity; alert on changes to `_msdcs` SRV records.

---

## Requirements

- Python 3, and the packages in `requirements.txt` (`impacket`, `pyasn1`, and `requests` for
  `--check --proxy`)
- `kkcldap.py`, which ships alongside and provides the CLDAP NetLogon responder
- root, to bind udp/53, udp/389, and tcp/88

```bash
pip install -r requirements.txt
```

## Files

- `EvilKDC.py`, the tool
- `kkcldap.py`, the NetLogon CLDAP responder helpers (required)
- `requirements.txt`

## Acknowledgements

EvilKDC builds on prior work in this space and stands on the shoulders of these tools and their
authors:

- **DogWhistle** (`1njected/DogWhistle`): weaponized the KDC Proxy as an attack surface (ASREPRoast,
  Kerberoast, spray, bruteforce *through* the proxy) and documented the IP-laundering and the
  DirectAccess client-certificate reachability behaviour.
- **Dementor** (`matrixeditor/dementor`): a Responder-style toolkit that includes a rogue Kerberos KDC
  for ASREQ-roasting (`PA-ENC-TIMESTAMP` capture), driven by LLMNR/NBT-NS/mDNS poisoning.
- **mitm6** (`dirkjanm/mitm6`): the DHCPv6 primary-DNS-takeover primitive used for the same-subnet
  delivery path.
- **kerbrute** (`ropnop/kerbrute`): Kerberos pre-auth username enumeration and RC4 downgrade.

EvilKDC's specific contribution is the **KDC-Proxy delivery vector**, using the internet-facing proxy
to funnel external clients' pre-authentication to a rogue KDC, together with the measured
characterization of exactly what that requires (see *Prerequisites*): standard-user ADIDNS cannot
redirect the locator, A-record spoofing alone is insufficient because SRV selection wins, there is no
NetBIOS/LLMNR fallback, and SRV+A control from a resolver position achieves full redirect while the
CLDAP identity check does not detect the impersonation.
