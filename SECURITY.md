# Security & Authorized Use

## Intended use

EvilKDC is an offensive-security research and red-team tool. It captures Kerberos
pre-authentication material by impersonating a domain controller to a Windows KDC Proxy. It is
intended **only** for use against systems that you own or for which you have **explicit, written
authorization** to test (for example, a signed penetration-test scope or engagement letter).

Do not run EvilKDC, or the network-takeover steps it documents (such as mitm6-based DHCPv6 DNS
takeover), on any network or host you are not authorized to assess. Doing so may be illegal and can
disrupt production services. The DNS/resolver-takeover step is deliberately not built into this tool
so that it remains a conscious, scoped action by the operator.

## No warranty / liability

This software is provided "as is", without warranty of any kind (see LICENSE). The author is not
responsible for misuse or for any damage resulting from its use. You are responsible for operating
within the law and within the bounds of your authorization.

## Operating notes

- Requires root and binds udp/53, udp/389, and tcp/88.
- Authentication fails for victims through the rogue KDC by design (no real TGT is issued); this is a
  detectable side effect. See "Detection & hardening" in the README.
- Captured credential material (`*_loot.txt`) is sensitive. Store, transmit, and dispose of it per
  your engagement's handling rules; do not commit it to version control.

## Reporting a vulnerability in EvilKDC

If you find a security issue in this tool itself (as opposed to the Windows KDC Proxy behavior it
demonstrates), please open an issue or contact the maintainer at https://cbev0x.github.io rather than
disclosing it in a way that could harm downstream users.

## Note on the underlying Microsoft behavior

The KDC Proxy behaviors this tool exercises (unauthenticated relay, the `HttpsClientAuth` default and
the HTTP.sys "negotiate ≠ require" client-certificate handling, and DC-locator trust in DNS + an
unauthenticated CLDAP response) are characteristics of the target service, not vulnerabilities in this
tool. Hardening guidance is documented in the README so defenders can act on it.
