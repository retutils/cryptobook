# Chapter 9 — TLS: Handshakes & Transport Realities

> *"DROWN showed that enabling SSLv2 on even a separate server with the same RSA key could decrypt TLS 1.2 sessions.  33% of all HTTPS servers were vulnerable at disclosure."*
> — The DROWN attack (2016)

---

## 9.1 TLS 1.2 vs. TLS 1.3 Handshake

### TLS 1.2 Handshake (2 round trips)

```
Client                              Server
  │                                    │
  │──── ClientHello ──────────────────▶│  (supported versions, cipher suites,
  │                                    │   random, extensions)
  │◀─── ServerHello ──────────────────│  (chosen version, cipher suite, random)
  │◀─── Certificate ──────────────────│  (server's X.509 cert chain)
  │◀─── ServerKeyExchange ────────────│  (DH/ECDH parameters + signature)
  │◀─── ServerHelloDone ──────────────│
  │                                    │
  │──── ClientKeyExchange ────────────▶│  (client's DH/ECDH share)
  │──── ChangeCipherSpec ─────────────▶│  (switching to encrypted)
  │──── Finished ─────────────────────▶│  (MAC of handshake transcript)
  │                                    │
  │◀─── ChangeCipherSpec ──────────────│
  │◀─── Finished ──────────────────────│
  │                                    │
  │◀═══ Encrypted Application Data ═══▶│
```

### TLS 1.3 Handshake (1 round trip)

```
Client                              Server
  │                                    │
  │──── ClientHello + KeyShare ───────▶│  (versions, ciphers, ECDH share)
  │                                    │
  │◀─── ServerHello + KeyShare ────────│  (chosen cipher, ECDH share)
  │◀─── {EncryptedExtensions} ─────────│  ← encrypted from here
  │◀─── {Certificate} ─────────────────│
  │◀─── {CertificateVerify} ───────────│
  │◀─── {Finished} ────────────────────│
  │                                    │
  │──── {Finished} ───────────────────▶│
  │                                    │
  │◀═══ Encrypted Application Data ═══▶│
```

Key improvements in TLS 1.3:
- **Removed**: RSA key exchange, static DH, RC4, 3DES, CBC mode, SHA-1, compression, renegotiation
- **Added**: Forward secrecy mandatory (ECDHE/DHE), 0-RTT (with replay protection), encrypted certificate

---

## 9.2 Inspecting TLS Configuration

### testssl.sh — The Gold Standard

```bash
# Full scan
testssl.sh target.com:443

# Quick checks
testssl.sh --protocols target.com:443          # Protocol versions
testssl.sh --ciphers target.com:443            # Cipher suites
testssl.sh --vulnerabilities target.com:443    # Known CVEs
testssl.sh --headers target.com:443            # Security headers

# Specific vulnerability checks
testssl.sh --poodle target.com:443
testssl.sh --robot target.com:443
testssl.sh --heartbleed target.com:443
testssl.sh --freak target.com:443
testssl.sh --logjam target.com:443
testssl.sh --drown target.com:443

# JSON output for reporting
testssl.sh --jsonfile results.json target.com:443
```

### sslyze — Python-Based Scanner

```bash
pip install sslyze
sslyze target.com

# Specific checks
sslyze --certinfo target.com
sslyze --robot target.com
sslyze --heartbleed target.com
```

### OpenSSL CLI

```bash
# Check supported protocols
for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
    echo | openssl s_client -connect target.com:443 \
      -$proto 2>/dev/null | head -5
done

# Dump the certificate chain
openssl s_client -connect target.com:443 -showcerts </dev/null 2>/dev/null | \
  openssl x509 -text -noout

# Check specific cipher suite
openssl s_client -connect target.com:443 -cipher RC4-SHA </dev/null

# Verify certificate
openssl s_client -connect target.com:443 -verify_return_error </dev/null
```

### Python TLS Scanner

```python
"""
tls_scanner.py — Quick TLS configuration audit.
"""
import ssl
import socket
import json

def scan_tls(host: str, port: int = 443) -> dict:
    """Comprehensive TLS scan of a target host."""
    results = {
        "host": host,
        "protocol": None,
        "cipher": None,
        "certificate": {},
        "issues": [],
    }
    
    # Check supported protocols
    protocols_to_test = {
        "TLSv1":   ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
    }
    
    for name, proto in protocols_to_test.items():
        if proto is None:
            continue
        try:
            ctx = ssl.SSLContext(proto)
            ctx.set_ciphers('ALL:@SECLEVEL=0')
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results["issues"].append(
                        f"WARN: Accepts deprecated {name}"
                    )
        except (ssl.SSLError, OSError):
            pass
    
    # Get current connection details
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                results["protocol"] = ssock.version()
                cipher = ssock.cipher()
                results["cipher"] = {
                    "name": cipher[0],
                    "version": cipher[1],
                    "bits": cipher[2],
                }
                
                cert = ssock.getpeercert()
                results["certificate"] = {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                    "serialNumber": cert.get('serialNumber'),
                    "san": [x[1] for x in cert.get('subjectAltName', [])],
                }
                
                # Check cipher strength
                if cipher[2] < 128:
                    results["issues"].append(
                        f"CRITICAL: Weak cipher ({cipher[0]}, {cipher[2]} bits)"
                    )
                
                # Check for forward secrecy
                if 'ECDHE' not in cipher[0] and 'DHE' not in cipher[0]:
                    results["issues"].append(
                        "WARN: No forward secrecy (no ECDHE/DHE)"
                    )
                    
    except Exception as e:
        results["issues"].append(f"ERROR: {e}")
    
    return results

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = scan_tls(target)
    print(json.dumps(result, indent=2))
```

---

## 9.3 Certificate Validation Pitfalls

### Common Certificate Issues

```python
"""
cert_check.py — Check for certificate validation issues.
"""
import ssl
import socket
from datetime import datetime

def audit_certificate(host: str, port: int = 443):
    """Check for common certificate problems."""
    issues = []
    
    # 1. Self-signed or untrusted CA
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        issues.append(f"CRITICAL: Certificate validation failed: {e}")
        # Connect without verification to inspect the cert anyway
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock) as ssock:
                cert = ssock.getpeercert(binary_form=True)
        return {"issues": issues}
    
    # 2. Expiry check
    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    days_left = (not_after - datetime.utcnow()).days
    if days_left < 0:
        issues.append(f"CRITICAL: Certificate expired {abs(days_left)} days ago")
    elif days_left < 30:
        issues.append(f"WARNING: Certificate expires in {days_left} days")
    
    # 3. Weak key check (via cert details)
    # In TLS 1.2, RSA keys < 2048 bits are weak
    
    # 4. SAN mismatch
    san = [x[1] for x in cert.get('subjectAltName', [])]
    if host not in san and f"*.{host.split('.', 1)[-1]}" not in san:
        issues.append(f"WARNING: Hostname {host} not in SAN: {san}")
    
    # 5. Wildcard certificate scope
    wildcards = [s for s in san if s.startswith('*')]
    if wildcards:
        issues.append(f"INFO: Wildcard cert covers: {wildcards}")
    
    return {"cert": cert, "days_until_expiry": days_left, "issues": issues}

# Usage:
# result = audit_certificate("target.com")
# for issue in result["issues"]:
#     print(issue)
```

### Certificate Pinning Bypass (Mobile)

```bash
# Frida-based SSL pinning bypass (Android)
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# objection (built on Frida)
objection -g com.target.app explore
> android sslpinning disable

# For iOS
objection -g com.target.app explore
> ios sslpinning disable
```

---

## 9.4 Notable TLS Attacks

### POODLE (2014) — SSL 3.0 Downgrade + CBC Padding Oracle

```python
"""
POODLE exploits SSL 3.0's non-deterministic CBC padding.
Unlike TLS (which uses PKCS#7), SSL 3.0 allows any padding bytes
as long as the last byte indicates the padding length.
This creates a padding oracle.
"""
print("""
POODLE Attack Flow:
1. Force victim's browser to make requests (via JavaScript)
2. Man-in-the-Middle: strip TLS, downgrade to SSL 3.0
3. For each request, move the target byte (cookie char) to the
   end of a CBC block
4. Replace the last encrypted block with the target block
5. If the server accepts (valid padding) → you've decrypted one byte
6. Probability: 1/256 per attempt → ~256 requests per byte
7. Total: ~256 * cookie_length requests to steal the session cookie
""")
```

### Heartbleed (2014) — OpenSSL Memory Disclosure

```python
"""
heartbleed_check.py — Check for Heartbleed (CVE-2014-0160).
"""
import socket
import struct

def check_heartbleed(host: str, port: int = 443) -> bool:
    """
    Send a heartbeat request with a claimed length larger than
    the actual payload. Vulnerable servers return extra memory.
    """
    # TLS ClientHello
    hello = bytes.fromhex(
        "16030100dc010000d80302534116"  # Truncated for brevity
        # ... full ClientHello needed for real test
    )
    
    # Heartbeat request: claim 16384 bytes, send only 1 byte
    heartbeat = bytes.fromhex(
        "18030200030100"  # type=heartbeat, version=TLS1.1, length=3
        # payload_length=0x0100 (256 bytes) but actual payload is 0 bytes
    )
    
    print(f"[*] Testing {host}:{port} for Heartbleed...")
    print(f"    Use nmap for reliable detection:")
    print(f"    nmap -p {port} --script ssl-heartbleed {host}")
    
    return False  # Placeholder — use nmap/testssl for real testing

# Better: use established tools
print("""
Heartbleed Detection:
  nmap -p 443 --script ssl-heartbleed target.com
  testssl.sh --heartbleed target.com:443
  sslyze --heartbleed target.com
""")
```

---

## 9.5 mTLS in Microservices

Mutual TLS (mTLS) is widely used in Kubernetes/microservice architectures.  Common weaknesses:

```python
"""
mtls_audit.py — Check mTLS configuration issues.
"""
import ssl
import socket

def check_mtls(host: str, port: int, 
               client_cert: str = None, 
               client_key: str = None):
    """Test mTLS requirements and configuration."""
    
    # 1. Does the server require client certificates?
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"[!] Server does NOT require client certificate")
                print(f"    This may be a finding in zero-trust environments")
    except ssl.SSLError as e:
        if "certificate required" in str(e).lower():
            print(f"[OK] Server requires client certificate")
        else:
            print(f"[?] SSL error: {e}")
    
    # 2. Does it accept self-signed client certs?
    if client_cert and client_key:
        try:
            ctx = ssl.create_default_context()
            ctx.load_cert_chain(client_cert, client_key)
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    print(f"[OK] Client cert accepted, connection established")
        except ssl.SSLError as e:
            print(f"[!] Client cert rejected: {e}")

print("""
mTLS Audit Checklist:
  □ Is client certificate required?
  □ Is the client CA properly restricted?
  □ Are client certificates validated (not just present)?
  □ Is certificate revocation checking enabled (CRL/OCSP)?
  □ Are client certificate subjects/SANs checked for authorization?
  □ Is the CA certificate properly protected?
  □ Is certificate rotation automated?
""")
```

---

## 9.6 TLS Testing Methodology

```bash
# ── COMPREHENSIVE TLS AUDIT ──

# 1. Protocol versions
echo "=== Protocols ==="
testssl.sh --protocols target.com:443

# 2. Cipher suites
echo "=== Cipher Suites ==="
testssl.sh --ciphers target.com:443

# 3. Known vulnerabilities
echo "=== Vulnerabilities ==="
testssl.sh --vulnerable target.com:443

# 4. Certificate chain
echo "=== Certificate ==="
testssl.sh --certinfo target.com:443

# 5. HTTP security headers
echo "=== Headers ==="
testssl.sh --headers target.com:443

# 6. Quick one-liner summary
echo "=== Full Report ==="
testssl.sh --json target.com:443
```

---

## 9.7 Key Takeaways

- **TLS 1.3** eliminates entire attack classes: no RSA key exchange, no CBC mode, forward secrecy is mandatory
- **TLS 1.0 and 1.1** are deprecated — their presence is a finding
- **testssl.sh** is your primary tool for TLS assessments — it covers protocols, ciphers, certificates, and known CVEs
- **Certificate validation** is a common source of bugs — disabled verification in code, expired certs, wrong hostnames
- **Certificate pinning bypass** is routine for mobile app testing (Frida/objection)
- **mTLS** in microservices often has gaps: missing client cert validation, overly broad CAs, no revocation checking
- **The big TLS attacks** (POODLE, DROWN, Heartbleed, ROBOT) are all well-tooled — scan for them on every engagement

---

**Next:** [Chapter 10 — Cloud KMS & IAM Boundaries →](10_cloud.md)
