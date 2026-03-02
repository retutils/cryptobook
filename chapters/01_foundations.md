# Chapter 1 — Why Cryptography Fails

> *"We discovered that Adobe had encrypted their users' passwords with 3DES in ECB mode, using the same key for every single password. Over 150 million credentials were exposed — not because 3DES was broken, but because someone chose the worst possible way to use it."*
> — Analysis of the 2013 Adobe breach

---

## 1.1 Cryptography, Cryptanalysis, and Crypto

Before we break anything, let's agree on vocabulary.

| Term | Meaning |
|---|---|
| **Cryptography** | The science of designing systems that protect data confidentiality, integrity, and authenticity |
| **Cryptanalysis** | The science of breaking those systems |
| **Crypto** | In this book: shorthand for cryptography and its implementations (not cryptocurrency) |

As offensive security practitioners, we live in the cryptanalysis lane — but we rarely attack the math.  We attack the **implementation**, the **configuration**, the **protocol**, and the **developer assumptions**.

---

## 1.2 The Weakest-Link Mental Model

Every cryptographic system is a chain:

```
┌──────────┐    ┌───────────┐    ┌──────────┐    ┌───────────┐
│ Algorithm │───▶│   Mode    │───▶│   Key    │───▶│  Protocol │
│ (AES-256) │    │ (CBC/GCM) │    │ Mgmt     │    │ (TLS 1.3) │
└──────────┘    └───────────┘    └──────────┘    └───────────┘
       │               │               │               │
       ▼               ▼               ▼               ▼
   Rarely the      Often the       Almost always    Where most
   weak link       weak link       a weak link      bugs live
```

**You only need to break one link.**

In nearly two decades of real-world crypto failures, the algorithm itself is almost never the problem.  The problems cluster around:

1. **Misuse** — correct algorithm, incorrect application
2. **Downgrade** — forcing a weaker algorithm or protocol version
3. **Key management** — hardcoded keys, poor rotation, leaky storage
4. **Randomness** — predictable IVs, nonces, or seeds
5. **Side channels** — timing, error messages, compression ratios

---

## 1.3 Failure Category: Misuse

Cryptographic misuse means using a correct, strong primitive in a way that destroys its security guarantees.

### Example: ECB Mode

AES-256 is considered unbreakable.  AES-256-ECB can leak your entire plaintext structure.

```python
from Crypto.Cipher import AES
import os

key = os.urandom(32)  # 256-bit key — perfectly strong

# ECB mode: each block encrypted independently
cipher_ecb = AES.new(key, AES.MODE_ECB)

# Repeating plaintext blocks produce repeating ciphertext blocks
block = b"YELLOW SUBMARINE"  # exactly 16 bytes
plaintext = block * 4  # 64 bytes of repeated blocks

ciphertext = cipher_ecb.encrypt(plaintext)

# All four 16-byte ciphertext blocks will be IDENTICAL
blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
print(f"All blocks identical: {len(set(blocks)) == 1}")  # True
```

The algorithm is fine.  The **mode** is the vulnerability.  This is exactly what Adobe did with 150 million passwords.

### Example: Nonce Reuse

AES-GCM is an authenticated encryption mode — the gold standard.  Reuse a nonce and you lose **both** confidentiality and authenticity.

```python
from Crypto.Cipher import AES
import os

key = os.urandom(32)
nonce = os.urandom(12)  # This MUST be unique per encryption

# First encryption — fine
cipher1 = AES.new(key, AES.MODE_GCM, nonce=nonce)
ct1, tag1 = cipher1.encrypt_and_digest(b"Transfer $100 to Alice")

# Second encryption — REUSING THE SAME NONCE
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
ct2, tag2 = cipher2.encrypt_and_digest(b"Transfer $999 to Eve!!")

# XOR the two ciphertexts to eliminate the keystream
xored = bytes(a ^ b for a, b in zip(ct1, ct2))
print(f"XOR of ciphertexts: {xored}")
# This XOR reveals the XOR of the two plaintexts — a classic crib drag target
# Worse: the authentication key (GHASH H) can be recovered
```

---

## 1.4 Failure Category: Downgrade Attacks

A downgrade attack forces a system to use a weaker version of a protocol or cipher suite that the attacker can break.

### Notable Downgrade Attacks

| Attack | Year | What was downgraded | Impact |
|---|---|---|---|
| **FREAK** | 2015 | RSA key exchange → 512-bit "export" RSA | MitM decryption |
| **Logjam** | 2015 | Diffie-Hellman → 512-bit DH | MitM decryption |
| **POODLE** | 2014 | TLS → SSL 3.0 | CBC padding oracle |
| **DROWN** | 2016 | TLS → SSLv2 (cross-protocol) | RSA key recovery |
| **Bar Mitzvah** | 2015 | TLS → RC4 suite | Plaintext recovery |

### Scanning for Downgrade Vulnerabilities

```bash
# Test for supported protocols and cipher suites
testssl.sh --protocols --cipher-per-proto target.com:443

# Quick check with nmap
nmap --script ssl-enum-ciphers -p 443 target.com

# Check for specific downgrade issues
sslyze --regular target.com
```

```python
"""
Quick Python check: does the server accept SSLv3 or weak suites?
"""
import ssl
import socket

def test_protocol(host, port, protocol):
    """Test if a host accepts a specific SSL/TLS protocol."""
    context = ssl.SSLContext(protocol)
    context.set_ciphers('ALL:@SECLEVEL=0')  # Allow weak ciphers for testing
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"[VULNERABLE] {host} accepts {ssock.version()}")
                return True
    except (ssl.SSLError, ConnectionError, OSError) as e:
        print(f"[OK] {host} rejects protocol: {e}")
        return False

# Test legacy protocols (these should all fail on a secure server)
test_protocol("target.com", 443, ssl.PROTOCOL_TLSv1)
test_protocol("target.com", 443, ssl.PROTOCOL_TLSv1_1)
```

---

## 1.5 Failure Category: Key Management

The strongest cipher in the world is useless if the key is:

- **Hardcoded** in source code or configuration files
- **Stored alongside** the encrypted data
- **Never rotated**
- **Shared** across environments (dev = staging = prod)
- **Derived** from predictable inputs

### Finding Hardcoded Keys and Secrets

```bash
# grep for high-entropy strings in source code
grep -rn --include="*.py" --include="*.js" --include="*.go" \
  -E '(key|secret|password|token)\s*=\s*["\x27][A-Za-z0-9+/=]{16,}' .

# Use trufflehog for entropy-based secret detection
trufflehog filesystem --directory . --only-verified

# Search git history for secrets that were "removed"
trufflehog git file://. --since-commit HEAD~100

# Check environment variables in Docker images
docker history --no-trunc <image> | grep -iE 'key|secret|password'
```

```python
"""
Detect common key management anti-patterns in Python source files.
"""
import re
import sys
from pathlib import Path

PATTERNS = [
    # Hardcoded hex keys
    (r'(?:key|secret|iv|nonce)\s*=\s*b?["\x27]([0-9a-fA-F]{32,})["\x27]',
     "Hardcoded hex key/secret"),
    # Base64-encoded keys
    (r'(?:key|secret)\s*=\s*b?["\x27]([A-Za-z0-9+/]{22,}={0,2})["\x27]',
     "Hardcoded base64 key/secret"),
    # Static IVs
    (r'(?:iv|nonce)\s*=\s*b?["\x27](.{8,})["\x27]',
     "Static IV/nonce"),
    # Key derived from deterministic input
    (r'(?:PBKDF2|scrypt|hkdf).*(?:salt\s*=\s*b?["\x27]{2}|salt\s*=\s*b?["\x27]\w+["\x27])',
     "Weak/static salt in KDF"),
]

def scan_file(filepath):
    findings = []
    content = filepath.read_text(errors='ignore')
    for pattern, description in PATTERNS:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count('\n') + 1
            findings.append((line_num, description, match.group(0)[:80]))
    return findings

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    for pyfile in target.rglob("*.py"):
        for line, desc, snippet in scan_file(pyfile):
            print(f"{pyfile}:{line} [{desc}] {snippet}")
```

---

## 1.6 Failure Category: Randomness

Cryptographic security depends on unpredictability.  When randomness fails, everything built on it collapses.

### Sources of Bad Randomness

| Source | Problem |
|---|---|
| `random.random()` (Python) | Mersenne Twister — predictable after 624 outputs |
| `Math.random()` (JavaScript) | xorshift128+ — recoverable internal state |
| `java.util.Random` | Linear congruential generator — trivially predictable |
| Low-entropy seed | `srand(time(NULL))` — ~1 second resolution |
| `/dev/urandom` at early boot | VM clones may share entropy pool |

### Exploiting Python's `random` Module

```python
"""
Demonstrate why random.random() must NEVER be used for security.
Python's random module uses a Mersenne Twister PRNG.
After observing 624 consecutive 32-bit outputs, the full internal
state can be recovered and all future outputs predicted.
"""
import random

# Simulate: attacker observes 624 outputs from the target application
target_rng = random.Random(42)  # unknown seed
observed = [target_rng.getrandbits(32) for _ in range(624)]

# Reconstruct internal state
def untemper(y):
    """Reverse the Mersenne Twister tempering transform."""
    # Undo: y ^= y >> 18  (top 18 bits unchanged, simple)
    y ^= y >> 18
    # Undo: y ^= (y << 15) & 0xEFC60000  (bottom 15 bits unchanged)
    y ^= (y << 15) & 0xEFC60000
    # Undo: y ^= (y << 7) & 0x9D2C5680
    # Bottom 7 bits are unchanged; recover 7 bits at a time
    tmp = y
    for _ in range(4):
        tmp = y ^ (tmp << 7) & 0x9D2C5680
    y = tmp
    # Undo: y ^= y >> 11  (top 11 bits unchanged; recover in two steps)
    y ^= (y >> 11) & 0xFFE00000  # bits 21–31 correct → recover bits 10–20
    y ^= y >> 22                 # then recover bits 0–9
    return y

# Clone the RNG
cloned_rng = random.Random()
state = [untemper(x) for x in observed]
cloned_rng.setstate((3, tuple(state + [624]), None))

# Predict the next outputs
for _ in range(10):
    real = target_rng.getrandbits(32)
    predicted = cloned_rng.getrandbits(32)
    assert real == predicted, "Prediction failed!"
    print(f"Predicted: {predicted} == Actual: {real} ✓")

print("\n[+] Successfully cloned the PRNG — all future outputs are predictable")
```

### What to Use Instead

```python
import secrets
import os

# Cryptographically secure random bytes
key = secrets.token_bytes(32)       # 256-bit key
nonce = os.urandom(12)              # 96-bit nonce
session_id = secrets.token_hex(16)  # 128-bit hex token
api_token = secrets.token_urlsafe(32)  # URL-safe base64 token
```

---

## 1.7 Threat Modeling for Crypto

When you're on an engagement, you can't test everything.  Here's a prioritized checklist for assessing cryptographic posture:

### Quick-Reference Crypto Assessment Checklist

```
┌─────────────────────────────────────────────────────────┐
│              CRYPTO ASSESSMENT CHECKLIST                │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  □ TRANSPORT                                            │
│    □ TLS version (reject < 1.2)                         │
│    □ Cipher suites (no RC4, DES, 3DES, export)          │
│    □ Certificate validation in client code              │
│    □ Certificate pinning (mobile apps)                  │
│                                                         │
│  □ DATA AT REST                                         │
│    □ Algorithm and mode (AES-GCM / ChaCha20-Poly1305)   │
│    □ Key storage (HSM / KMS / file / env var?)          │
│    □ IV/nonce generation (random? counter? static?)     │
│    □ Key rotation policy                                │
│                                                         │
│  □ AUTHENTICATION                                       │
│    □ Password hashing (bcrypt/scrypt/argon2 + cost)     │
│    □ Token format (JWT? session? API key?)              │
│    □ Token signing algorithm and key management         │
│    □ Session entropy and lifecycle                      │
│                                                         │
│  □ SECRETS                                              │
│    □ Hardcoded keys / passwords in source               │
│    □ Secrets in git history                             │
│    □ Secrets in environment variables / config files    │
│    □ Secrets in logs or error messages                  │
│                                                         │
│  □ RANDOMNESS                                           │
│    □ CSPRNG usage for all security-sensitive values      │
│    □ Sufficient entropy at generation time               │
│    □ No predictable seeds                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Automated Initial Assessment

```python
"""
crypto_triage.py — Quick automated crypto posture check for a target host.
Combines SSL/TLS checks with header analysis.
"""
import ssl
import socket
import json
from urllib.request import urlopen, Request
from urllib.error import URLError

def check_tls(host, port=443):
    """Check TLS configuration of a target host."""
    results = {"host": host, "issues": []}
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                
                results["tls_version"] = version
                results["cipher_suite"] = cipher[0]
                results["cipher_bits"] = cipher[2]
                
                # Check for weak TLS versions
                if version in ("TLSv1", "TLSv1.1"):
                    results["issues"].append(
                        f"CRITICAL: Server uses deprecated {version}"
                    )
                
                # Check cipher strength
                if cipher[2] < 128:
                    results["issues"].append(
                        f"WEAK: Cipher {cipher[0]} uses only {cipher[2]} bits"
                    )
                
                # Check certificate expiry
                import datetime
                not_after = datetime.datetime.strptime(
                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                )
                days_left = (not_after - datetime.datetime.utcnow()).days
                if days_left < 30:
                    results["issues"].append(
                        f"WARNING: Certificate expires in {days_left} days"
                    )
                    
    except ssl.SSLError as e:
        results["issues"].append(f"SSL Error: {e}")
    except Exception as e:
        results["issues"].append(f"Connection error: {e}")
    
    return results

def check_security_headers(host):
    """Check for crypto-relevant security headers."""
    headers_to_check = {
        "Strict-Transport-Security": "Missing HSTS header",
        "Content-Security-Policy": "Missing CSP header",
    }
    results = {"issues": []}
    
    try:
        req = Request(f"https://{host}", method="HEAD")
        resp = urlopen(req, timeout=10)
        for header, issue in headers_to_check.items():
            if header.lower() not in [h.lower() for h in resp.headers]:
                results["issues"].append(f"INFO: {issue}")
            else:
                results[header] = resp.headers[header]
    except URLError as e:
        results["issues"].append(f"HTTP Error: {e}")
    
    return results

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    
    print(f"\n{'='*60}")
    print(f" Crypto Triage: {target}")
    print(f"{'='*60}\n")
    
    tls = check_tls(target)
    print(f"TLS Version:  {tls.get('tls_version', 'N/A')}")
    print(f"Cipher Suite: {tls.get('cipher_suite', 'N/A')}")
    print(f"Key Bits:     {tls.get('cipher_bits', 'N/A')}")
    
    headers = check_security_headers(target)
    
    all_issues = tls["issues"] + headers["issues"]
    if all_issues:
        print(f"\n⚠️  Issues Found ({len(all_issues)}):")
        for issue in all_issues:
            print(f"  • {issue}")
    else:
        print("\n✅ No obvious crypto issues detected")
```

---

## 1.8 Key Takeaways

- **Crypto fails at the implementation layer**, not the math layer.  Your targets are misuse, downgrade, key management, randomness, and side channels.
- **ECB, nonce reuse, hardcoded keys** — these are the low-hanging fruit you'll find on nearly every engagement.
- **Use the checklist** to structure your crypto assessment.  Prioritize transport → secrets → authentication → data-at-rest.
- **Automate the boring parts** — TLS scanning, secret detection in code, header checks — so you can spend time on the creative attacks.
- The rest of this book dives deep into each failure category.  You'll learn not just *what* breaks, but *how* to break it, *prove* it, and *report* it.

---

**Next:** [Chapter 2 — XOR, OTP, and Stream Failures →](02_streams.md)
