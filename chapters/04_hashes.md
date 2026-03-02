# Chapter 4 — Hashes: Integrity and Length Extension

> *"We generated two PDF files with the same SHA-1 hash — one a legitimate contract, the other a backdoored version. Nine quintillion SHA-1 operations and $110,000 in cloud compute later, SHA-1 was dead."*
> — The SHAttered attack (2017)

---

## 4.1 What a Hash Function Does

A cryptographic hash function maps arbitrary input to a fixed-length output with three security properties:

| Property | Definition | Broken = |
|---|---|---|
| **Preimage resistance** | Given `h`, hard to find `m` where `H(m) = h` | Can reverse a hash to find the original input |
| **Second preimage resistance** | Given `m₁`, hard to find `m₂ ≠ m₁` where `H(m₁) = H(m₂)` | Can find a different input that matches a specific hash |
| **Collision resistance** | Hard to find any `m₁ ≠ m₂` where `H(m₁) = H(m₂)` | Can create two different inputs with the same hash |

### Common Hash Functions

```python
import hashlib

message = b"Hash me!"

# MD5 — BROKEN (collisions practical since 2004)
print(f"MD5:      {hashlib.md5(message).hexdigest()}")

# SHA-1 — BROKEN (SHAttered 2017, chosen-prefix 2020)
print(f"SHA-1:    {hashlib.sha1(message).hexdigest()}")

# SHA-256 — Current standard
print(f"SHA-256:  {hashlib.sha256(message).hexdigest()}")

# SHA-3 — Alternative standard (Keccak, different internal structure)
print(f"SHA3-256: {hashlib.sha3_256(message).hexdigest()}")

# BLAKE2 — Fast, modern, used in WireGuard
print(f"BLAKE2b:  {hashlib.blake2b(message).hexdigest()}")
```

---

## 4.2 MD5 Collisions: Still Dangerous

MD5 collisions have been practical since 2004 (Wang & Yu).  In 2008, researchers used MD5 collisions to forge a rogue CA certificate.  The Flame malware (2012) used an MD5 collision to forge Windows Update signatures.

### Generating MD5 Collisions with HashClash

```bash
# Install HashClash (Marc Stevens' tool)
git clone https://github.com/cr-marcstevens/hashclash.git
cd hashclash && mkdir build && cd build && cmake .. && make

# Generate identical-prefix collision (two files with same MD5)
./md5_fastcoll -o collision1.bin collision2.bin

# Verify
md5sum collision1.bin collision2.bin
# Both will show the SAME MD5 hash despite different content!
```

### Detecting MD5 in Your Target

```python
"""
Scan source code for MD5 usage — any of these may be a finding.
"""
import re
import sys
from pathlib import Path

MD5_PATTERNS = [
    r'md5\s*\(',
    r'MD5\s*\(',
    r'hashlib\.md5',
    r'MessageDigest\.getInstance\s*\(\s*["\']MD5',
    r'crypto\.createHash\s*\(\s*["\']md5',
    r'MD5\.Create\(\)',
    r'Digest::MD5',
    r'md5_hex\(',
    r'wp_hash_password',  # WordPress uses MD5
]

def scan_for_md5(path: Path):
    findings = []
    for pattern in MD5_PATTERNS:
        for filepath in path.rglob('*'):
            if filepath.is_file() and filepath.suffix in ('.py', '.js', '.go',
                '.java', '.rb', '.php', '.cs', '.ts'):
                try:
                    content = filepath.read_text(errors='ignore')
                    for i, line in enumerate(content.splitlines(), 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append((filepath, i, line.strip()))
                except Exception:
                    pass
    return findings

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    for fp, line, content in scan_for_md5(target):
        print(f"[MD5] {fp}:{line}  {content[:100]}")
```

---

## 4.3 SHA-1 Collisions: SHAttered and Beyond

### The SHAttered Attack (2017)

Google/CWI produced two PDFs with the same SHA-1 hash.  Cost: ~$110,000 in GPU time.

### Chosen-Prefix Attack (2020)

Leurent & Peyrin upgraded this to a **chosen-prefix** collision: given any two different prefixes, find suffixes that make both files have the same SHA-1.  Cost dropped to ~$45,000.

```python
"""
Check if files are relying on SHA-1 for integrity.
"""
import hashlib
import subprocess

def check_git_sha1():
    """Check if git is using SHA-1 (most installations still do)."""
    result = subprocess.run(
        ['git', 'rev-parse', 'HEAD'],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        commit_hash = result.stdout.strip()
        if len(commit_hash) == 40:  # SHA-1 produces 40 hex chars
            print(f"[!] This git repo uses SHA-1 for object IDs")
            print(f"    Current HEAD: {commit_hash}")
            print(f"    Consider: git config --global init.defaultObjectFormat sha256")
        else:
            print(f"[OK] This git repo may use SHA-256")

check_git_sha1()
```

---

## 4.4 Length Extension Attacks

This is one of the most underappreciated practical crypto attacks.  If an application computes `H(secret || message)` using MD5, SHA-1, or SHA-256, an attacker who knows `H(secret || message)` and `len(secret)` can compute `H(secret || message || padding || extension)` **without knowing the secret**.

### Why It Works: Merkle-Damgård Construction

MD5, SHA-1, and SHA-256 all use the Merkle-Damgård construction:

```
┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐
│ Block 1│──▶│ Block 2│──▶│ Block 3│──▶│  Pad   │──▶ H(m)
└────────┘   └────────┘   └────────┘   └────────┘
     │            │            │            │
   f(IV,B1)→s1  f(s1,B2)→s2  f(s2,B3)→s3  f(s3,pad)→hash

The final hash IS the internal state.
If you know the hash, you know the state after the last block.
You can continue hashing from that point.
```

### Length Extension Attack Implementation

```python
"""
length_extension.py — Exploit the Merkle-Damgård construction
to forge MAC tags computed as H(secret || message).
"""
import struct
import hashlib

def sha256_padding(msg_len: int) -> bytes:
    """Compute SHA-256 padding for a message of given byte length."""
    # SHA-256 padding: 0x80, then zeros, then 64-bit bit length
    bit_len = msg_len * 8
    padding = b'\x80'
    # Pad to 56 mod 64 bytes (448 mod 512 bits)
    padding += b'\x00' * ((55 - msg_len % 64) % 64)
    padding += struct.pack('>Q', bit_len)
    return padding

def sha256_extend(original_hash: str, original_len: int,
                   extension: bytes) -> tuple:
    """
    Given H(secret||msg) and len(secret||msg), compute
    H(secret||msg||padding||extension) without knowing the secret.
    
    Returns: (new_hash, forged_message_suffix)
    """
    # Parse the original hash into SHA-256 state variables
    h = [int(original_hash[i:i+8], 16) for i in range(0, 64, 8)]
    
    # Calculate the padding that was applied to the original message
    pad = sha256_padding(original_len)
    
    # The total length processed so far
    processed_len = original_len + len(pad)
    
    # Now extend: compute SHA-256 starting from the known state
    # We need to use the internal compression function
    # For simplicity, we'll use hashpumpy or hlextend in practice
    
    # The forged message that the victim will see:
    forged_suffix = pad + extension
    
    return forged_suffix

# ─── Practical Example ───
SECRET = b"my_secret_key_123"  # Unknown to attacker
message = b"amount=100&to=alice"

# Server computes this MAC (vulnerable construction)
mac = hashlib.sha256(SECRET + message).hexdigest()
print(f"Original MAC: {mac}")
print(f"Original msg: {message}")

# Attacker knows: mac, len(SECRET)=17, message
# Attacker wants to append: &to=eve&amount=999

# In practice, use hashpump:
# $ hashpump -s <mac> -d <message> -k <secret_len> -a <extension>

print(f"\n[Tool] Use hashpump for the actual attack:")
print(f"  hashpump -s {mac} -d '{message.decode()}' -k {len(SECRET)} "
      f"-a '&to=eve&amount=999'")
```

### Using hashpump (The Practical Tool)

```bash
# Install hashpump
pip install hashpumpy

# Or from source:
git clone https://github.com/bwall/HashPump.git
cd HashPump && make && sudo make install
```

```python
"""
length_extension_hashpump.py — Using hashpumpy for the actual attack.
"""
import hashlib
try:
    import hashpumpy
except ImportError:
    print("pip install hashpumpy")
    exit(1)

SECRET = b"my_secret_key_123"
original_msg = b"amount=100&to=alice"
original_mac = hashlib.sha256(SECRET + original_msg).hexdigest()

# Attack: extend the message without knowing the secret
extension = b"&to=eve&amount=999"
new_mac, new_msg = hashpumpy.hashpump(
    original_mac,
    original_msg,
    extension,
    len(SECRET)  # Attacker must know (or guess) the secret length
)

print(f"Original MAC: {original_mac}")
print(f"Forged MAC:   {new_mac}")
print(f"Forged msg:   {new_msg}")

# Verify: the server will accept this!
verification = hashlib.sha256(SECRET + new_msg).hexdigest()
print(f"\nServer computes: {verification}")
print(f"Forged matches:  {verification == new_mac} ✓")
```

### What's Immune to Length Extension

| Hash | Vulnerable? | Why |
|---|---|---|
| MD5 | ✅ Yes | Merkle-Damgård |
| SHA-1 | ✅ Yes | Merkle-Damgård |
| SHA-256 | ✅ Yes | Merkle-Damgård |
| SHA-512 | ✅ Yes | Merkle-Damgård |
| **SHA-3 (Keccak)** | ❌ No | Sponge construction |
| **BLAKE2** | ❌ No | Different finalization |
| **HMAC** | ❌ No | Double hashing with key |

---

## 4.5 HMAC: The Fix

HMAC (Hash-based Message Authentication Code) prevents length extension by using the key in **both** an inner and outer hash:

```
HMAC(K, m) = H( (K ⊕ opad) || H( (K ⊕ ipad) || m ) )
```

```python
import hmac
import hashlib

secret = b"my_secret_key_123"
message = b"amount=100&to=alice"

# CORRECT: Use HMAC
mac = hmac.new(secret, message, hashlib.sha256).hexdigest()
print(f"HMAC-SHA256: {mac}")

# Verify
def verify_mac(secret, message, received_mac):
    computed = hmac.new(secret, message, hashlib.sha256).hexdigest()
    # Always use constant-time comparison!
    return hmac.compare_digest(computed, received_mac)

print(f"Valid: {verify_mac(secret, message, mac)}")

# Length extension attack FAILS against HMAC
# There is no way to extend the inner hash without knowing K
```

### Common HMAC Mistakes

```python
# ❌ WRONG: H(key || message) — vulnerable to length extension
bad_mac = hashlib.sha256(secret + message).hexdigest()

# ❌ WRONG: H(message || key) — still weak (second preimage)
bad_mac2 = hashlib.sha256(message + secret).hexdigest()

# ❌ WRONG: Non-constant-time comparison
if computed_mac == received_mac:  # TIMING ORACLE!
    pass

# ✅ CORRECT: HMAC with constant-time comparison
good_mac = hmac.new(secret, message, hashlib.sha256).hexdigest()
if hmac.compare_digest(good_mac, received_mac):
    pass
```

---

## 4.6 Lab: Length Extension Attack

```python
"""
lab_length_extension.py

SCENARIO: A web app signs API requests using SHA-256(secret + params).
The API parses parameters left-to-right, so later values override earlier ones.

  Original request:  user=guest&role=viewer
  Original MAC:      <provided>
  Secret length:     16 bytes (you figured this out through enumeration)

GOAL: Forge a valid request with &role=admin appended.

1. Install hashpumpy: pip install hashpumpy
2. Use the length extension to compute new MAC
3. Verify your forged request is accepted by the server
"""
import hashlib
import hashpumpy

SECRET_LEN = 16  # Determined through brute force / info leak
original_msg = b"user=guest&role=viewer"
# In a real scenario, this comes from observing a valid request
SECRET = b"0123456789abcdef"  # We DON'T know this in real attack
original_mac = hashlib.sha256(SECRET + original_msg).hexdigest()

# YOUR ATTACK CODE:
extension = b"&role=admin"
new_mac, new_msg = hashpumpy.hashpump(
    original_mac, original_msg, extension, SECRET_LEN
)

# VERIFY (server-side check)
server_mac = hashlib.sha256(SECRET + new_msg).hexdigest()
assert server_mac == new_mac, "Attack failed!"

# Parse the forged parameters (last role= wins)
params = new_msg.split(b'&')
role_values = [p.split(b'=')[1] for p in params if p.startswith(b'role=')]
print(f"Forged role: {role_values[-1].decode()}")  # admin!
print(f"Attack successful ✓")
```

---

## 4.7 Key Takeaways

- **MD5 and SHA-1** have practical collision attacks — never use them for integrity or signatures.
- **Length extension** is a devastating attack against `H(secret||message)` — use HMAC instead.
- **HMAC** prevents length extension and is the correct way to build MACs from hash functions.
- **SHA-3 and BLAKE2** are immune to length extension by design.
- Always use **constant-time comparison** (`hmac.compare_digest`) for MAC verification.
- When auditing, scan for `md5()`, `sha1()`, and `H(key||msg)` patterns — they're common findings.

---

**Next:** [Chapter 5 — Passwords & Slow-Hash Logic →](05_passwords.md)
