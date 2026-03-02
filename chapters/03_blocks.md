# Chapter 3 — Block Ciphers: Structure and Tampering

> *"The padding oracle in ASP.NET let us decrypt any ciphertext and forge any cookie — all by observing whether the server returned a 200 or a 500. Microsoft rated it Critical and patched it within days."*
> — CVE-2010-3332 (Padding Oracle / POET attack)

---

## 3.1 Block Cipher Basics

Unlike stream ciphers that process data byte-by-byte, block ciphers operate on **fixed-size blocks**.

| Cipher | Block Size | Key Sizes | Status |
|---|---|---|---|
| DES | 64 bits (8 bytes) | 56 bits | ❌ Broken — brute-forceable |
| 3DES | 64 bits | 112/168 bits | ⚠️ Deprecated (Sweet32) |
| AES | 128 bits (16 bytes) | 128/192/256 bits | ✅ Standard |
| Blowfish | 64 bits | 32–448 bits | ⚠️ Legacy (small block) |

AES is the only block cipher you should encounter in modern systems.  If you see DES, 3DES, or Blowfish — that's already a finding.

### AES in 30 Seconds

AES takes a 16-byte plaintext block and a key, runs 10/12/14 rounds (for 128/192/256-bit keys) of substitution-permutation operations, and produces a 16-byte ciphertext block.  The algorithm itself is solid.  **The vulnerability is always in how blocks are chained together** — the **mode of operation**.

---

## 3.2 Modes of Operation

A mode of operation defines how a block cipher processes messages longer than one block.

### ECB — Electronic Codebook

Each block is encrypted independently with the same key.

```python
from Crypto.Cipher import AES
import os

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

# Identical plaintext blocks → identical ciphertext blocks
block_a = b"AAAAAAAAAAAAAAAA"  # 16 bytes
block_b = b"BBBBBBBBBBBBBBBB"

ct_a1 = cipher.encrypt(block_a)
ct_a2 = cipher.encrypt(block_a)  # Same input
ct_b  = cipher.encrypt(block_b)

print(f"ct(A) == ct(A): {ct_a1 == ct_a2}")  # True!
print(f"ct(A) == ct(B): {ct_a1 == ct_b}")   # False

# This is why ECB leaks patterns — the "ECB penguin" problem
```

### CBC — Cipher Block Chaining

Each plaintext block is XORed with the previous ciphertext block before encryption.  Requires an IV.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)
iv = os.urandom(16)  # Must be random, unpredictable, unique

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
plaintext = b"Same block repeated sixteen times"
ciphertext = cipher.encrypt(pad(plaintext, 16))

# Decrypt
cipher_dec = AES.new(key, AES.MODE_CBC, iv=iv)
decrypted = unpad(cipher_dec.decrypt(ciphertext), 16)
assert decrypted == plaintext
```

### CTR — Counter Mode

Turns a block cipher into a stream cipher by encrypting sequential counter values.

```python
from Crypto.Cipher import AES
import os

key = os.urandom(16)
nonce = os.urandom(8)  # 8-byte nonce for AES-CTR

cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(b"No padding needed - any length works")

cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)
plaintext = cipher_dec.decrypt(ciphertext)
print(plaintext.decode())
```

### GCM — Galois/Counter Mode

CTR + authentication.  The gold standard for AEAD.

```python
from Crypto.Cipher import AES
import os

key = os.urandom(32)   # 256-bit key
nonce = os.urandom(12)  # 96-bit nonce — MUST be unique

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher.update(b"authenticated but unencrypted header")  # AAD
ciphertext, tag = cipher.encrypt_and_digest(b"secret payload")

# Decrypt and verify
cipher_dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher_dec.update(b"authenticated but unencrypted header")
try:
    plaintext = cipher_dec.decrypt_and_verify(ciphertext, tag)
    print(f"Decrypted: {plaintext.decode()}")
except ValueError:
    print("TAMPERED — authentication failed!")
```

---

## 3.3 Attack: ECB Pattern Leakage

ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks.  This leaks structure.

### The ECB Penguin

```python
"""
ecb_penguin.py — Demonstrate how ECB mode leaks image structure.
Encrypt a bitmap image with ECB and observe that the image
structure is preserved in the ciphertext.
"""
from Crypto.Cipher import AES
import os

def ecb_encrypt_bmp(input_path: str, output_path: str):
    """Encrypt a BMP file with AES-ECB, preserving the header."""
    with open(input_path, 'rb') as f:
        header = f.read(54)      # BMP header (unencrypted)
        body = f.read()          # Pixel data
    
    # Pad body to multiple of 16
    padded = body + b'\x00' * (16 - len(body) % 16)
    
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_body = cipher.encrypt(padded)
    
    with open(output_path, 'wb') as f:
        f.write(header)
        f.write(encrypted_body[:len(body)])
    
    print(f"[+] ECB-encrypted BMP saved to {output_path}")
    print(f"[!] Open both images — the structure is still visible!")

# Usage: ecb_encrypt_bmp("penguin.bmp", "penguin_ecb.bmp")
```

### Detecting ECB in the Wild

```python
"""
Detect ECB mode by looking for repeated ciphertext blocks.
"""
def detect_ecb(ciphertext: bytes, block_size: int = 16) -> dict:
    """Check if ciphertext has repeated blocks (ECB indicator)."""
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    
    total = len(blocks)
    unique = len(set(blocks))
    repeated = total - unique
    
    return {
        "total_blocks": total,
        "unique_blocks": unique,
        "repeated_blocks": repeated,
        "likely_ecb": repeated > 0,
        "repetition_ratio": repeated / total if total > 0 else 0
    }

# Test with ECB-encrypted data
key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)
# Simulated structured data (like Adobe's password database)
plaintext = b"password12345678" * 100  # Repeated 16-byte blocks
ct = cipher.encrypt(plaintext)

result = detect_ecb(ct)
print(f"Likely ECB: {result['likely_ecb']}")
print(f"Repeated blocks: {result['repeated_blocks']}/{result['total_blocks']}")
```

---

## 3.4 Attack: CBC Padding Oracle

The **padding oracle attack** (Vaudenay, 2002) is one of the most important practical crypto attacks.  It lets you decrypt any CBC ciphertext **without knowing the key** — using only the ability to distinguish between valid and invalid padding.

### PKCS#7 Padding

```
Block size: 16 bytes

"HELLO"           → "HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
"HELLO WORLD!!!!" → "HELLO WORLD!!!!\x10\x10...\x10" (full extra block)
"EXACTLY16BYTES!!" → "EXACTLY16BYTES!!\x10\x10...\x10"

Last byte tells you the padding length.
Valid: \x01, \x02\x02, \x03\x03\x03, ... \x10\x10...\x10
```

### How the Attack Works

```
CBC Decryption:
                    
  C[i-1]     C[i]
    │          │
    │    ┌─────┴─────┐
    │    │  AES⁻¹(K) │
    │    └─────┬─────┘
    │          │
    └──── ⊕ ───┘
          │
        P[i]

  P[i] = AES⁻¹(C[i]) ⊕ C[i-1]

If we modify C[i-1], we directly control P[i].
The padding oracle tells us whether our modification
produces valid padding in P[i].
```

### Padding Oracle Exploit

```python
"""
padding_oracle.py — Full padding oracle attack implementation.
Decrypts CBC ciphertext one byte at a time using only a
padding validity oracle.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# ─── TARGET SETUP (simulates vulnerable server) ───

SECRET_KEY = os.urandom(16)

def encrypt(plaintext: bytes) -> bytes:
    """Encrypt with AES-CBC (returns IV || ciphertext)."""
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pad(plaintext, 16))

def padding_oracle(ciphertext: bytes) -> bool:
    """
    The oracle: returns True if padding is valid.
    In the real world, this is a server returning 200 vs 500,
    or a timing difference, or a different error message.
    """
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=iv)
    try:
        unpad(cipher.decrypt(ct), 16)
        return True
    except ValueError:
        return False

# ─── ATTACK ───

def attack_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Decrypt a single block using the padding oracle."""
    intermediate = bytearray(16)  # AES⁻¹(target_block)
    decrypted = bytearray(16)
    
    for byte_pos in range(15, -1, -1):  # Right to left
        padding_val = 16 - byte_pos      # \x01, \x02, ..., \x10
        
        # Set already-known bytes to produce desired padding
        crafted = bytearray(16)
        for k in range(byte_pos + 1, 16):
            crafted[k] = intermediate[k] ^ padding_val
        
        # Brute-force the unknown byte
        for guess in range(256):
            crafted[byte_pos] = guess
            test = bytes(crafted) + target_block
            
            if padding_oracle(test):
                # Verify it's not a false positive (for byte_pos == 15)
                if byte_pos == 15:
                    crafted[14] ^= 1
                    if not padding_oracle(bytes(crafted) + target_block):
                        continue
                    crafted[14] ^= 1
                
                intermediate[byte_pos] = guess ^ padding_val
                decrypted[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break
    
    return bytes(decrypted)

def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Full padding oracle attack — decrypt entire ciphertext."""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""
    
    for i in range(1, len(blocks)):
        decrypted = attack_block(blocks[i-1], blocks[i])
        plaintext += decrypted
        print(f"  Block {i}: {decrypted}")
    
    # Remove PKCS#7 padding
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]

# ─── DEMO ───
secret = b"The password is: hunter2! Don't tell anyone."
ct = encrypt(secret)
print(f"Ciphertext: {ct.hex()[:64]}...")
print(f"\nAttacking...\n")

recovered = padding_oracle_attack(ct)
print(f"\nRecovered: {recovered.decode()}")
assert recovered == secret
print("✓ Padding oracle attack successful!")
```

### Real-World Padding Oracles

| CVE | Target | Oracle Signal |
|---|---|---|
| CVE-2010-3332 | ASP.NET | Different HTTP error codes |
| CVE-2014-3566 | SSL 3.0 (POODLE) | Connection reset vs. alert |
| CVE-2016-2107 | OpenSSL | Timing difference |
| Lucky13 | TLS CBC | Timing (~microseconds) |

---

## 3.5 Attack: Bit-Flipping in CBC

In CBC mode, flipping a bit in ciphertext block `C[i-1]` flips the **same bit** in plaintext block `P[i]` (at the cost of corrupting `P[i-1]`).

```python
"""
cbc_bitflip.py — Modify encrypted data without knowing the key.
Classic attack: change "role=user" to "role=admin" in an encrypted cookie.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

KEY = os.urandom(16)

def encrypt_cookie(username: str) -> bytes:
    """Create an encrypted cookie."""
    cookie = f"user={username}&role=user&ts=1234567890".encode()
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pad(cookie, 16))

def decrypt_cookie(data: bytes) -> dict:
    """Decrypt and parse cookie."""
    iv, ct = data[:16], data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ct), 16)
    # Parse key=value pairs
    parts = plaintext.decode(errors='replace').split('&')
    return {k: v for k, v in (p.split('=', 1) for p in parts if '=' in p)}

# ─── Attack ───
ct = encrypt_cookie("attacker")
print(f"Original cookie:  {decrypt_cookie(ct)}")

# We know the plaintext structure: "user=attacker&role=user&ts=..."
# With username "attacker" (8 chars), the full plaintext is:
#   Byte index: 0         1         2
#               0123456789012345|6789012345678901|...
#   Content:    user=attacker&ro|le=user&ts=12345|...
#               ← Block 1 (16) →← Block 2 (16) →
#
# The 'u' in "role=user" → plaintext byte 19 → block 2, index 3
# To flip P[i], we XOR C[i-1] at the same offset with (old ⊕ new)
# C[i-1] here = first ciphertext block, which starts after the 16-byte IV

ct_array = bytearray(ct)

# target_offset = start of ciphertext block 1 (bytes 16–31, after IV)
target_offset = 16

# Change "user" to "admn" in role value (same length = 4 bytes)
# These bytes are at block2[3..6], so we modify block1[3..6]
old = b"user"
new = b"admn"

for i in range(len(old)):
    pos = target_offset + 3 + i  # ciphertext byte = IV_len + block1_offset
    ct_array[pos] ^= old[i] ^ new[i]

modified = bytes(ct_array)
result = decrypt_cookie(modified)
print(f"Modified cookie:  {result}")
print(f"Role changed to:  {result.get('role', 'PARSE ERROR')}")
```

---

## 3.6 Attack: CTR Bit-Flipping

CTR mode is even more susceptible — since `P = Keystream ⊕ C`, flipping a ciphertext bit flips the corresponding plaintext bit **exactly**, with no collateral damage.

```python
"""
ctr_bitflip.py — Precise bit-flipping in CTR mode.
No block corruption — surgical modification of any byte.
"""
from Crypto.Cipher import AES
import os

KEY = os.urandom(16)
NONCE = os.urandom(8)

def encrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(data)

def decrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.decrypt(data)

# Original message
plaintext = b'{"amount": 100, "to": "alice"}'
ct = encrypt(plaintext)
print(f"Original:  {decrypt(ct).decode()}")

# Change "100" to "900" — only need to flip one byte
# '1' = 0x31, '9' = 0x39, XOR difference = 0x08
ct_mod = bytearray(ct)
amount_pos = plaintext.index(b'1')  # Position of '1' in "100"
ct_mod[amount_pos] ^= ord('1') ^ ord('9')

print(f"Modified:  {decrypt(bytes(ct_mod)).decode()}")
# {"amount": 900, "to": "alice"}  — $100 became $900!
```

---

## 3.7 Attack: GCM Nonce Reuse

AES-GCM is an AEAD cipher — it provides both confidentiality and authenticity.  But **reusing a nonce** destroys both properties and leaks the authentication key (GHASH H).

```python
"""
gcm_nonce_reuse.py — Demonstrate why GCM nonce reuse is catastrophic.
Two encryptions with the same nonce allow:
1. XOR of plaintexts (same as any stream cipher)
2. Recovery of the GHASH authentication key H
3. Forgery of arbitrary authenticated ciphertexts
"""
from Crypto.Cipher import AES
import os

key = os.urandom(16)
nonce = os.urandom(12)

# ⚠️  Two encryptions with the same nonce
cipher1 = AES.new(key, AES.MODE_GCM, nonce=nonce)
ct1, tag1 = cipher1.encrypt_and_digest(b"Transfer $100 to Alice")

cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
ct2, tag2 = cipher2.encrypt_and_digest(b"Transfer $999 to Eveil")

# 1. Confidentiality broken — XOR of ciphertexts = XOR of plaintexts
xored = bytes(a ^ b for a, b in zip(ct1, ct2))
print(f"ct1 ⊕ ct2 reveals plaintext structure: {xored.hex()}")

# 2. Authentication broken — GHASH key H can be recovered from:
#    tag1 ⊕ tag2 = f(ct1) ⊕ f(ct2)  where f is polynomial in H
#    Solving for H in GF(2^128) is straightforward
tag_xor = bytes(a ^ b for a, b in zip(tag1, tag2))
print(f"tag1 ⊕ tag2 = {tag_xor.hex()}")
print("[!] GHASH key H can be recovered from this — enables forgery")

# Prevention: NEVER reuse nonces with GCM
# Use a 96-bit random nonce + limit to 2^32 encryptions per key
# Or use AES-GCM-SIV which is nonce-misuse resistant
```

---

## 3.8 Defensive Takeaways

| Recommendation | Why |
|---|---|
| Use AES-GCM or ChaCha20-Poly1305 | AEAD — authenticates AND encrypts |
| Never use ECB mode | Pattern leakage |
| Never use CBC without careful padding validation | Padding oracle attacks |
| Generate unique nonces/IVs | Nonce reuse kills GCM and CTR |
| Encrypt-then-MAC (if not using AEAD) | Prevents oracle attacks |
| Validate and reject modified ciphertexts early | Bit-flipping defense |

---

## 3.9 Lab: Build a Padding Oracle Exploit

```python
"""
lab_padding_oracle.py — Your challenge:

A web application encrypts user tokens with AES-CBC.
The /api/verify endpoint returns:
  - 200 if the token decrypts and has valid padding
  - 403 if the token decrypts but padding is invalid
  - 401 if the token is invalid for other reasons

Your target token (hex): (generated at runtime)
Endpoint: http://localhost:5000/api/verify?token=<hex>

Goal: Decrypt the token using only the padding oracle.

Hint: The implementation above (padding_oracle_attack) works —
      just swap the oracle function to make HTTP requests.
"""
import requests

def remote_oracle(ciphertext: bytes) -> bool:
    """Query the remote oracle."""
    resp = requests.get(
        "http://localhost:5000/api/verify",
        params={"token": ciphertext.hex()}
    )
    return resp.status_code != 403  # 403 = bad padding

# Replace `padding_oracle` in the attack code with `remote_oracle`
# and run the full attack against the target token.
```

---

## 3.10 Key Takeaways

- **ECB leaks patterns** — any repeated plaintext block produces a repeated ciphertext block.  Finding ECB in production is an instant vulnerability.
- **CBC padding oracle** is a devastating attack — decrypt anything without the key.  Look for differential error responses.
- **Bit-flipping** in CBC and CTR allows data modification without decryption.  Unauthenticated encryption is malleable.
- **GCM nonce reuse** destroys both confidentiality and authenticity and leaks the authentication key.
- **AEAD (GCM, ChaCha20-Poly1305)** is the only correct choice for new systems — it binds encryption and authentication together.

---

**Next:** [Chapter 4 — Hashes: Integrity and Length Extension →](04_hashes.md)
