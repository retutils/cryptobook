# Chapter 2 — XOR, OTP, and Stream Failures

> *"WEP was supposed to provide 'wired equivalent privacy.' Instead, it provided a live demo of what happens when you reuse a stream cipher keystream. Every Wi-Fi network in 2003 was an open book."*

---

## 2.1 XOR: The Fundamental Operation

Every stream cipher, every block cipher mode, every one-time pad — they all come down to XOR.

### Properties of XOR

```
A ⊕ 0 = A          (identity)
A ⊕ A = 0          (self-inverse)
A ⊕ B = B ⊕ A      (commutative)
```

The critical property for cryptanalysis is **self-inverse**:

```
  C = P ⊕ K    (encrypt)
  P = C ⊕ K    (decrypt)
```

And if you XOR two ciphertexts encrypted with the **same key**:

```
  C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
```

The key cancels out.  This is the foundation of every key-reuse attack.

### XOR in Python

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (truncates to shorter length)."""
    return bytes(x ^ y for x, y in zip(a, b))

key =        b"SECRETKEY1234567"
plaintext1 = b"Attack at dawn!!"
plaintext2 = b"Retreat at dusk!"

ct1 = xor_bytes(plaintext1, key)
ct2 = xor_bytes(plaintext2, key)

# Decrypt: XOR ciphertext with key
assert xor_bytes(ct1, key) == plaintext1

# Key cancellation: XOR two ciphertexts
xored = xor_bytes(ct1, ct2)
assert xored == xor_bytes(plaintext1, plaintext2)
print(f"Key cancelled: ct1⊕ct2 == p1⊕p2: True")
```

---

## 2.2 The One-Time Pad

The OTP is the only cipher with **provable perfect secrecy** (Shannon, 1949).  Its rules:

1. Key is truly random
2. Key is at least as long as the plaintext
3. Key is **never reused**

Break any rule and the cipher is destroyed.  The OTP is a theoretical benchmark, not a practical cipher.  Stream ciphers exist to approximate OTP behavior with a short, reusable key — and that's where the trouble starts.

---

## 2.3 Stream Ciphers: Stretching a Short Key

A stream cipher expands a short key (+ optional nonce) into a long **keystream**, then XORs the plaintext.

### RC4

RC4 was ubiquitous: WEP, WPA-TKIP, SSL/TLS, Microsoft Office, PDF encryption.  Now broken and banned from TLS (RFC 7465).

```python
"""
RC4 implementation — educational only.  DO NOT USE IN PRODUCTION.
"""
def rc4(key: bytes, data: bytes) -> bytes:
    # Key Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)

key = b"WEPkey"
plaintext = b"This is a secret message"
ciphertext = rc4(key, plaintext)
decrypted = rc4(key, ciphertext)  # Encrypt and decrypt are the same
assert decrypted == plaintext
```

### ChaCha20

ChaCha20 is the modern standard — used in TLS 1.3, WireGuard, and the `noise` protocol.

```python
from Crypto.Cipher import ChaCha20
import os

key = os.urandom(32)    # 256-bit key
nonce = os.urandom(12)  # 96-bit nonce — MUST be unique per message

cipher = ChaCha20.new(key=key, nonce=nonce)
ciphertext = cipher.encrypt(b"Confidential data here")

cipher_dec = ChaCha20.new(key=key, nonce=nonce)
plaintext = cipher_dec.decrypt(ciphertext)
print(f"Decrypted: {plaintext.decode()}")
```

---

## 2.4 Attack: Key Reuse / Two-Time Pad

If a stream cipher key+nonce pair is ever reused, the attacker can XOR the two ciphertexts and recover both plaintexts via **crib dragging**.

### Crib Dragging Attack

```python
"""
crib_drag.py — Interactive crib-dragging attack on XOR'd plaintexts.
"""
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def crib_drag(xored_plaintexts: bytes, crib: str) -> list:
    """Slide a known word across the XOR of two plaintexts."""
    crib_bytes = crib.encode()
    results = []
    for i in range(len(xored_plaintexts) - len(crib_bytes) + 1):
        chunk = xored_plaintexts[i:i + len(crib_bytes)]
        candidate = xor_bytes(chunk, crib_bytes)
        try:
            decoded = candidate.decode('ascii')
            if all(c.isprintable() or c.isspace() for c in decoded):
                results.append((i, decoded))
        except (UnicodeDecodeError, ValueError):
            pass
    return results

# ─── Simulation ───
import os
key = os.urandom(50)
p1 = b"The secret meeting is at the warehouse tonight"
p2 = b"Send the documents to the usual drop location "

c1 = xor_bytes(p1, key[:len(p1)])
c2 = xor_bytes(p2, key[:len(p2)])

# Attacker XORs ciphertexts to eliminate key
p1_xor_p2 = xor_bytes(c1, c2)

print("=== Crib Dragging Attack ===\n")
for crib in ["the ", " the ", "at ", "to ", "meet", "send", "secret"]:
    hits = crib_drag(p1_xor_p2, crib)
    if hits:
        print(f"Crib: '{crib}'")
        for pos, result in hits:
            print(f"  Position {pos:2d}: '{result}'")
```

### Real-World Key Reuse Disasters

| System | Key Reuse Bug | Impact |
|---|---|---|
| **WEP** | 24-bit IV → collisions after ~5000 packets | Complete Wi-Fi decryption |
| **MS-Office 97-2003** | Same RC4 key for entire document | Full document recovery |
| **PPTP VPN** | Same RC4 key for both directions | Full session decryption |

---

## 2.5 Attack: RC4 Biases

RC4 has statistical biases — the second byte of output is 0x00 with probability ~2/256 instead of 1/256.

```python
"""Demonstrate the RC4 second-byte bias."""
from collections import Counter
import os

def rc4_keystream(key: bytes, length: int) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    output = bytearray()
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        output.append(S[(S[i] + S[j]) % 256])
    return bytes(output)

NUM_SAMPLES = 100_000
second_bytes = Counter()
for _ in range(NUM_SAMPLES):
    key = os.urandom(16)
    ks = rc4_keystream(key, 3)
    second_bytes[ks[1]] += 1

expected = NUM_SAMPLES / 256
actual_zero = second_bytes[0]
ratio = actual_zero / expected
print(f"Bias ratio: {ratio:.2f}x (should be ~2.0)")
print(f"{'BIAS CONFIRMED ✓' if ratio > 1.5 else 'Run more samples'}")
```

In TLS with RC4, an attacker forces millions of connections, collects ciphertexts at the same position, and uses statistical biases to recover each plaintext byte (e.g., session cookies).

---

## 2.6 Attack: ChaCha20 Nonce Reuse

ChaCha20 isn't vulnerable to RC4's biases, but nonce reuse still destroys it:

```python
from Crypto.Cipher import ChaCha20
import os

key = os.urandom(32)
nonce = os.urandom(12)

# ⚠️  Same key + nonce = same keystream
p1 = b"Launch the missiles at midnight"
p2 = b"Cancel the operation immediat"

c1 = ChaCha20.new(key=key, nonce=nonce).encrypt(p1)
c2 = ChaCha20.new(key=key, nonce=nonce).encrypt(p2)

xored = bytes(a ^ b for a, b in zip(c1, c2))
assert xored == bytes(a ^ b for a, b in zip(p1, p2))
print("Nonce reuse: ct1⊕ct2 == p1⊕p2 ✓  → apply crib dragging")

# Prevention: use XChaCha20 with a 24-byte random nonce
# Collision probability is negligible with 192-bit nonces
```

---

## 2.7 WEP: A Complete Case Study

WEP combined almost every stream cipher failure into one protocol:

1. **RC4 key = [3-byte IV] || [fixed WEP key]** — only 16.7M possible IVs
2. **IV sent in cleartext** — enables related-key attacks (FMS attack)
3. **No authentication** — allows packet injection
4. **CRC-32 integrity** — linear, malleable, allows bit-flipping

**Result:** Full WEP key recovery in < 60 seconds.

```bash
# Cracking WEP with aircrack-ng
airmon-ng start wlan0
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 --write capture wlan0mon
aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF wlan0mon
aircrack-ng capture-01.cap
# KEY FOUND! [ 1A:2B:3C:4D:5E ]  (in ~42 seconds)
```

---

## 2.8 Lab: Crib-Dragging Challenge

```python
"""
lab_crib_drag.py — Recover two messages from a two-time pad.
"""
import os
from binascii import hexlify

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

_key = os.urandom(100)
_m1 = b"The quick brown fox jumps over the lazy dog near the river"
_m2 = b"Pack my box with five dozen liquor jugs before midnight  "

c1 = xor_bytes(_m1, _key[:len(_m1)])
c2 = xor_bytes(_m2, _key[:len(_m2)])

print(f"C1 = {hexlify(c1).decode()}")
print(f"C2 = {hexlify(c2).decode()}")
print(f"\nC1⊕C2 = {hexlify(xor_bytes(c1, c2)).decode()}")
print("\nYour task: crib-drag with words like 'the ', 'with', 'over'")
```

---

## 2.9 Key Takeaways

- **XOR is the foundation** of stream ciphers.  `C1 ⊕ C2 = P1 ⊕ P2` when the keystream is reused.
- **Nonce/key reuse** is the cardinal sin of stream ciphers.  Two-time pad → crib drag → plaintext recovery.
- **RC4 is dead.**  Biases enable statistical plaintext recovery.  WEP was the most spectacular failure.
- **ChaCha20 is the modern standard**, but still vulnerable to nonce reuse.  Prefer XChaCha20 for random nonces.
- **Crib dragging** is the go-to technique for two-time pads — practice it for CTFs and real engagements.

| Do | Don't |
|---|---|
| Use ChaCha20-Poly1305 or AES-GCM | Use RC4 for anything |
| Generate nonces with `os.urandom()` | Reuse nonces |
| Use XChaCha20 (24-byte nonce) for random nonces | Assume the library manages nonces |

---

**Next:** [Chapter 3 — Block Ciphers: Structure and Tampering →](03_blocks.md)
