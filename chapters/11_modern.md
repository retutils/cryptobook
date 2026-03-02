# Chapter 11 — Modern Primitives & PQC

> *"Harvest now, decrypt later. Every encrypted communication intercepted today is sitting in storage, waiting for a sufficiently powerful quantum computer to break it open."*
> — NSA advisory on post-quantum migration, 2015

---

## 11.1 AEAD: The Modern Standard

Authenticated Encryption with Associated Data (AEAD) combines encryption and integrity in one operation.  No more "encrypt-then-MAC vs. MAC-then-encrypt" debates.

### AES-GCM

```python
"""
aes_gcm.py — The most widely used AEAD construction.
"""
from Crypto.Cipher import AES
import os

def aead_encrypt(key: bytes, plaintext: bytes, 
                  aad: bytes = b"") -> tuple:
    """Encrypt with AES-256-GCM."""
    nonce = os.urandom(12)  # 96-bit nonce — MUST be unique
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)  # Authenticated but not encrypted
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                  tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and verify AES-256-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Example: encrypted message with authenticated metadata
key = os.urandom(32)
metadata = b"from=alice&to=bob&timestamp=1234567890"
message = b"This is the secret payload"

nonce, ct, tag = aead_encrypt(key, message, aad=metadata)
print(f"Nonce: {nonce.hex()}")
print(f"Ciphertext: {ct.hex()}")
print(f"Tag: {tag.hex()}")

# Decrypt and verify
plaintext = aead_decrypt(key, nonce, ct, tag, aad=metadata)
print(f"Decrypted: {plaintext.decode()}")

# Tamper with metadata → authentication fails
try:
    tampered_aad = b"from=eve&to=bob&timestamp=1234567890"
    aead_decrypt(key, nonce, ct, tag, aad=tampered_aad)
except ValueError as e:
    print(f"Tamper detected ✓ — {e}")
```

### ChaCha20-Poly1305

```python
"""
chacha20_poly1305.py — Software-friendly AEAD (no AES-NI needed).
Used by WireGuard, TLS 1.3, and the Noise protocol.
"""
from Crypto.Cipher import ChaCha20_Poly1305
import os

key = os.urandom(32)
nonce = os.urandom(12)

cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
cipher.update(b"public header")  # AAD
ciphertext, tag = cipher.encrypt_and_digest(b"secret data")

# Decrypt
cipher_dec = ChaCha20_Poly1305.new(key=key, nonce=nonce)
cipher_dec.update(b"public header")
plaintext = cipher_dec.decrypt_and_verify(ciphertext, tag)
print(f"ChaCha20-Poly1305: {plaintext.decode()}")
```

### AES-GCM-SIV (Nonce-Misuse Resistant)

```python
"""
AES-GCM-SIV: if you accidentally reuse a nonce, you only lose
confidentiality for identical plaintexts — you don't lose
authentication (unlike standard GCM).
"""
# Not in PyCryptodome — available in libsodium bindings
# pip install pysodium
print("""
AES-GCM-SIV:
- Nonce-misuse resistant: reusing nonce only leaks if same plaintext
- Standard GCM: nonce reuse → lose BOTH confidentiality AND authenticity
- SIV: slightly slower, but much safer in practice
- Recommended when nonce uniqueness is hard to guarantee
  (distributed systems, multi-datacenter, etc.)
""")
```

---

## 11.2 Key Derivation Functions

### HKDF — Extract-then-Expand

```python
"""
hkdf.py — Derive multiple keys from a single shared secret.
"""
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import os

# A shared secret (e.g., from ECDH key exchange)
shared_secret = os.urandom(32)
salt = os.urandom(32)  # One salt — store alongside the derived keys

# Derive separate keys using same salt but different context labels
# This is the standard HKDF pattern (RFC 5869):
#   HKDF-Extract(salt, secret) → PRK
#   HKDF-Expand(PRK, context, length) → key material
encryption_key = HKDF(
    master=shared_secret,
    key_len=32,
    salt=salt,
    hashmod=SHA256,
    context=b"encryption"   # Different context = different key
)

mac_key = HKDF(
    master=shared_secret,
    key_len=32,
    salt=salt,              # Same salt as above
    hashmod=SHA256,
    context=b"authentication"
)

print(f"Encryption key: {encryption_key.hex()}")
print(f"MAC key:        {mac_key.hex()}")
print(f"Different keys from same secret: {encryption_key != mac_key}")
```

### PBKDF2

```python
"""
PBKDF2 — Password-Based Key Derivation (RFC 8018).
"""
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
import os

password = b"user-supplied-password"
salt = os.urandom(16)

# Derive an encryption key from a password
key = PBKDF2(
    password,
    salt,
    dkLen=32,
    count=600_000,  # OWASP 2023 recommendation for SHA-256
    prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
)

print(f"Derived key: {key.hex()}")
print(f"Salt:        {salt.hex()}")
# Store salt alongside encrypted data — it's not secret
```

---

## 11.3 Signal Protocol / Double Ratchet

The Signal Protocol (used in Signal, WhatsApp, Facebook Messenger) provides:
- **Forward secrecy**: compromising a key doesn't decrypt past messages
- **Post-compromise security**: the protocol self-heals after a compromise

```
┌─────────────────────────────────────────────────┐
│              Double Ratchet Overview             │
├─────────────────────────────────────────────────┤
│                                                  │
│  DH Ratchet (Asymmetric)                        │
│  ┌──────┐   ┌──────┐   ┌──────┐                │
│  │ DH₁  │──▶│ DH₂  │──▶│ DH₃  │──▶ ...        │
│  └──────┘   └──────┘   └──────┘                │
│      │          │          │                     │
│      ▼          ▼          ▼                     │
│  Root KDF   Root KDF   Root KDF                 │
│      │          │          │                     │
│      ▼          ▼          ▼                     │
│  Chain Key  Chain Key  Chain Key                │
│      │          │          │                     │
│      ▼          ▼          ▼                     │
│  Symmetric Ratchet (per-message)                │
│  ┌────┐ ┌────┐ ┌────┐                          │
│  │Msg1│ │Msg2│ │Msg3│ ...                       │
│  └────┘ └────┘ └────┘                          │
│                                                  │
│  Each message has a unique key.                 │
│  New DH exchange every turn.                    │
│  Forward secrecy: past keys deleted.            │
│  Post-compromise: new DH heals the chain.       │
└─────────────────────────────────────────────────┘
```

```python
"""
Simplified Double Ratchet concept — key derivation chain.
"""
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import os

def chain_ratchet(chain_key: bytes) -> tuple:
    """Derive a message key and new chain key from the current chain key."""
    msg_key = HKDF(chain_key, 32, b"msg-salt", SHA256, context=b"msg")
    new_chain = HKDF(chain_key, 32, b"chain-salt", SHA256, context=b"chain")
    return new_chain, msg_key

# Initialize chain
chain_key = os.urandom(32)

# Each message gets a unique key
for i in range(5):
    chain_key, msg_key = chain_ratchet(chain_key)
    print(f"Message {i+1} key: {msg_key.hex()[:32]}...")
    # After use, msg_key is deleted
    # Even if chain_key is compromised, past msg_keys are unrecoverable

print("\nForward secrecy: past message keys cannot be derived from current state")
```

---

## 11.4 Post-Quantum Cryptography

Quantum computers break RSA, DH, ECDH, ECDSA, and EdDSA.  They do NOT break AES (just halve the key strength) or SHA-256.

### What Quantum Computers Break

| Algorithm | Quantum Attack | Effective Security |
|---|---|---|
| RSA-2048 | Shor's algorithm | ❌ Broken |
| ECDSA P-256 | Shor's (ECDLP) | ❌ Broken |
| DH/ECDH | Shor's | ❌ Broken |
| AES-128 | Grover's search | ⚠️ 64-bit (upgrade to AES-256) |
| AES-256 | Grover's search | ✅ 128-bit (still secure) |
| SHA-256 | Grover's | ✅ 128-bit (still secure) |

### NIST PQC Standards (Finalized 2024)

```python
"""
pqc_overview.py — The new post-quantum standards.
"""
print("""
NIST Post-Quantum Cryptography Standards:

1. ML-KEM (FIPS 203) — Key Encapsulation
   - Based on: Module-Lattice (CRYSTALS-Kyber)
   - Replaces: RSA key exchange, ECDH
   - Key sizes: ML-KEM-512 (128-bit), ML-KEM-768 (192-bit), ML-KEM-1024 (256-bit)
   - Performance: faster than RSA, larger keys (~1.5 KB public key)

2. ML-DSA (FIPS 204) — Digital Signatures
   - Based on: Module-Lattice (CRYSTALS-Dilithium)
   - Replaces: RSA signatures, ECDSA, EdDSA
   - Signature sizes: ~2.5-4.5 KB (much larger than ECDSA's 64 bytes)

3. SLH-DSA (FIPS 205) — Hash-Based Signatures
   - Based on: SPHINCS+
   - Replaces: RSA/ECDSA signatures (conservative choice)
   - Larger signatures (~17-50 KB) but based on hash security only
   - Good for: long-term signatures where size doesn't matter
""")
```

### Using PQC Libraries

```python
"""
Using the oqs-python library (Open Quantum Safe).
pip install liboqs-python
"""
try:
    import oqs

    # Key Encapsulation (like ECDH but quantum-resistant)
    kem = oqs.KeyEncapsulation("Kyber512")
    
    # Alice generates a keypair
    public_key = kem.generate_keypair()
    
    # Bob encapsulates a shared secret
    ciphertext, shared_secret_bob = kem.encap_secret(public_key)
    
    # Alice decapsulates
    shared_secret_alice = kem.decap_secret(ciphertext)
    
    assert shared_secret_alice == shared_secret_bob
    print(f"KEM shared secret: {shared_secret_alice.hex()[:32]}...")
    print(f"Public key size:   {len(public_key)} bytes")
    print(f"Ciphertext size:   {len(ciphertext)} bytes")
    
    # Digital Signatures
    sig = oqs.Signature("Dilithium2")
    signer_public = sig.generate_keypair()
    
    message = b"Post-quantum signed document"
    signature = sig.sign(message)
    
    is_valid = sig.verify(message, signature, signer_public)
    print(f"\nSignature valid: {is_valid}")
    print(f"Signature size:  {len(signature)} bytes")
    print(f"Public key size: {len(signer_public)} bytes")

except ImportError:
    print("Install: pip install liboqs-python")
    print("Or use: https://github.com/open-quantum-safe/liboqs-python")
```

### Hybrid Key Exchange (Transition Strategy)

```python
"""
hybrid_key_exchange.py — Combine classical + PQC for defense-in-depth.
If either algorithm is broken, the other still protects the session.
"""
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import os

# Classical: ECDH (Curve25519)
alice_classical = ECC.generate(curve='Curve25519')
bob_classical = ECC.generate(curve='Curve25519')

# Post-quantum: ML-KEM (simulated here)
# In production, use liboqs or similar
pqc_shared = os.urandom(32)  # Placeholder for ML-KEM shared secret
ecdh_shared = os.urandom(32)  # Placeholder for ECDH shared secret

# Combine both shared secrets with HKDF
hybrid_key = HKDF(
    master=ecdh_shared + pqc_shared,  # Concatenate both
    key_len=32,
    salt=None,
    hashmod=SHA256,
    context=b"hybrid-tls-key"
)

print(f"ECDH shared:   {ecdh_shared.hex()[:32]}...")
print(f"PQC shared:    {pqc_shared.hex()[:32]}...")
print(f"Hybrid key:    {hybrid_key.hex()}")
print("\nIf quantum breaks ECDH → PQC still protects")
print("If PQC has a flaw  → ECDH still protects")
```

---

## 11.5 "Harvest Now, Decrypt Later"

```python
"""
The threat: adversaries are recording encrypted traffic TODAY,
planning to decrypt it when quantum computers are available.
"""
print("""
Timeline Assessment:

  TODAY: Encrypted TLS 1.3 traffic (ECDHE + AES-256-GCM)
    │
    ▼
  CAPTURED: By nation-state adversary, stored indefinitely
    │
    ▼
  20XX: Cryptographically relevant quantum computer (CRQC)
    │
    ▼
  DECRYPTED: ECDH key exchange broken → session key recovered
              → All stored traffic decrypted in bulk

What's at risk:
  - Government/military classified communications
  - Medical records with long-term relevance
  - Financial data, M&A negotiations
  - Intellectual property, trade secrets
  - Personal data with lifetime relevance

Migration priority:
  1. Data with >10 year confidentiality requirement → migrate NOW
  2. Government/defense → mandated by 2035 (CNSA 2.0)
  3. Financial sector → follow regulator guidance
  4. General enterprise → plan and budget for migration
""")
```

---

## 11.6 Key Takeaways

- **AEAD (AES-GCM / ChaCha20-Poly1305)** is the only correct way to encrypt — it binds authentication to encryption
- **HKDF** is the standard for deriving multiple keys from a shared secret — always use it over raw hashing
- **Signal's Double Ratchet** provides forward secrecy and post-compromise security — the gold standard for messaging
- **Post-quantum** standards are finalized (ML-KEM, ML-DSA, SLH-DSA) — start planning migration
- **Hybrid key exchange** (classical + PQC) is the safe transition strategy
- **Harvest now, decrypt later** is a real threat for long-lived secrets — the time to act is before quantum computers arrive

---

**Next:** [Chapter 12 — Exploitability & Reporting →](12_reporting.md)
