# Chapter 7 — Asymmetric Crypto: Primes & Curves

> *"The PlayStation 3's ECDSA signing key was recovered because Sony used the same random nonce `k` for every signature.  One equation, one unknown.  The entire PS3 code-signing infrastructure collapsed in a single line of algebra."*
> — fail0verflow, 2010

---

## 7.1 RSA Fundamentals

RSA security relies on the difficulty of factoring the product of two large primes.

### Key Generation

```python
"""
rsa_basics.py — RSA key generation, encryption, and signing from scratch.
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate an RSA key pair
key = RSA.generate(2048)
print(f"Key size:  {key.size_in_bits()} bits")
print(f"Public e:  {key.e}")
print(f"Modulus n: {key.n}")  # n = p * q

# Export keys
private_pem = key.export_key()
public_pem = key.publickey().export_key()

# Encryption with OAEP padding
cipher = PKCS1_OAEP.new(key.publickey())
ciphertext = cipher.encrypt(b"Secret message")

# Decryption
cipher_dec = PKCS1_OAEP.new(key)
plaintext = cipher_dec.decrypt(ciphertext)
print(f"Decrypted: {plaintext.decode()}")

# Signing
h = SHA256.new(b"Sign this document")
signature = pkcs1_15.new(key).sign(h)
print(f"Signature: {signature.hex()[:40]}...")

# Verification
try:
    pkcs1_15.new(key.publickey()).verify(h, signature)
    print("Signature valid ✓")
except (ValueError, TypeError):
    print("Signature invalid ✗")
```

### Textbook RSA (Insecure — For Understanding Only)

```python
"""
Textbook RSA — no padding, vulnerable to many attacks.
Shown ONLY to understand why padding (OAEP) is essential.
"""
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

# Key generation
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# Encrypt: c = m^e mod n
message = b"Hello RSA"
m = bytes_to_long(message)
c = pow(m, e, n)
print(f"Ciphertext: {c}")

# Decrypt: m = c^d mod n
m_dec = pow(c, d, n)
plaintext = long_to_bytes(m_dec)
print(f"Decrypted: {plaintext.decode()}")

# This is INSECURE because:
# 1. Deterministic — same plaintext always gives same ciphertext
# 2. Malleable — c1 * c2 mod n = encrypt(m1 * m2)
# 3. Small message attack — if m < n^(1/e), just take the e-th root
```

---

## 7.2 Attack: Small Public Exponent

If `e = 3` and the plaintext `m` is small enough that `m³ < n`, then `c = m³` and the plaintext can be recovered by computing the cube root.

```python
"""
small_e_attack.py — Recover plaintext when e=3 and m is small.
"""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import gmpy2

# Setup: RSA with e=3
p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 3

# Small message
message = b"short"
m = bytes_to_long(message)

# Encrypt: c = m^3 mod n
# If m^3 < n, then c = m^3 (no modular reduction!)
c = pow(m, e, n)

# Attack: compute cube root
m_recovered, is_exact = gmpy2.iroot(c, e)
if is_exact:
    print(f"Recovered: {long_to_bytes(int(m_recovered)).decode()}")
    print("Small exponent attack successful ✓")

# With e=3 and the same plaintext sent to 3 different keys,
# you can use the Chinese Remainder Theorem (Håstad's attack)
```

### Håstad's Broadcast Attack

```python
"""
hastad_broadcast.py — When the same message is encrypted to
e=3 different public keys, CRT recovers the plaintext.
"""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import gmpy2

def generate_rsa_e3():
    while True:
        p, q = getPrime(1024), getPrime(1024)
        n = p * q
        phi = (p-1) * (q-1)
        if phi % 3 != 0:  # Ensure e=3 is coprime to phi
            return n

# Three recipients with e=3
n1, n2, n3 = generate_rsa_e3(), generate_rsa_e3(), generate_rsa_e3()
e = 3

message = b"Attack at dawn"
m = bytes_to_long(message)

c1 = pow(m, e, n1)
c2 = pow(m, e, n2)
c3 = pow(m, e, n3)

# Chinese Remainder Theorem
def crt(remainders, moduli):
    N = 1
    for n in moduli:
        N *= n
    result = 0
    for r, n in zip(remainders, moduli):
        Ni = N // n
        xi = int(gmpy2.invert(Ni, n))
        result += r * Ni * xi
    return result % N

m_cubed = crt([c1, c2, c3], [n1, n2, n3])
m_recovered, exact = gmpy2.iroot(m_cubed, 3)
print(f"Recovered: {long_to_bytes(int(m_recovered)).decode()}")
```

---

## 7.3 Attack: Bleichenbacher (PKCS#1 v1.5)

The Bleichenbacher attack (1998) exploits RSA with PKCS#1 v1.5 padding.  By observing whether decryption produces valid padding, an attacker can decrypt any ciphertext using ~1 million adaptive queries.

```python
"""
bleichenbacher_concept.py — Conceptual overview.
The full attack requires a PKCS#1 v1.5 padding oracle.
"""

# PKCS#1 v1.5 padding format:
# 0x00 0x02 [random non-zero bytes] 0x00 [message]
#
# The oracle: does decryption produce a valid 0x00 0x02 prefix?
#
# Attack outline:
# 1. Start with target ciphertext c
# 2. Multiply: c' = c * s^e mod n  (for chosen values of s)
# 3. Decryption of c' = m*s mod n  (RSA homomorphism)
# 4. If the oracle says "valid padding," we know:
#    2*B <= m*s mod n < 3*B  where B = 2^(8*(k-2))
# 5. Each valid s narrows the range of possible m
# 6. After ~1M queries, m is uniquely determined

print("""
Bleichenbacher Attack Summary:
- Exploits PKCS#1 v1.5 padding oracle
- ~1 million chosen ciphertexts needed
- Applicable to: TLS RSA key exchange (ROBOT attack, 2017)
- Fix: Use OAEP padding, or move to ECDH key exchange

Tools:
- ROBOT scanner: https://robotattack.org
- TLS testing: testssl.sh --robot
""")
```

```bash
# Test for ROBOT vulnerability
testssl.sh --robot target.com:443

# Or with nmap
nmap --script ssl-robot -p 443 target.com
```

---

## 7.4 Attack: Shared Primes (Batch GCD)

If two RSA moduli share a prime factor, both can be factored instantly.

```python
"""
batch_gcd.py — Factor RSA keys that share prime factors.
"""
from math import gcd
from Crypto.Util.number import getPrime

# Simulate: two keys accidentally share a prime
shared_p = getPrime(1024)
q1 = getPrime(1024)
q2 = getPrime(1024)

n1 = shared_p * q1
n2 = shared_p * q2

# Attack: GCD reveals the shared factor
common = gcd(n1, n2)
if common > 1:
    print(f"Shared factor found!")
    print(f"p  = {common}")
    print(f"q1 = {n1 // common}")
    print(f"q2 = {n2 // common}")
    print(f"Both keys are now fully factored ✓")

# In 2012, Heninger et al. scanned all RSA keys on the public internet:
# - Collected ~7.1 million RSA moduli from TLS and SSH
# - Found 0.2% (>14,000) shared factors due to poor RNG at key generation
# - Embedded devices (routers, IoT) were the worst offenders
```

### Scanning Multiple Keys

```bash
# Collect RSA public keys from a range
for ip in $(cat targets.txt); do
    echo | openssl s_client -connect $ip:443 2>/dev/null | \
    openssl x509 -pubkey -noout >> public_keys.pem
done

# Extract moduli
openssl rsa -pubin -in key.pem -modulus -noout
```

```python
"""
Batch GCD on a collection of RSA moduli.
"""
from math import gcd
from functools import reduce

def batch_gcd(moduli):
    """Find all pairwise GCDs efficiently."""
    vulnerable = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if g > 1 and g != moduli[i] and g != moduli[j]:
                vulnerable.append((i, j, g))
    return vulnerable

# Example with synthetic data
moduli = [
    getPrime(512) * getPrime(512),  # normal
    shared_p * getPrime(512),        # shares p
    shared_p * getPrime(512),        # shares p
    getPrime(512) * getPrime(512),  # normal
]

results = batch_gcd(moduli)
for i, j, factor in results:
    print(f"Keys [{i}] and [{j}] share factor {factor}")
```

---

## 7.5 Elliptic Curve Cryptography

ECC provides equivalent security to RSA with much smaller keys.

| Security Level | RSA Key Size | ECC Key Size |
|---|---|---|
| 128-bit | 3072 bits | 256 bits |
| 192-bit | 7680 bits | 384 bits |
| 256-bit | 15360 bits | 512 bits |

### ECDSA Signing and Verification

```python
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Generate key pair (P-256 curve)
key = ECC.generate(curve='P-256')
print(f"Private key (d): {key.d}")
print(f"Public key (x):  {key.pointQ.x}")
print(f"Public key (y):  {key.pointQ.y}")

# Sign
message = b"Transfer $1000 to Alice"
h = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(h)
print(f"Signature: {signature.hex()[:40]}...")

# Verify
verifier = DSS.new(key.public_key(), 'fips-186-3')
try:
    verifier.verify(SHA256.new(message), signature)
    print("ECDSA signature valid ✓")
except ValueError:
    print("ECDSA signature invalid ✗")
```

---

## 7.6 Attack: ECDSA Nonce Reuse

If the random nonce `k` is reused across two ECDSA signatures, the private key can be recovered with simple algebra.

```python
"""
ecdsa_nonce_reuse.py — Recover ECDSA private key from nonce reuse.
This is exactly how fail0verflow broke the PS3 signing key.
"""
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, inverse

# Generate a key (we'll recover it from nonce reuse)
key = ECC.generate(curve='P-256')
private_d = int(key.d)
n = int(key.pointQ.curve.order)

print(f"Original private key (d): {private_d}")

# Sign two messages with the SAME nonce (the vulnerability)
# We need to extract r, s values from the signatures
msg1 = b"Message one"
msg2 = b"Message two"

h1 = SHA256.new(msg1)
h2 = SHA256.new(msg2)

# For demonstration, we sign normally and then show the recovery math
signer = DSS.new(key, 'fips-186-3', randfunc=None)

# In practice, if k is reused, both signatures have the same r value
# Let's simulate with known values
import random
k = random.randrange(1, n)  # Same k used twice!

# Manual ECDSA signing with fixed k
G = key.pointQ.curve.G  # Generator point
R = k * ECC.EccPoint(G.x, G.y, curve='P-256')  # k*G
r = int(R.x) % n

z1 = bytes_to_long(SHA256.new(msg1).digest()) % n
z2 = bytes_to_long(SHA256.new(msg2).digest()) % n

k_inv = inverse(k, n)
s1 = (k_inv * (z1 + r * private_d)) % n
s2 = (k_inv * (z2 + r * private_d)) % n

print(f"\nSignature 1: r={r}, s1={s1}")
print(f"Signature 2: r={r}, s2={s2}")
print(f"Same r value → same k → nonce reuse detected!\n")

# ─── ATTACK: Recover private key ───
# From the equations:
#   s1 = k⁻¹(z1 + r*d) mod n
#   s2 = k⁻¹(z2 + r*d) mod n
# Subtract:
#   s1 - s2 = k⁻¹(z1 - z2) mod n
# Therefore:
#   k = (z1 - z2) / (s1 - s2) mod n

k_recovered = ((z1 - z2) * inverse(s1 - s2, n)) % n
assert k_recovered == k, "k recovery failed"
print(f"Recovered k:  {k_recovered}")

# Now recover private key d:
#   d = (s1*k - z1) / r mod n
d_recovered = ((s1 * k_recovered - z1) * inverse(r, n)) % n
print(f"Recovered d:  {d_recovered}")
print(f"Original  d:  {private_d}")
print(f"Keys match:   {d_recovered == private_d} ✓")
```

### Invalid Curve Attacks

```python
"""
When a library doesn't validate that a received public key
is on the expected curve, an attacker can send points on
weaker curves and recover the private key.

Defense: Always validate public keys before use.
"""
from Crypto.PublicKey import ECC

def validate_ecc_point(x, y, curve='P-256'):
    """Validate that a point is on the expected curve."""
    try:
        key = ECC.construct(curve=curve, point_x=x, point_y=y)
        return True
    except (ValueError, TypeError):
        return False

# Always validate received public keys!
received_x = 12345678901234567890  # Untrusted input
received_y = 98765432109876543210

if validate_ecc_point(received_x, received_y):
    print("Point is on the curve — safe to use")
else:
    print("INVALID POINT — reject! Possible invalid curve attack")
```

---

## 7.7 Diffie-Hellman Key Exchange

```python
"""
Diffie-Hellman — key agreement without pre-shared secrets.
"""
from Crypto.PublicKey import DH
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# In practice, use well-known groups (RFC 3526, RFC 7919)
# Here's the conceptual flow:

# Alice generates parameters and key pair
# Bob generates key pair with same parameters
# Both compute shared_secret = other_public ^ my_private mod p

# Modern approach: use X25519 (Curve25519 ECDH)
from Crypto.PublicKey import ECC

alice_key = ECC.generate(curve='Curve25519')
bob_key = ECC.generate(curve='Curve25519')

# In a full implementation, use the ECDH protocol
# shared_secret = alice_private * bob_public = bob_private * alice_public

print("Diffie-Hellman Key Exchange:")
print(f"  Alice public: {alice_key.public_key().export_key(format='raw').hex()[:40]}...")
print(f"  Bob public:   {bob_key.public_key().export_key(format='raw').hex()[:40]}...")
```

### Small Subgroup Attacks

```python
"""
If DH parameters aren't properly validated, an attacker
can send a public key in a small subgroup, limiting the
shared secret to a small set of values (brute-forceable).

Defense: Validate that received DH public keys satisfy:
  1 < y < p-1
  y^q mod p == 1  (for safe primes: check y^2 mod p != 1)
"""
print("""
DH Small Subgroup Attack:
1. Attacker sends g^0 = 1 as their "public key"
   → Shared secret is always 1
   
2. Attacker sends g^(p-1)/small_factor as public key
   → Shared secret is in a small subgroup
   → Brute-force recovers private key modulo small_factor

Logjam (2015):
- Downgraded DH to 512-bit "export" parameters
- Precomputation for common 512-bit primes
- Cost: ~$100 in cloud compute per target
""")
```

---

## 7.8 Key Takeaways

- **RSA** is still widely used but has many pitfalls: small exponents, PKCS#1 v1.5 padding oracles (Bleichenbacher/ROBOT), shared primes
- **Always use OAEP** for RSA encryption and **PSS** for RSA signatures — never textbook RSA or PKCS#1 v1.5
- **ECDSA nonce reuse** is a catastrophic, easily exploitable vulnerability — it reveals the private key algebraically (PS3 hack)
- **Batch GCD** can factor RSA keys that share prime factors — a real threat for IoT/embedded devices with poor RNG
- **DH key exchange** must use validated parameters and safe primes — small subgroup attacks and Logjam are real

---

**Next:** [Chapter 8 — JWT & Token Manipulation →](08_tokens.md)
