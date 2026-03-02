# Chapter 12 — Exploitability & Reporting

> *"The client's response was: 'AES-256 is unbreakable, so we're fine.' They had AES-256 in ECB mode, a hardcoded key in their GitHub repo, and no authentication on the ciphertext.  Communicating this required more diplomacy than the exploit itself."*

---

## 12.1 The Exploitability Spectrum

Not all crypto weaknesses are equal.  Your job as a pentester is to map each finding to the **exploitability spectrum** and communicate the real risk.

```
  THEORETICAL ◄──────────────────────────────────────►  WEAPONIZED
       │                                                      │
  "Mathematically     "Practical with      "Script          "Automated
   possible but        significant          kiddie can       tool, one
   no known            resources"           do it with       command"
   practical attack"                        a tutorial"       
       │                    │                    │              │
   AES-256 timing     Batch GCD on          CBC padding     JWT alg:none
   side-channel        RSA keys             oracle attack    exploit
       │                    │                    │              │
   INFORMATIONAL         MEDIUM                HIGH          CRITICAL
```

### Severity Classification Framework

```python
"""
crypto_severity.py — Classify crypto findings by exploitability.
"""

SEVERITY_MATRIX = {
    # (exploitability, impact) → severity
    ("trivial",    "confidentiality"): "CRITICAL",
    ("trivial",    "integrity"):       "CRITICAL",
    ("trivial",    "authentication"):  "CRITICAL",
    ("moderate",   "confidentiality"): "HIGH",
    ("moderate",   "integrity"):       "HIGH",
    ("moderate",   "authentication"):  "HIGH",
    ("difficult",  "confidentiality"): "MEDIUM",
    ("difficult",  "integrity"):       "MEDIUM",
    ("difficult",  "authentication"):  "MEDIUM",
    ("theoretical","any"):             "LOW/INFORMATIONAL",
}

COMMON_FINDINGS = [
    {
        "title": "JWT Algorithm None Accepted",
        "exploitability": "trivial",
        "impact": "authentication",
        "severity": "CRITICAL",
        "proof": "Forge admin token with alg:none, access admin panel",
    },
    {
        "title": "AES-ECB Mode Used for Sensitive Data",
        "exploitability": "trivial",
        "impact": "confidentiality",
        "severity": "HIGH",
        "proof": "Demonstrate pattern leakage in encrypted data",
    },
    {
        "title": "CBC Padding Oracle",
        "exploitability": "moderate",
        "impact": "confidentiality",
        "severity": "HIGH",
        "proof": "Decrypt session token via padding oracle",
    },
    {
        "title": "MD5 Used for File Integrity",
        "exploitability": "moderate",
        "impact": "integrity",
        "severity": "MEDIUM",
        "proof": "Generate collision with hashclash",
    },
    {
        "title": "TLS 1.0 Supported",
        "exploitability": "difficult",
        "impact": "confidentiality",
        "severity": "MEDIUM",
        "proof": "BEAST/POODLE attack chain demonstration",
    },
    {
        "title": "RSA 2048-bit Key (PQC Consideration)",
        "exploitability": "theoretical",
        "impact": "confidentiality",
        "severity": "INFORMATIONAL",
        "proof": "No current practical attack; future quantum risk",
    },
]

print("Common Crypto Findings:\n")
for f in COMMON_FINDINGS:
    print(f"  [{f['severity']:14s}] {f['title']}")
    print(f"  {'':14s}   Exploitability: {f['exploitability']}")
    print(f"  {'':14s}   Proof: {f['proof']}")
    print()
```

---

## 12.2 Writing Crypto Findings for Pentest Reports

### Finding Template

```markdown
## [SEVERITY] Finding Title

### Description
What the vulnerability is, in 2-3 sentences that a technical reader
can immediately understand.

### Impact
What an attacker can achieve by exploiting this vulnerability.
Be specific: "decrypt all user sessions" not "confidentiality impact."

### Evidence
Step-by-step reproduction with screenshots/code.
Include the exact request/response or tool output.

### Risk Rating
- **Likelihood:** How easy is it to exploit? (Trivial / Moderate / Difficult)
- **Impact:** What's the worst case? (Critical / High / Medium / Low)
- **Overall:** Combined severity rating

### Remediation
Specific, actionable fix with code examples if possible.
Include both the quick fix and the ideal long-term solution.

### References
- CVE numbers
- Relevant standards (NIST, OWASP)
- Tool documentation
```

### Example: Padding Oracle Finding

```python
"""
Generate a structured pentest finding for a padding oracle.
"""
finding = {
    "title": "CBC Padding Oracle in Session Token Decryption",
    "severity": "HIGH",
    "cvss": "7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    
    "description": """
The application uses AES-256-CBC to encrypt session tokens. The 
/api/validate endpoint returns distinguishable error responses for 
invalid padding (HTTP 500 with "Decryption error") versus valid 
padding with invalid token content (HTTP 403 with "Unauthorized"). 
This differential response constitutes a padding oracle that enables 
complete decryption of any session token without knowledge of the 
encryption key.
    """.strip(),
    
    "impact": """
An attacker can:
1. Decrypt any user's session token, revealing the plaintext user ID,
   role, and session metadata
2. Forge arbitrary session tokens to impersonate any user, including 
   administrators
3. No authentication is required — the oracle is accessible without
   a valid session
   
Estimated attack time: ~15 minutes per token (automated).
    """.strip(),
    
    "evidence": """
1. Captured a valid session token from the Set-Cookie header
2. Submitted modified tokens to /api/validate
3. Observed differential responses (500 vs 403)
4. Ran padding oracle attack script (attached)
5. Successfully decrypted the token:
   Original: [encrypted blob]
   Decrypted: {"uid":1,"role":"user","exp":1735689600}
6. Forged admin token:
   Forged: {"uid":1,"role":"admin","exp":1735689600}
7. Used forged token to access /admin → HTTP 200
    """.strip(),
    
    "remediation": {
        "immediate": (
            "Normalize error responses: return the same HTTP status "
            "and body for all decryption failures, regardless of cause."
        ),
        "long_term": (
            "Migrate from AES-CBC to AES-GCM (authenticated encryption). "
            "This makes the token tamper-evident and eliminates padding "
            "oracle attacks entirely. Additionally, sign tokens with HMAC "
            "and verify the signature before decryption."
        ),
        "code_example": '''
# Before (vulnerable):
try:
    plaintext = decrypt_cbc(token)
except PaddingError:
    return Response("Decryption error", 500)  # ← Oracle!

# After (fixed):
try:
    plaintext = decrypt_gcm(token)  # AEAD: decrypt + verify
except (DecryptionError, AuthenticationError):
    return Response("Invalid token", 401)  # Same response always
'''
    },
    
    "references": [
        "CWE-209: Generation of Error Message Containing Sensitive Information",
        "CWE-347: Improper Verification of Cryptographic Signature",
        "Vaudenay, S. 'Security Flaws Induced by CBC Padding' (EUROCRYPT 2002)",
        "OWASP Testing Guide: Testing for Padding Oracle",
    ]
}

# Pretty-print the finding
print(f"{'='*60}")
print(f"[{finding['severity']}] {finding['title']}")
print(f"CVSS: {finding['cvss']}")
print(f"{'='*60}")
print(f"\nDESCRIPTION:\n{finding['description']}")
print(f"\nIMPACT:\n{finding['impact']}")
print(f"\nREMEDIATION (Immediate):\n{finding['remediation']['immediate']}")
print(f"\nREMEDIATION (Long-term):\n{finding['remediation']['long_term']}")
```

---

## 12.3 Communicating Risk to Non-Technical Stakeholders

```python
"""
Translating crypto findings for executives and managers.
"""
TRANSLATIONS = {
    "AES-ECB mode in use": {
        "technical": "ECB mode encrypts identical plaintext blocks to identical "
                     "ciphertext blocks, leaking data patterns.",
        "executive": "Your encryption is like a codebook where the same word "
                     "always gets the same code — an attacker can see patterns "
                     "in your data without decrypting it.",
        "business_impact": "Sensitive data patterns (e.g., repeated transactions, "
                          "account numbers) are visible to anyone with access to "
                          "the encrypted data.",
    },
    "JWT alg:none accepted": {
        "technical": "The server accepts JWTs with algorithm 'none', bypassing "
                     "signature verification entirely.",
        "executive": "Your login system accepts tickets with no signature. Anyone "
                     "can write their own ticket claiming to be any user, "
                     "including an administrator.",
        "business_impact": "Complete authentication bypass. Any attacker can access "
                          "any account, including admin accounts, without a password.",
    },
    "Padding oracle vulnerability": {
        "technical": "Differential error responses during CBC decryption allow "
                     "an attacker to decrypt ciphertexts byte-by-byte.",
        "executive": "Your system accidentally gives away hints about encrypted "
                     "data through its error messages. An attacker can use "
                     "these hints to decode everything, like a game of 20 "
                     "questions played millions of times.",
        "business_impact": "Attacker can decrypt any encrypted session or data "
                          "without needing the encryption key. This includes "
                          "session tokens and any encrypted user data.",
    },
    "TLS 1.0 supported": {
        "technical": "The server supports TLS 1.0, which is vulnerable to "
                     "BEAST and POODLE attacks.",
        "executive": "Your server supports an old, broken version of the "
                     "encryption protocol, similar to using a lock from the "
                     "1990s that locksmiths can pick. Modern browsers have "
                     "already dropped support for it.",
        "business_impact": "Non-compliance with PCI DSS, HIPAA, and other "
                          "regulatory frameworks. Potential for encrypted "
                          "traffic interception.",
    },
}

for finding, translations in TRANSLATIONS.items():
    print(f"\n{'─'*60}")
    print(f"Finding: {finding}")
    print(f"{'─'*60}")
    print(f"  Technical:       {translations['technical'][:80]}...")
    print(f"  Executive:       {translations['executive'][:80]}...")
    print(f"  Business Impact: {translations['business_impact'][:80]}...")
```

---

## 12.4 Remediation Guidance Patterns

```python
"""
remediation_templates.py — Standard remediation guidance for common findings.
"""

REMEDIATIONS = {
    "weak_symmetric": {
        "finding": "DES/3DES/RC4/Blowfish in use",
        "fix": "Migrate to AES-256-GCM or ChaCha20-Poly1305",
        "code": """
# Before
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)

# After
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
""",
    },
    "weak_hash": {
        "finding": "MD5/SHA-1 used for integrity or signatures",
        "fix": "Migrate to SHA-256 or SHA-3. For MACs, use HMAC-SHA-256.",
        "code": """
# Before
digest = hashlib.md5(data).hexdigest()

# After
digest = hashlib.sha256(data).hexdigest()
# Or for authentication:
mac = hmac.new(key, data, hashlib.sha256).hexdigest()
""",
    },
    "weak_password_hash": {
        "finding": "Fast hash (SHA-256) or weak algorithm for passwords",
        "fix": "Use Argon2id with memory_cost=65536, time_cost=3, parallelism=4",
        "code": """
# Before
hashed = hashlib.sha256(salt + password).hexdigest()

# After
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
""",
    },
    "jwt_issues": {
        "finding": "JWT algorithm confusion or weak signing",
        "fix": "Whitelist algorithms server-side. Use RS256 with proper key management.",
        "code": """
# Before (vulnerable)
decoded = jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)['alg'])

# After (secure)
decoded = jwt.decode(token, public_key, algorithms=['RS256'])  # Whitelist!
""",
    },
    "no_tls_13": {
        "finding": "TLS 1.0/1.1 supported or TLS 1.3 not available",
        "fix": "Disable TLS 1.0/1.1, enable TLS 1.3, use strong cipher suites only",
        "code": """
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;

# Apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
""",
    },
}

for key, r in REMEDIATIONS.items():
    print(f"\n[{r['finding']}]")
    print(f"  Fix: {r['fix']}")
```

---

## 12.5 Responsible Disclosure for Crypto Bugs

```
┌─────────────────────────────────────────────────────────┐
│            Crypto Bug Disclosure Checklist               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. VERIFY the vulnerability is real                    │
│     □ Reproduce reliably                                │
│     □ Confirm it's exploitable, not just theoretical    │
│     □ Test in your own environment, not production      │
│                                                         │
│  2. ASSESS the scope                                    │
│     □ How many users/systems are affected?              │
│     □ Is it a library bug (broad) or app bug (narrow)?  │
│     □ Is there active exploitation?                     │
│                                                         │
│  3. REPORT through proper channels                      │
│     □ Check for security.txt or bug bounty program      │
│     □ Use encrypted communication (PGP/Signal)          │
│     □ Include: description, impact, PoC, remediation    │
│     □ Set a disclosure deadline (90 days standard)      │
│                                                         │
│  4. COORDINATE the fix                                  │
│     □ Work with vendor on timeline                      │
│     □ Provide remediation guidance                      │
│     □ Verify the fix addresses the root cause           │
│                                                         │
│  5. DISCLOSE responsibly                                │
│     □ Wait for patch to be available                    │
│     □ Publish advisory with technical details           │
│     □ Credit the vendor for rapid response              │
│                                                         │
│  Special: Library/protocol vulnerabilities              │
│     □ Request CVE from MITRE or CNA                     │
│     □ Coordinate with downstream users                  │
│     □ Consider embargo period for critical bugs         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 12.6 Lab: Write a Pentest Finding

```python
"""
lab_writing_finding.py — Practice writing a professional crypto finding.

SCENARIO:
During a web application penetration test, you discovered the following:

1. The application uses AES-CBC to encrypt API tokens
2. The /api/refresh endpoint returns HTTP 400 with message
   "Invalid padding" when padding is incorrect, and HTTP 401 with
   "Invalid token" when padding is correct but token is invalid
3. You successfully decrypted a user's API token using a padding
   oracle attack (256 requests per byte)
4. The decrypted token contains: user_id, role, expiry timestamp
5. You forged an admin token and accessed /admin/users

YOUR TASK:
Write a complete pentest finding using the template in section 12.2.
Include:
- Clear title and severity rating
- Non-technical impact description
- Step-by-step evidence
- Both immediate and long-term remediation
- CVSS score justification

BONUS:
- Write an executive summary version (3 sentences max)
- Write a developer-focused remediation with code examples
"""
print("""
Your finding should answer these questions:
1. What did you find? (one sentence)
2. Why does it matter? (business impact)
3. How did you prove it? (evidence)
4. How do they fix it? (remediation)
5. How urgent is it? (severity)
""")
```

---

## 12.7 Comprehensive Crypto Audit Checklist

```python
"""
crypto_audit_checklist.py — Master checklist for crypto assessments.
"""

CHECKLIST = {
    "Transport Security": [
        "TLS version (reject < 1.2, prefer 1.3)",
        "Cipher suites (no RC4, DES, 3DES, NULL, export)",
        "Forward secrecy (ECDHE/DHE required)",
        "Certificate chain validity",
        "Certificate pinning (mobile apps)",
        "HSTS header present and correctly configured",
        "No mixed content (HTTP resources on HTTPS pages)",
    ],
    "Encryption at Rest": [
        "Algorithm and mode (AES-GCM or ChaCha20-Poly1305)",
        "Key storage (HSM/KMS, not in code/config)",
        "IV/nonce generation (random, unique per message)",
        "Key rotation policy and implementation",
        "No ECB mode",
        "Authenticated encryption (AEAD preferred)",
    ],
    "Hashing and Integrity": [
        "No MD5 or SHA-1 for security purposes",
        "HMAC for message authentication (not H(key||msg))",
        "Constant-time MAC comparison",
    ],
    "Password Storage": [
        "Argon2id, bcrypt, or scrypt (not fast hashes)",
        "Adequate cost parameters",
        "Unique random salt per password",
        "No password length limits preventing strong passwords",
    ],
    "Token and Session Management": [
        "JWT: algorithm whitelist (not from header)",
        "JWT: no alg:none accepted",
        "JWT: no RS256→HS256 confusion",
        "Sufficient token entropy (128+ bits)",
        "Token expiry enforced",
        "Sensitive data not stored in JWT payload",
    ],
    "Key Management": [
        "No hardcoded keys in source code",
        "No secrets in git history",
        "No secrets in environment variables (prefer KMS/Vault)",
        "Key separation (dev ≠ staging ≠ production)",
        "Key rotation automated",
    ],
    "Randomness": [
        "CSPRNG for all security-sensitive values",
        "No use of Math.random/random.random for crypto",
        "Sufficient entropy at generation time",
    ],
}

print("=" * 60)
print("  CRYPTO AUDIT MASTER CHECKLIST")
print("=" * 60)
for category, items in CHECKLIST.items():
    print(f"\n── {category} ──")
    for item in items:
        print(f"  □ {item}")
```

---

## 12.8 Key Takeaways

- **Exploitability determines severity** — a theoretical weakness is not the same as a one-click exploit.  Rate accordingly.
- **Structure your findings** consistently: description, impact, evidence, remediation, references.
- **Translate for your audience** — executives need business impact, developers need code fixes, compliance needs CVE references.
- **Always provide remediation** — a finding without a fix is just complaining.  Include both quick fixes and long-term solutions.
- **Responsible disclosure** matters — follow the 90-day standard, coordinate with vendors, request CVEs for library bugs.
- **Use the checklist** — systematic assessment catches more issues than ad-hoc testing.

---

## Closing: The Offensive Crypto Mindset

Cryptography is the last line of defense.  When everything else fails — firewalls bypassed, authentication broken, network compromised — encryption is supposed to protect the data.

But encryption only works if it's **correctly implemented**.  Your job is to find the gaps between the math and the code, between the specification and the configuration, between the vendor's marketing and the reality of the deployment.

The attacks in this book are not theoretical.  Every one of them has been used in real engagements, real CVEs, real data breaches.  The developers you're testing aren't stupid — they're just optimizing for different things.  Your findings help them see what they missed.

Break things responsibly.  Report clearly.  Fix the root cause.

**Good hunting.**
