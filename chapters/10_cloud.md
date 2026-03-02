# Chapter 10 — Cloud KMS & IAM Boundaries

> *"We escalated from a read-only S3 role to decrypting every secret in the account. The KMS key policy allowed any IAM principal with kms:Decrypt — and our compromised role had it through a wildcard policy."*

---

## 10.1 Envelope Encryption Model

Cloud providers don't encrypt your data directly with the master key.  They use **envelope encryption**:

```
┌─────────────────────────────────────────────────────────┐
│                  Envelope Encryption                    │
│                                                         │
│   Master Key (KMS)                                      │
│       │                                                 │
│       ▼                                                 │
│   ┌──────────┐                                          │
│   │ Encrypt  │──▶ Encrypted Data Key (stored with data) │
│   └──────────┘                                          │
│       ▲                                                 │
│       │                                                 │
│   Data Key (plaintext, ephemeral)                       │
│       │                                                 │
│       ▼                                                 │
│   ┌──────────┐                                          │
│   │ Encrypt  │──▶ Encrypted Data                        │
│   │  (AES)   │                                          │
│   └──────────┘                                          │
│                                                         │
│  Process:                                               │
│  1. KMS generates a Data Key (DEK)                      │
│  2. DEK encrypts your data (AES-GCM)                    │
│  3. KMS encrypts the DEK with the Master Key (KEK)      │
│  4. Encrypted DEK stored alongside encrypted data       │
│  5. Plaintext DEK deleted from memory                   │
└─────────────────────────────────────────────────────────┘
```

---

## 10.2 AWS KMS

### Key Operations

```python
"""
aws_kms.py — Common AWS KMS operations and attack patterns.
"""
import boto3
import json
import base64

kms = boto3.client('kms')

# ─── LEGITIMATE OPERATIONS ───

def encrypt_data(key_id: str, plaintext: bytes) -> bytes:
    """Encrypt data using KMS."""
    response = kms.encrypt(
        KeyId=key_id,
        Plaintext=plaintext,
        EncryptionAlgorithm='SYMMETRIC_DEFAULT'  # AES-256-GCM
    )
    return response['CiphertextBlob']

def decrypt_data(ciphertext: bytes) -> bytes:
    """Decrypt data using KMS (key ID is embedded in ciphertext)."""
    response = kms.decrypt(
        CiphertextBlob=ciphertext,
        EncryptionAlgorithm='SYMMETRIC_DEFAULT'
    )
    return response['Plaintext']

def generate_data_key(key_id: str) -> dict:
    """Generate an envelope encryption data key."""
    response = kms.generate_data_key(
        KeyId=key_id,
        KeySpec='AES_256'
    )
    return {
        'plaintext_key': response['Plaintext'],      # Use, then delete
        'encrypted_key': response['CiphertextBlob'],  # Store with data
    }
```

### Auditing KMS Key Policies

```python
"""
kms_audit.py — Audit AWS KMS key policies for common misconfigurations.
"""
import boto3
import json

def audit_kms_keys():
    """Scan all KMS keys for policy issues."""
    kms = boto3.client('kms')
    findings = []
    
    # List all customer-managed keys
    paginator = kms.get_paginator('list_keys')
    for page in paginator.paginate():
        for key in page['Keys']:
            key_id = key['KeyId']
            
            try:
                # Get key policy
                policy_response = kms.get_key_policy(
                    KeyId=key_id, PolicyName='default'
                )
                policy = json.loads(policy_response['Policy'])
                
                # Get key metadata
                meta = kms.describe_key(KeyId=key_id)['KeyMetadata']
                
                # Skip AWS-managed keys
                if meta['KeyManager'] == 'AWS':
                    continue
                
                # Check each policy statement
                for stmt in policy.get('Statement', []):
                    principal = stmt.get('Principal', {})
                    action = stmt.get('Action', [])
                    effect = stmt.get('Effect', 'Deny')
                    condition = stmt.get('Condition', {})
                    
                    if isinstance(action, str):
                        action = [action]
                    
                    # Finding: kms:* (all permissions)
                    if 'kms:*' in action and effect == 'Allow':
                        if principal == '*' or principal == {'AWS': '*'}:
                            if not condition:
                                findings.append({
                                    'key_id': key_id,
                                    'severity': 'CRITICAL',
                                    'finding': 'Key allows kms:* to everyone',
                                    'statement': stmt
                                })
                    
                    # Finding: kms:Decrypt without conditions
                    decrypt_actions = [a for a in action 
                                      if 'Decrypt' in a or a == 'kms:*']
                    if decrypt_actions and effect == 'Allow':
                        if not condition:
                            findings.append({
                                'key_id': key_id,
                                'severity': 'HIGH',
                                'finding': f'Decrypt allowed without conditions',
                                'principal': principal,
                            })
                    
                    # Finding: Key rotation not enabled
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation['KeyRotationEnabled']:
                            findings.append({
                                'key_id': key_id,
                                'severity': 'MEDIUM',
                                'finding': 'Key rotation not enabled',
                            })
                    except Exception:
                        pass
                        
            except Exception as e:
                findings.append({
                    'key_id': key_id,
                    'severity': 'INFO',
                    'finding': f'Could not audit: {e}',
                })
    
    return findings

# Run audit
findings = audit_kms_keys()
for f in findings:
    print(f"[{f['severity']}] {f['key_id'][:12]}... — {f['finding']}")
```

---

## 10.3 Secrets in the Wrong Places

### Scanning for Exposed Secrets

```bash
# AWS CLI: check for secrets in environment variables
aws lambda get-function-configuration --function-name myFunc | \
  jq '.Environment.Variables'

# Check SSM Parameter Store for unencrypted secrets
aws ssm describe-parameters --query "Parameters[?Type=='String']" | \
  jq '.[].Name'

# Check for secrets in EC2 user data
aws ec2 describe-instances --query \
  "Reservations[].Instances[].[InstanceId,UserData]" --output text

# Check CloudFormation templates for hardcoded secrets
grep -rn --include="*.yaml" --include="*.json" \
  -iE '(password|secret|apikey|token)\s*[:=]' templates/
```

```python
"""
secrets_scanner.py — Scan AWS for exposed secrets.
"""
import boto3
import base64
import re
import json

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'["\']?[0-9a-zA-Z/+]{40}["\']?', 'Possible AWS Secret Key'),
    (r'password\s*[=:]\s*["\'][^"\']+', 'Hardcoded Password'),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', 'Private Key'),
    (r'mongodb://[^\s]+', 'MongoDB Connection String'),
    (r'postgres://[^\s]+', 'PostgreSQL Connection String'),
]

def scan_lambda_env_vars():
    """Scan Lambda functions for secrets in environment variables."""
    client = boto3.client('lambda')
    findings = []
    
    paginator = client.get_paginator('list_functions')
    for page in paginator.paginate():
        for func in page['Functions']:
            env_vars = func.get('Environment', {}).get('Variables', {})
            for key, value in env_vars.items():
                for pattern, desc in SECRET_PATTERNS:
                    if re.search(pattern, value):
                        findings.append({
                            'source': f"Lambda:{func['FunctionName']}",
                            'variable': key,
                            'type': desc,
                            'value': value[:20] + '...',
                        })
    return findings

def scan_ec2_userdata():
    """Scan EC2 user data for secrets."""
    ec2 = boto3.client('ec2')
    findings = []
    
    instances = ec2.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            try:
                userdata = ec2.describe_instance_attribute(
                    InstanceId=instance['InstanceId'],
                    Attribute='userData'
                )
                if 'Value' in userdata.get('UserData', {}):
                    decoded = base64.b64decode(
                        userdata['UserData']['Value']
                    ).decode(errors='ignore')
                    for pattern, desc in SECRET_PATTERNS:
                        if re.search(pattern, decoded):
                            findings.append({
                                'source': f"EC2:{instance['InstanceId']}",
                                'type': desc,
                            })
            except Exception:
                pass
    return findings

# Run scans
print("=== Lambda Environment Variables ===")
for f in scan_lambda_env_vars():
    print(f"  [{f['type']}] {f['source']} → {f['variable']}")

print("\n=== EC2 User Data ===")
for f in scan_ec2_userdata():
    print(f"  [{f['type']}] {f['source']}")
```

---

## 10.4 Attack: KMS Privilege Escalation

```python
"""
kms_escalation.py — Paths from limited access to full decryption.
"""
print("""
Common KMS Privilege Escalation Paths:

1. kms:CreateGrant
   → Attacker grants themselves kms:Decrypt on the target key
   → Immediate access to all encrypted data

2. kms:PutKeyPolicy  
   → Attacker rewrites the key policy to allow their principal
   → Full key control

3. iam:PassRole + lambda:CreateFunction
   → Create a Lambda with a role that has kms:Decrypt
   → Invoke Lambda to decrypt secrets

4. ssm:GetParameter + kms:Decrypt
   → Read encrypted SSM parameters
   → KMS auto-decrypts if the caller has kms:Decrypt

5. s3:GetObject + kms:Decrypt
   → Read S3 objects encrypted with SSE-KMS
   → Transparent decryption if caller has both permissions

6. secretsmanager:GetSecretValue
   → Secrets Manager handles KMS decryption internally
   → Only needs secretsmanager:GetSecretValue (and the key policy
     must allow the caller's principal)
""")

# Check your current permissions
import boto3
sts = boto3.client('sts')
identity = sts.get_caller_identity()
print(f"Current identity: {identity['Arn']}")

# Enumerate KMS grants
kms = boto3.client('kms')
try:
    keys = kms.list_keys()['Keys']
    for key in keys[:5]:
        try:
            grants = kms.list_grants(KeyId=key['KeyId'])['Grants']
            for grant in grants:
                print(f"\nKey: {key['KeyId'][:12]}...")
                print(f"  Grantee: {grant['GranteePrincipal']}")
                print(f"  Operations: {grant['Operations']}")
        except Exception:
            pass
except Exception as e:
    print(f"Cannot list keys: {e}")
```

---

## 10.5 HashiCorp Vault

```bash
# Common Vault audit commands
vault secrets list                    # List secret engines
vault read secret/data/production     # Read a secret
vault audit list                      # Check audit backends

# Check for auth method issues
vault auth list
vault token lookup                    # Current token info
vault token capabilities secret/*    # What can current token do?

# Enumerate accessible paths
vault kv list secret/
vault kv list secret/production/
```

```python
"""
vault_audit.py — Audit HashiCorp Vault configuration.
"""
import requests
import os

VAULT_ADDR = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN', '')

def vault_request(path, method='GET'):
    headers = {'X-Vault-Token': VAULT_TOKEN}
    url = f"{VAULT_ADDR}/v1/{path}"
    resp = requests.request(method, url, headers=headers)
    return resp.json() if resp.status_code == 200 else None

def audit_vault():
    findings = []
    
    # Check seal status
    health = vault_request('sys/health')
    if health:
        if not health.get('sealed'):
            findings.append("INFO: Vault is unsealed")
        if health.get('initialized') and not health.get('sealed'):
            findings.append("INFO: Vault is initialized and running")
    
    # Check audit devices
    audit = vault_request('sys/audit')
    if audit and not audit.get('data'):
        findings.append("WARNING: No audit devices enabled — no audit trail")
    
    # Check auth methods  
    auth = vault_request('sys/auth')
    if auth:
        for path, config in auth.get('data', {}).items():
            if config.get('type') == 'token' and 'root' in path:
                findings.append(f"INFO: Root token auth at {path}")
    
    # Check token TTL
    token_info = vault_request('auth/token/lookup-self')
    if token_info:
        ttl = token_info.get('data', {}).get('ttl', 0)
        if ttl == 0:
            findings.append("CRITICAL: Current token has no TTL (never expires)")
    
    return findings

for finding in audit_vault():
    print(f"  {finding}")
```

---

## 10.6 Key Takeaways

- **Envelope encryption** is how all cloud KMS systems work — understand the DEK/KEK model
- **KMS key policies** are the primary control — audit for wildcard principals, missing conditions, and overly broad permissions
- **`kms:CreateGrant` and `kms:PutKeyPolicy`** are privilege escalation vectors — treat them as high-risk permissions
- **Secrets leak** through Lambda env vars, EC2 user data, CloudFormation templates, and SSM parameters
- **Key rotation** should be enabled for all customer-managed KMS keys
- **Vault audit** should always have audit devices enabled and tokens with TTLs

---

**Next:** [Chapter 11 — Modern Primitives & PQC →](11_modern.md)
