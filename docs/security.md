# Raybeam Security

## Overview

Raybeam's security model is built around LDAP-based authentication with role-based access control. This document covers the security architecture, threat model, best practices, and compliance considerations.

## Security Model

### Authentication

**Method**: HTTP Basic Authentication with LDAP backend

```
Client → Basic Auth Header → LDAP Bind → User Verification
```

**Key Properties**:
- No local password storage
- Centralized credential management via LDAP
- Standard HTTP Basic Auth (RFC 7617)
- Credentials verified on every request (stateless)

### Authorization Levels

Raybeam implements a three-tier authorization model:

| Level | Description | Requirements |
|-------|-------------|-------------|
| **Public** | Read-only access to user keys | None |
| **User** | Self-service key management | Valid LDAP credentials |
| **Admin** | Manage keys for any user | LDAP admin group membership |

### Authorization Matrix

| Endpoint | Public | User | Admin |
|----------|--------|------|-------|
| `GET /info` | ✅ | ✅ | ✅ |
| `GET /users/:sam/ssh-keys` | ✅ | ✅ | ✅ |
| `GET /users/:sam/ssh-keys/:fp` | ✅ | ✅ | ✅ |
| `GET /users/@me/ssh-keys` | ❌ | ✅ | ✅ |
| `PUT /users/@me/ssh-keys` | ❌ | ✅ | ✅ |
| `DELETE /users/@me/ssh-keys` | ❌ | ✅ | ✅ |
| `DELETE /users/@me/ssh-keys/:fp` | ❌ | ✅ | ✅ |
| `PUT /users/:sam/ssh-keys` | ❌ | ✅ (self) | ✅ |
| `DELETE /users/:sam/ssh-keys` | ❌ | ❌ | ✅ |
| `DELETE /users/:sam/ssh-keys/:fp` | ❌ | ✅ (self) | ✅ |

## LDAP Integration

### Authentication Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. Client sends Basic Auth header                      │
│    Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=       │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Server decodes credentials                           │
│    username: alice                                      │
│    password: secret123                                  │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 3. LDAP Bind Attempt                                    │
│    - Connect to LDAP server                             │
│    - Find user DN by sAMAccountName                     │
│    - Attempt bind with user DN + password               │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 4. Success: Retrieve User Info                          │
│    - DN: CN=Alice,OU=Users,DC=example,DC=com            │
│    - Groups: [CN=Engineers,..., CN=Admins,...]          │
│    - sAMAccountName: alice                              │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 5. Store in Request Context                             │
│    c.Locals("user", ldapUser)                           │
└─────────────────────────────────────────────────────────┘
```

### LDAP Configuration

**Required Settings**:
```bash
--ldap-server         # LDAP server URL (ldap:// or ldaps://)
--ldap-base-dn        # Base DN for user searches
--ldap-read-user      # Service account username
--ldap-read-password  # Service account password
--ldap-admin-group-dn # Admin group DN for authorization
```

**Service Account**:
- Read-only LDAP account for user lookups
- Credentials stored in memory only
- Used for sAMAccountName → DN resolution

**Security Considerations**:
- Use `ldaps://` (LDAP over TLS) for production
- Restrict service account permissions to read-only
- Store credentials in environment variables or secrets manager
- Rotate service account credentials regularly

### Admin Group Authorization

```go
// Pseudo-code for admin check
func isAdmin(user User, adminGroupDN string) bool {
    for _, group := range user.Groups {
        if group == adminGroupDN {
            return true
        }
    }
    return false
}
```

**Admin Group Configuration**:
```bash
# Example: Active Directory
--ldap-admin-group-dn "CN=Raybeam Admins,OU=Groups,DC=example,DC=com"

# Example: OpenLDAP
--ldap-admin-group-dn "cn=raybeam-admins,ou=groups,dc=example,dc=com"
```

**Authorization Rules**:
1. User authenticated via LDAP ✅
2. For multi-user operations:
   - If `sAMAccountNames == authenticated user`: allow (self-service)
   - Else: check admin group membership
3. Admin group DN match: allow
4. Otherwise: `403 Forbidden`

## SSH Key Security

### Key Validation

Raybeam uses `golang.org/x/crypto/ssh` for parsing and validation:

```go
// Validation process
key, _, _, _, err := ssh.ParseAuthorizedKey(rawKey)
if err != nil {
    return errCouldNotParseSSHKey
}

// Normalize: strip comments
normalizedKey := ssh.MarshalAuthorizedKey(key)

// Generate fingerprint
fingerprint := ssh.FingerprintSHA256(key)
```

**Accepted Key Types**:
- `ssh-rsa` (RSA)
- `ssh-dss` (DSA, deprecated)
- `ecdsa-sha2-nistp256/384/521` (ECDSA)
- `ssh-ed25519` (Ed25519, recommended)

**Key Requirements**:
- Valid OpenSSH public key format
- Successfully parses with crypto/ssh
- No minimum key length enforced (rely on SSH best practices)

### Fingerprint Generation

**Format**: SHA256:base64

**Example**: `SHA256:hSZQXa36JqMa2L3TRhc0t6RHSXVO3gy6rYx7RrVS2HA`

**Properties**:
- Unique identifier per key
- Cryptographically secure (SHA256)
- Compatible with OpenSSH (`ssh-keygen -l -E sha256`)

**Duplicate Prevention**:
```go
// Check before upload
keyExists, err := models.KeyExistsForUser(tx, dn, fingerprint)
if keyExists {
    return errSSHKeyAlreadyUploaded
}
```

## Data Security

### BoltDB Security

**File Permissions**:
```go
db, err := bbolt.Open(dbLocation, 0600, nil)
//                                  ^^^^ owner read/write only
```

**Storage Security**:
- Database file readable only by Raybeam process user
- No encryption at rest (filesystem encryption recommended)
- ACID transactions prevent corruption
- No SQL injection (key-value store)

**Backup Security**:
```bash
# BoltDB supports hot backups
# Ensure backup files have same permissions
cp /var/lib/raybeam/db.bolt /backup/db.bolt.$(date +%s)
chmod 0600 /backup/db.bolt.*
```

### Sensitive Data

**What's Stored**:
- SSH public keys (not sensitive, designed for distribution)
- LDAP DNs (user identifiers, semi-sensitive)

**What's NOT Stored**:
- LDAP passwords (verified, never stored)
- Private keys (never transmitted)
- Session tokens (stateless design)

**Data Sensitivity**:
- SSH public keys: Public by design
- LDAP DNs: Contains user organizational structure
- Fingerprints: Derived from public keys

## Network Security

### TLS/HTTPS

**Raybeam does NOT provide built-in TLS**. Deploy behind a reverse proxy:

```
Client → HTTPS → Reverse Proxy → HTTP → Raybeam
                  (TLS termination)
```

**Recommended Reverse Proxies**:
- Traefik (automatic Let's Encrypt)
- nginx (manual certificate management)
- Caddy (automatic HTTPS)
- HAProxy (TCP + HTTP)

**TLS Configuration Example (nginx)**:
```nginx
server {
    listen 443 ssl http2;
    server_name raybeam.example.com;

    ssl_certificate /etc/ssl/certs/raybeam.crt;
    ssl_certificate_key /etc/ssl/private/raybeam.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://raybeam:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Why TLS is Critical**:
- Basic Auth credentials transmitted in every request
- Base64 encoding is NOT encryption
- Credentials visible in plaintext without TLS
- Man-in-the-middle attacks possible

### Rate Limiting

**Raybeam does NOT implement rate limiting**. Configure at reverse proxy:

**nginx Example**:
```nginx
limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;

location /users/ {
    limit_req zone=auth burst=20 nodelay;
    proxy_pass http://raybeam:8080;
}
```

**Traefik Example**:
```yaml
http:
  middlewares:
    rate-limit:
      rateLimit:
        average: 100
        burst: 50
```

**Recommended Limits**:
- Authentication endpoints: 10-20 requests/minute per IP
- Public read endpoints: 100-500 requests/minute per IP
- Admin operations: 5-10 requests/minute per user

### Firewall Rules

**Inbound**:
```bash
# Allow HTTPS from internet
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow Raybeam from reverse proxy only (internal)
iptables -A INPUT -s 172.18.0.0/16 -p tcp --dport 8080 -j ACCEPT

# Allow LDAP from Raybeam to LDAP server
iptables -A OUTPUT -d <ldap-server> -p tcp --dport 389 -j ACCEPT
iptables -A OUTPUT -d <ldap-server> -p tcp --dport 636 -j ACCEPT
```

**Outbound**:
```bash
# Allow LDAP queries
iptables -A OUTPUT -p tcp --dport 389 -j ACCEPT  # LDAP
iptables -A OUTPUT -p tcp --dport 636 -j ACCEPT  # LDAPS
```

## Threat Model

### Threats and Mitigations

#### 1. Credential Theft

**Threat**: Attacker obtains LDAP credentials

**Attack Vectors**:
- Man-in-the-middle (no TLS)
- Network sniffing (no TLS)
- Browser history (credentials in URL)
- Log files (credentials in access logs)

**Mitigations**:
- ✅ Deploy with HTTPS/TLS (reverse proxy)
- ✅ Never use credentials in query parameters
- ✅ Sanitize logs to exclude Authorization headers
- ⚠️ Use LDAP over TLS (ldaps://)
- ⚠️ Implement 2FA at LDAP level (beyond Raybeam scope)

#### 2. Privilege Escalation

**Threat**: Regular user gains admin privileges

**Attack Vectors**:
- LDAP group injection
- Admin group DN misconfiguration
- Session hijacking

**Mitigations**:
- ✅ LDAP group membership verified on every request (stateless)
- ✅ Exact DN match required for admin group
- ✅ No client-side authorization state (all server-side)
- ⚠️ Secure LDAP server against group membership tampering
- ⚠️ Audit admin group membership changes

#### 3. SSH Key Injection

**Threat**: Attacker uploads malicious SSH key

**Attack Vectors**:
- Malformed key parsing exploit
- Buffer overflow in key parsing
- Key with embedded commands

**Mitigations**:
- ✅ golang.org/x/crypto/ssh validation (well-audited library)
- ✅ Key normalization (strip comments)
- ✅ Fingerprint-based duplicate prevention
- ✅ Authorization required for upload (LDAP user or admin)
- ℹ️ SSH public keys are safe by design (no code execution)

#### 4. Brute Force Authentication

**Threat**: Attacker brute forces LDAP credentials

**Attack Vectors**:
- Password guessing attacks
- Credential stuffing
- Dictionary attacks

**Mitigations**:
- ⚠️ Rate limiting (reverse proxy)
- ⚠️ IP-based blocking (fail2ban)
- ⚠️ LDAP account lockout policies
- ⚠️ Monitoring for failed authentication attempts
- ℹ️ LDAP enforces password policies

#### 5. Denial of Service (DoS)

**Threat**: Attacker overwhelms Raybeam service

**Attack Vectors**:
- Request flooding
- Large payload uploads
- LDAP query amplification

**Mitigations**:
- ⚠️ Rate limiting (reverse proxy)
- ⚠️ Request size limits (reverse proxy)
- ⚠️ Connection limits (reverse proxy)
- ⚠️ Monitoring and alerting
- ℹ️ Stateless design reduces resource exhaustion

#### 6. Data Exfiltration

**Threat**: Attacker downloads all SSH keys

**Attack Vectors**:
- Public read endpoints
- Bulk user enumeration
- Multi-user query abuse

**Mitigations**:
- ℹ️ SSH public keys are designed for distribution
- ⚠️ Rate limiting prevents bulk scraping
- ⚠️ Monitor for suspicious access patterns
- ⚠️ LDAP controls user enumeration
- ✅ No sensitive data beyond public keys

#### 7. Database Compromise

**Threat**: Attacker gains access to BoltDB file

**Attack Vectors**:
- File system access
- Container escape
- Backup theft

**Mitigations**:
- ✅ File permissions 0600 (owner only)
- ⚠️ Filesystem encryption (LUKS, dm-crypt)
- ⚠️ Encrypted backups
- ⚠️ Secure container runtime (AppArmor, SELinux)
- ℹ️ Data is public keys (limited sensitivity)

#### 8. LDAP Server Compromise

**Threat**: Attacker compromises LDAP infrastructure

**Attack Vectors**:
- LDAP admin account theft
- LDAP server vulnerability exploit
- Man-in-the-middle on LDAP queries

**Mitigations**:
- ⚠️ Use ldaps:// (LDAP over TLS)
- ⚠️ Secure LDAP infrastructure (beyond Raybeam)
- ⚠️ Monitor LDAP for unauthorized changes
- ⚠️ Validate LDAP TLS certificates
- ℹ️ Raybeam trusts LDAP as source of truth

## Security Best Practices

### Deployment Checklist

**Before Production Deployment**:

- [ ] Deploy behind HTTPS/TLS reverse proxy
- [ ] Use `ldaps://` for LDAP connections
- [ ] Configure rate limiting on reverse proxy
- [ ] Set up firewall rules (restrict port 8080)
- [ ] Enable filesystem encryption for BoltDB
- [ ] Implement encrypted backups
- [ ] Configure LDAP service account with minimal permissions
- [ ] Set strong admin group DN
- [ ] Enable access logging
- [ ] Set up monitoring and alerting
- [ ] Test admin authorization boundaries
- [ ] Verify file permissions (0600 for db.bolt)
- [ ] Remove default credentials (if any)
- [ ] Document admin group membership process

### Operational Security

**Regular Tasks**:
- Rotate LDAP service account credentials quarterly
- Review admin group membership monthly
- Audit logs for suspicious activity weekly
- Backup database daily (encrypted)
- Test disaster recovery quarterly
- Update Raybeam to latest version monthly

**Monitoring**:
- Failed authentication attempts (potential brute force)
- Admin operations (key uploads/deletions for other users)
- Unusual access patterns (bulk key retrievals)
- LDAP connection failures (potential infrastructure issues)

**Incident Response**:
1. Identify compromised accounts (LDAP logs + Raybeam logs)
2. Rotate LDAP credentials for affected users
3. Remove compromised SSH keys
4. Review admin group membership
5. Audit recent admin operations
6. Update security controls as needed

### Defense in Depth

**Layer 1: Network**
- TLS/HTTPS (reverse proxy)
- Firewall rules
- Rate limiting
- IP allowlisting (optional)

**Layer 2: Authentication**
- LDAP credential verification
- No local password storage
- Service account minimal permissions

**Layer 3: Authorization**
- User vs admin separation
- LDAP group membership verification
- Self-service boundaries

**Layer 4: Application**
- Input validation (SSH key parsing)
- Stateless design (no session hijacking)
- Error handling (no information disclosure)

**Layer 5: Data**
- BoltDB file permissions (0600)
- Filesystem encryption (optional)
- Encrypted backups (optional)

## Compliance Considerations

### GDPR (General Data Protection Regulation)

**Data Collected**:
- LDAP DNs (user identifiers)
- SSH public keys

**Compliance Notes**:
- SSH public keys: Not personally identifiable (technical identifiers)
- LDAP DNs: May contain name information (semi-PII)
- No sensitive personal data stored
- Users can delete own keys (right to erasure)
- Admins can delete user keys (data subject requests)

**Recommendations**:
- Document data retention policy
- Implement audit logging for compliance
- Provide user self-service deletion (@me endpoints)
- Regular backup cleanup (remove old backups)

### SOC 2 (System and Organization Controls)

**Control Objectives**:
- **CC6.1 (Logical Access)**: LDAP authentication + admin groups ✅
- **CC6.2 (Authorization)**: Role-based access control ✅
- **CC6.6 (Audit Logging)**: Fiber logger middleware ✅
- **CC6.7 (Credential Management)**: LDAP-based, no local storage ✅

**Recommendations**:
- Implement structured JSON logging
- Add audit trail for admin operations
- Enable log retention (90+ days)
- Monitor for unauthorized access

### CIS Controls

**Relevant Controls**:
- **CIS 4 (Secure Configuration)**: BoltDB permissions, HTTPS enforcement
- **CIS 5 (Account Management)**: LDAP-based authentication
- **CIS 6 (Access Control)**: Admin group authorization
- **CIS 8 (Audit Logging)**: Request logging via Fiber middleware

## Security Reporting

### Reporting Security Issues

**Contact**: Security issues should be reported via GitHub Security Advisories

**Process**:
1. Do NOT open public GitHub issues for security vulnerabilities
2. Use GitHub Security Advisory: https://github.com/netresearch/raybeam/security/advisories
3. Provide detailed reproduction steps
4. Allow 90 days for remediation before public disclosure

**Response Timeline**:
- Initial response: Within 7 days
- Triage and validation: Within 14 days
- Fix development: Based on severity (critical: <30 days)
- Public disclosure: After fix release + 14 days

### Security Updates

**Notification Channels**:
- GitHub Security Advisories
- GitHub Releases (changelog)
- Dependabot alerts (for known CVEs)

**Update Policy**:
- Critical security fixes: Patch release within 7 days
- High severity: Patch release within 30 days
- Medium/low severity: Next minor release

## Security Audit History

### Known Issues

**Current**: None reported

### Past Issues

**None**: Project has not had security vulnerabilities reported to date

### Third-Party Audits

**Status**: No third-party security audit performed yet

**Recommendation**: Organizations with strict security requirements should conduct internal security review or third-party penetration testing before production deployment.

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls v8](https://www.cisecurity.org/controls)
- [RFC 7617 - HTTP Basic Authentication](https://tools.ietf.org/html/rfc7617)
- [LDAP RFC 4511](https://tools.ietf.org/html/rfc4511)
- [OpenSSH Security Best Practices](https://www.openssh.com/security.html)