# Raybeam Architecture

## Overview

Raybeam is a lightweight, stateless HTTP service for managing SSH public keys with LDAP-based authentication. The architecture follows clean separation of concerns with three primary layers: CLI, Server, and Storage.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HTTP Client                           │
│                    (curl, scripts, apps)                     │
└────────────────┬────────────────────────────────────────────┘
                 │ HTTP/REST
                 │ Basic Auth
┌────────────────▼────────────────────────────────────────────┐
│                      Fiber Web Server                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                 Middleware Chain                      │  │
│  │  Logger → Auth Middleware → Route Handlers           │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────┬─────────────────────────────┬──────────────────┘
             │                             │
             │ LDAP Bind                   │ BoltDB Ops
             │ User Lookup                 │ CRUD
             │                             │
┌────────────▼─────────────┐  ┌───────────▼──────────────────┐
│      LDAP Server          │  │        BoltDB                │
│                           │  │                              │
│  - User Authentication    │  │  Bucket: ssh_keys            │
│  - Group Membership       │  │  Key: LDAP DN                │
│  - DN Resolution          │  │  Value: []SSHKey (JSON)      │
└───────────────────────────┘  └──────────────────────────────┘
```

## Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐       │
│  │   root.go    │  │  serve.go   │  │  build.go    │       │
│  │              │  │             │  │              │       │
│  │  - Cobra CLI │  │  - Init DB  │  │  - Version   │       │
│  │  - Version   │  │  - Init SRV │  │  - VCS Info  │       │
│  └──────────────┘  └─────────────┘  └──────────────┘       │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│                       Server Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  service.go  │  │auth_middle   │  │route_ssh_key │      │
│  │              │  │ware.go       │  │.go           │      │
│  │  - Fiber App │  │              │  │              │      │
│  │  - Routes    │  │  - Basic Auth│  │  - CRUD Ops  │      │
│  │  - LDAP      │  │  - User Auth │  │  - SSH Parse │      │
│  │  - DB Ref    │  │  - Admin Chk │  │  - Multi-usr │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│                       Model Layer                            │
│  ┌──────────────────────────────────────────────────┐       │
│  │                  ssh_key.go                       │       │
│  │                                                   │       │
│  │  type SSHKey struct {                            │       │
│  │    Fingerprint string                            │       │
│  │    Key         string                            │       │
│  │  }                                               │       │
│  │                                                   │       │
│  │  - GetKeysForUser(tx, dn)                       │       │
│  │  - SetKeysForUser(tx, dn, keys)                 │       │
│  │  - DeleteKeyFromUser(tx, dn, fingerprint)       │       │
│  │  - DeleteKeysForUser(tx, dn)                    │       │
│  └──────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────┘
```

## Request Flow

### Authentication Flow

```
Client Request
     │
     ├─> Authorization: Basic <base64(user:pass)>
     │
     ▼
[authMiddleware]
     │
     ├─> Decode Basic Auth Header
     ├─> Extract username:password
     │
     ▼
[LDAP Authentication]
     │
     ├─> LDAP Bind with credentials
     ├─> Lookup user by sAMAccountName
     ├─> Retrieve user DN and groups
     │
     ▼
[Authorization Check]
     │
     ├─> Store user in context
     └─> Continue to handler
         │
         ▼
    [Route Handler]
```

### Admin Authorization Flow

```
[isAdminMiddleware]
     │
     ├─> Authenticate user (same as authMiddleware)
     │
     ▼
[Check Self-Service]
     │
     ├─> Is sAMAccountNames == authenticated user?
     │   ├─> YES: Allow (self-service)
     │   └─> NO: Check admin group
     │
     ▼
[Check Admin Group]
     │
     ├─> Iterate user.Groups[]
     ├─> Compare with ldapAdminGroupDN
     │   ├─> MATCH: Allow (admin)
     │   └─> NO MATCH: 403 Forbidden
     │
     ▼
[Route Handler]
```

### SSH Key Upload Flow

```
Client Request
     │
     ├─> PUT /users/:sAMAccountNames/ssh-keys
     ├─> Body: ssh-rsa AAAAB3...
     │
     ▼
[isAdminMiddleware]
     │
     ├─> Authenticate and authorize
     │
     ▼
[handleHTTPPutUsersSSHKey]
     │
     ├─> Split comma-separated sAMAccountNames
     ├─> For each sAMAccountName:
     │    │
     │    ├─> LDAP lookup user by sAMAccountName
     │    ├─> Get user DN
     │    │
     │    ▼
     │   [uploadSSHKeyForDN]
     │    │
     │    ├─> Parse SSH key with golang.org/x/crypto/ssh
     │    ├─> Strip comment (MarshalAuthorizedKey)
     │    ├─> Generate SHA256 fingerprint
     │    │
     │    ▼
     │   [BoltDB Transaction]
     │    │
     │    ├─> Check if key exists (by fingerprint)
     │    ├─> Get existing keys for user DN
     │    ├─> Append new key
     │    ├─> Marshal to JSON
     │    ├─> Put: dn -> []SSHKey
     │    │
     │    └─> Commit transaction
     │
     └─> Return 201 Created
```

### SSH Key Retrieval Flow (Public)

```
Client Request
     │
     ├─> GET /users/alice,bob/ssh-keys
     │
     ▼
[handleHTTPGetUsersSSHKeys]
     │
     ├─> Split comma-separated sAMAccountNames
     ├─> For each sAMAccountName:
     │    │
     │    ├─> LDAP lookup user by sAMAccountName
     │    ├─> Get user DN
     │    │
     │    ▼
     │   [getSSHKeysForDN]
     │    │
     │    ├─> BoltDB View transaction
     │    ├─> Get value for DN key
     │    ├─> Unmarshal JSON to []SSHKey
     │    │
     │    └─> Return keys
     │
     ├─> Aggregate keys by DN
     │
     ▼
[Response Formatting]
     │
     ├─> Check Accept header
     │   ├─> application/json: Return JSON
     │   └─> text/plain: Format as authorized_keys
     │
     └─> Send response
```

## Data Model

### BoltDB Schema

**Bucket**: `ssh_keys`

**Key-Value Structure**:
```
Key:   []byte("CN=Alice,OU=Users,DC=example,DC=com")
Value: []byte(`[
  {
    "fingerprint": "SHA256:hSZQXa36...",
    "key": "ssh-rsa AAAAB3NzaC1yc2E...\n"
  },
  {
    "fingerprint": "SHA256:anotherFP...",
    "key": "ssh-ed25519 AAAAC3NzaC1lZ...\n"
  }
]`)
```

### Data Relationships

```
LDAP User (sAMAccountName)
     │
     │ lookup
     ▼
LDAP DN (Distinguished Name)
     │
     │ BoltDB key
     ▼
[]SSHKey (JSON array)
     │
     ├─> SSHKey { Fingerprint, Key }
     ├─> SSHKey { Fingerprint, Key }
     └─> SSHKey { Fingerprint, Key }
```

### Why LDAP DN as Key?

- **Uniqueness**: DN is globally unique within LDAP directory
- **Immutability**: DN doesn't change when user attributes change (typically)
- **Direct Mapping**: No need for additional user ID translation
- **LDAP Native**: Aligns with LDAP's natural identifier

### SSHKey Model

```go
type SSHKey struct {
    Fingerprint string `json:"fingerprint"`  // SHA256:base64...
    Key         string `json:"key"`          // ssh-rsa AAAAB...\n
}
```

**Properties**:
- `Fingerprint`: SHA256 hash in OpenSSH format (SHA256:base64)
- `Key`: Normalized SSH public key (comment stripped, newline-terminated)

## Technology Stack

### Core Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Go | 1.24+ / 1.25.1 | Programming language and runtime |
| gofiber/fiber | v2.52.9 | High-performance HTTP framework |
| bbolt | v1.4.3 | Embedded key-value database |
| simple-ldap-go | v1.0.3 | LDAP authentication library |
| cobra | v1.10.1 | CLI framework |
| golang.org/x/crypto | v0.42.0 | SSH key parsing and validation |

### Why These Choices?

**Fiber over net/http**:
- High performance (Express.js-like API)
- Built-in middleware (logger, CORS, etc.)
- Easy context management
- Lower learning curve for contributors

**BoltDB over SQLite/PostgreSQL**:
- Zero dependencies (pure Go)
- ACID transactions
- File-based (simple backups)
- Perfect for key-value workload
- No server management required

**simple-ldap-go over go-ldap**:
- Higher-level abstractions
- Simplified authentication flow
- Active Directory support built-in
- Connection pooling included

**Cobra over flag**:
- Subcommand support
- Auto-generated help
- Flag management
- Industry standard for Go CLIs

## Architectural Patterns

### Clean Architecture

Raybeam follows clean architecture principles:

```
Outer Layer (CLI) → Middle Layer (Server/Handlers) → Inner Layer (Models)
                ↓                                    ↓
         Frameworks/Drivers                    Business Logic
```

**Benefits**:
- Easy to test (mock LDAP, mock DB)
- Framework-independent business logic
- Clear dependency direction (inward)
- Easy to understand and maintain

### Middleware Pattern

```go
Request → Logger → Auth → isAdmin → Handler
```

**Middleware Composition**:
- `logger.New()`: HTTP request logging
- `authMiddleware`: LDAP authentication
- `isAdminMiddleware`: Admin authorization + authentication

**Benefits**:
- Separation of concerns
- Reusable authentication logic
- Clear authorization boundaries

### Repository Pattern (Simplified)

```go
// Models package acts as repository
models.GetKeysForUser(tx, dn)
models.SetKeysForUser(tx, dn, keys)
models.DeleteKeyFromUser(tx, dn, fingerprint)
```

**Benefits**:
- Database logic isolated in models package
- Transactions handled explicitly
- Easy to test with mock transactions

## Scalability Considerations

### Current Limitations

**Single Writer (BoltDB)**:
- BoltDB allows only one writer at a time
- Read transactions can run concurrently
- Suitable for <10K operations/second
- File-based storage limits horizontal scaling

**Stateless Server**:
- ✅ Multiple server instances possible (with shared BoltDB file)
- ❌ File locking prevents true horizontal scaling
- ❌ No distributed transactions

### Performance Characteristics

**Expected Performance**:
- Read operations: <5ms (BoltDB read transaction)
- Write operations: <10ms (BoltDB write transaction)
- LDAP auth: 50-200ms (network dependent)
- Total request time: 100-300ms for authenticated writes

**Bottlenecks**:
1. LDAP authentication latency (network)
2. BoltDB write serialization (single writer)
3. SSH key parsing (CPU, negligible)

### Scaling Strategies

**Vertical Scaling** (Recommended):
- Increase server resources (CPU, RAM)
- Use faster storage (SSD, NVMe)
- Optimize LDAP connection pooling
- Enable LDAP query caching (simple-ldap-go feature)

**Horizontal Scaling** (Limited):
- Deploy read-only replicas with BoltDB file replication
- Use load balancer with sticky sessions
- Consider migration to PostgreSQL for true horizontal scaling

**Caching Strategy**:
- LDAP user lookups can be cached (simple-ldap-go)
- SSH keys rarely change (no application-level cache needed)
- BoltDB memory-maps file for OS-level caching

## Security Architecture

### Defense in Depth

```
Layer 1: Network Security
     │   - TLS/HTTPS (reverse proxy)
     │   - Firewall rules
     │   - Rate limiting (reverse proxy)
     │
     ▼
Layer 2: Authentication
     │   - LDAP credential verification
     │   - Basic Auth over HTTPS only
     │   - No local password storage
     │
     ▼
Layer 3: Authorization
     │   - User vs Admin separation
     │   - LDAP group membership check
     │   - Self-service vs admin operations
     │
     ▼
Layer 4: Input Validation
     │   - SSH key parsing (crypto/ssh)
     │   - Fingerprint validation
     │   - DN sanitization
     │
     ▼
Layer 5: Storage Security
     │   - BoltDB file permissions (0600)
     │   - Transaction ACID guarantees
     │   - No SQL injection (key-value store)
```

### Threat Model

**Threats Mitigated**:
- ✅ Credential stuffing (LDAP rate limiting)
- ✅ Privilege escalation (admin group check)
- ✅ SSH key injection (crypto/ssh validation)
- ✅ Unauthorized key access (authorization checks)
- ✅ File tampering (BoltDB ACID transactions)

**Threats Requiring External Mitigation**:
- ⚠️ Man-in-the-middle (deploy with HTTPS/TLS)
- ⚠️ DDoS attacks (reverse proxy rate limiting)
- ⚠️ Brute force auth (reverse proxy fail2ban)
- ⚠️ LDAP server compromise (secure LDAP infrastructure)

## Deployment Architecture

### Recommended Production Setup

```
                Internet
                    │
                    ▼
            ┌───────────────┐
            │   Traefik     │  HTTPS termination
            │   or nginx    │  Rate limiting
            └───────┬───────┘  Access logs
                    │ HTTP (internal)
                    ▼
            ┌───────────────┐
            │   Raybeam     │  Port 8080
            │   Container   │  Stateless
            └───────┬───────┘
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
┌───────────────┐       ┌──────────────┐
│  BoltDB File  │       │ LDAP Server  │
│  (volume)     │       │              │
└───────────────┘       └──────────────┘
```

### Container Orchestration

**Docker Compose** (Simple deployments):
```yaml
services:
  raybeam:
    image: ghcr.io/netresearch/raybeam:latest
    volumes:
      - /var/lib/raybeam:/raybeam/data
    environment:
      - LDAP_SERVER=ldap://ldap.example.com
    networks:
      - traefik_network
```

**Kubernetes** (Enterprise deployments):
- Deployment with replicas=1 (BoltDB limitation)
- PersistentVolumeClaim for BoltDB file
- Service with ClusterIP
- Ingress for TLS termination
- ConfigMap for configuration

## Monitoring and Observability

### Health Checks

```bash
# Application health
curl http://localhost:8080/info

# LDAP connectivity
# (implicit in authentication attempts)

# BoltDB health
# (implicit in read/write operations)
```

### Logging

**Fiber Logger Middleware**:
```
[INFO] 2025-09-29 10:15:30 | 200 | 125ms | GET /users/alice/ssh-keys
[WARN] 2025-09-29 10:15:45 | 401 | 250ms | PUT /users/@me/ssh-keys
```

**Recommended Log Collection**:
- Stdout/stderr capture (Docker logs)
- Log aggregation (Elasticsearch, Loki)
- Metrics extraction (access patterns, error rates)

### Metrics to Monitor

**Application**:
- Request rate (requests/second)
- Response time (p50, p95, p99)
- Error rate (4xx, 5xx)
- Authentication success/failure rate

**Infrastructure**:
- BoltDB file size growth
- Disk I/O utilization
- Memory usage
- LDAP connection pool usage

## Future Architecture Considerations

### Potential Enhancements

1. **Database Migration**:
   - PostgreSQL for horizontal scaling
   - Keep schema simple: (dn, fingerprint, key) table
   - Trade-off: Deployment complexity vs scalability

2. **Caching Layer**:
   - Redis for LDAP user lookups
   - TTL-based cache invalidation
   - Reduce LDAP load significantly

3. **Audit Logging**:
   - Structured JSON logs
   - Track admin operations
   - Compliance requirements (SOC2, etc.)

4. **API Versioning**:
   - `/v1/users/...` path prefix
   - Backward compatibility guarantees
   - Deprecation strategy

5. **Metrics Endpoint**:
   - Prometheus `/metrics` endpoint
   - Application-level metrics
   - Business metrics (keys uploaded, users active)

### Non-Goals

**What Raybeam Will NOT Do**:
- ❌ SSH key generation (client responsibility)
- ❌ Key rotation automation (policy-driven, external)
- ❌ Certificate authority (use SSH CA instead)
- ❌ Key usage tracking (use SSH server logs)
- ❌ Web UI (API-first design, use CLI/API)

## References

- [BoltDB Architecture](https://github.com/etcd-io/bbolt#design)
- [Fiber Framework Docs](https://docs.gofiber.io/)
- [LDAP RFC 4511](https://tools.ietf.org/html/rfc4511)
- [OpenSSH Key Format](https://datatracker.ietf.org/doc/html/rfc4716)
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)