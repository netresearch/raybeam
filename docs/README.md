# Raybeam Documentation

Welcome to the Raybeam documentation! This directory contains comprehensive guides for using, deploying, and developing Raybeam.

## Quick Navigation

### For Users

- **[API Reference](api.md)** - Complete REST API documentation with examples
  - Endpoint specifications
  - Authentication and authorization
  - Request/response formats
  - Common workflows

### For Operators

- **[Deployment Guide](deployment.md)** - Deploy Raybeam in any environment
  - Docker and Docker Compose
  - Kubernetes deployment
  - Binary installation with systemd
  - Backup and recovery
  - Monitoring and troubleshooting

- **[Security Documentation](security.md)** - Security model and best practices
  - LDAP authentication and authorization
  - Threat model and mitigations
  - Compliance considerations (GDPR, SOC 2)
  - Security hardening checklist

### For Developers

- **[Development Guide](development.md)** - Contributing to Raybeam
  - Development environment setup
  - Project structure
  - Coding standards
  - Testing practices
  - Pull request process

- **[Architecture Documentation](architecture.md)** - System design and internals
  - Component architecture
  - Request flows
  - Data model
  - Technology stack justification
  - Scalability considerations

## Getting Started

### Quick Start

1. **Deploy Raybeam**:
   ```bash
   docker run -d \
     -p 8080:8080 \
     -v /var/lib/raybeam:/db \
     ghcr.io/netresearch/raybeam:latest \
     raybeam serve \
       -s ldap://ldap.example.com \
       -b "DC=example,DC=com" \
       -u "readonly" \
       -p "password" \
       -g "CN=Admins,DC=example,DC=com"
   ```

2. **Upload your SSH key**:
   ```bash
   curl -u username:password -T ~/.ssh/id_rsa.pub \
     http://localhost:8080/users/@me/ssh-keys
   ```

3. **Retrieve keys**:
   ```bash
   curl http://localhost:8080/users/username/ssh-keys
   ```

For detailed deployment instructions, see the [Deployment Guide](deployment.md).

## Documentation Structure

```
docs/
├── README.md           # This file - documentation index
├── api.md              # REST API reference
├── architecture.md     # System design and architecture
├── security.md         # Security model and best practices
├── deployment.md       # Deployment and operations guide
└── development.md      # Development workflow and contributing
```

## Common Tasks

### API Usage

- **Upload SSH Key**: [API Reference → Upload SSH Key](api.md#upload-ssh-key-self)
- **List Keys**: [API Reference → List SSH Keys](api.md#list-ssh-keys-for-users)
- **Delete Keys**: [API Reference → Delete SSH Keys](api.md#delete-all-ssh-keys-self)
- **Multi-User Operations**: [API Reference → Multi-User Operations](api.md#ssh-key-management---multi-user-operations)

### Deployment

- **Docker Compose**: [Deployment Guide → Docker Compose](deployment.md#docker-compose-recommended)
- **Kubernetes**: [Deployment Guide → Kubernetes](deployment.md#kubernetes-deployment)
- **With Traefik**: [Deployment Guide → With Traefik](deployment.md#with-traefik-recommended)
- **Backup**: [Deployment Guide → Backup and Recovery](deployment.md#backup-and-recovery)

### Security

- **LDAP Configuration**: [Security → LDAP Integration](security.md#ldap-integration)
- **TLS Setup**: [Security → TLS/HTTPS](security.md#tlshttps)
- **Threat Model**: [Security → Threat Model](security.md#threat-model)
- **Security Checklist**: [Deployment Guide → Security Hardening](deployment.md#security-hardening)

### Development

- **Setup Environment**: [Development Guide → Getting Started](development.md#getting-started)
- **Project Structure**: [Development Guide → Project Structure](development.md#project-structure)
- **Adding Features**: [Development Guide → Adding New Features](development.md#adding-new-features)
- **Running Tests**: [Development Guide → Testing](development.md#testing)

## Key Concepts

### Authentication & Authorization

Raybeam uses **LDAP-based authentication** with **role-based access control**:

- **Public**: Read-only access to SSH keys (no auth required)
- **User**: Self-service key management via LDAP credentials
- **Admin**: Manage keys for any user via LDAP group membership

See [Security Documentation](security.md#security-model) for details.

### Data Storage

Raybeam uses **BoltDB** for embedded key-value storage:

- Single file database (`db.bolt`)
- ACID transactions
- SSH keys stored per user (LDAP DN as key)
- No external database required

See [Architecture Documentation](architecture.md#data-model) for details.

### API Design

Raybeam provides a **REST API** with dual response formats:

- **text/plain** (default): SSH `authorized_keys` format for direct use
- **application/json**: Structured responses for programmatic access

See [API Reference](api.md#response-formats) for details.

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify LDAP server connectivity
   - Check service account credentials
   - Validate Base DN configuration
   - See: [Deployment Guide → Troubleshooting](deployment.md#ldap-authentication-failures)

2. **Admin Authorization Issues**
   - Verify user is member of admin LDAP group
   - Check admin group DN matches exactly
   - Validate LDAP group membership query
   - See: [Deployment Guide → Admin Authorization Issues](deployment.md#admin-authorization-issues)

3. **Database Errors**
   - Check file permissions (should be 0600)
   - Verify disk space availability
   - Consider restoring from backup
   - See: [Deployment Guide → Database Issues](deployment.md#database-issues)

For more troubleshooting guidance, see:
- [Deployment Guide → Troubleshooting](deployment.md#troubleshooting)
- [Development Guide → Troubleshooting Development Issues](development.md#troubleshooting-development-issues)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    HTTP Client                           │
│               (curl, scripts, apps)                      │
└────────────────┬────────────────────────────────────────┘
                 │ HTTP Basic Auth
                 ▼
┌─────────────────────────────────────────────────────────┐
│                  Raybeam Server                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Logger → Auth Middleware → Route Handlers       │  │
│  └──────────────────────────────────────────────────┘  │
└─────────┬─────────────────────────────┬─────────────────┘
          │                             │
          ▼                             ▼
  ┌───────────────┐              ┌─────────────┐
  │  LDAP Server  │              │   BoltDB    │
  │  (Auth)       │              │  (Storage)  │
  └───────────────┘              └─────────────┘
```

For detailed architecture information, see [Architecture Documentation](architecture.md).

## Security Considerations

**Production Deployment Requirements**:

- ✅ Deploy behind HTTPS/TLS reverse proxy
- ✅ Use `ldaps://` for LDAP connections
- ✅ Configure rate limiting
- ✅ Enable access logging and monitoring
- ✅ Implement encrypted backups
- ✅ Restrict file permissions (BoltDB: 0600)
- ✅ Follow principle of least privilege for LDAP service account

For comprehensive security guidance, see [Security Documentation](security.md).

## Performance Characteristics

**Expected Performance**:
- Read operations: <5ms (BoltDB)
- Write operations: <10ms (BoltDB)
- LDAP authentication: 50-200ms (network dependent)
- Total request time: 100-300ms for authenticated writes

**Scalability**:
- Single-writer limitation (BoltDB)
- Suitable for <10K operations/second
- Vertical scaling recommended
- Read replicas possible with file replication

For performance details, see [Architecture Documentation](architecture.md#scalability-considerations).

## Contributing

Contributions are welcome! Please read the [Development Guide](development.md) before submitting pull requests.

**Quick Start for Contributors**:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes with tests
4. Run tests: `go test ./...`
5. Commit with conventional commit format
6. Submit pull request

See [Development Guide → Contributing](development.md#contributing) for detailed guidelines.

## Resources

### External Documentation

- [Go Documentation](https://go.dev/doc/)
- [Fiber Framework](https://docs.gofiber.io/)
- [BoltDB](https://github.com/etcd-io/bbolt)
- [LDAP RFC](https://tools.ietf.org/html/rfc4511)
- [OpenSSH](https://www.openssh.com/)

### Project Links

- **Repository**: https://github.com/netresearch/raybeam
- **Issues**: https://github.com/netresearch/raybeam/issues
- **Discussions**: https://github.com/netresearch/raybeam/discussions
- **Container Registry**: https://github.com/netresearch/raybeam/pkgs/container/raybeam
- **Releases**: https://github.com/netresearch/raybeam/releases

## License

Raybeam is released under the MIT License. See [LICENSE](../LICENSE) for details.

## Support

- **Bug Reports**: [GitHub Issues](https://github.com/netresearch/raybeam/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/netresearch/raybeam/discussions)
- **Security Issues**: [Security Advisories](https://github.com/netresearch/raybeam/security/advisories)

---

**Need help?** Start with the [API Reference](api.md) or [Deployment Guide](deployment.md), or open a [discussion](https://github.com/netresearch/raybeam/discussions).