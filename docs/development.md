# Raybeam Development Guide

## Overview

This guide covers setting up a development environment, project structure, coding standards, testing practices, and contributing to Raybeam.

## Getting Started

### Prerequisites

- **Go**: 1.24.0 or later (toolchain 1.25.1)
- **Git**: For version control
- **Docker**: For testing with LDAP (optional but recommended)
- **Make**: For build automation (optional)

### Clone Repository

```bash
git clone https://github.com/netresearch/raybeam.git
cd raybeam
```

### Install Dependencies

```bash
go mod download
go mod verify
```

### Build from Source

```bash
# Build binary
go build -o raybeam .

# Build with version info
go build -ldflags="-X 'main.Version=$(git rev-parse HEAD)'" -o raybeam .

# Install to GOPATH/bin
go install .
```

### Run Locally

**Option 1: With existing LDAP server**

```bash
./raybeam serve \
  -d /tmp/raybeam.db \
  -s ldap://your-ldap-server:389 \
  -b "DC=example,DC=com" \
  -u "CN=readonly,DC=example,DC=com" \
  -p "password" \
  -g "CN=Admins,DC=example,DC=com"
```

**Option 2: With Docker LDAP (for testing)**

```bash
# Start OpenLDAP test server
docker run -d \
  --name test-ldap \
  -p 389:389 \
  -e LDAP_ORGANISATION="Example Inc" \
  -e LDAP_DOMAIN="example.org" \
  -e LDAP_ADMIN_PASSWORD="admin" \
  osixia/openldap:latest

# Run Raybeam against test LDAP
./raybeam serve \
  -d /tmp/raybeam.db \
  -s ldap://localhost:389 \
  -b "dc=example,dc=org" \
  -u "cn=admin,dc=example,dc=org" \
  -p "admin" \
  -g "cn=admins,dc=example,dc=org"
```

### Verify Installation

```bash
# Check version
./raybeam --version

# Test API
curl http://localhost:8080/info
```

## Project Structure

```
raybeam/
├── cmd/                        # CLI commands
│   ├── root.go                # Cobra root command + version
│   └── serve.go               # Serve command + configuration
├── internal/                  # Private application code
│   ├── build/                 # Build-time metadata
│   │   └── build.go           # Version extraction from VCS
│   ├── models/                # Data models
│   │   └── ssh_key.go         # SSHKey model + DB operations
│   └── server/                # HTTP server
│       ├── service.go         # Fiber app initialization + routing
│       ├── auth_middleware.go # Authentication + authorization
│       ├── route_ssh_key.go   # SSH key CRUD handlers
│       ├── route_info.go      # Server info handler
│       └── utils.go           # Helper functions
├── main.go                    # Application entry point
├── go.mod                     # Go module definition
├── go.sum                     # Dependency checksums
├── Dockerfile                 # Container image build
├── README.md                  # Project overview
├── LICENSE                    # MIT license
└── .github/workflows/         # GitHub Actions CI/CD
    ├── docker.yml             # Docker image builds
    └── release.yml            # Binary releases
```

### Package Organization

**cmd/**: Command-line interface logic
- Cobra command definitions
- Flag parsing and validation
- Application bootstrapping

**internal/build/**: Build metadata
- VCS revision extraction
- Version information

**internal/models/**: Data layer
- Database schema (BoltDB buckets)
- CRUD operations
- Data validation

**internal/server/**: HTTP layer
- Route definitions
- Middleware (auth, logging)
- Request handlers
- Response formatting

## Development Workflow

### Feature Development

```bash
# 1. Create feature branch
git checkout -b feature/add-key-expiration

# 2. Make changes
# ... edit files ...

# 3. Run tests
go test ./...

# 4. Build and test locally
go build -o raybeam .
./raybeam serve <flags>

# 5. Commit with conventional commit message
git add .
git commit -m "feat: add SSH key expiration support"

# 6. Push and create PR
git push origin feature/add-key-expiration
```

### Conventional Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```bash
git commit -m "feat(api): add bulk key deletion endpoint"
git commit -m "fix(auth): handle LDAP connection timeout"
git commit -m "docs: update deployment guide with k8s example"
git commit -m "test(models): add SSHKey validation tests"
```

## Coding Standards

### Go Style

Follow [Effective Go](https://go.dev/doc/effective_go) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

**Key Principles**:
- Use `gofmt` for formatting (enforced)
- Use meaningful variable names
- Keep functions small and focused
- Document exported functions and types
- Handle errors explicitly

**Example**:

```go
// Good
func GetKeysForUser(tx *bbolt.Tx, dn string) ([]SSHKey, error) {
    b := tx.Bucket(SSHKeyBucket)
    keysForUser := b.Get([]byte(dn))
    if keysForUser == nil {
        return []SSHKey{}, nil
    }

    var keys []SSHKey
    if err := json.Unmarshal(keysForUser, &keys); err != nil {
        return nil, err
    }

    return keys, nil
}

// Bad: Poor naming, no error handling
func gku(t *bbolt.Tx, d string) []SSHKey {
    b := t.Bucket(SSHKeyBucket)
    k := b.Get([]byte(d))
    var keys []SSHKey
    json.Unmarshal(k, &keys)
    return keys
}
```

### Error Handling

```go
// Define custom errors
var (
    ErrSSHKeyNotFound = errors.New("SSH key not found")
    ErrInvalidFingerprint = errors.New("invalid fingerprint format")
)

// Return errors, don't panic
func GetKeyForUser(tx *bbolt.Tx, dn, fingerprint string) (SSHKey, error) {
    keys, err := GetKeysForUser(tx, dn)
    if err != nil {
        return SSHKey{}, err
    }

    for _, key := range keys {
        if key.Fingerprint == fingerprint {
            return key, nil
        }
    }

    return SSHKey{}, ErrSSHKeyNotFound
}

// Check errors with errors.Is
if err := doSomething(); err != nil {
    if errors.Is(err, ErrSSHKeyNotFound) {
        // Handle specific error
    }
    return err
}
```

### Naming Conventions

**Packages**: lowercase, single word
```go
package server  // Good
package serverUtils  // Bad
```

**Types**: PascalCase
```go
type SSHKey struct { }  // Good
type sshKey struct { }  // Bad (unexported)
```

**Functions**: PascalCase (exported), camelCase (private)
```go
func GetKeysForUser() { }  // Good (exported)
func parseAuthHeader() { }  // Good (private)
func get_keys() { }  // Bad (underscore)
```

**Variables**: camelCase
```go
var ldapServer string  // Good
var LDAP_SERVER string  // Bad
```

## Testing

### Current Test Coverage

```
internal/server/auth_middleware_test.go
├── Basic auth parsing (5 tests)
└── LDAP authentication (6 tests)

Total coverage: ~15% (auth middleware only)
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run with verbose output
go test -v ./...

# Run specific test
go test -v ./internal/server -run TestBasicAuth

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Writing Tests

**Table-Driven Tests** (Recommended):

```go
func TestBasicAuth(t *testing.T) {
    tests := []struct {
        name        string
        authHeader  string
        wantUser    string
        wantPass    string
        wantErr     error
    }{
        {
            name:       "valid credentials",
            authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret")),
            wantUser:   "alice",
            wantPass:   "secret",
            wantErr:    nil,
        },
        {
            name:       "missing header",
            authHeader: "",
            wantUser:   "",
            wantPass:   "",
            wantErr:    ErrAuthHeaderMissing,
        },
        {
            name:       "malformed base64",
            authHeader: "Basic %%%%",
            wantUser:   "",
            wantPass:   "",
            wantErr:    ErrAuthHeaderMalformed,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            gotUser, gotPass, gotErr := basicAuth(tt.authHeader)

            if gotUser != tt.wantUser {
                t.Errorf("user = %q, want %q", gotUser, tt.wantUser)
            }
            if gotPass != tt.wantPass {
                t.Errorf("pass = %q, want %q", gotPass, tt.wantPass)
            }
            if gotErr != tt.wantErr {
                t.Errorf("err = %v, want %v", gotErr, tt.wantErr)
            }
        })
    }
}
```

**Testing with LDAP**:

Tests requiring LDAP use environment variables:

```bash
# Set environment variables
export LDAP_SERVER=ldap://localhost:389
export LDAP_BASE_DN=dc=example,dc=org
export LDAP_READ_USER=cn=admin,dc=example,dc=org
export LDAP_READ_PASSWORD=admin

# Run tests
go test ./internal/server
```

**Mock Testing** (Recommended for new tests):

```go
// Use interfaces for mocking
type LDAPAuthenticator interface {
    CheckPasswordForSAMAccountName(sam, password string) (*ldap.User, error)
}

// Mock implementation
type MockLDAP struct {
    users map[string]string  // sAMAccountName -> password
}

func (m *MockLDAP) CheckPasswordForSAMAccountName(sam, password string) (*ldap.User, error) {
    if m.users[sam] == password {
        return &ldap.User{SAMAccountName: sam}, nil
    }
    return nil, ErrAuthFailed
}

// Test with mock
func TestAuthMiddlewareWithMock(t *testing.T) {
    mockLDAP := &MockLDAP{
        users: map[string]string{
            "alice": "secret",
        },
    }

    // Test authentication logic without real LDAP
}
```

### Testing Guidelines

**Coverage Goals**:
- Models: 80%+ coverage
- Handlers: 70%+ coverage
- Middleware: 90%+ coverage

**What to Test**:
- ✅ Business logic (key validation, auth logic)
- ✅ Error handling paths
- ✅ Edge cases (empty inputs, malformed data)
- ✅ Authorization boundaries (user vs admin)
- ❌ Third-party libraries (trust crypto/ssh, bbolt, fiber)

## Adding New Features

### Example: Add Key Expiration

**1. Update Data Model** (`internal/models/ssh_key.go`):

```go
type SSHKey struct {
    Fingerprint string    `json:"fingerprint"`
    Key         string    `json:"key"`
    ExpiresAt   time.Time `json:"expires_at,omitempty"`  // New field
}
```

**2. Add Validation** (`internal/server/route_ssh_key.go`):

```go
func (s *Server) uploadSSHKeyForDN(dn string, rawKey []byte, expiresAt time.Time) error {
    key, _, _, _, err := ssh.ParseAuthorizedKey(rawKey)
    if err != nil {
        return errCouldNotParseSSHKey
    }

    // Validate expiration
    if !expiresAt.IsZero() && expiresAt.Before(time.Now()) {
        return errors.New("expiration date must be in the future")
    }

    keyEntry := models.SSHKey{
        Fingerprint: ssh.FingerprintSHA256(key),
        Key:         string(ssh.MarshalAuthorizedKey(key)),
        ExpiresAt:   expiresAt,
    }

    // ... rest of upload logic
}
```

**3. Update Handler** (`internal/server/route_ssh_key.go`):

```go
func (s *Server) handleHTTPPutUsersMeSSHKey(c *fiber.Ctx) error {
    user := c.Locals("user").(ldap.User)

    // Parse optional expiration query parameter
    expiresAt := time.Time{}
    if expiresAtStr := c.Query("expires_at"); expiresAtStr != "" {
        var err error
        expiresAt, err = time.Parse(time.RFC3339, expiresAtStr)
        if err != nil {
            return sendError(c, fiber.StatusBadRequest, "invalid expires_at format")
        }
    }

    if err := s.uploadSSHKeyForDN(user.DN(), c.Body(), expiresAt); err != nil {
        return sendError(c, fiber.StatusInternalServerError, err.Error())
    }

    return c.SendStatus(fiber.StatusCreated)
}
```

**4. Add Tests**:

```go
func TestSSHKeyExpiration(t *testing.T) {
    tests := []struct {
        name      string
        expiresAt time.Time
        wantErr   error
    }{
        {
            name:      "valid future expiration",
            expiresAt: time.Now().Add(30 * 24 * time.Hour),
            wantErr:   nil,
        },
        {
            name:      "past expiration",
            expiresAt: time.Now().Add(-1 * time.Hour),
            wantErr:   errors.New("expiration date must be in the future"),
        },
        {
            name:      "no expiration",
            expiresAt: time.Time{},
            wantErr:   nil,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test expiration validation
        })
    }
}
```

**5. Update Documentation**:
- Update `docs/api.md` with new query parameter
- Update `README.md` usage examples
- Add migration notes if breaking change

## Dependencies

### Core Dependencies

```go
require (
    github.com/go-ldap/ldap/v3 v3.4.11           // LDAP client
    github.com/gofiber/fiber/v2 v2.52.9          // Web framework
    github.com/netresearch/simple-ldap-go v1.0.3 // LDAP wrapper
    github.com/spf13/cobra v1.10.1               // CLI framework
    go.etcd.io/bbolt v1.4.3                      // Embedded database
    golang.org/x/crypto v0.42.0                  // SSH key parsing
)
```

### Adding Dependencies

```bash
# Add new dependency
go get github.com/example/package

# Update go.mod
go mod tidy

# Verify checksums
go mod verify

# Commit changes
git add go.mod go.sum
git commit -m "chore(deps): add github.com/example/package"
```

### Dependency Updates

Dependencies are automatically updated via [Renovate](https://renovatebot.com/):

```json
// renovate.json
{
  "extends": ["config:base"],
  "packageRules": [
    {
      "matchUpdateTypes": ["minor", "patch"],
      "automerge": true
    }
  ]
}
```

Manual update:

```bash
# Update specific dependency
go get -u github.com/gofiber/fiber/v2

# Update all dependencies (careful!)
go get -u ./...
go mod tidy
```

## Continuous Integration

### GitHub Actions Workflows

**Docker Build** (`.github/workflows/docker.yml`):
- Triggers: release publish, weekly cron, master push
- Builds multi-platform images (linux/amd64, arm64, etc.)
- Pushes to ghcr.io

**Release** (`.github/workflows/release.yml`):
- Triggers: release publish
- Builds binaries for linux and darwin (amd64)
- Attaches to GitHub release

### Local Testing

Simulate CI locally:

```bash
# Build Docker image
docker build -t raybeam:test .

# Run container
docker run --rm raybeam:test raybeam --version

# Test multi-stage build
docker build --target builder -t raybeam:builder .
docker build --target runner -t raybeam:runner .
```

## Debugging

### Logging

Add debug logging:

```go
import "log"

func (s *Server) handleHTTPGetUsersMeSSHKeys(c *fiber.Ctx) error {
    user := c.Locals("user").(ldap.User)
    log.Printf("[DEBUG] Getting keys for user: %s (DN: %s)", user.SAMAccountName, user.DN())

    keys, err := s.getSSHKeysForDN(user.DN())
    if err != nil {
        log.Printf("[ERROR] Failed to get keys: %v", err)
        return sendError(c, fiber.StatusInternalServerError, "internal server error")
    }

    log.Printf("[DEBUG] Found %d keys for user %s", len(keys), user.SAMAccountName)
    // ... rest of handler
}
```

### Debugging with Delve

```bash
# Install Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug main.go
dlv debug . -- serve -d /tmp/raybeam.db -s ldap://localhost:389 ...

# Debug tests
dlv test ./internal/server

# Set breakpoints
(dlv) break internal/server/route_ssh_key.go:72
(dlv) continue
```

### LDAP Debugging

```bash
# Test LDAP connectivity
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=org" \
  -w admin \
  -b "dc=example,dc=org" \
  "(objectClass=*)"

# Check user attributes
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=org" \
  -w admin \
  -b "dc=example,dc=org" \
  "(sAMAccountName=alice)" \
  dn memberOf
```

## Performance Profiling

### CPU Profiling

```go
import (
    "os"
    "runtime/pprof"
)

func main() {
    // Start CPU profiling
    f, _ := os.Create("cpu.prof")
    pprof.StartCPUProfile(f)
    defer pprof.StopCPUProfile()

    // Run application
    cmd.Execute()
}
```

Analyze:

```bash
go tool pprof cpu.prof
(pprof) top10
(pprof) list functionName
```

### Memory Profiling

```go
import (
    "os"
    "runtime/pprof"
)

func main() {
    defer func() {
        f, _ := os.Create("mem.prof")
        pprof.WriteHeapProfile(f)
        f.Close()
    }()

    cmd.Execute()
}
```

Analyze:

```bash
go tool pprof mem.prof
(pprof) top10
(pprof) list functionName
```

### Benchmarking

```go
func BenchmarkGetKeysForUser(b *testing.B) {
    // Setup
    db, _ := bbolt.Open("/tmp/bench.db", 0600, nil)
    defer db.Close()

    // Benchmark
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        db.View(func(tx *bbolt.Tx) error {
            _, _ = models.GetKeysForUser(tx, "CN=Alice,DC=example,DC=com")
            return nil
        })
    }
}
```

Run:

```bash
go test -bench=. -benchmem ./internal/models
```

## Contributing

### Pull Request Process

1. **Fork** the repository
2. **Create** feature branch: `git checkout -b feature/my-feature`
3. **Implement** feature with tests
4. **Run** tests: `go test ./...`
5. **Format** code: `go fmt ./...`
6. **Commit** with conventional commit message
7. **Push** to your fork
8. **Create** pull request to `master` branch

### PR Requirements

- [ ] Code follows Go style guidelines
- [ ] Tests added for new functionality
- [ ] All tests pass (`go test ./...`)
- [ ] Documentation updated (if applicable)
- [ ] Conventional commit message format
- [ ] No breaking changes (or clearly documented)

### Code Review

Pull requests require:
- 1+ approvals from maintainers
- All CI checks passing
- No merge conflicts with master

## Release Process

### Versioning

Raybeam uses [Semantic Versioning](https://semver.org/):

```
MAJOR.MINOR.PATCH

1.0.0 → 1.0.1 (patch: bug fix)
1.0.1 → 1.1.0 (minor: new feature, backward compatible)
1.1.0 → 2.0.0 (major: breaking change)
```

### Creating a Release

1. **Update version** (if using version constants)
2. **Tag release**:
   ```bash
   git tag -a v1.2.3 -m "Release v1.2.3: Add key expiration support"
   git push origin v1.2.3
   ```
3. **Create GitHub release**:
   - Go to GitHub repository
   - Releases → Draft new release
   - Select tag v1.2.3
   - Add release notes
   - Publish release
4. **Automated workflows**:
   - Docker images built and pushed
   - Binaries built and attached to release

### Release Notes Template

```markdown
## What's Changed

### Features
- Add SSH key expiration support (#123)
- Improve admin authorization logging (#124)

### Bug Fixes
- Fix LDAP connection timeout handling (#125)
- Correct fingerprint validation edge case (#126)

### Documentation
- Update deployment guide with Kubernetes examples (#127)

**Full Changelog**: https://github.com/netresearch/raybeam/compare/v1.2.2...v1.2.3
```

## Troubleshooting Development Issues

### "Package not found"

```bash
# Clean module cache
go clean -modcache
go mod download
go mod tidy
```

### "Import cycle detected"

- Reorganize packages to remove circular dependencies
- Consider extracting shared code to new package
- Use interfaces to break dependencies

### "Tests fail with LDAP timeout"

```bash
# Ensure LDAP container is running
docker ps | grep ldap

# Check LDAP connectivity
nc -zv localhost 389

# Set environment variables
export LDAP_SERVER=ldap://localhost:389
export LDAP_BASE_DN=dc=example,dc=org
export LDAP_READ_USER=cn=admin,dc=example,dc=org
export LDAP_READ_PASSWORD=admin
```

## Resources

### Go Resources

- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Go Project Layout](https://github.com/golang-standards/project-layout)

### Library Documentation

- [Fiber Framework](https://docs.gofiber.io/)
- [BoltDB](https://github.com/etcd-io/bbolt)
- [Cobra CLI](https://github.com/spf13/cobra)
- [simple-ldap-go](https://github.com/netresearch/simple-ldap-go)

### Security

- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [Go Security Best Practices](https://go.dev/doc/security/best-practices)

## Contact

- **Issues**: https://github.com/netresearch/raybeam/issues
- **Discussions**: https://github.com/netresearch/raybeam/discussions
- **Security**: https://github.com/netresearch/raybeam/security/advisories