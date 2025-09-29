# AGENTS.md — internal/

<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2025-09-29 -->

## Overview

This directory contains the core business logic for Raybeam, organized into three packages:

- **models/** — Data models and BoltDB CRUD operations for SSH keys
- **server/** — HTTP server, Fiber routes, middleware (auth/admin), handlers
- **build/** — Build metadata (version from VCS revision)

**Entry flow:** `main.go` → `cmd/serve.go` → `server.New()` → `server.Listen()`

## Setup & environment

No special setup required for this package. Dependencies are managed at root level via `go.mod`.

**Testing with LDAP:**

```bash
# Integration tests require LDAP env vars
export LDAP_SERVER=ldap://localhost:389
export LDAP_BASE_DN=dc=example,dc=org
export LDAP_READ_USER=cn=admin,dc=example,dc=org
export LDAP_READ_PASSWORD=admin

# Unit tests without LDAP
go test ./internal/server -short  # Skips integration tests
```

## Build & tests (file-scoped)

```bash
# Test specific package
go test ./internal/models -v
go test ./internal/server -v -race

# Test with coverage
go test ./internal/... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out

# Vet and format
go vet ./internal/...
go fmt ./internal/...
```

## Code style & conventions

### Package organization

- **models/**: Pure data layer, no HTTP knowledge
  - Functions take `*bbolt.Tx` (transaction) as first param
  - Return `(data, error)` tuples
  - Use sentinel errors like `ErrSSHKeyNotFound`

- **server/**: HTTP layer, knows about Fiber
  - Handlers take `*fiber.Ctx` and return `error`
  - Use middleware composition: `logger → auth → isAdmin → handler`
  - Return errors via `sendError(c, statusCode, message)`

### Naming

- **Exported:** `GetKeysForUser`, `Server`, `SSHKey`
- **Private:** `authMiddleware`, `basicAuth`, `sendError`
- **Constants:** `SSHKeyBucket` (exported vars for config)

### Error handling

```go
// Good: Explicit error return
func GetKeyForUser(tx *bbolt.Tx, dn, fingerprint string) (SSHKey, error) {
    keys, err := GetKeysForUser(tx, dn)
    if err != nil {
        return SSHKey{}, err
    }
    // ... rest of function
}

// Good: Sentinel errors
var ErrSSHKeyNotFound = errors.New("SSH key not found")

// Bad: Ignoring errors
_ = doSomething()  // Never ignore errors

// Bad: Panic for business logic
if key == nil {
    panic("key not found")  // Use error returns instead
}
```

### Logging

```go
// Good: Fiber middleware logs all requests automatically
// No need for manual logging in happy path

// Good: Log errors before returning
if err := s.deleteSSHKeysForDN(dn); err != nil {
    log.Printf("Failed to delete keys for %s: %v", dn, err)
    return sendError(c, fiber.StatusInternalServerError, "internal server error")
}

// Bad: Exposing internal details to users
return sendError(c, 500, err.Error())  // Leaks DB errors
```

## Security & safety

### LDAP authentication

- All credentials verified via LDAP on every request (stateless)
- Basic Auth header decoded and validated in `authMiddleware`
- Admin group membership checked via DN string comparison
- No session state stored server-side

### SSH key validation

- All keys parsed via `golang.org/x/crypto/ssh.ParseAuthorizedKey`
- Comments stripped during upload (normalized storage)
- Fingerprints use SHA256 (OpenSSH format)
- Duplicate detection via fingerprint comparison

### Database safety

- All writes use BoltDB transactions (`db.Update`)
- All reads use read transactions (`db.View`)
- Keys stored as JSON-encoded slices keyed by LDAP DN
- File permissions: `0600` (owner read/write only)

### Input validation

```go
// Good: Validate before use
user, err := authMiddleware(c.Get(fiber.HeaderAuthorization), s.ldap)
if err != nil {
    return unauthorized(err.Error())
}

// Good: Validate SSH keys
key, _, _, _, err := ssh.ParseAuthorizedKey(rawKey)
if err != nil {
    return errCouldNotParseSSHKey
}

// Bad: Trust user input
dn := c.Params("dn")  // Never use params directly in DB queries
```

## PR/commit checklist

- [ ] Godoc comments added for new exported functions/types
- [ ] Table-driven tests added for new logic
- [ ] Error paths tested (not just happy path)
- [ ] No `panic()` in handlers or business logic
- [ ] Middleware composition correct (logger → auth → handler)
- [ ] HTTP status codes appropriate (200, 201, 401, 403, 404, 500)
- [ ] No secrets or DN patterns exposed in error messages

## Good vs. bad examples

**Good examples:**

- `internal/models/ssh_key.go` — Clean CRUD with godoc, explicit errors
- `internal/server/auth_middleware.go` — Proper error handling, sentinel errors
- `internal/server/auth_middleware_test.go` — Table-driven tests with subtests

**Bad patterns to avoid:**

```go
// Bad: No error check
keys, _ := models.GetKeysForUser(tx, dn)

// Bad: Generic error
return errors.New("failed")  // Be specific

// Bad: No transaction
b := s.db.Bucket(models.SSHKeyBucket)  // Must be in View/Update

// Bad: Exposing internals
return sendError(c, 500, err.Error())  // Shows DB errors to user
```

## When stuck

1. **models/** questions:
   - Check BoltDB docs: https://github.com/etcd-io/bbolt
   - See `GetKeysForUser` for transaction pattern
   - All functions follow `(tx, params...) (result, error)` signature

2. **server/** questions:
   - Check Fiber docs: https://docs.gofiber.io/
   - See `handleHTTPGetUsersMeSSHKeys` for response formatting pattern
   - Middleware chain: `app.Get(path, middleware1, middleware2, handler)`

3. **Testing:**
   - Use `testing.T.Run()` for subtests
   - Mock LDAP with interfaces if needed
   - See `internal/server/auth_middleware_test.go` for examples

4. Open draft PR with `[WIP]` for design discussions

## House Rules (Defaults)

This section inherits from root `AGENTS.md` but adds internal-specific rules:

### Error handling

- **Sentinel errors:** Define at package level (`var ErrX = errors.New(...)`)
- **Error wrapping:** Use `fmt.Errorf("context: %w", err)` for wrapping
- **HTTP errors:** Use `sendError()` helper; never expose internal details

### Testing

- **Unit tests:** Mock LDAP; use in-memory BoltDB if possible
- **Integration tests:** Check env vars; skip with `t.Skip()` if not set
- **Coverage target:** 80% for models, 70% for server handlers

### Database

- **Transactions:** Always use `db.View()` or `db.Update()`
- **Keys:** Use LDAP DN as primary key (unique, immutable)
- **Values:** JSON-encoded structs; version-agnostic (additive changes only)

### HTTP

- **Content negotiation:** Check `Accept` header; support `text/plain` and `application/json`
- **Status codes:**
  - `200 OK` — successful read/delete
  - `201 Created` — successful create
  - `401 Unauthorized` — missing/invalid auth
  - `403 Forbidden` — authenticated but not authorized (admin)
  - `404 Not Found` — resource doesn't exist
  - `500 Internal Server Error` — server-side failure

## Decision log

- **No ORM:** Using raw BoltDB transactions for simplicity and control
- **JSON storage:** Keys stored as JSON arrays; flexible for future schema evolution
- **Stateless auth:** LDAP verified on every request; no session management needed
- **Fiber middleware:** Using built-in logger; consider structured logging for v2