# AGENTS.md (root)

<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2025-09-29 -->

This file explains repo-wide conventions for the Raybeam SSH key store and where to find scoped rules.

**Precedence:** the *closest* `AGENTS.md` to your changes wins. Root holds global defaults only.

## Project overview

Raybeam is a lightweight SSH public key store written in Go with LDAP authentication. It provides a REST API for managing SSH keys with role-based access control.

- **Language:** Go 1.24+ (toolchain 1.25.1)
- **Frameworks:** Fiber v2 (HTTP), BoltDB (storage), simple-ldap-go (auth)
- **Entry points:** `main.go` → `cmd/` (Cobra CLI) → `internal/server/` (HTTP handlers)
- **Documentation:** See [`docs/`](docs/) for comprehensive guides

## Global rules

- **Keep diffs small:** PRs should be <300 net LOC (excluding locks/generated files); split larger changes
- **Atomic commits:** Use Conventional Commits format (`feat(scope):`, `fix:`, `docs:`)
- **Ask first before:**
  - Adding heavy dependencies or changing core frameworks
  - Running full end-to-end test suites in CI
  - Repo-wide refactors that touch >10 files

## Minimal pre-commit checks

All commands must pass before committing:

```bash
# Format code
go fmt ./...

# Vet code
go vet ./...

# Run tests
go test ./... -race -cover

# Build to ensure no compilation errors
go build -o raybeam .
```

## Code style & conventions

- **Format:** `gofmt -s` (tabs for indentation, enforced by `.editorconfig`)
- **Naming:** Exported functions/types use `PascalCase`, private use `camelCase`
- **Errors:** Return errors explicitly; use `errors.New()` for sentinels; wrap with `fmt.Errorf("%w", err)`
- **Comments:** Document all exported types and functions with godoc comments
- **Imports:** Group stdlib → external → internal, use `goimports` for sorting

## Security & safety

- **No secrets in VCS:** LDAP passwords via environment variables or secret managers only
- **Input validation:** SSH keys validated via `golang.org/x/crypto/ssh.ParseAuthorizedKey`
- **Database permissions:** BoltDB file must have `0600` permissions (owner read/write only)
- **LDAP over TLS:** Use `ldaps://` in production; never plain `ldap://`
- **Dependencies:** All deps must be latest stable; run `go mod tidy` and verify checksums

## Testing requirements

- **Coverage goal:** 70%+ for handlers, 80%+ for models
- **Table-driven tests:** Prefer `[]struct{name, input, want, wantErr}` pattern
- **Mocking:** Use interfaces for LDAP/DB mocking; avoid real LDAP in unit tests
- **Integration tests:** Require `LDAP_SERVER` etc. env vars; skip if not set

Example test pattern:

```go
func TestGetKeysForUser(t *testing.T) {
    tests := []struct {
        name    string
        dn      string
        want    []SSHKey
        wantErr bool
    }{
        {"empty", "CN=User", []SSHKey{}, false},
        // ... more cases
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // test implementation
        })
    }
}
```

## PR/commit checklist

- [ ] Code formatted with `go fmt`
- [ ] All tests pass (`go test ./...`)
- [ ] No new `go vet` warnings
- [ ] Godoc comments added for exported items
- [ ] Updated `docs/` if API or behavior changed
- [ ] Conventional commit message format
- [ ] No secrets or sensitive data in commit

## Good vs. bad examples

**Good examples to follow:**
- `internal/models/ssh_key.go` — Clean CRUD operations with godoc comments
- `internal/server/auth_middleware.go` — Comprehensive error handling
- `internal/server/auth_middleware_test.go` — Table-driven tests

**Patterns to avoid:**
- Naked returns in functions >10 lines
- `panic()` for non-initialization errors
- Ignoring errors with `_ =`
- HTTP handlers without proper status codes

## When stuck

1. Check [`docs/`](docs/) directory:
   - `docs/architecture.md` — system design and data flow
   - `docs/api.md` — endpoint specifications
   - `docs/development.md` — setup and workflow
2. Read godoc comments in relevant packages
3. Open a draft PR with `[WIP]` prefix to discuss approach
4. Ask in GitHub Discussions for design questions

## House Rules (Defaults)

### 4.1 Commits & branching

- **Format:** Conventional Commits (`feat(server):`, `fix(models):`, `docs:`)
- **Breaking changes:** Add `BREAKING CHANGE:` footer; requires major version bump
- **Branch naming:** `feature/description`, `fix/issue-123`, `docs/update-api`

### 4.2 Type-safety & design

- **Go principles:** Follow standard Go idioms from Effective Go
- **SOLID principles:** Single responsibility, composition over inheritance
- **Error handling:** Errors are values; handle explicitly; don't use exceptions
- **Interfaces:** Keep small and focused; accept interfaces, return structs

### 4.3 Dependency hygiene

- **Stable versions only:** No pre-releases unless critical security fix
- **Minimal deps:** Avoid adding deps for trivial functionality
- **Security:** Run `go list -m all | nancy sleuth` for vulnerability checks
- **Updates:** Renovate bot handles automated updates; review carefully

### 4.4 Don't guess — verify

- **Primary sources:** Go official docs, library godoc, vendor documentation
- **Uncertainty:** Check implementation in vendor code or add TODO for clarification
- **API contracts:** Verify behavior with tests rather than assumptions

### 4.5 API & versioning

- **REST principles:** Follow HTTP semantics (GET idempotent, POST creates, etc.)
- **Status codes:** Use appropriate codes (200, 201, 401, 403, 404, 500)
- **Versioning:** Not currently versioned; breaking changes require v2 module path
- **Content negotiation:** Support `text/plain` and `application/json` via Accept header

### 4.6 Security & compliance

- **Secret management:** Environment variables or mount secrets; never hardcode
- **Input validation:** Validate all user input; sanitize for logs
- **LDAP auth:** Verify credentials on every request (stateless design)
- **Dependency scanning:** CI runs security checks on all deps

### 4.7 Observability & ops

- **Logging:** Fiber middleware logs all HTTP requests (method, path, status, duration)
- **Structured logs:** Use `log.Printf` with consistent format; consider structured logger for v2
- **Metrics:** Not yet implemented; `/info` endpoint provides version info
- **Health checks:** Use GET `/info` for liveness checks

### 4.8 Licensing

- **Project license:** MIT (see LICENSE file)
- **Dependencies:** Verify all deps have compatible licenses (MIT, BSD, Apache 2.0)
- **SPDX:** Not currently used; acceptable for future additions

## Index of scoped AGENTS.md

Currently, Raybeam has a simple structure with no nested AGENTS.md files:

- `./cmd/AGENTS.md` — *Not yet created* (CLI commands and flag parsing)
- `./internal/AGENTS.md` — *Not yet created* (See sections below for inline guidance)

**Inline scope for internal packages:**

- **internal/models/** — Database models and CRUD operations
  - Pattern: Keep DB logic in models, not handlers
  - Style: Godoc all exported functions; return errors explicitly

- **internal/server/** — HTTP server, routes, and middleware
  - Pattern: Middleware → handler → model → response
  - Style: Use Fiber context methods; return errors via `sendError()`

- **internal/build/** — Build metadata (version from VCS)
  - Pattern: Read-only runtime reflection
  - Style: Keep minimal; no business logic

## When instructions conflict

1. **Nearest AGENTS.md wins:** Scoped rules override root
2. **Explicit user prompts override files:** User intent is authoritative
3. **EditorConfig wins for formatting:** `.editorconfig` defines whitespace rules
4. **Go conventions trump personal style:** Follow Effective Go and Go Code Review Comments

## Decision log

- **No golangci-lint config:** Using standard `go vet` and `go fmt` for simplicity; add `.golangci.yml` if needed
- **No Makefile yet:** Added below as fundamental; wraps common commands
- **EditorConfig present:** Respects tabs for Go, spaces for YAML/Markdown
- **Tests use env vars for LDAP:** Integration tests skip if LDAP not configured; unit tests mock where possible