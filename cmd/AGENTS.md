# AGENTS.md — cmd/

<!-- Managed by agent: keep sections and order; edit content, not structure. Last updated: 2025-09-29 -->

## Overview

This directory contains CLI command definitions using Cobra framework:

- **root.go** — Root command, version info, error handling
- **serve.go** — HTTP server command with LDAP/DB configuration flags

**Entry flow:** `main.go` → `cmd.Execute()` → Cobra command routing → `serve.RunE()`

## Setup & environment

No special setup required. All dependencies managed at root `go.mod`.

**Testing CLI:**

```bash
# Build binary
go build -o raybeam .

# Test help output
./raybeam --help
./raybeam serve --help

# Test with minimal flags (will fail without LDAP)
./raybeam serve -s ldap://localhost:389 -b dc=example,dc=org -u admin -p password -g cn=admins,dc=example,dc=org
```

## Build & tests (file-scoped)

```bash
# Test cmd package
go test ./cmd -v

# Build with version info
go build -ldflags="-X 'raybeam/internal/build.Version=$(git rev-parse HEAD)'" -o raybeam .

# Verify CLI behavior
./raybeam --version
./raybeam serve --help
```

## Code style & conventions

### Cobra patterns

```go
// Good: Define command with RunE for error handling
var serveCmd = &cobra.Command{
    Use:   "serve",
    Short: "Run the Raybeam server",
    RunE: func(cmd *cobra.Command, args []string) error {
        // ... implementation
        return err  // Return errors, don't log.Fatal
    },
}

// Good: Flag validation in init()
func init() {
    serveCmd.Flags().StringVarP(&ldapServer, "ldap-server", "s", "ldap://localhost:389", "LDAP server URL")
    serveCmd.MarkFlagRequired("ldap-server")
}

// Bad: Panic in command logic
func(cmd *cobra.Command, args []string) error {
    if err != nil {
        panic(err)  // Use return err instead
    }
}
```

### Flag naming

- **Long form:** Use kebab-case: `--ldap-server`, `--http-address`
- **Short form:** Single letter: `-s`, `-l`, `-d`
- **Environment:** Not currently supported; flags only

### Error handling

```go
// Good: Return errors to Cobra
if err := db.Update(...); err != nil {
    return err  // Cobra prints error and exits with code 1
}

// Good: Defer cleanup with error handling
defer func(db *bbolt.DB) {
    _ = db.Close()  // OK to ignore close errors in defer
}(db)

// Bad: log.Fatal in command logic
if err != nil {
    log.Fatal(err)  // Bypasses Cobra error handling
}
```

## Security & safety

### Flags and secrets

- **Never hardcode secrets:** LDAP password required via `-p` flag
- **Future:** Consider environment variable support for secrets
- **Validation:** Required flags enforced by Cobra (`MarkFlagRequired`)

### Configuration

```go
// Current: Flags only
./raybeam serve -s ldaps://ldap.example.com -u readonly -p $LDAP_PASSWORD

// Future consideration: Config file support
// (Not yet implemented; flags are sufficient for current use case)
```

## PR/commit checklist

- [ ] New flags have both long (`--flag`) and short (`-f`) forms
- [ ] Required flags marked with `MarkFlagRequired()`
- [ ] Help text (`Short` and `Long`) updated
- [ ] Default values appropriate for development
- [ ] Command tested manually (`./raybeam <cmd> --help`)
- [ ] Errors returned via `RunE`, not `log.Fatal`

## Good vs. bad examples

**Good examples:**

- `cmd/serve.go` — Complete command with all lifecycle: flags, init, validation, execution
- `cmd/root.go` — Simple root with version and error handling

**Patterns to follow:**

```go
// Good: Descriptive help text
var serveCmd = &cobra.Command{
    Use:   "serve",
    Short: "Run the Raybeam HTTP server",
    Long: `Starts the Raybeam server with LDAP authentication.
Requires a running LDAP server and BoltDB file path.`,
}

// Good: Required flags
serveCmd.MarkFlagRequired("ldap-read-user")
serveCmd.MarkFlagRequired("ldap-read-password")

// Good: Deferred cleanup
defer func(db *bbolt.DB) {
    _ = db.Close()
}(db)
```

**Patterns to avoid:**

```go
// Bad: No help text
var cmd = &cobra.Command{Use: "serve"}

// Bad: Ignoring errors
db, _ := bbolt.Open(dbLocation, 0600, nil)

// Bad: Using Run instead of RunE
Run: func(cmd *cobra.Command, args []string) {
    err := doSomething()
    if err != nil {
        log.Fatal(err)  // Use RunE and return err
    }
},
```

## When stuck

1. **Cobra documentation:** https://github.com/spf13/cobra
2. **Flag patterns:** See `serve.go` for comprehensive example
3. **Lifecycle:** `init()` registers flags → `RunE` executes → return error
4. **Testing:** Build binary and test manually; consider adding CLI integration tests

## House Rules (Defaults)

This section inherits from root `AGENTS.md` but adds cmd-specific rules:

### Command structure

- **Use `RunE` not `Run`:** Always return errors properly
- **Flag binding:** Use `*VarP` methods for direct variable binding
- **Init pattern:** Register flags in `init()`, validate in `RunE`

### Flag design

- **Sensible defaults:** Flags should have dev-friendly defaults where possible
- **Required flags:** Mark explicitly with `MarkFlagRequired()`
- **Help text:** Every flag needs clear, concise description

### Exit codes

- **Success:** Return `nil` from `RunE` (exit code 0)
- **Error:** Return `error` from `RunE` (Cobra sets exit code 1)
- **Never:** Use `os.Exit()` or `log.Fatal()` in command logic

## Decision log

- **Flags only, no config file:** Current use case doesn't justify config file complexity
- **Version from VCS:** Using `internal/build` package to extract git revision at build time
- **Required flags:** LDAP credentials must be explicit; no empty defaults for security