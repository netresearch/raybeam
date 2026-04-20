//go:build e2e

// Package raybeamserver brings up a live raybeam HTTP server bound to an
// ephemeral port, backed by a real BoltDB file and a real LDAP client. It is
// the e2e-tier equivalent of httptest.NewServer.
//
// Only compiled under the `e2e` build tag.
package raybeamserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"raybeam/internal/models"
	"raybeam/internal/server"
	"testing"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
	"go.etcd.io/bbolt"
)

// Instance represents a running raybeam server.
type Instance struct {
	// BaseURL is the root HTTP URL (e.g. http://127.0.0.1:54321).
	BaseURL string
	// Client is a ready-to-use HTTP client with a sensible timeout.
	Client *http.Client
	// ServeErr receives the single error produced by (*server.Server).Serve
	// if the accept loop exits unexpectedly. Nil on clean shutdown.
	ServeErr <-chan error
}

// Config collects the knobs a caller might want to change. Zero values pick
// reasonable defaults.
type Config struct {
	LDAPConfig   ldap.Config
	ReadUser     string
	ReadPass     string
	AdminGroupDN string
}

// Start launches a raybeam server on an ephemeral port and returns an
// Instance ready for HTTP traffic. The server is gracefully shut down in
// t.Cleanup.
func Start(ctx context.Context, t *testing.T, cfg Config) *Instance {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "raybeam-e2e.bolt")

	db, err := bbolt.Open(dbPath, 0o600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("raybeamserver: bbolt.Open %s: %v", dbPath, err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(models.SSHKeyBucket)
		return e
	}); err != nil {
		_ = db.Close()
		t.Fatalf("raybeamserver: create bucket: %v", err)
	}

	srv, err := server.New(db, cfg.LDAPConfig, cfg.ReadUser, cfg.ReadPass, cfg.AdminGroupDN)
	if err != nil {
		_ = db.Close()
		t.Fatalf("raybeamserver: server.New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = db.Close()
		t.Fatalf("raybeamserver: net.Listen: %v", err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		_ = db.Close()
		t.Fatalf("raybeamserver: expected *net.TCPAddr, got %T", ln.Addr())
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", addr.Port)

	serveErr := make(chan error, 1)
	go func() {
		// Serve blocks until Shutdown() or a fatal error.
		serveErr <- srv.Serve(ln)
	}()

	inst := &Instance{
		BaseURL:  baseURL,
		Client:   &http.Client{Timeout: 10 * time.Second},
		ServeErr: serveErr,
	}

	// Wait for the server to be reachable before handing it to the test.
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := waitForReady(waitCtx, inst); err != nil {
		_ = srv.Shutdown()
		<-serveErr
		_ = db.Close()
		_ = os.Remove(dbPath)
		t.Fatalf("raybeamserver: server did not become ready: %v", err)
	}

	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Logf("raybeamserver: shutdown: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Logf("raybeamserver: serve exited with: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Logf("raybeamserver: shutdown timed out waiting for Serve")
		}
		_ = db.Close()
	})

	return inst
}

// waitForReady polls /info until the server responds 2xx or the context
// expires. /info is unauthenticated so it's a perfect liveness probe.
func waitForReady(ctx context.Context, inst *Instance) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, inst.BaseURL+"/info", nil)
	if err != nil {
		return err
	}
	probe := &http.Client{Timeout: 500 * time.Millisecond}
	var lastErr error
	for {
		if ctx.Err() != nil {
			if lastErr != nil {
				return fmt.Errorf("%w (last probe: %v)", ctx.Err(), lastErr)
			}
			return ctx.Err()
		}
		resp, err := probe.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
}
