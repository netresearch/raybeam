package server

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestServerServeAndShutdown exercises Serve + Shutdown against a real OS
// port with the mock LDAP client. This is still a unit test — no LDAP
// container, no external deps — but it covers the listener-handoff path
// used by the e2e tier.
func TestServerServeAndShutdown(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("newTestServer: %v", err)
	}
	defer cleanup()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		t.Fatalf("expected *net.TCPAddr, got %T", ln.Addr())
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// Wait until the server is reachable.
	client := &http.Client{Timeout: 500 * time.Millisecond}
	baseURL := "http://127.0.0.1:" + strconv.Itoa(addr.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready := false
	for ctx.Err() == nil {
		resp, err := client.Get(baseURL + "/info")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		_ = srv.Shutdown()
		<-serveErr
		t.Fatal("server did not become ready within 5s")
	}

	if err := srv.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	select {
	case err := <-serveErr:
		// fasthttp returns nil on graceful shutdown.
		if err != nil {
			t.Errorf("Serve exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s after Shutdown")
	}
}

