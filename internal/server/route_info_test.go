package server

import (
	"net/http/httptest"
	"raybeam/internal/build"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestHandleHTTPGetInfo verifies that /info returns a JSON document containing
// the build version and source repository values from the build package.
func TestHandleHTTPGetInfo(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("newTestServer: %v", err)
	}
	defer cleanup()

	req := httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("Accept", fiber.MIMEApplicationJSON)
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("srv.app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}

	var body struct {
		Version string `json:"version"`
		Source  string `json:"source"`
	}
	parseJSONResponse(t, resp, &body)

	if body.Source != build.Repository {
		t.Errorf("source = %q, want %q", body.Source, build.Repository)
	}
	// build.Version is populated at link-time; in `go test` it resolves to "unknown"
	// or the vcs.revision of the test binary. Either way it must be non-empty.
	if body.Version == "" {
		t.Errorf("version is empty, want non-empty string")
	}
}

// TestHandleHTTPGetInfo_NoAuthRequired confirms the /info endpoint is publicly
// accessible (no basic auth).
func TestHandleHTTPGetInfo_NoAuthRequired(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("newTestServer: %v", err)
	}
	defer cleanup()

	// Deliberately send no Authorization header.
	req := httptest.NewRequest("GET", "/info", nil)
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("srv.app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("status = %d, want %d (endpoint should be public)", resp.StatusCode, fiber.StatusOK)
	}
}
