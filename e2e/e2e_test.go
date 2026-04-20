//go:build e2e

// Package e2e spins up a real raybeam HTTP server backed by a real OpenLDAP
// testcontainer and exercises the public API over the wire with a normal
// http.Client. If an e2e test fails, something a user would see is broken.
package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"raybeam/internal/testsupport/ldapcontainer"
	"raybeam/internal/testsupport/raybeamserver"
)

// A valid-but-disposable ed25519 SSH public key. Generated offline; it has
// no corresponding private key on this host. Used purely to exercise the
// SSH-key parser + storage roundtrip.
const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7z4v9YJYKCtq4pmYiFhMxL5yWw8ODKzpQx7aB1ppkZ raybeam-e2e-test"

type harness struct {
	ldap *ldapcontainer.Container
	srv  *raybeamserver.Instance
}

func startHarness(ctx context.Context, t *testing.T) *harness {
	t.Helper()
	c := ldapcontainer.Start(ctx, t)
	s := raybeamserver.Start(ctx, t, raybeamserver.Config{
		LDAPConfig:   c.LDAPConfig,
		ReadUser:     c.Fixtures.ReadUser,
		ReadPass:     c.Fixtures.ReadPass,
		AdminGroupDN: c.Fixtures.AdminGroupDN,
	})
	return &harness{ldap: c, srv: s}
}

func basicAuth(user, pass string) string {
	raw := user + ":" + pass
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

func (h *harness) do(t *testing.T, method, path string, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, h.srv.BaseURL+path, rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.srv.Client.Do(req)
	if err != nil {
		t.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, out interface{}) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// --- tests ---

func TestE2E_Info_IsUnauthenticated(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)

	resp := h.do(t, http.MethodGet, "/info", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /info: status=%d", resp.StatusCode)
	}

	var info struct {
		Version string `json:"version"`
		Source  string `json:"source"`
	}
	decodeJSON(t, resp, &info)
	if info.Source == "" {
		t.Error("expected non-empty source URL in /info payload")
	}
	// Version is whatever runtime/debug reports; in test binaries it's
	// typically "unknown" — we just check the field came back.
	if info.Version == "" {
		t.Error("expected non-empty version string in /info payload")
	}
}

func TestE2E_MeEndpoint_RequiresAuth(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)

	resp := h.do(t, http.MethodGet, "/users/@me/ssh-keys", nil, map[string]string{
		"Accept": "application/json",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("expected WWW-Authenticate Basic challenge, got %q", got)
	}
}

func TestE2E_MeEndpoint_RejectsWrongPassword(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)

	resp := h.do(t, http.MethodGet, "/users/@me/ssh-keys", nil, map[string]string{
		"Authorization": basicAuth(h.ldap.Fixtures.User1UID, "wrong-password"),
		"Accept":        "application/json",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with bad password, got %d body=%s", resp.StatusCode, readBody(t, resp))
	}
}

func TestE2E_UploadAndFetchOwnSSHKey(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)
	auth := basicAuth(h.ldap.Fixtures.User1UID, h.ldap.Fixtures.User1Password)

	// Empty list to start.
	resp := h.do(t, http.MethodGet, "/users/@me/ssh-keys", nil, map[string]string{
		"Authorization": auth,
		"Accept":        "application/json",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial GET @me/ssh-keys: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var initial struct {
		Success bool                   `json:"success"`
		Keys    map[string]interface{} `json:"keys"`
	}
	decodeJSON(t, resp, &initial)
	if !initial.Success {
		t.Fatal("expected success=true on initial list")
	}
	if len(initial.Keys) != 0 {
		t.Fatalf("expected empty key list initially, got %d keys", len(initial.Keys))
	}

	// Upload.
	resp = h.do(t, http.MethodPut, "/users/@me/ssh-keys", []byte(testSSHKey), map[string]string{
		"Authorization": auth,
		"Accept":        "application/json",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT @me/ssh-keys: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	// Fetch via JSON.
	resp = h.do(t, http.MethodGet, "/users/@me/ssh-keys", nil, map[string]string{
		"Authorization": auth,
		"Accept":        "application/json",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-upload GET: status=%d", resp.StatusCode)
	}
	var listed struct {
		Success bool `json:"success"`
		Keys    map[string]struct {
			Fingerprint string `json:"fingerprint"`
			Key         string `json:"key"`
		} `json:"keys"`
	}
	decodeJSON(t, resp, &listed)
	if len(listed.Keys) != 1 {
		t.Fatalf("expected 1 key after upload, got %d", len(listed.Keys))
	}
	var fingerprint string
	for fp := range listed.Keys {
		fingerprint = fp
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Errorf("fingerprint should be SHA256:<base64>, got %q", fingerprint)
	}
}

func TestE2E_AuthorizedKeysFormat_MatchesSSHExpectations(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)
	auth := basicAuth(h.ldap.Fixtures.User1UID, h.ldap.Fixtures.User1Password)

	// Upload key first.
	resp := h.do(t, http.MethodPut, "/users/@me/ssh-keys", []byte(testSSHKey), map[string]string{
		"Authorization": auth,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	// Public lookup (no Accept: JSON) — the authorized_keys-style endpoint
	// is what a real OpenSSH AuthorizedKeysCommand would call via curl.
	publicPath := "/users/" + url.PathEscape(h.ldap.Fixtures.User1UID) + "/ssh-keys"
	resp = h.do(t, http.MethodGet, publicPath, nil, nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public GET: status=%d body=%q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "ssh-ed25519 ") {
		t.Errorf("expected authorized_keys line to start with ssh-ed25519, got:\n%s", body)
	}
	if !strings.Contains(body, "# Keys uploaded by ") {
		t.Errorf("expected DN comment line, got:\n%s", body)
	}
}

func TestE2E_MissingUser_Returns404(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)

	resp := h.do(t, http.MethodGet, "/users/nobody-here/ssh-keys", nil, map[string]string{
		"Accept": "application/json",
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for missing user, got %d body=%s", resp.StatusCode, readBody(t, resp))
	}
}

func TestE2E_DeleteSingleKey_FrontToBack(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)
	auth := basicAuth(h.ldap.Fixtures.User1UID, h.ldap.Fixtures.User1Password)

	// Upload, list, grab fingerprint, delete, verify gone.
	resp := h.do(t, http.MethodPut, "/users/@me/ssh-keys", []byte(testSSHKey), map[string]string{
		"Authorization": auth,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	resp = h.do(t, http.MethodGet, "/users/@me/ssh-keys", nil, map[string]string{
		"Authorization": auth,
		"Accept":        "application/json",
	})
	var listed struct {
		Keys map[string]struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	decodeJSON(t, resp, &listed)
	if len(listed.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listed.Keys))
	}
	var fp string
	for f := range listed.Keys {
		fp = f
	}

	// URL-safe encode the fingerprint. raybeam's route does
	// base64url -> base64 conversion at the server side; the client sends
	// base64url.
	urlSafeFp := strings.NewReplacer("+", "-", "/", "_").Replace(fp)

	deletePath := fmt.Sprintf("/users/@me/ssh-keys/%s", urlSafeFp)
	resp = h.do(t, http.MethodDelete, deletePath, nil, map[string]string{
		"Authorization": auth,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	// Verify empty again.
	resp = h.do(t, http.MethodGet, "/users/@me/ssh-keys", nil, map[string]string{
		"Authorization": auth,
		"Accept":        "application/json",
	})
	var after struct {
		Keys map[string]interface{} `json:"keys"`
	}
	decodeJSON(t, resp, &after)
	if len(after.Keys) != 0 {
		t.Fatalf("expected key list empty after delete, got %d", len(after.Keys))
	}
}

func TestE2E_NonAdminCannotUploadForOtherUsers(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)
	// user1 tries to PUT a key onto user2's account.
	auth := basicAuth(h.ldap.Fixtures.User1UID, h.ldap.Fixtures.User1Password)

	targetPath := "/users/" + url.PathEscape(h.ldap.Fixtures.User2UID) + "/ssh-keys"
	resp := h.do(t, http.MethodPut, targetPath, []byte(testSSHKey), map[string]string{
		"Authorization": auth,
		"Accept":        "application/json",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin uploading to another user, got %d body=%s",
			resp.StatusCode, readBody(t, resp))
	}
}

func TestE2E_AdminCanManageOtherUsersKeys(t *testing.T) {
	ctx := context.Background()
	h := startHarness(ctx, t)
	// root is in the admins group (see ldapcontainer fixtures) and should
	// be able to upload a key on behalf of user2.
	adminAuth := basicAuth(h.ldap.Fixtures.AdminUID, h.ldap.Fixtures.AdminUserPass)

	targetPath := "/users/" + url.PathEscape(h.ldap.Fixtures.User2UID) + "/ssh-keys"
	resp := h.do(t, http.MethodPut, targetPath, []byte(testSSHKey), map[string]string{
		"Authorization": adminAuth,
		"Accept":        "application/json",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for admin upload, got %d body=%s", resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	// Public lookup (unauthenticated) now sees user2's key.
	resp = h.do(t, http.MethodGet, targetPath, nil, map[string]string{
		"Accept": "application/json",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public GET after admin upload: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var listed struct {
		Keys map[string]map[string]struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	decodeJSON(t, resp, &listed)
	if len(listed.Keys) == 0 {
		t.Fatal("expected keys returned for user2 after admin upload")
	}
}
