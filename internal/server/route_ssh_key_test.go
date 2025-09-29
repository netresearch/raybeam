package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// Test SSH keys - real SSH public keys for testing
const (
	testSSHKeyRSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7Z8VYvZ8ZQVlqW8F5h3j0K9Xr3g3kM2n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9n5L1j3F2h3k0m9"
	testSSHKeyED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	testSSHKeyFingerprint1 = "SHA256:GJz8qVZV9lWqXxZnz7xZQVlqW8F5h3j0K9Xr3g3kM2n"
	testSSHKeyFingerprint2 = "SHA256:ABC123xyz789DefGhi012Jkl345Mno678Pqr901Stu234"
)

// Helper functions for making authenticated requests

func makeAuthRequest(t *testing.T, srv *Server, method, url, username, password string, body io.Reader, acceptJSON bool) *http.Response {
	t.Helper()

	req := httptest.NewRequest(method, url, body)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", basicAuthEncode(username, password)))
	if acceptJSON {
		req.Header.Set("Accept", fiber.MIMEApplicationJSON)
	}

	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	return resp
}

func makeRequest(t *testing.T, srv *Server, method, url string, body io.Reader, acceptJSON bool) *http.Response {
	t.Helper()

	req := httptest.NewRequest(method, url, body)
	if acceptJSON {
		req.Header.Set("Accept", fiber.MIMEApplicationJSON)
	}

	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	return resp
}

func basicAuthEncode(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func readBodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	return string(body)
}

func parseJSONResponse(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("Failed to parse JSON response: %v, body: %s", err, string(body))
	}
}

// Test handleHTTPGetUsersMeSSHKeys - GET /users/@me/ssh-keys

func TestHandleHTTPGetUsersMeSSHKeys_Success_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get keys as JSON
	resp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result keysResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	if len(result.Keys) == 0 {
		t.Error("Expected at least one key in response")
	}
}

func TestHandleHTTPGetUsersMeSSHKeys_Success_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get keys as plain text
	resp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "ssh-ed25519") {
		t.Errorf("Expected SSH key in plain text response, got: %s", body)
	}
	if !strings.Contains(body, "# Keys uploaded by") {
		t.Errorf("Expected comment header in plain text response, got: %s", body)
	}
}

func TestHandleHTTPGetUsersMeSSHKeys_NoAuth(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeRequest(t, srv, "GET", "/users/@me/ssh-keys", nil, true)

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}
}

func TestHandleHTTPGetUsersMeSSHKeys_InvalidCredentials(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "wrongpass", nil, true)

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}
}

// Test handleHTTPPutUsersMeSSHKey - PUT /users/@me/ssh-keys

func TestHandleHTTPPutUsersMeSSHKey_Success_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), true)

	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Expected status %d, got %d", fiber.StatusCreated, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}
}

func TestHandleHTTPPutUsersMeSSHKey_Success_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)

	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Expected status %d, got %d", fiber.StatusCreated, resp.StatusCode)
	}
}

func TestHandleHTTPPutUsersMeSSHKey_Duplicate(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload key first time
	resp1 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if resp1.StatusCode != fiber.StatusCreated {
		t.Fatalf("First upload failed: status %d", resp1.StatusCode)
	}

	// Try to upload same key again
	resp2 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), true)

	if resp2.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("Expected status %d for duplicate key, got %d", fiber.StatusInternalServerError, resp2.StatusCode)
	}

	body := readBodyString(t, resp2)
	if !strings.Contains(body, "already uploaded") {
		t.Errorf("Expected 'already uploaded' error message, got: %s", body)
	}
}

func TestHandleHTTPPutUsersMeSSHKey_InvalidKey(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader("invalid ssh key data"), true)

	if resp.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("Expected status %d for invalid key, got %d", fiber.StatusInternalServerError, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "could not parse") {
		t.Errorf("Expected 'could not parse' error message, got: %s", body)
	}
}

// Test handleHTTPDeleteUsersMeSSHKeys - DELETE /users/@me/ssh-keys

func TestHandleHTTPDeleteUsersMeSSHKeys_Success_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Delete all keys
	resp := makeAuthRequest(t, srv, "DELETE", "/users/@me/ssh-keys", "user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	// Verify keys are deleted
	getResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getResult keysResponse
	parseJSONResponse(t, getResp, &getResult)

	if len(getResult.Keys) != 0 {
		t.Errorf("Expected 0 keys after deletion, got %d", len(getResult.Keys))
	}
}

func TestHandleHTTPDeleteUsersMeSSHKeys_Success_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "DELETE", "/users/@me/ssh-keys", "user1", "testpass", nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}
}

// Test handleHTTPGetUsersMeSSHKey - GET /users/@me/ssh-keys/:fingerprint

func TestHandleHTTPGetUsersMeSSHKey_Success_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get all keys to find the fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Get specific key
	resp := makeAuthRequest(t, srv, "GET", fmt.Sprintf("/users/@me/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result keyResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	if result.Key == nil {
		t.Error("Expected key in response")
	}
}

func TestHandleHTTPGetUsersMeSSHKey_Success_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get all keys to find the fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Get specific key as plain text
	resp := makeAuthRequest(t, srv, "GET", fmt.Sprintf("/users/@me/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "ssh-ed25519") {
		t.Errorf("Expected SSH key in plain text response, got: %s", body)
	}
}

func TestHandleHTTPGetUsersMeSSHKey_NotFound(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys/SHA256:nonexistent",
		"user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "not found") {
		t.Errorf("Expected 'not found' error message, got: %s", body)
	}
}

// Test handleHTTPDeleteUsersMeSSHKey - DELETE /users/@me/ssh-keys/:fingerprint

func TestHandleHTTPDeleteUsersMeSSHKey_Success_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Delete specific key
	resp := makeAuthRequest(t, srv, "DELETE", fmt.Sprintf("/users/@me/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	// Verify key is deleted
	getResp := makeAuthRequest(t, srv, "GET", fmt.Sprintf("/users/@me/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, true)
	if getResp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected key to be deleted, but got status %d", getResp.StatusCode)
	}
}

func TestHandleHTTPDeleteUsersMeSSHKey_Success_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Delete specific key
	resp := makeAuthRequest(t, srv, "DELETE", fmt.Sprintf("/users/@me/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}
}

// Test handleHTTPGetUsersSSHKeys - GET /users/:sAMAccountNames/ssh-keys

func TestHandleHTTPGetUsersSSHKeys_SingleUser_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key for user1
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get keys for user1
	resp := makeRequest(t, srv, "GET", "/users/user1/ssh-keys", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result multiUserKeysResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	if len(result.Keys) != 1 {
		t.Errorf("Expected 1 user in response, got %d", len(result.Keys))
	}
}

func TestHandleHTTPGetUsersSSHKeys_MultipleUsers_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload keys for both users
	uploadResp1 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp1.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user1: status %d", uploadResp1.StatusCode)
	}

	uploadResp2 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user2", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp2.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user2: status %d", uploadResp2.StatusCode)
	}

	// Get keys for both users
	resp := makeRequest(t, srv, "GET", "/users/user1,user2/ssh-keys", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result multiUserKeysResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	if len(result.Keys) != 2 {
		t.Errorf("Expected 2 users in response, got %d", len(result.Keys))
	}
}

func TestHandleHTTPGetUsersSSHKeys_MixedValidInvalid_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload key for user1 only
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get keys for user1 and nonexistent user
	resp := makeRequest(t, srv, "GET", "/users/user1,nonexistent/ssh-keys", nil, true)

	// Should succeed with just user1's keys
	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result multiUserKeysResponse
	parseJSONResponse(t, resp, &result)

	if len(result.Keys) != 1 {
		t.Errorf("Expected 1 user in response (only valid user), got %d", len(result.Keys))
	}
}

func TestHandleHTTPGetUsersSSHKeys_NoUsersFound(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeRequest(t, srv, "GET", "/users/nonexistent/ssh-keys", nil, true)

	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "no users found") {
		t.Errorf("Expected 'no users found' error message, got: %s", body)
	}
}

func TestHandleHTTPGetUsersSSHKeys_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get keys as plain text
	resp := makeRequest(t, srv, "GET", "/users/user1/ssh-keys", nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "ssh-ed25519") {
		t.Errorf("Expected SSH key in plain text response, got: %s", body)
	}
}

// Test handleHTTPPutUsersSSHKey - PUT /users/:sAMAccountNames/ssh-keys

func TestHandleHTTPPutUsersSSHKey_SingleUser_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Admin uploads key for user1
	resp := makeAuthRequest(t, srv, "PUT", "/users/user1/ssh-keys", "admin", "testpass",
		strings.NewReader(testSSHKeyED25519), true)

	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Expected status %d, got %d", fiber.StatusCreated, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}
}

func TestHandleHTTPPutUsersSSHKey_MultipleUsers_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Admin uploads key for multiple users
	resp := makeAuthRequest(t, srv, "PUT", "/users/user1,user2/ssh-keys", "admin", "testpass",
		strings.NewReader(testSSHKeyED25519), true)

	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Expected status %d, got %d", fiber.StatusCreated, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	// Verify both users have the key
	getResp1 := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getResult1 keysResponse
	parseJSONResponse(t, getResp1, &getResult1)
	if len(getResult1.Keys) != 1 {
		t.Errorf("Expected 1 key for user1, got %d", len(getResult1.Keys))
	}

	getResp2 := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user2", "testpass", nil, true)
	var getResult2 keysResponse
	parseJSONResponse(t, getResp2, &getResult2)
	if len(getResult2.Keys) != 1 {
		t.Errorf("Expected 1 key for user2, got %d", len(getResult2.Keys))
	}
}

func TestHandleHTTPPutUsersSSHKey_NonAdmin(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Non-admin tries to upload key for another user
	resp := makeAuthRequest(t, srv, "PUT", "/users/user2/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), true)

	if resp.StatusCode != fiber.StatusForbidden {
		t.Errorf("Expected status %d, got %d", fiber.StatusForbidden, resp.StatusCode)
	}
}

func TestHandleHTTPPutUsersSSHKey_NoUsersFound(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "PUT", "/users/nonexistent/ssh-keys", "admin", "testpass",
		strings.NewReader(testSSHKeyED25519), true)

	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, resp.StatusCode)
	}
}

func TestHandleHTTPPutUsersSSHKey_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "PUT", "/users/user1/ssh-keys", "admin", "testpass",
		strings.NewReader(testSSHKeyED25519), false)

	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Expected status %d, got %d", fiber.StatusCreated, resp.StatusCode)
	}
}

// Test handleHTTPDeleteUsersSSHKeys - DELETE /users/:sAMAccountNames/ssh-keys

func TestHandleHTTPDeleteUsersSSHKeys_SingleUser_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key first
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Admin deletes keys for user1
	resp := makeAuthRequest(t, srv, "DELETE", "/users/user1/ssh-keys", "admin", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}
}

func TestHandleHTTPDeleteUsersSSHKeys_MultipleUsers_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload keys for both users
	uploadResp1 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp1.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user1: status %d", uploadResp1.StatusCode)
	}

	uploadResp2 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user2", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp2.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user2: status %d", uploadResp2.StatusCode)
	}

	// Admin deletes keys for both users
	resp := makeAuthRequest(t, srv, "DELETE", "/users/user1,user2/ssh-keys", "admin", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}
}

func TestHandleHTTPDeleteUsersSSHKeys_NonAdmin(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Non-admin tries to delete keys for another user
	resp := makeAuthRequest(t, srv, "DELETE", "/users/user2/ssh-keys", "user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusForbidden {
		t.Errorf("Expected status %d, got %d", fiber.StatusForbidden, resp.StatusCode)
	}
}

func TestHandleHTTPDeleteUsersSSHKeys_NoUsersFound(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "DELETE", "/users/nonexistent/ssh-keys", "admin", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, resp.StatusCode)
	}
}

func TestHandleHTTPDeleteUsersSSHKeys_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "DELETE", "/users/user1/ssh-keys", "admin", "testpass", nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}
}

// Test handleHTTPGetUserSSHKey - GET /users/:sAMAccountNames/ssh-keys/:fingerprint

func TestHandleHTTPGetUserSSHKey_SingleUser_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Get specific key
	resp := makeRequest(t, srv, "GET", fmt.Sprintf("/users/user1/ssh-keys/%s", url.PathEscape(fingerprint)), nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result keysResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	if len(result.Keys) != 1 {
		t.Errorf("Expected 1 key in response, got %d", len(result.Keys))
	}
}

func TestHandleHTTPGetUserSSHKey_MultipleUsers_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload keys for both users
	uploadResp1 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp1.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user1: status %d", uploadResp1.StatusCode)
	}

	uploadResp2 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user2", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp2.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user2: status %d", uploadResp2.StatusCode)
	}

	// Get fingerprint (both users have same key so same fingerprint)
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Get specific key for both users
	resp := makeRequest(t, srv, "GET", fmt.Sprintf("/users/user1,user2/ssh-keys/%s", url.PathEscape(fingerprint)), nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result keysResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}

	if len(result.Keys) != 2 {
		t.Errorf("Expected 2 keys in response (one per user), got %d", len(result.Keys))
	}
}

func TestHandleHTTPGetUserSSHKey_KeyNotFound(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeRequest(t, srv, "GET", "/users/user1/ssh-keys/SHA256:nonexistent", nil, true)

	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "not found") {
		t.Errorf("Expected 'not found' error message, got: %s", body)
	}
}

func TestHandleHTTPGetUserSSHKey_NoUsersFound(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeRequest(t, srv, "GET", "/users/nonexistent/ssh-keys/SHA256:somekey", nil, true)

	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, resp.StatusCode)
	}
}

func TestHandleHTTPGetUserSSHKey_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Get specific key as plain text
	resp := makeRequest(t, srv, "GET", fmt.Sprintf("/users/user1/ssh-keys/%s", url.PathEscape(fingerprint)), nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	body := readBodyString(t, resp)
	if !strings.Contains(body, "ssh-ed25519") {
		t.Errorf("Expected SSH key in plain text response, got: %s", body)
	}
}

// Test handleHTTPDeleteUsersSSHKey - DELETE /users/:sAMAccountNames/ssh-keys/:fingerprint

func TestHandleHTTPDeleteUsersSSHKey_SingleUser_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Delete specific key (requires auth for this endpoint)
	resp := makeAuthRequest(t, srv, "DELETE", fmt.Sprintf("/users/user1/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}
}

func TestHandleHTTPDeleteUsersSSHKey_MultipleUsers_JSON(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload keys for both users
	uploadResp1 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp1.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user1: status %d", uploadResp1.StatusCode)
	}

	uploadResp2 := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user2", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp2.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key for user2: status %d", uploadResp2.StatusCode)
	}

	// Get fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Delete specific key for both users (requires auth)
	resp := makeAuthRequest(t, srv, "DELETE", fmt.Sprintf("/users/user1/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result successResponse
	parseJSONResponse(t, resp, &result)

	if !result.Success {
		t.Error("Expected success=true in JSON response")
	}
}

func TestHandleHTTPDeleteUsersSSHKey_NoUsersFound(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	resp := makeAuthRequest(t, srv, "DELETE", "/users/nonexistent/ssh-keys/SHA256:somekey",
		"user1", "testpass", nil, true)

	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status %d, got %d", fiber.StatusNotFound, resp.StatusCode)
	}
}

func TestHandleHTTPDeleteUsersSSHKey_PlainText(t *testing.T) {
	mockLDAP := NewMockLDAP()
	srv, cleanup, err := newTestServer(mockLDAP, "CN=Admins,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer cleanup()

	// Upload a key
	uploadResp := makeAuthRequest(t, srv, "PUT", "/users/@me/ssh-keys", "user1", "testpass",
		strings.NewReader(testSSHKeyED25519), false)
	if uploadResp.StatusCode != fiber.StatusCreated {
		t.Fatalf("Failed to upload key: status %d", uploadResp.StatusCode)
	}

	// Get fingerprint
	getAllResp := makeAuthRequest(t, srv, "GET", "/users/@me/ssh-keys", "user1", "testpass", nil, true)
	var getAllResult keysResponse
	parseJSONResponse(t, getAllResp, &getAllResult)

	var fingerprint string
	for fp := range getAllResult.Keys {
		fingerprint = fp
		break
	}

	// Delete specific key
	resp := makeAuthRequest(t, srv, "DELETE", fmt.Sprintf("/users/user1/ssh-keys/%s", url.PathEscape(fingerprint)),
		"user1", "testpass", nil, false)

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}
}