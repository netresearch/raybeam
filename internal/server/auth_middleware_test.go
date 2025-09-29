package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	ldap "github.com/netresearch/simple-ldap-go"
)

func TestBasicAuthWithNonBasicAuthHeader(t *testing.T) {
	_, _, err := basicAuth("Bearer a")
	if err != ErrAuthHeaderMissing {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMissing, err)
	}
}

func TestBasicAuthWithMalformedHeader(t *testing.T) {
	_, _, err := basicAuth("Basic %%%%")
	if err != ErrAuthHeaderMalformed {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMalformed, err)
	}
}

func TestBasicAuthWithMalformedHeader2(t *testing.T) {
	_, _, err := basicAuth("Basic aaaa")
	if err != ErrAuthHeaderMalformed {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMalformed, err)
	}
}

func TestBasicAuthWithExclamationMark(t *testing.T) {
	wantCN := "readuser!"
	wantPassword := "readuser!"

	gotCN, gotPassword, err := basicAuth(fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", wantCN, wantPassword)))))
	if err != nil {
		t.Errorf("expected no error, got %q", err)
		return
	}

	if gotCN != wantCN {
		t.Errorf("expected CN %q, got %q", wantCN, gotCN)
	}

	if gotPassword != wantPassword {
		t.Errorf("expected password %q, got %q", wantPassword, gotPassword)
	}
}

func TestBasicAuth(t *testing.T) {
	wantCN := "readuser"
	wantPassword := "readuser"

	gotCN, gotPassword, err := basicAuth(fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", wantCN, wantPassword)))))
	if err != nil {
		t.Errorf("expected no error, got %q", err)
		return
	}

	if gotCN != wantCN {
		t.Errorf("expected CN %q, got %q", wantCN, gotCN)
	}

	if gotPassword != wantPassword {
		t.Errorf("expected password %q, got %q", wantPassword, gotPassword)
	}
}

func TestAuthMiddlewareInvalidCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	l, err := getWorkingLdap()
	if err != nil {
		t.Skip(err)
		return
	}

	u := url.UserPassword("demoooopleasefail", "pleasefailll")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	if _, err := authMiddleware(fmt.Sprintf("Basic %s", auth), l); err != ErrAuthFailed {
		t.Errorf("expected error %q, got %q", ErrAuthFailed, err)
	}
}

func TestAuthMiddlewareWithInvalidAuthorizationHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	l, err := getWorkingLdap()
	if err != nil {
		t.Skip(err)
		return
	}

	if _, err = authMiddleware("Basic %%%%", l); err != ErrAuthHeaderMalformed {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMalformed, err)
	}
}

func TestAuthMiddlewareWithInvalidCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	l, err := getWorkingLdap()
	if err != nil {
		t.Skip(err)
		return
	}

	u := url.UserPassword("demoooopleasefail", "pleasefailll")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	if _, err = authMiddleware(fmt.Sprintf("Basic %s", auth), l); err != ErrAuthFailed {
		t.Errorf("expected error %q, got %q", ErrAuthFailed, err)
	}
}

func TestAuthMiddlewareWithInvalidCredentials2(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	l, err := getWorkingLdap()
	if err != nil {
		t.Skip(err)
		return
	}

	u := url.UserPassword("readuser", "pleasefailll")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	if _, err := authMiddleware(fmt.Sprintf("Basic %s", auth), l); err != ErrAuthFailed {
		t.Errorf("expected error %q, got %q", ErrAuthFailed, err)
	}
}

func getWorkingLdap() (*ldap.LDAP, error) {
	server, found := os.LookupEnv("LDAP_SERVER")
	if !found {
		return nil, errors.New("LDAP_SERVER not set")
	}

	baseDN, found := os.LookupEnv("LDAP_BASE_DN")
	if !found {
		return nil, errors.New("LDAP_BASE_DN not set")
	}

	readUser, found := os.LookupEnv("LDAP_READ_USER")
	if !found {
		return nil, errors.New("LDAP_READ_USER not set")
	}

	readPassword, found := os.LookupEnv("LDAP_READ_PASSWORD")
	if !found {
		return nil, errors.New("LDAP_READ_PASSWORD not set")
	}

	config := ldap.Config{
		Server:            server,
		BaseDN:            baseDN,
		IsActiveDirectory: false,
	}

	return ldap.New(config, readUser, readPassword)
}

// Helper to create basic auth header
func makeBasicAuthHeader(username, password string) string {
	credentials := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// TestIsAdminMiddleware_UserInAdminGroup tests that a user who is in the admin group is allowed access
func TestIsAdminMiddleware_UserInAdminGroup(t *testing.T) {
	mockLDAP := NewMockLDAP()
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// Create request with admin credentials - use PUT which requires isAdminMiddleware
	req := httptest.NewRequest("PUT", "/users/user1/ssh-keys", nil)
	req.Header.Set("Authorization", makeBasicAuthHeader("admin", "testpass"))

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Admin should be allowed (middleware should call next handler)
	// We expect 400 (bad request for missing body) not 401/403
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		t.Errorf("expected admin user to be allowed, got status %d", resp.StatusCode)
	}
}

// TestIsAdminMiddleware_UserMatchesParam tests that a user accessing their own resource is allowed
func TestIsAdminMiddleware_UserMatchesParam(t *testing.T) {
	mockLDAP := NewMockLDAP()
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// Create request where user1 accesses their own resource
	req := httptest.NewRequest("PUT", "/users/user1/ssh-keys", nil)
	req.Header.Set("Authorization", makeBasicAuthHeader("user1", "testpass"))

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// User accessing their own resource should be allowed
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		t.Errorf("expected user to access own resource, got status %d", resp.StatusCode)
	}
}

// TestIsAdminMiddleware_UserNotInAdminGroupNotSelf tests that a regular user cannot access another user's resource
func TestIsAdminMiddleware_UserNotInAdminGroupNotSelf(t *testing.T) {
	mockLDAP := NewMockLDAP()
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// Create request where user1 tries to access user2's resource
	req := httptest.NewRequest("PUT", "/users/user2/ssh-keys", nil)
	req.Header.Set("Authorization", makeBasicAuthHeader("user1", "testpass"))

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Should be forbidden
	if resp.StatusCode != 403 {
		t.Errorf("expected status 403 (Forbidden), got %d", resp.StatusCode)
	}
}

// TestIsAdminMiddleware_UserWithMultipleGroupsIncludingAdmin tests user with multiple groups including admin
func TestIsAdminMiddleware_UserWithMultipleGroupsIncludingAdmin(t *testing.T) {
	mockLDAP := NewMockLDAP()
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// The "admin" user in MockLDAP has multiple groups including the admin group
	req := httptest.NewRequest("PUT", "/users/user1/ssh-keys", nil)
	req.Header.Set("Authorization", makeBasicAuthHeader("admin", "testpass"))

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Admin user with multiple groups should be allowed
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		t.Errorf("expected admin user with multiple groups to be allowed, got status %d", resp.StatusCode)
	}
}

// TestIsAdminMiddleware_CaseInsensitiveGroupDN tests that group DN matching is case-insensitive
func TestIsAdminMiddleware_CaseInsensitiveGroupDN(t *testing.T) {
	// Create a custom mock LDAP with mixed-case group DN
	mockLDAP := &MockLDAP{
		users: map[string]*ldap.User{
			"admin": {
				SAMAccountName: "admin",
				Groups: []string{
					// Lowercase version of admin group
					"cn=admins,ou=groups,dc=example,dc=com",
					"CN=Users,OU=Groups,DC=example,DC=com",
				},
			},
		},
		password: "testpass",
	}

	// Use uppercase admin group DN in server config
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// Request with admin user (who has lowercase group DN)
	req := httptest.NewRequest("PUT", "/users/user1/ssh-keys", nil)
	req.Header.Set("Authorization", makeBasicAuthHeader("admin", "testpass"))

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Should match despite case difference
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		t.Errorf("expected case-insensitive group DN match to allow access, got status %d", resp.StatusCode)
	}
}

// TestIsAdminMiddleware_MissingAuthHeader tests that requests without auth header are denied
func TestIsAdminMiddleware_MissingAuthHeader(t *testing.T) {
	mockLDAP := NewMockLDAP()
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// Create request without Authorization header
	req := httptest.NewRequest("PUT", "/users/user1/ssh-keys", nil)

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Should be unauthorized or forbidden
	// The isAdminMiddleware returns 403 for missing auth when it calls unauthorized()
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		t.Errorf("expected status 401 or 403 for missing auth header, got %d", resp.StatusCode)
	}
}

// TestIsAdminMiddleware_InvalidCredentials tests that requests with invalid credentials are denied
func TestIsAdminMiddleware_InvalidCredentials(t *testing.T) {
	mockLDAP := NewMockLDAP()
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// Create request with wrong password
	req := httptest.NewRequest("PUT", "/users/user1/ssh-keys", nil)
	req.Header.Set("Authorization", makeBasicAuthHeader("admin", "wrongpassword"))

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Should be forbidden (403) from isAdminMiddleware's unauthorized() function
	if resp.StatusCode != 403 {
		t.Errorf("expected status 403 for invalid credentials, got %d", resp.StatusCode)
	}
}

// TestIsAdminMiddleware_NonExistentUser tests that requests with non-existent user are denied
func TestIsAdminMiddleware_NonExistentUser(t *testing.T) {
	mockLDAP := NewMockLDAP()
	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	srv, cleanup, err := newTestServer(mockLDAP, adminGroupDN)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	defer cleanup()

	// Create request with non-existent user
	req := httptest.NewRequest("PUT", "/users/user1/ssh-keys", nil)
	req.Header.Set("Authorization", makeBasicAuthHeader("nonexistent", "testpass"))

	// Test the request
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Should be forbidden (403) from isAdminMiddleware's unauthorized() function
	if resp.StatusCode != 403 {
		t.Errorf("expected status 403 for non-existent user, got %d", resp.StatusCode)
	}
}
