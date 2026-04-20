//go:build integration

// Integration tier: exercise raybeam's LDAP-facing code against a real
// OpenLDAP server running in a testcontainer. No mocks. Failures here mean
// something about raybeam's auth/search assumptions no longer matches how
// a real directory server behaves.

package server_test

import (
	"context"
	"errors"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	ldap "github.com/netresearch/simple-ldap-go"

	"raybeam/internal/testsupport/ldapcontainer"
)

func TestIntegration_LDAP_BindSucceedsWithValidCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := ldapcontainer.Start(ctx, t)

	client := c.NewLDAPClient(t)

	user, err := client.CheckPasswordForSAMAccountName(c.Fixtures.User1UID, c.Fixtures.User1Password)
	if err != nil {
		t.Fatalf("CheckPasswordForSAMAccountName: unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("CheckPasswordForSAMAccountName: user is nil")
	}
	if user.SAMAccountName != c.Fixtures.User1UID {
		t.Errorf("SAMAccountName = %q, want %q", user.SAMAccountName, c.Fixtures.User1UID)
	}
	if user.DN() != c.Fixtures.User1DN {
		t.Errorf("DN = %q, want %q", user.DN(), c.Fixtures.User1DN)
	}
}

func TestIntegration_LDAP_BindFailsWithInvalidPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := ldapcontainer.Start(ctx, t)

	client := c.NewLDAPClient(t)

	_, err := client.CheckPasswordForSAMAccountName(c.Fixtures.User1UID, "definitely-not-the-password")
	if err == nil {
		t.Fatal("CheckPasswordForSAMAccountName: expected error on wrong password, got nil")
	}
	// Real OpenLDAP returns LDAPResultInvalidCredentials. The raybeam auth
	// middleware specifically checks for this, so regressions here would
	// break real deployments.
	var ldapErr *goldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("expected *goldap.Error, got %T: %v", err, err)
	}
	if ldapErr.ResultCode != goldap.LDAPResultInvalidCredentials {
		t.Errorf("ResultCode = %d, want %d (LDAPResultInvalidCredentials)",
			ldapErr.ResultCode, goldap.LDAPResultInvalidCredentials)
	}
}

func TestIntegration_LDAP_FindUserBySAMAccountNameNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := ldapcontainer.Start(ctx, t)

	client := c.NewLDAPClient(t)

	_, err := client.FindUserBySAMAccountName("nobody-here")
	if !errors.Is(err, ldap.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestIntegration_LDAP_FindUsersBySAMAccountNamesReturnsAllMatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := ldapcontainer.Start(ctx, t)

	client := c.NewLDAPClient(t)

	users, err := client.FindUsersBySAMAccountNames([]string{
		c.Fixtures.User1UID,
		c.Fixtures.User2UID,
		"absolutely-nobody",
	})
	if err != nil {
		t.Fatalf("FindUsersBySAMAccountNames: %v", err)
	}
	// Non-existent users are simply skipped by simple-ldap-go. raybeam's
	// route handlers rely on that behaviour (they 404 when the result is
	// empty instead of when individual entries are missing).
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2: %+v", len(users), users)
	}

	got := map[string]bool{}
	for _, u := range users {
		got[u.SAMAccountName] = true
	}
	if !got[c.Fixtures.User1UID] || !got[c.Fixtures.User2UID] {
		t.Errorf("missing expected users; got keys=%v", got)
	}
}

func TestIntegration_LDAP_AdminGroupMembershipReflected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := ldapcontainer.Start(ctx, t)

	client := c.NewLDAPClient(t)

	// The admin user IS a member of the admin group; the regular user is
	// NOT. raybeam's isAdminMiddleware uses User.IsMemberOf to gate admin
	// routes, so the memberof overlay from the bitnami image needs to be
	// populating the memberOf attribute on the user entry.
	adminUser, err := client.CheckPasswordForSAMAccountName(c.Fixtures.AdminUID, c.Fixtures.AdminUserPass)
	if err != nil {
		t.Fatalf("bind admin: %v", err)
	}
	if !adminUser.IsMemberOf(c.Fixtures.AdminGroupDN) {
		t.Errorf("admin user %q not reported as member of %q; Groups=%v",
			c.Fixtures.AdminUID, c.Fixtures.AdminGroupDN, adminUser.Groups)
	}

	regularUser, err := client.CheckPasswordForSAMAccountName(c.Fixtures.User1UID, c.Fixtures.User1Password)
	if err != nil {
		t.Fatalf("bind regular user: %v", err)
	}
	if regularUser.IsMemberOf(c.Fixtures.AdminGroupDN) {
		t.Errorf("regular user %q unexpectedly reported as admin group member; Groups=%v",
			c.Fixtures.User1UID, regularUser.Groups)
	}
}

func TestIntegration_LDAP_InitFailsOnWrongReadCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := ldapcontainer.Start(ctx, t)

	// ldap.New eagerly binds with the service-account credentials. Wrong
	// credentials must surface at startup, not on the first user request.
	_, err := ldap.New(c.LDAPConfig, c.Fixtures.ReadUser, "wrong-service-password")
	if err == nil {
		t.Fatal("ldap.New: expected error on wrong read credentials, got nil")
	}
}

func TestIntegration_LDAP_StartupTimeReported(t *testing.T) {
	// This "test" documents the typical cost of spinning up the LDAP
	// testcontainer so CI maintainers can spot regressions. It is not a
	// real assertion.
	ctx := context.Background()
	c := ldapcontainer.Start(ctx, t)
	t.Logf("OpenLDAP testcontainer start + seed took %s", c.StartupTime)
}
