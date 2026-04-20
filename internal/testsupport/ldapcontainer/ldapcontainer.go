//go:build integration || e2e

// Package ldapcontainer spins up an OpenLDAP container (via testcontainers-go)
// and pre-seeds it with fixtures suitable for exercising raybeam's LDAP paths.
//
// This package is only compiled under the `integration` or `e2e` build tags so
// it never pulls Docker dependencies into a normal `go test` / `go build` run.
package ldapcontainer

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	ldap "github.com/netresearch/simple-ldap-go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/openldap"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Fixtures are populated into the seeded directory and exposed so tests can
// reference the same DNs/credentials without magic strings.
type Fixtures struct {
	BaseDN       string
	UsersOU      string
	GroupsOU     string
	AdminUser    string // full admin bind DN
	AdminPass    string
	ReadUser     string // service account DN used by raybeam for read-only binds
	ReadPass     string
	AdminGroupDN string // DN of the group that grants admin rights in raybeam

	// User1 is a regular user (not in admin group).
	User1UID      string
	User1DN       string
	User1Password string

	// User2 is a second regular user (for multi-user tests).
	User2UID      string
	User2DN       string
	User2Password string

	// AdminUID is a user that IS a member of AdminGroupDN.
	AdminUID      string
	AdminUserDN   string
	AdminUserPass string
}

// Container bundles the running OpenLDAP container with its connection
// details. Terminate via t.Cleanup — callers don't have to close anything.
type Container struct {
	raw          *openldap.OpenLDAPContainer
	ConnStr      string // ldap://host:port — safe to pass to simple-ldap-go
	LDAPConfig   ldap.Config
	Fixtures     Fixtures
	StartupTime  time.Duration // how long from Run() to ready-with-fixtures
}

// Start launches the OpenLDAP container and seeds it with fixtures. The
// container is automatically terminated when the test (or its parent) ends.
func Start(ctx context.Context, t *testing.T) *Container {
	t.Helper()

	started := time.Now()

	const (
		baseDN    = "dc=example,dc=org"
		adminUser = "admin"
		adminPass = "adminpassword" // matches bitnami openldap defaults
	)

	// Use bitnamilegacy — the testcontainers-go openldap module pins to this
	// image. The base image does NOT load the memberof overlay by default;
	// we enable it post-start via cn=config (see enableMemberofOverlay).
	ctr, err := openldap.Run(
		ctx,
		"bitnamilegacy/openldap:2.6.6",
		openldap.WithAdminUsername(adminUser),
		openldap.WithAdminPassword(adminPass),
		openldap.WithRoot(baseDN),
		testcontainers.WithWaitStrategy(
			wait.ForLog("** Starting slapd **").WithStartupTimeout(90*time.Second),
			wait.ForListeningPort("1389/tcp").WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("openldap.Run: %v", err)
	}
	t.Cleanup(func() {
		// Use a short-lived context so termination doesn't block forever.
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := ctr.Terminate(termCtx); err != nil {
			t.Logf("ldapcontainer: terminate: %v", err)
		}
	})

	connStr, err := ctr.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("openldap.ConnectionString: %v", err)
	}
	// simple-ldap-go's isExampleServer() matches 'localhost' — force an IP to
	// avoid that code path.
	connStr = strings.Replace(connStr, "//localhost:", "//127.0.0.1:", 1)

	// The bitnami openldap image doesn't load the memberof overlay out of
	// the box, so User.IsMemberOf would always return false. Enable it
	// before we seed the directory so memberOf is populated as groups are
	// added.
	if err := enableMemberofOverlay(ctx, ctr); err != nil {
		t.Fatalf("enable memberof overlay: %v", err)
	}

	fx := Fixtures{
		BaseDN:       baseDN,
		UsersOU:      "ou=people," + baseDN,
		GroupsOU:     "ou=groups," + baseDN,
		AdminUser:    fmt.Sprintf("cn=%s,%s", adminUser, baseDN),
		AdminPass:    adminPass,
		AdminGroupDN: "cn=admins,ou=groups," + baseDN,

		// raybeam's read-only service account — bound via simple-ldap-go.
		// We re-use the directory admin as the 'read user' to keep fixture
		// setup minimal; in production this would be a dedicated service user.
		ReadUser: fmt.Sprintf("cn=%s,%s", adminUser, baseDN),
		ReadPass: adminPass,

		User1UID:      "alice",
		User1DN:       "uid=alice,ou=people," + baseDN,
		User1Password: "alicepass",

		User2UID:      "bob",
		User2DN:       "uid=bob,ou=people," + baseDN,
		User2Password: "bobpass",

		AdminUID:      "root",
		AdminUserDN:   "uid=root,ou=people," + baseDN,
		AdminUserPass: "rootpass",
	}

	seedFixtures(ctx, t, connStr, fx)

	cfg := ldap.Config{
		Server:            connStr,
		BaseDN:            baseDN,
		IsActiveDirectory: false,
	}

	return &Container{
		raw:         ctr,
		ConnStr:     connStr,
		LDAPConfig:  cfg,
		Fixtures:    fx,
		StartupTime: time.Since(started),
	}
}

// seedFixtures populates OUs, users, and groups via a direct LDAP bind (the
// bitnami image's ldapadd CLI is usable too, but direct binds let us surface
// errors more cleanly and avoid temp files).
func seedFixtures(ctx context.Context, t *testing.T, connStr string, fx Fixtures) {
	t.Helper()

	var conn *goldap.Conn
	var err error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = goldap.DialURL(connStr)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("ldapcontainer: dial %s: %v", connStr, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Bind(fx.AdminUser, fx.AdminPass); err != nil {
		t.Fatalf("ldapcontainer: bind as %q: %v", fx.AdminUser, err)
	}

	// Organizational Units
	addOU := func(dn, ou string) {
		req := goldap.NewAddRequest(dn, nil)
		req.Attribute("objectClass", []string{"organizationalUnit"})
		req.Attribute("ou", []string{ou})
		if err := conn.Add(req); err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("ldapcontainer: add OU %s: %v", dn, err)
		}
	}
	addOU(fx.UsersOU, "people")
	addOU(fx.GroupsOU, "groups")

	// Users
	addUser := func(uid, password string, uidNumber int) {
		dn := fmt.Sprintf("uid=%s,%s", uid, fx.UsersOU)
		req := goldap.NewAddRequest(dn, nil)
		req.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "shadowAccount"})
		req.Attribute("uid", []string{uid})
		req.Attribute("cn", []string{uid})
		req.Attribute("sn", []string{uid})
		req.Attribute("givenName", []string{uid})
		req.Attribute("mail", []string{uid + "@example.org"})
		req.Attribute("userPassword", []string{password})
		req.Attribute("uidNumber", []string{fmt.Sprintf("%d", uidNumber)})
		req.Attribute("gidNumber", []string{"1000"})
		req.Attribute("homeDirectory", []string{"/home/" + uid})
		if err := conn.Add(req); err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("ldapcontainer: add user %s: %v", dn, err)
		}
	}
	addUser(fx.User1UID, fx.User1Password, 10001)
	addUser(fx.User2UID, fx.User2Password, 10002)
	addUser(fx.AdminUID, fx.AdminUserPass, 10003)

	// Admin group — uses groupOfNames. The bitnami OpenLDAP image has the
	// memberof overlay loaded by default, so User.IsMemberOf will work.
	groupReq := goldap.NewAddRequest(fx.AdminGroupDN, nil)
	groupReq.Attribute("objectClass", []string{"groupOfNames"})
	groupReq.Attribute("cn", []string{"admins"})
	groupReq.Attribute("member", []string{fx.AdminUserDN})
	if err := conn.Add(groupReq); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("ldapcontainer: add admin group: %v", err)
	}
}

// enableMemberofOverlay loads the memberof module and attaches it as an
// overlay to the primary database. Equivalent to:
//
//	ldapadd -Q -Y EXTERNAL -H ldapi:/// <<EOF
//	dn: cn=module{0},cn=config
//	changetype: modify
//	add: olcModuleLoad
//	olcModuleLoad: memberof.so
//	-
//
//	dn: olcOverlay=memberof,olcDatabase={2}mdb,cn=config
//	objectClass: olcOverlayConfig
//	objectClass: olcMemberOf
//	olcOverlay: memberof
//	olcMemberOfDangling: ignore
//	olcMemberOfRefInt: TRUE
//	olcMemberOfGroupOC: groupOfNames
//	olcMemberOfMemberAD: member
//	olcMemberOfMemberOfAD: memberOf
//	EOF
//
// run inside the container as the system root via EXTERNAL SASL bind.
func enableMemberofOverlay(ctx context.Context, ctr *openldap.OpenLDAPContainer) error {
	// NOTE: the absolute path is required. The bitnami image ships
	// memberof.so under /opt/bitnami/openldap/lib/openldap, but the
	// `olcModulePath` configured on cn=module{0},cn=config points at
	// /opt/bitnami/openldap/libexec/openldap (which does not contain
	// memberof.so). Using an absolute path sidesteps that mismatch.
	ldif := []byte(`dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: /opt/bitnami/openldap/lib/openldap/memberof.so
-

dn: olcOverlay=memberof,olcDatabase={2}mdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfDangling: ignore
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
`)

	const ldifPath = "/tmp/memberof.ldif"
	if err := ctr.CopyToContainer(ctx, ldif, ldifPath, 0o644); err != nil {
		return fmt.Errorf("copy memberof ldif: %w", err)
	}
	code, output, err := ctr.Exec(ctx, []string{
		"ldapmodify", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", ldifPath,
	})
	if err != nil {
		return fmt.Errorf("exec ldapmodify: %w", err)
	}
	if code != 0 {
		var out []byte
		if output != nil {
			// Best-effort read for diagnostics. We intentionally ignore the
			// error; slow output copies shouldn't mask the ldapmodify exit
			// code.
			buf := make([]byte, 4096)
			n, _ := output.Read(buf)
			out = buf[:n]
		}
		return fmt.Errorf("ldapmodify exit %d: %s", code, out)
	}
	return nil
}

// NewLDAPClient returns a live simple-ldap-go client bound with the read-only
// service account. Useful when tests want to drive LDAP paths directly
// (integration tier) without the raybeam HTTP layer.
func (c *Container) NewLDAPClient(t *testing.T) *ldap.LDAP {
	t.Helper()
	client, err := ldap.New(c.LDAPConfig, c.Fixtures.ReadUser, c.Fixtures.ReadPass)
	if err != nil {
		t.Fatalf("ldapcontainer: ldap.New: %v", err)
	}
	return client
}
