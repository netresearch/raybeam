package server

import (
	"os"
	"raybeam/internal/models"
	"reflect"
	"unsafe"

	"github.com/gofiber/fiber/v2"
	ldap "github.com/netresearch/simple-ldap-go"
	"go.etcd.io/bbolt"
)

// LDAPClient interface defines the LDAP operations needed by the server.
// This interface allows for mock implementations in tests.
type LDAPClient interface {
	FindUserBySAMAccountName(sAMAccountName string) (*ldap.User, error)
	FindUsersBySAMAccountNames(sAMAccountNames []string) ([]*ldap.User, error)
	CheckPasswordForSAMAccountName(sAMAccountName, password string) (*ldap.User, error)
}

// MockLDAP implements LDAPClient for testing.
type MockLDAP struct {
	users    map[string]*ldap.User
	password string // single password for all test users
}

// setObjectDN uses reflection to set the DN field in an ldap.Object (which has unexported fields).
func setObjectDN(obj interface{}, dn string) {
	// Get the reflect.Value of the object
	v := reflect.ValueOf(obj).Elem()

	// Find the embedded Object field
	objField := v.FieldByName("Object")
	if !objField.IsValid() {
		return
	}

	// Use unsafe to access unexported field
	dnField := objField.FieldByName("dn")
	if dnField.IsValid() {
		// Make the field settable using unsafe pointer
		dnFieldPtr := unsafe.Pointer(dnField.UnsafeAddr())
		*(*string)(dnFieldPtr) = dn
	}
}

// NewMockLDAP creates a mock LDAP client with predefined test users.
func NewMockLDAP() *MockLDAP {
	adminUser := &ldap.User{
		SAMAccountName: "admin",
		Groups: []string{
			"CN=Admins,OU=Groups,DC=example,DC=com",
			"CN=Users,OU=Groups,DC=example,DC=com",
		},
	}
	setObjectDN(adminUser, "CN=admin,OU=Users,DC=example,DC=com")

	regularUser := &ldap.User{
		SAMAccountName: "user1",
		Groups: []string{
			"CN=Users,OU=Groups,DC=example,DC=com",
		},
	}
	setObjectDN(regularUser, "CN=user1,OU=Users,DC=example,DC=com")

	user2 := &ldap.User{
		SAMAccountName: "user2",
		Groups: []string{
			"CN=Users,OU=Groups,DC=example,DC=com",
		},
	}
	setObjectDN(user2, "CN=user2,OU=Users,DC=example,DC=com")

	return &MockLDAP{
		users: map[string]*ldap.User{
			"admin": adminUser,
			"user1": regularUser,
			"user2": user2,
		},
		password: "testpass",
	}
}

// FindUserBySAMAccountName returns a mock user or ErrUserNotFound.
func (m *MockLDAP) FindUserBySAMAccountName(sAMAccountName string) (*ldap.User, error) {
	if user, ok := m.users[sAMAccountName]; ok {
		return user, nil
	}
	return nil, ldap.ErrUserNotFound
}

// FindUsersBySAMAccountNames returns mock users, skipping any not found.
func (m *MockLDAP) FindUsersBySAMAccountNames(sAMAccountNames []string) ([]*ldap.User, error) {
	results := make([]*ldap.User, 0, len(sAMAccountNames))
	for _, name := range sAMAccountNames {
		if user, ok := m.users[name]; ok {
			results = append(results, user)
		}
	}
	return results, nil
}

// CheckPasswordForSAMAccountName validates credentials and returns the user.
func (m *MockLDAP) CheckPasswordForSAMAccountName(sAMAccountName, password string) (*ldap.User, error) {
	user, ok := m.users[sAMAccountName]
	if !ok {
		return nil, ldap.ErrUserNotFound
	}

	if password != m.password {
		return nil, ldap.ErrSAMAccountNameDuplicated // Reuse error type for invalid credentials
	}

	return user, nil
}

// newTestServer creates a Server instance for testing with mock dependencies.
func newTestServer(ldapClient LDAPClient, adminGroupDN string) (*Server, func(), error) {
	// Create temporary database file
	tmpfile, err := os.CreateTemp("", "raybeam-test-*.db")
	if err != nil {
		return nil, nil, err
	}
	dbPath := tmpfile.Name()
	_ = tmpfile.Close()

	// Open BoltDB
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		_ = os.Remove(dbPath)
		return nil, nil, err
	}

	// Initialize SSH keys bucket
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(models.SSHKeyBucket)
		return err
	})
	if err != nil {
		_ = db.Close()
		_ = os.Remove(dbPath)
		return nil, nil, err
	}

	// Create server with mock LDAP client
	srv := &Server{
		app:              nil, // Will be initialized by init()
		db:               db,
		ldap:             ldapClient,
		ldapAdminGroupDN: adminGroupDN,
	}

	// Initialize Fiber app and routes
	srv.app = fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(500).SendString(err.Error())
		},
	})
	srv.init()

	cleanup := func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
	}

	return srv, cleanup, nil
}
