package server

import (
	"os"
	"raybeam/internal/models"

	"github.com/gofiber/fiber/v2"
	ldap "github.com/netresearch/simple-ldap-go"
	"go.etcd.io/bbolt"
)

// MockLDAP implements LDAPClient for testing.
type MockLDAP struct {
	users    map[string]*ldap.User
	password string // single password for all test users
}

// NewMockLDAP creates a mock LDAP client with predefined test users.
func NewMockLDAP() *MockLDAP {
	adminUser := &ldap.User{
		Object:         ldap.NewObject("admin", "CN=admin,OU=Users,DC=example,DC=com"),
		SAMAccountName: "admin",
		Groups: []string{
			"CN=Admins,OU=Groups,DC=example,DC=com",
			"CN=Users,OU=Groups,DC=example,DC=com",
		},
	}

	regularUser := &ldap.User{
		Object:         ldap.NewObject("user1", "CN=user1,OU=Users,DC=example,DC=com"),
		SAMAccountName: "user1",
		Groups: []string{
			"CN=Users,OU=Groups,DC=example,DC=com",
		},
	}

	user2 := &ldap.User{
		Object:         ldap.NewObject("user2", "CN=user2,OU=Users,DC=example,DC=com"),
		SAMAccountName: "user2",
		Groups: []string{
			"CN=Users,OU=Groups,DC=example,DC=com",
		},
	}

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
