// Package server implements the HTTP API server for Raybeam.
// It provides REST endpoints for SSH key management with LDAP authentication.
package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	ldap "github.com/netresearch/simple-ldap-go"
	"go.etcd.io/bbolt"
)

// Server represents the Raybeam HTTP server with its dependencies.
// It manages the Fiber application, BoltDB connection, and LDAP client.
type Server struct {
	app *fiber.App
	db  *bbolt.DB

	ldap             *ldap.LDAP
	ldapAdminGroupDN string
}

// New creates a new Raybeam server instance with the provided configuration.
// It initializes the LDAP connection, Fiber app, and sets up all routes.
// Returns an error if LDAP connection fails.
func New(db *bbolt.DB, ldapConfig ldap.Config, ldapReadUser, ldapReadPassword, ldapAdminGroupDN string) (*Server, error) {
	l, err := ldap.New(ldapConfig, ldapReadUser, ldapReadPassword)
	if err != nil {
		return nil, err
	}

	srv := &Server{
		fiber.New(),
		db,

		l,
		ldapAdminGroupDN,
	}

	srv.init()

	return srv, nil
}

func (s *Server) init() {
	s.app.Use(logger.New())

	s.app.Get("/info", s.handleHTTPGetInfo)

	s.app.Get("/users/@me/ssh-keys", s.authMiddleware, s.handleHTTPGetUsersMeSSHKeys)
	s.app.Put("/users/@me/ssh-keys", s.authMiddleware, s.handleHTTPPutUsersMeSSHKey)
	s.app.Delete("/users/@me/ssh-keys", s.authMiddleware, s.handleHTTPDeleteUsersMeSSHKeys)

	s.app.Get("/users/@me/ssh-keys/:fingerprint", s.authMiddleware, s.handleHTTPGetUsersMeSSHKey)
	s.app.Delete("/users/@me/ssh-keys/:fingerprint", s.authMiddleware, s.handleHTTPDeleteUsersMeSSHKey)

	s.app.Get("/users/:sAMAccountNames/ssh-keys", s.handleHTTPGetUsersSSHKeys)
	s.app.Put("/users/:sAMAccountNames/ssh-keys", s.isAdminMiddleware, s.handleHTTPPutUsersSSHKey)
	s.app.Delete("/users/:sAMAccountNames/ssh-keys", s.isAdminMiddleware, s.handleHTTPDeleteUsersSSHKeys)

	s.app.Get("/users/:sAMAccountNames/ssh-keys/:fingerprint", s.handleHTTPGetUserSSHKey)
	s.app.Delete("/users/:sAMAccountNames/ssh-keys/:fingerprint", s.authMiddleware, s.handleHTTPDeleteUsersSSHKey)
}

// Listen starts the HTTP server on the specified address.
// The address should be in the format ":port" or "host:port".
// This is a blocking call that runs until the server is shut down.
func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}
