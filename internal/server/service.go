package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	ldap "github.com/netresearch/simple-ldap-go"
	"go.etcd.io/bbolt"
)

type Server struct {
	app *fiber.App
	db  *bbolt.DB

	ldap             *ldap.LDAP
	ldapAdminGroupDN string
}

func New(db *bbolt.DB, ldapServer, ldapBaseDN, ldapReadUser, ldapReadPassword, ldapAdminGroupDN string, isAD bool) (*Server, error) {
	l, err := ldap.New(ldapServer, ldapBaseDN, ldapReadUser, ldapReadPassword, isAD)
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

func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}
