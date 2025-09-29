package server

import (
	"encoding/base64"
	"errors"
	"strings"

	ldap2 "github.com/go-ldap/ldap/v3"
	ldap "github.com/netresearch/simple-ldap-go"

	"github.com/gofiber/fiber/v2"
)

var (
	ErrAuthHeaderMissing   = errors.New("authorization header not found")
	ErrAuthHeaderMalformed = errors.New("authorization was not in the format of 'username:password'")
	ErrAuthFailed          = errors.New("authorization failed")
)

// errorResponse represents an authentication/authorization error response
type errorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

func basicAuth(auth string) (string, string, error) {
	if len(auth) < 6 || strings.ToLower(auth[:6]) != "basic " {
		return "", "", ErrAuthHeaderMissing
	}

	raw, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", ErrAuthHeaderMalformed
	}

	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", ErrAuthHeaderMalformed
	}

	return parts[0], parts[1], nil
}

func authMiddleware(authHeader string, l *ldap.LDAP) (*ldap.User, error) {
	sAMAccountName, password, err := basicAuth(authHeader)
	if err != nil {
		return nil, err
	}

	user, err := l.CheckPasswordForSAMAccountName(sAMAccountName, password)
	if err != nil {
		e, ok := err.(*ldap2.Error)
		if ok {
			if e.ResultCode == ldap2.LDAPResultInvalidCredentials {
				return nil, ErrAuthFailed
			}
		}

		if err == ldap.ErrUserNotFound {
			return nil, ErrAuthFailed
		}

		if err == ldap.ErrSAMAccountNameDuplicated {
			return nil, ErrAuthFailed
		}

		return nil, err
	}

	return user, nil
}

func (s *Server) authMiddleware(c *fiber.Ctx) error {
	unauthorized := func(reason string) error {
		c.Set(fiber.HeaderWWWAuthenticate, "Basic realm=Restricted")
		c.Status(fiber.StatusUnauthorized)

		if c.Get(fiber.HeaderAccept) == fiber.MIMEApplicationJSON {
			return c.JSON(errorResponse{
				Success: false,
				Error:   reason,
			})
		}

		return c.SendString(reason)
	}

	user, err := authMiddleware(c.Get(fiber.HeaderAuthorization), s.ldap)
	if err != nil {
		return unauthorized(err.Error())
	}

	c.Locals("user", *user)

	return c.Next()
}

func (s *Server) isAdminMiddleware(c *fiber.Ctx) error {
	unauthorized := func(reason string) error {
		c.Set(fiber.HeaderWWWAuthenticate, "Basic realm=Restricted")

		if c.Get(fiber.HeaderAccept) == fiber.MIMEApplicationJSON {
			return c.Status(fiber.StatusForbidden).JSON(errorResponse{
				Success: false,
				Error:   reason,
			})
		}

		return c.Status(fiber.StatusForbidden).SendString(reason)
	}

	user, err := authMiddleware(c.Get(fiber.HeaderAuthorization), s.ldap)
	if err != nil {
		return unauthorized(err.Error())
	}

	c.Locals("user", *user)

	if c.Params("sAMAccountNames") == user.SAMAccountName {
		return c.Next()
	}

	if user.IsMemberOf(s.ldapAdminGroupDN) {
		return c.Next()
	}

	return unauthorized("not in admin group")
}
