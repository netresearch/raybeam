package server

import (
	"errors"
	"fmt"
	"raybeam/internal/models"
	"strings"

	"github.com/gofiber/fiber/v2"
	ldap "github.com/netresearch/simple-ldap-go"
	"go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

var (
	errCouldNotParseSSHKey   = errors.New("could not parse SSH key")
	errSSHKeyAlreadyUploaded = errors.New("SSH key already uploaded")
)

// JSON response types for typed API responses
type (
	successResponse struct {
		Success bool `json:"success"`
	}

	keysResponse struct {
		Success bool                     `json:"success"`
		Keys    map[string]models.SSHKey `json:"keys"`
	}

	multiUserKeysResponse struct {
		Success bool                                `json:"success"`
		Keys    map[string]map[string]models.SSHKey `json:"keys"`
	}

	keyResponse struct {
		Success bool           `json:"success"`
		Key     *models.SSHKey `json:"key"`
	}
)

func (s *Server) getSSHKeyForDN(dn, fingerprint string) (*models.SSHKey, error) {
	var key models.SSHKey

	if err := s.db.View(func(tx *bbolt.Tx) error {
		k, err := models.GetKeyForUser(tx, dn, fingerprint)
		if err != nil {
			return err
		}

		key = k

		return nil
	}); err != nil {
		return nil, err
	}

	return &key, nil
}

func (s *Server) getSSHKeysForDN(dn string) (map[string]models.SSHKey, error) {
	keys := make(map[string]models.SSHKey)

	if err := s.db.View(func(tx *bbolt.Tx) error {
		keysForDN, err := models.GetKeysForUser(tx, dn)
		if err != nil {
			return err
		}

		for _, key := range keysForDN {
			keys[key.Fingerprint] = key
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return keys, nil
}

func (s *Server) deleteSSHKeysForDN(dn string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return models.DeleteKeysForUser(tx, dn)
	})
}

func (s *Server) deleteSSHKeyForDN(dn, fingerprint string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return models.DeleteKeyFromUser(tx, dn, fingerprint)
	})
}

func (s *Server) uploadSSHKeyForDN(dn string, rawKey []byte) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey(rawKey)
	if err != nil {
		return errCouldNotParseSSHKey
	}

	// Remove the comment from the key
	rawKey = ssh.MarshalAuthorizedKey(key)

	keyEntry := models.SSHKey{
		Fingerprint: ssh.FingerprintSHA256(key),
		Key:         string(rawKey),
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		keyExists, err := models.KeyExistsForUser(tx, dn, keyEntry.Fingerprint)
		if err != nil {
			return err
		}

		if keyExists {
			return errSSHKeyAlreadyUploaded
		}

		keys, err := models.GetKeysForUser(tx, dn)
		if err != nil {
			return err
		}

		return models.SetKeysForUser(tx, dn, append(keys, keyEntry))
	})
}

func (s *Server) handleHTTPGetUsersMeSSHKeys(c *fiber.Ctx) error {
	user := c.Locals("user").(ldap.User)

	keys, err := s.getSSHKeysForDN(user.DN())
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "internal server error")
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(keysResponse{
			Success: true,
			Keys:    keys,
		})
	}

	rawKeys := []string{fmt.Sprintf("# Keys uploaded by \"%s\"\n", user.DN())}
	for _, key := range keys {
		rawKeys = append(rawKeys, key.Key)
	}

	return c.SendString(strings.Join(rawKeys, ""))
}

func (s *Server) handleHTTPPutUsersMeSSHKey(c *fiber.Ctx) error {
	user := c.Locals("user").(ldap.User)

	if err := s.uploadSSHKeyForDN(user.DN(), c.Body()); err != nil {
		return sendError(c, fiber.StatusInternalServerError, err.Error())
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusCreated).JSON(successResponse{
			Success: true,
		})
	}

	return c.SendStatus(fiber.StatusCreated)
}

func (s *Server) handleHTTPDeleteUsersMeSSHKeys(c *fiber.Ctx) error {
	user := c.Locals("user").(ldap.User)

	if err := s.deleteSSHKeysForDN(user.DN()); err != nil {
		return sendError(c, fiber.StatusInternalServerError, "internal server error")
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(successResponse{
			Success: true,
		})
	}

	return c.SendStatus(fiber.StatusOK)
}

func (s *Server) handleHTTPGetUsersMeSSHKey(c *fiber.Ctx) error {
	user := c.Locals("user").(ldap.User)
	fingerprint := c.Params("fingerprint")

	key, err := s.getSSHKeyForDN(user.DN(), fingerprint)
	if err != nil {
		if errors.Is(err, models.ErrSSHKeyNotFound) {
			return sendError(c, fiber.StatusNotFound, "ssh key not found")
		}

		return sendError(c, fiber.StatusInternalServerError, "internal server error")
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(keyResponse{
			Success: true,
			Key:     key,
		})
	}

	return c.SendString(key.Key)
}

func (s *Server) handleHTTPDeleteUsersSSHKeys(c *fiber.Ctx) error {
	sAMAccountNames := strings.Split(c.Params("sAMAccountNames"), ",")

	for _, sAMAccountName := range sAMAccountNames {
		user, err := s.ldap.FindUserBySAMAccountName(sAMAccountName)
		if err != nil {
			return sendError(c, fiber.StatusNotFound, fmt.Sprintf("user \"%s\" not found", sAMAccountName))
		}

		if err := s.deleteSSHKeysForDN(user.DN()); err != nil {
			return sendError(c, fiber.StatusInternalServerError, "internal server error")
		}
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(successResponse{
			Success: true,
		})
	}

	return c.SendStatus(fiber.StatusOK)
}

func (s *Server) handleHTTPGetUsersSSHKeys(c *fiber.Ctx) error {
	sAMAccountNames := strings.Split(c.Params("sAMAccountNames"), ",")
	keys := make(map[string]map[string]models.SSHKey)

	for _, sAMAccountName := range sAMAccountNames {
		user, err := s.ldap.FindUserBySAMAccountName(sAMAccountName)
		if err != nil {
			return sendError(c, fiber.StatusNotFound, fmt.Sprintf("user \"%s\" not found", sAMAccountName))
		}

		userKeys, err := s.getSSHKeysForDN(user.DN())
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, "internal server error")
		}

		keys[user.DN()] = userKeys
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(multiUserKeysResponse{
			Success: true,
			Keys:    keys,
		})
	}

	rawKeys := make([]string, 0)
	for dn, userKeys := range keys {
		rawKeys = append(rawKeys, fmt.Sprintf("# Keys uploaded by \"%s\"\n", dn))
		for _, key := range userKeys {
			rawKeys = append(rawKeys, key.Key)
		}
	}

	return c.SendString(strings.Join(rawKeys, ""))
}

func (s *Server) handleHTTPPutUsersSSHKey(c *fiber.Ctx) error {
	sAMAccountNames := strings.Split(c.Params("sAMAccountNames"), ",")

	for _, sAMAccountName := range sAMAccountNames {
		user, err := s.ldap.FindUserBySAMAccountName(sAMAccountName)
		if err != nil {
			return sendError(c, fiber.StatusNotFound, fmt.Sprintf("user \"%s\" not found", sAMAccountName))
		}

		if err := s.uploadSSHKeyForDN(user.DN(), c.Body()); err != nil {
			return sendError(c, fiber.StatusInternalServerError, err.Error())
		}
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusCreated).JSON(successResponse{
			Success: true,
		})
	}

	return c.SendStatus(fiber.StatusCreated)
}

func (s *Server) handleHTTPDeleteUsersMeSSHKey(c *fiber.Ctx) error {
	user := c.Locals("user").(ldap.User)
	fingerprint := c.Params("fingerprint")

	if err := s.deleteSSHKeyForDN(user.DN(), fingerprint); err != nil {
		return sendError(c, fiber.StatusInternalServerError, "internal server error")
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(successResponse{
			Success: true,
		})
	}

	return c.SendStatus(fiber.StatusOK)
}

func (s *Server) handleHTTPGetUserSSHKey(c *fiber.Ctx) error {
	sAMAccountNames := strings.Split(c.Params("sAMAccountNames"), ",")
	fingerprint := c.Params("fingerprint")
	keys := make(map[string]models.SSHKey)

	for _, sAMAccountName := range sAMAccountNames {
		user, err := s.ldap.FindUserBySAMAccountName(sAMAccountName)
		if err != nil {
			return sendError(c, fiber.StatusNotFound, fmt.Sprintf("user \"%s\" not found", sAMAccountName))
		}

		key, err := s.getSSHKeyForDN(user.DN(), fingerprint)
		if err != nil {
			if errors.Is(err, models.ErrSSHKeyNotFound) {
				return sendError(c, fiber.StatusNotFound, "ssh key not found")
			}

			return sendError(c, fiber.StatusInternalServerError, "internal server error")
		}

		keys[user.DN()] = *key
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(keysResponse{
			Success: true,
			Keys:    keys,
		})
	}

	rawKeys := make([]string, 0)
	for dn, key := range keys {
		rawKeys = append(rawKeys, fmt.Sprintf("# Keys uploaded by \"%s\"\n", dn))
		rawKeys = append(rawKeys, key.Key)
	}

	return c.SendString(strings.Join(rawKeys, ""))
}

func (s *Server) handleHTTPDeleteUsersSSHKey(c *fiber.Ctx) error {
	sAMAccountNames := strings.Split(c.Params("sAMAccountNames"), ",")
	fingerprint := c.Params("fingerprint")

	for _, sAMAccountName := range sAMAccountNames {
		user, err := s.ldap.FindUserBySAMAccountName(sAMAccountName)
		if err != nil {
			return sendError(c, fiber.StatusNotFound, fmt.Sprintf("user \"%s\" not found", sAMAccountName))
		}

		if err := s.deleteSSHKeyForDN(user.DN(), fingerprint); err != nil {
			return sendError(c, fiber.StatusInternalServerError, "internal server error")
		}
	}

	if acceptsJson(c) {
		return c.Status(fiber.StatusOK).JSON(successResponse{
			Success: true,
		})
	}

	return c.SendStatus(fiber.StatusOK)
}
