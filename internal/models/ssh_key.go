// Package models provides data models and database operations for Raybeam.
package models

import (
	"encoding/json"
	"errors"
	"slices"

	"go.etcd.io/bbolt"
)

var (
	// SSHKeyBucket is the BoltDB bucket name for storing SSH keys.
	// Keys are stored with LDAP DN as the key and JSON-encoded []SSHKey as the value.
	SSHKeyBucket = []byte("ssh_keys")

	// ErrSSHKeyNotFound is returned when a requested SSH key fingerprint is not found.
	ErrSSHKeyNotFound = errors.New("SSH key not found")
)

// SSHKey represents an SSH public key with its fingerprint.
// Keys are stored without comments and fingerprints use SHA256 format.
type SSHKey struct {
	Fingerprint string `json:"fingerprint"` // SHA256 fingerprint (e.g., SHA256:base64...)
	Key         string `json:"key"`         // SSH public key in authorized_keys format
}

// GetKeysForUser retrieves all SSH keys associated with a user's LDAP DN.
// Returns an empty slice if no keys are found (not an error).
// Returns an error only if database read or JSON unmarshaling fails.
func GetKeysForUser(tx *bbolt.Tx, dn string) ([]SSHKey, error) {
	b := tx.Bucket(SSHKeyBucket)
	keysForUser := b.Get([]byte(dn))
	if keysForUser == nil {
		return []SSHKey{}, nil
	}

	var keys []SSHKey
	if err := json.Unmarshal(keysForUser, &keys); err != nil {
		return nil, err
	}

	return keys, nil
}

// GetKeyForUser retrieves a specific SSH key by fingerprint for a user's LDAP DN.
// Returns ErrSSHKeyNotFound if the fingerprint doesn't exist for this user.
// Returns other errors if database read or JSON unmarshaling fails.
func GetKeyForUser(tx *bbolt.Tx, dn, fingerprint string) (SSHKey, error) {
	keys, err := GetKeysForUser(tx, dn)
	if err != nil {
		return SSHKey{}, err
	}

	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			return key, nil
		}
	}

	return SSHKey{}, ErrSSHKeyNotFound
}

// KeyExistsForUser checks if a specific SSH key fingerprint exists for a user.
// Returns (true, nil) if the key exists, (false, nil) if not found.
// Returns (false, error) only if database read or JSON unmarshaling fails.
func KeyExistsForUser(tx *bbolt.Tx, dn, fingerprint string) (bool, error) {
	_, err := GetKeyForUser(tx, dn, fingerprint)
	if err != nil {
		if errors.Is(err, ErrSSHKeyNotFound) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// SetKeysForUser replaces all SSH keys for a user's LDAP DN.
// The keys slice completely replaces any existing keys (use carefully).
// An empty slice will effectively delete all keys for the user.
func SetKeysForUser(tx *bbolt.Tx, dn string, keys []SSHKey) error {
	rawKeys, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	b := tx.Bucket(SSHKeyBucket)
	return b.Put([]byte(dn), rawKeys)
}

// DeleteKeyFromUser removes a specific SSH key by fingerprint from a user's keys.
// If the fingerprint doesn't exist, the operation succeeds silently (idempotent).
// All other keys remain unchanged.
func DeleteKeyFromUser(tx *bbolt.Tx, dn, fingerprint string) error {
	keys, err := GetKeysForUser(tx, dn)
	if err != nil {
		return err
	}

	// Use slices.DeleteFunc for efficient filtering (Go 1.21+)
	newKeys := slices.DeleteFunc(keys, func(k SSHKey) bool {
		return k.Fingerprint == fingerprint
	})

	return SetKeysForUser(tx, dn, newKeys)
}

// DeleteKeysForUser removes all SSH keys for a user's LDAP DN.
// If no keys exist for the DN, the operation succeeds silently (idempotent).
func DeleteKeysForUser(tx *bbolt.Tx, dn string) error {
	b := tx.Bucket(SSHKeyBucket)
	return b.Delete([]byte(dn))
}
