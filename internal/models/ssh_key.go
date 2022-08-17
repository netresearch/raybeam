package models

import (
	"encoding/json"
	"errors"

	"go.etcd.io/bbolt"
)

var (
	SSHKeyBucket      = []byte("ssh_keys")
	ErrSSHKeyNotFound = errors.New("SSH key not found")
)

type SSHKey struct {
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key"`
}

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

func SetKeysForUser(tx *bbolt.Tx, dn string, keys []SSHKey) error {
	rawKeys, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	b := tx.Bucket(SSHKeyBucket)
	return b.Put([]byte(dn), rawKeys)
}

func DeleteKeyFromUser(tx *bbolt.Tx, dn, fingerprint string) error {
	keys, err := GetKeysForUser(tx, dn)
	if err != nil {
		return err
	}

	newKeys := make([]SSHKey, 0)
	for _, k := range keys {
		if k.Fingerprint == fingerprint {
			continue
		}

		newKeys = append(newKeys, k)
	}

	return SetKeysForUser(tx, dn, newKeys)
}

func DeleteKeysForUser(tx *bbolt.Tx, dn string) error {
	b := tx.Bucket(SSHKeyBucket)
	return b.Delete([]byte(dn))
}
