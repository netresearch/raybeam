package models

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

// newTestDB opens a fresh BoltDB in a temp file and initializes the SSHKeyBucket.
// It returns the DB handle and a cleanup function that closes the DB and removes the file.
func newTestDB(t *testing.T) (*bbolt.DB, func()) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}

	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(SSHKeyBucket)
		return e
	}); err != nil {
		_ = db.Close()
		t.Fatalf("CreateBucketIfNotExists: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = os.Remove(path)
	}
	return db, cleanup
}

// sampleKeys returns a deterministic set of SSH keys for test fixtures.
func sampleKeys() []SSHKey {
	return []SSHKey{
		{Fingerprint: "SHA256:aaa", Key: "ssh-ed25519 AAAA key-a"},
		{Fingerprint: "SHA256:bbb", Key: "ssh-ed25519 AAAA key-b"},
		{Fingerprint: "SHA256:ccc", Key: "ssh-ed25519 AAAA key-c"},
	}
}

// writeKeys stores the given keys for dn in a write transaction.
func writeKeys(t *testing.T, db *bbolt.DB, dn string, keys []SSHKey) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return SetKeysForUser(tx, dn, keys)
	}); err != nil {
		t.Fatalf("SetKeysForUser: %v", err)
	}
}

// writeRaw writes the given raw bytes under dn, useful for simulating a corrupt JSON value.
func writeRaw(t *testing.T, db *bbolt.DB, dn string, raw []byte) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(SSHKeyBucket).Put([]byte(dn), raw)
	}); err != nil {
		t.Fatalf("Put raw: %v", err)
	}
}

func TestGetKeysForUser_EmptyReturnsEmptySlice(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	var got []SSHKey
	err := db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, "CN=missing,DC=example,DC=com")
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeysForUser error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(got))
	}
}

func TestGetKeysForUser_ReturnsStoredKeys(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	want := sampleKeys()
	writeKeys(t, db, dn, want)

	var got []SSHKey
	err := db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, dn)
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeysForUser error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("want %d keys, got %d", len(want), len(got))
	}
	for i, k := range want {
		if got[i].Fingerprint != k.Fingerprint || got[i].Key != k.Key {
			t.Errorf("key[%d] = %+v, want %+v", i, got[i], k)
		}
	}
}

func TestGetKeysForUser_CorruptJSONReturnsError(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=corrupt,DC=example,DC=com"
	writeRaw(t, db, dn, []byte("{ this is not valid json"))

	err := db.View(func(tx *bbolt.Tx) error {
		_, e := GetKeysForUser(tx, dn)
		return e
	})
	if err == nil {
		t.Fatal("expected error for corrupt JSON, got nil")
	}
}

func TestGetKeyForUser_FoundReturnsKey(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	keys := sampleKeys()
	writeKeys(t, db, dn, keys)

	var got SSHKey
	err := db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeyForUser(tx, dn, "SHA256:bbb")
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeyForUser error: %v", err)
	}
	if got.Fingerprint != "SHA256:bbb" {
		t.Errorf("got fingerprint %q, want SHA256:bbb", got.Fingerprint)
	}
	if got.Key != "ssh-ed25519 AAAA key-b" {
		t.Errorf("got key %q, want ssh-ed25519 AAAA key-b", got.Key)
	}
}

func TestGetKeyForUser_NotFoundReturnsErrSSHKeyNotFound(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())

	err := db.View(func(tx *bbolt.Tx) error {
		_, e := GetKeyForUser(tx, dn, "SHA256:does-not-exist")
		return e
	})
	if !errors.Is(err, ErrSSHKeyNotFound) {
		t.Fatalf("expected ErrSSHKeyNotFound, got %v", err)
	}
}

func TestGetKeyForUser_UnknownUserReturnsErrSSHKeyNotFound(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	err := db.View(func(tx *bbolt.Tx) error {
		_, e := GetKeyForUser(tx, "CN=ghost,DC=example,DC=com", "SHA256:aaa")
		return e
	})
	if !errors.Is(err, ErrSSHKeyNotFound) {
		t.Fatalf("expected ErrSSHKeyNotFound for unknown user, got %v", err)
	}
}

func TestGetKeyForUser_PropagatesUnderlyingError(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=broken,DC=example,DC=com"
	writeRaw(t, db, dn, []byte("not json"))

	err := db.View(func(tx *bbolt.Tx) error {
		_, e := GetKeyForUser(tx, dn, "SHA256:anything")
		return e
	})
	if err == nil {
		t.Fatal("expected propagated error from GetKeysForUser, got nil")
	}
	if errors.Is(err, ErrSSHKeyNotFound) {
		t.Fatalf("expected JSON error, got ErrSSHKeyNotFound")
	}
}

func TestKeyExistsForUser_TrueWhenPresent(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())

	var exists bool
	err := db.View(func(tx *bbolt.Tx) error {
		e, errE := KeyExistsForUser(tx, dn, "SHA256:aaa")
		exists = e
		return errE
	})
	if err != nil {
		t.Fatalf("KeyExistsForUser error: %v", err)
	}
	if !exists {
		t.Fatal("expected exists=true for known fingerprint")
	}
}

func TestKeyExistsForUser_FalseWhenAbsent(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())

	var exists bool
	err := db.View(func(tx *bbolt.Tx) error {
		e, errE := KeyExistsForUser(tx, dn, "SHA256:unknown")
		exists = e
		return errE
	})
	if err != nil {
		t.Fatalf("KeyExistsForUser error: %v", err)
	}
	if exists {
		t.Fatal("expected exists=false for unknown fingerprint")
	}
}

func TestKeyExistsForUser_FalseAndErrorOnCorruptData(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=broken,DC=example,DC=com"
	writeRaw(t, db, dn, []byte("not json"))

	var exists bool
	err := db.View(func(tx *bbolt.Tx) error {
		e, errE := KeyExistsForUser(tx, dn, "SHA256:aaa")
		exists = e
		return errE
	})
	if err == nil {
		t.Fatal("expected error from corrupt data, got nil")
	}
	if errors.Is(err, ErrSSHKeyNotFound) {
		t.Fatal("expected a non-NotFound error, got ErrSSHKeyNotFound")
	}
	if exists {
		t.Fatal("expected exists=false when underlying read fails")
	}
}

func TestSetKeysForUser_OverwritesExistingEntries(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())

	replacement := []SSHKey{{Fingerprint: "SHA256:zzz", Key: "ssh-ed25519 AAAA key-z"}}
	writeKeys(t, db, dn, replacement)

	var got []SSHKey
	err := db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, dn)
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeysForUser error: %v", err)
	}
	if len(got) != 1 || got[0].Fingerprint != "SHA256:zzz" {
		t.Fatalf("expected only replacement key, got %+v", got)
	}
}

func TestSetKeysForUser_EmptySliceClearsKeys(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())
	writeKeys(t, db, dn, []SSHKey{})

	var got []SSHKey
	err := db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, dn)
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeysForUser error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 keys after SetKeysForUser([]), got %d", len(got))
	}
}

func TestDeleteKeyFromUser_RemovesOnlyMatchingFingerprint(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())

	if err := db.Update(func(tx *bbolt.Tx) error {
		return DeleteKeyFromUser(tx, dn, "SHA256:bbb")
	}); err != nil {
		t.Fatalf("DeleteKeyFromUser error: %v", err)
	}

	var got []SSHKey
	err := db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, dn)
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeysForUser error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 remaining keys, got %d", len(got))
	}
	for _, k := range got {
		if k.Fingerprint == "SHA256:bbb" {
			t.Fatalf("deleted fingerprint still present: %+v", k)
		}
	}
}

func TestDeleteKeyFromUser_IdempotentWhenFingerprintMissing(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())

	if err := db.Update(func(tx *bbolt.Tx) error {
		return DeleteKeyFromUser(tx, dn, "SHA256:does-not-exist")
	}); err != nil {
		t.Fatalf("DeleteKeyFromUser returned error on missing fp: %v", err)
	}

	var got []SSHKey
	_ = db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, dn)
		got = k
		return e
	})
	if len(got) != len(sampleKeys()) {
		t.Fatalf("expected all keys intact (%d), got %d", len(sampleKeys()), len(got))
	}
}

func TestDeleteKeyFromUser_PropagatesReadError(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=broken,DC=example,DC=com"
	writeRaw(t, db, dn, []byte("not json"))

	err := db.Update(func(tx *bbolt.Tx) error {
		return DeleteKeyFromUser(tx, dn, "SHA256:aaa")
	})
	if err == nil {
		t.Fatal("expected error from corrupt data, got nil")
	}
}

func TestDeleteKeysForUser_RemovesAllForDN(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	dn := "CN=user1,DC=example,DC=com"
	writeKeys(t, db, dn, sampleKeys())

	if err := db.Update(func(tx *bbolt.Tx) error {
		return DeleteKeysForUser(tx, dn)
	}); err != nil {
		t.Fatalf("DeleteKeysForUser error: %v", err)
	}

	// The bucket entry itself should be gone.
	var raw []byte
	_ = db.View(func(tx *bbolt.Tx) error {
		raw = tx.Bucket(SSHKeyBucket).Get([]byte(dn))
		return nil
	})
	if raw != nil {
		t.Fatalf("expected nil raw value after delete, got %q", string(raw))
	}

	// And GetKeysForUser should return an empty slice.
	var got []SSHKey
	err := db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, dn)
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeysForUser error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 keys after DeleteKeysForUser, got %d", len(got))
	}
}

func TestDeleteKeysForUser_IdempotentOnUnknownDN(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	// Seed a different DN so the bucket is non-empty overall.
	writeKeys(t, db, "CN=other,DC=example,DC=com", sampleKeys())

	if err := db.Update(func(tx *bbolt.Tx) error {
		return DeleteKeysForUser(tx, "CN=ghost,DC=example,DC=com")
	}); err != nil {
		t.Fatalf("DeleteKeysForUser on unknown dn returned error: %v", err)
	}

	// Other user's keys untouched.
	var got []SSHKey
	_ = db.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, "CN=other,DC=example,DC=com")
		got = k
		return e
	})
	if len(got) != len(sampleKeys()) {
		t.Fatalf("expected other user's keys intact, got %d", len(got))
	}
}

// TestKeysRoundTripAcrossDBReopens verifies that keys survive a close/reopen cycle.
func TestKeysRoundTripAcrossDBReopens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roundtrip.db")

	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(SSHKeyBucket)
		return e
	}); err != nil {
		_ = db.Close()
		t.Fatalf("CreateBucketIfNotExists: %v", err)
	}

	dn := "CN=persist,DC=example,DC=com"
	want := sampleKeys()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return SetKeysForUser(tx, dn, want)
	}); err != nil {
		_ = db.Close()
		t.Fatalf("SetKeysForUser: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	db2, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("bbolt.Open (reopen): %v", err)
	}
	defer func() {
		_ = db2.Close()
		_ = os.Remove(path)
	}()

	var got []SSHKey
	err = db2.View(func(tx *bbolt.Tx) error {
		k, e := GetKeysForUser(tx, dn)
		got = k
		return e
	})
	if err != nil {
		t.Fatalf("GetKeysForUser after reopen: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("want %d keys after reopen, got %d", len(want), len(got))
	}
	for i, k := range want {
		if got[i] != k {
			t.Errorf("key[%d] = %+v, want %+v", i, got[i], k)
		}
	}
}
