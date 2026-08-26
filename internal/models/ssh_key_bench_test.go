package models

import (
	"fmt"
	"testing"

	"go.etcd.io/bbolt"
)

// BenchmarkSetKeysForUser measures the cost of serializing and writing a key set.
func BenchmarkSetKeysForUser(b *testing.B) {
	dir := b.TempDir()
	db := openBenchDB(b, dir)
	defer func() { _ = db.Close() }()
	dn := "CN=bench,DC=example,DC=com"
	keys := sampleKeys()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		_ = db.Update(func(tx *bbolt.Tx) error {
			return SetKeysForUser(tx, fmt.Sprintf("%s-%d", dn, i%10), keys)
		})
	}
}

// BenchmarkGetKeysForUser measures read path.
func BenchmarkGetKeysForUser(b *testing.B) {
	dir := b.TempDir()
	db := openBenchDB(b, dir)
	defer func() { _ = db.Close() }()
	dn := "CN=bench,DC=example,DC=com"
	_ = db.Update(func(tx *bbolt.Tx) error { return SetKeysForUser(tx, dn, sampleKeys()) })
	b.ResetTimer()
	for b.Loop() {
		_ = db.View(func(tx *bbolt.Tx) error {
			_, _ = GetKeysForUser(tx, dn)
			return nil
		})
	}
}

// BenchmarkGetKeyForUser measures single-key lookup.
func BenchmarkGetKeyForUser(b *testing.B) {
	dir := b.TempDir()
	db := openBenchDB(b, dir)
	defer func() { _ = db.Close() }()
	dn := "CN=bench,DC=example,DC=com"
	_ = db.Update(func(tx *bbolt.Tx) error { return SetKeysForUser(tx, dn, sampleKeys()) })
	b.ResetTimer()
	for b.Loop() {
		_ = db.View(func(tx *bbolt.Tx) error {
			_, _ = GetKeyForUser(tx, dn, "SHA256:bbb")
			return nil
		})
	}
}

func openBenchDB(b *testing.B, dir string) *bbolt.DB {
	b.Helper()
	path := dir + "/bench.db"
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		b.Fatalf("bbolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(SSHKeyBucket)
		return e
	}); err != nil {
		_ = db.Close()
		b.Fatalf("CreateBucketIfNotExists: %v", err)
	}
	return db
}
