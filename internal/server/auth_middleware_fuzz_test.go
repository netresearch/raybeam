package server

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// FuzzBasicAuth feeds arbitrary Authorization header values to basicAuth,
// which parses them before any LDAP call is made. It must never panic,
// must fail only with its two documented errors, and every accepted
// header must decode to credentials that survive a re-encode round trip.
func FuzzBasicAuth(f *testing.F) {
	seeds := []string{
		"",
		"Basic",
		"Basic ",
		"basic Zm9vOmJhcg==",
		"BASIC Zm9vOmJhcg==",
		"Basic Og==",
		"Basic Zm9v",
		"Basic %%%%",
		"Basic aaaa",
		"Bearer abc",
		"Basic dXNlcjpwYXNzOndpdGg6Y29sb25z",
		"basİc Zm9vOmJhcg==",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, header string) {
		user, password, err := basicAuth(header)
		if err != nil {
			if !errors.Is(err, ErrAuthHeaderMissing) && !errors.Is(err, ErrAuthHeaderMalformed) {
				t.Fatalf("unexpected error %v for header %q", err, header)
			}
			if user != "" || password != "" {
				t.Fatalf("credentials %q/%q returned together with error %v", user, password, err)
			}
			return
		}

		if !strings.EqualFold(header[:6], "basic ") {
			t.Fatalf("accepted header without a Basic scheme: %q", header)
		}
		if strings.Contains(user, ":") {
			t.Fatalf("username %q contains the ':' separator", user)
		}

		reencoded := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
		gotUser, gotPassword, err := basicAuth(reencoded)
		if err != nil || gotUser != user || gotPassword != password {
			t.Fatalf("round trip of %q/%q gave %q/%q, err %v", user, password, gotUser, gotPassword, err)
		}
	})
}
