package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	ldap "github.com/netresearch/simple-ldap-go"
)

func TestBasicAuthWithNonBasicAuthHeader(t *testing.T) {
	_, _, err := basicAuth("Bearer a")
	if err != ErrAuthHeaderMissing {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMissing, err)
	}
}

func TestBasicAuthWithMalformedHeader(t *testing.T) {
	_, _, err := basicAuth("Basic %%%%")
	if err != ErrAuthHeaderMalformed {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMalformed, err)
	}
}

func TestBasicAuthWithMalformedHeader2(t *testing.T) {
	_, _, err := basicAuth("Basic aaaa")
	if err != ErrAuthHeaderMalformed {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMalformed, err)
	}
}

func TestBasicAuthWithExclamationMark(t *testing.T) {
	wantCN := "readuser!"
	wantPassword := "readuser!"

	gotCN, gotPassword, err := basicAuth(fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", wantCN, wantPassword)))))
	if err != nil {
		t.Errorf("expected no error, got %q", err)
		return
	}

	if gotCN != wantCN {
		t.Errorf("expected CN %q, got %q", wantCN, gotCN)
	}

	if gotPassword != wantPassword {
		t.Errorf("expected password %q, got %q", wantPassword, gotPassword)
	}
}

func TestBasicAuth(t *testing.T) {
	wantCN := "readuser"
	wantPassword := "readuser"

	gotCN, gotPassword, err := basicAuth(fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", wantCN, wantPassword)))))
	if err != nil {
		t.Errorf("expected no error, got %q", err)
		return
	}

	if gotCN != wantCN {
		t.Errorf("expected CN %q, got %q", wantCN, gotCN)
	}

	if gotPassword != wantPassword {
		t.Errorf("expected password %q, got %q", wantPassword, gotPassword)
	}
}

func TestAuthMiddlewareInvalidCredentials(t *testing.T) {
	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	u := url.UserPassword("demoooopleasefail", "pleasefailll")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	if _, err := authMiddleware(fmt.Sprintf("Basic %s", auth), l); err != ErrAuthFailed {
		t.Errorf("expected error %q, got %q", ErrAuthFailed, err)
	}
}

func TestAuthMiddleware(t *testing.T) {
	wantSAMAccountName := "readuser"
	wantCN := "Readuser Readuser"
	wantDN := fmt.Sprintf("cn=%s,ou=systeme,ou=benutzer,ou=netresearch,dc=netresearch,dc=nr", wantCN)

	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	u := url.UserPassword(wantSAMAccountName, "readuser")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	user, err := authMiddleware(fmt.Sprintf("Basic %s", auth), l)
	if err != nil {
		t.Error(err)
		return
	}

	if strings.ToLower(user.CN) != strings.ToLower(wantCN) {
		t.Errorf("got CN \"%s\", want CN \"%s\"", strings.ToLower(user.CN), strings.ToLower(wantCN))
	}

	if strings.ToLower(user.DN) != strings.ToLower(wantDN) {
		t.Errorf("got DN \"%s\", want DN \"%s\"", strings.ToLower(user.DN), strings.ToLower(wantDN))
	}

	if strings.ToLower(user.SAMAccountName) != strings.ToLower(wantSAMAccountName) {
		t.Errorf("got SAMAccountName \"%s\", want SAMAccountName \"%s\"", strings.ToLower(user.SAMAccountName), strings.ToLower(wantCN))
	}
}

func TestAuthMiddlewareWithInvalidAuthorizationHeader(t *testing.T) {
	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	if _, err = authMiddleware("Basic %%%%", l); err != ErrAuthHeaderMalformed {
		t.Errorf("expected error %q, got %q", ErrAuthHeaderMalformed, err)
	}
}

func TestAuthMiddlewareWithInvalidCredentials(t *testing.T) {
	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	u := url.UserPassword("demoooopleasefail", "pleasefailll")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	if _, err = authMiddleware(fmt.Sprintf("Basic %s", auth), l); err != ErrAuthFailed {
		t.Errorf("expected error %q, got %q", ErrAuthFailed, err)
	}
}

func TestAuthMiddlewareWithInvalidCredentials2(t *testing.T) {
	l, err := getWorkingLdap()
	if err != nil {
		t.Error(err)
		return
	}

	u := url.UserPassword("readuser", "pleasefailll")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	if _, err := authMiddleware(fmt.Sprintf("Basic %s", auth), l); err != ErrAuthFailed {
		t.Errorf("expected error %q, got %q", ErrAuthFailed, err)
	}
}

func TestAuthMiddlewareWithUnreachableServer(t *testing.T) {
	l := ldap.New("ldap://please-fail", "", "", "")

	u := url.UserPassword("readuser", "readuser")
	auth := base64.StdEncoding.EncodeToString([]byte(u.String()))

	_, err := authMiddleware(fmt.Sprintf("Basic %s", auth), l)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func getWorkingLdap() (ldap.LDAP, error) {
	server, found := os.LookupEnv("LDAP_SERVER")
	if !found {
		return ldap.LDAP{}, errors.New("LDAP_SERVER not set")
	}

	baseDN, found := os.LookupEnv("LDAP_BASE_DN")
	if !found {
		return ldap.LDAP{}, errors.New("LDAP_BASE_DN not set")
	}

	readUser, found := os.LookupEnv("LDAP_READ_USER")
	if !found {
		return ldap.LDAP{}, errors.New("LDAP_READ_USER not set")
	}

	readPassword, found := os.LookupEnv("LDAP_READ_PASSWORD")
	if !found {
		return ldap.LDAP{}, errors.New("LDAP_READ_PASSWORD not set")
	}

	return ldap.New(server, baseDN, readUser, readPassword), nil
}
