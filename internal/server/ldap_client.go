package server

import (
	ldap "github.com/netresearch/simple-ldap-go"
)

// LDAPClient interface defines the LDAP operations needed by the server.
// This interface allows for mock implementations in tests.
type LDAPClient interface {
	FindUserBySAMAccountName(sAMAccountName string) (*ldap.User, error)
	FindUsersBySAMAccountNames(sAMAccountNames []string) ([]*ldap.User, error)
	CheckPasswordForSAMAccountName(sAMAccountName, password string) (*ldap.User, error)
}
