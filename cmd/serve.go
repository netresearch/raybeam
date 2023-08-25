package cmd

import (
	"log"
	"raybeam/internal/models"
	"raybeam/internal/server"

	"github.com/spf13/cobra"
	"go.etcd.io/bbolt"
)

var httpAddress, ldapServer, ldapBaseDN, dbLocation, readUser, readPassword, ldapAdminGroupDB string
var ldapIsAd bool

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the Raybeam server",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := bbolt.Open(dbLocation, 0600, nil)
		if err != nil {
			return err
		}

		defer func(db *bbolt.DB) {
			// Don't handle error since we're exiting anyway
			_ = db.Close()
		}(db)

		if err := db.Update(func(tx *bbolt.Tx) error {
			if _, err := tx.CreateBucketIfNotExists(models.SSHKeyBucket); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return err
		}

		srv, err := server.New(db, ldapServer, ldapBaseDN, readUser, readPassword, ldapAdminGroupDB, ldapIsAd)
		if err != nil {
			return err
		}

		return srv.Listen(httpAddress)
	},
}

func init() {
	serveCmd.Flags().StringVarP(&httpAddress, "http-address", "l", ":8080", "HTTP address to listen on")

	serveCmd.Flags().StringVarP(&ldapServer, "ldap-server", "s", "ldap://localhost:389", "LDAP server to connect to")
	serveCmd.Flags().StringVarP(&ldapBaseDN, "ldap-base-dn", "b", "dc=example,dc=com", "LDAP base DN to search from")

	serveCmd.Flags().StringVarP(&dbLocation, "database", "d", "./db.bolt", "Location of the BoltDB database")

	serveCmd.Flags().StringVarP(&readUser, "ldap-read-user", "u", "", "LDAP user to use for read-only operations")
	serveCmd.Flags().StringVarP(&readPassword, "ldap-read-password", "p", "", "LDAP password to use for read-only operations")

	serveCmd.Flags().StringVarP(&ldapAdminGroupDB, "ldap-admin-group-dn", "g", "", "LDAP group DN to use for identifying administrators")

	serveCmd.Flags().BoolVar(&ldapIsAd, "ldap-is-ad", false, "Whether the LDAP server is Active Directory")

	if err := serveCmd.MarkFlagRequired("ldap-read-user"); err != nil {
		log.Fatalln(err)
	}

	if err := serveCmd.MarkFlagRequired("ldap-read-password"); err != nil {
		log.Fatalln(err)
	}

	if err := serveCmd.MarkFlagRequired("ldap-admin-group-dn"); err != nil {
		log.Fatalln(err)
	}

	rootCmd.AddCommand(serveCmd)
}
