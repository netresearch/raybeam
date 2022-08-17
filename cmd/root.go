package cmd

import (
	"fmt"
	"os"
	"raybeam/internal/build"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "raybeam",
	Short:   "A simple public key store, currently supporting only SSH keys",
	Version: build.Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Ignore errors that occur by printing to stderr, because where are we going to print them
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
