package cmd

import (
	"fmt"
	"os"
	"raybeam/internal/build"

	"github.com/spf13/cobra"
)

// rootCmd's Version is assigned at Execute() time rather than at the
// var declaration so that package main's init() has a chance to forward
// the release ldflag into build.Version first. Go initializes imported
// packages before the importer, so cmd.init() runs before main.init();
// capturing build.Version here would freeze it at the pre-ldflag value.
var rootCmd = &cobra.Command{
	Use:   "raybeam",
	Short: "A simple public key store, currently supporting only SSH keys",
}

func Execute() {
	rootCmd.Version = build.Version
	if err := rootCmd.Execute(); err != nil {
		// Ignore errors that occur by printing to stderr, because where are we going to print them
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
