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
	rootCmd.Version = formatVersion(build.Version, build.CommitHash)
	if err := rootCmd.Execute(); err != nil {
		// Ignore errors that occur by printing to stderr, because where are we going to print them
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// formatVersion assembles cobra's Version string from build.Version
// (release tag) and build.CommitHash (git SHA). Layout:
//
//	<version>                  - commit unset (local go run) OR
//	                             commit == version (VCS fallback,
//	                             no ldflag tag — dedup)
//	<version> (<commit-short>) - commit set and distinct from version
//	                             (tagged release)
//
// Extracted for unit-testability.
func formatVersion(version, commit string) string {
	if commit == "" || commit == version {
		return version
	}

	short := commit
	if len(short) > 7 {
		short = short[:7]
	}

	return version + " (" + short + ")"
}
