package main

import (
	"raybeam/cmd"
	buildpkg "raybeam/internal/build"
)

// Build-injected version metadata. Populated by release.yml's ldflags:
//
//	-X main.version=<release-tag>
//	-X main.build=<commit-sha>
//
// Forwarded into internal/build at init() so `raybeam --version`
// reports release info. Empty on `go run` / untagged builds, in which
// case internal/build falls back to ReadBuildInfo's vcs.revision.
var (
	version = ""
	build   = ""
)

// forwardBuildMetadata copies the build-injected package-main vars
// into the internal/build package. Extracted from init() for direct
// unit-testability. Empty inputs are treated as "not injected" and
// leave the existing buildpkg defaults in place.
func forwardBuildMetadata(v, b string) {
	if v != "" {
		buildpkg.Version = v
	}
	if b != "" {
		buildpkg.CommitHash = b
	}
}

func init() {
	forwardBuildMetadata(version, build)
}

func main() {
	cmd.Execute()
}
