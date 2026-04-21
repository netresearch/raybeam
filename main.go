package main

import (
	"raybeam/cmd"
	buildpkg "raybeam/internal/build"
)

// Build-injected version metadata:
//
//	version   <- release.yml's ldflags: -X main.version=<release-tag>
//	build     <- release.yml's ldflags: -X main.build=<commit-sha>
//	buildTime <- build-go-attest.yml's auto-build-timestamp step:
//	             -X main.buildTime=<ISO-8601 commit timestamp>
//
// Forwarded into internal/build at init() so `raybeam --version`
// reports release info. Empty on `go run` / untagged builds, in which
// case internal/build falls back to ReadBuildInfo's vcs.revision.
//
// buildTime is declared to receive the auto-build-timestamp output
// even though raybeam doesn't currently surface a timestamp. The
// declaration is required: auto-build-timestamp fails the build step
// when the ldflag would have nowhere to land on older Go toolchains.
var (
	version   = ""
	build     = ""
	buildTime = ""
)

// forwardBuildMetadata copies the build-injected package-main vars
// into the internal/build package. Extracted from init() for direct
// unit-testability. Empty inputs are treated as "not injected" and
// leave the existing buildpkg defaults in place. buildTime is
// accepted but not currently surfaced in cobra's --version output.
func forwardBuildMetadata(v, b, t string) {
	if v != "" {
		buildpkg.Version = v
	}
	if b != "" {
		buildpkg.CommitHash = b
	}
	_ = t // reserved for future use; declared so the ldflag has a target.
}

func init() {
	forwardBuildMetadata(version, build, buildTime)
}

func main() {
	cmd.Execute()
}
