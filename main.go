package main

import (
	"raybeam/cmd"
	buildpkg "raybeam/internal/build"
)

// Build-injected version metadata. Populated by release.yml's ldflags
// (`-X main.version=<tag>`, `-X main.build=<commit-sha>`); forwarded
// into internal/build at init() so `raybeam --version` reports the
// release tag on tagged releases. Empty on `go run` / untagged
// builds, in which case internal/build falls back to ReadBuildInfo's
// vcs.revision as before.
var (
	version = ""
	build   = ""
)

func init() {
	if version != "" {
		buildpkg.Version = version
	}
	_ = build // reserved — ldflag target, not currently consumed.
}

func main() {
	cmd.Execute()
}
