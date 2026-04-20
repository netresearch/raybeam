package build

import (
	"runtime/debug"
)

const Repository = "https://github.com/netresearch/raybeam"

// Version is the release tag or VCS-derived commit SHA. Populated by
// main.init via ldflags on tagged releases; falls back to
// ReadBuildInfo's vcs.revision for untagged builds.
var Version = func() string {
	if vcsRevision != "" {
		return vcsRevision
	}

	return "unknown"
}()

// CommitHash is the git SHA the binary was built from. Populated by
// main.init via ldflags (release-time) or set from ReadBuildInfo's
// vcs.revision at package init.
var CommitHash = vcsRevision

// vcsRevision is the VCS revision reported by runtime/debug once at
// package init. Both Version and CommitHash key off it so we only
// scan build.Settings once.
var vcsRevision = func() string {
	info, hasInfo := debug.ReadBuildInfo()
	if !hasInfo {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}

	return ""
}()
