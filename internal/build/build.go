package build

import (
	"runtime/debug"
)

const Repository = "https://github.com/netresearch/raybeam"

// Version is the release tag or VCS-derived commit SHA. Populated by
// main.init via ldflags on tagged releases; falls back to
// ReadBuildInfo's vcs.revision for untagged builds.
var Version = vcsRevisionOr("unknown")

// CommitHash is the git SHA the binary was built from. Populated by
// main.init via ldflags (release-time) or set from ReadBuildInfo's
// vcs.revision at package init.
var CommitHash = vcsRevisionOr("")

// vcsRevisionOr returns the vcs.revision recorded in the build info,
// falling back to the provided default when ReadBuildInfo has no
// VCS settings (e.g. CGO-free static builds in contexts that strip
// them). Used as the initializer for both Version and CommitHash so
// the module is fully self-describing without ldflags.
func vcsRevisionOr(fallback string) string {
	if info, hasInfo := debug.ReadBuildInfo(); hasInfo {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}

	return fallback
}
