package build

import (
	"runtime/debug"
)

const Repository = "https://github.com/netresearch/raybeam"

var Version = func() string {
	if info, hasInfo := debug.ReadBuildInfo(); hasInfo {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}

	return "unknown"
}()
