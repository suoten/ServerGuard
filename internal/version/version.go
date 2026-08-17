package version

import "fmt"

// Version information set at build time
var (
	Version   = "0.2.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
	GoVersion = "unknown"
	OS        = "unknown"
	Arch      = "unknown"
)

// FullVersion returns the full version string.
func FullVersion() string {
	return fmt.Sprintf("ServerGuard %s (built %s, commit %s, %s/%s)",
		Version, BuildTime, GitCommit, OS, Arch)
}

// ShortVersion returns just the version number.
func ShortVersion() string {
	return Version
}
