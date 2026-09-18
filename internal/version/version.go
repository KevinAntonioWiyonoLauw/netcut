// language: Go, file: internal/version/version.go
package version

// Version is the release identifier, overridden at build time with
// -ldflags "-X .../internal/version.Version=vX.Y.Z".
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)
