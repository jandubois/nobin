// Package version exists as a separate importable package so that projects
// pinning nobin as a Go tool dependency can import it to keep the module
// version visible as a direct (not indirect) require in their go.mod.
// This prevents Dependabot from losing track of the dependency.
package version

// Version is set at build time via -ldflags "-X github.com/jandubois/nobin/version.Version=..."
var Version = "dev"
