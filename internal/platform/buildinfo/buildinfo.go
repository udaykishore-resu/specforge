// Package buildinfo carries the identity of the running binary.
//
// The values are set at link time by the build (see the Makefile's LDFLAGS) and
// fall back to what the Go toolchain embedded in the module's build info. A
// binary that cannot say which commit produced it is a binary you cannot
// correlate with an incident, a deployment record or an audit finding, so the
// unknown case is reported explicitly rather than left blank.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// These are populated with -ldflags -X at build time.
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

const unknown = "unknown"

var once sync.Once

// resolve fills any value the linker did not set from the embedded build info.
// `go build` records the VCS revision automatically, so a plain `go build`
// still produces a binary that knows its commit.
func resolve() {
	once.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if ok {
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if Commit == "" {
						Commit = shorten(s.Value)
					}
				case "vcs.time":
					if Date == "" {
						Date = s.Value
					}
				case "vcs.modified":
					if s.Value == "true" && Version == "" {
						Version = "dev-dirty"
					}
				}
			}
			if Version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
				Version = info.Main.Version
			}
		}
		if Version == "" {
			Version = "dev"
		}
		if Commit == "" {
			Commit = unknown
		}
		if Date == "" {
			Date = unknown
		}
	})
}

func shorten(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the build identity.
func Get() Info {
	resolve()
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String renders the identity for a startup log line.
func (i Info) String() string {
	var b strings.Builder
	b.WriteString(i.Version)
	b.WriteString(" (")
	b.WriteString(i.Commit)
	b.WriteString(", built ")
	b.WriteString(i.BuildDate)
	b.WriteString(", ")
	b.WriteString(i.GoVersion)
	b.WriteString(")")
	return b.String()
}

// Release reports whether this looks like a released build rather than a local
// or dirty one. Deployment gates use it: shipping an unidentifiable binary to
// production defeats the provenance chain the pipeline exists to maintain.
func Release() bool {
	resolve()
	return Version != "dev" && Version != "dev-dirty" &&
		Commit != unknown && !strings.HasSuffix(Version, "-dirty")
}

// HandleVersionFlag prints the build identity and reports whether the process
// should exit.
//
// Every binary answers `--version` before it reads configuration or opens a
// connection. That ordering is what makes it usable as a release gate and as
// the first question during an incident: a binary that must reach its database
// before it can say which commit it is cannot answer when the database is the
// problem.
func HandleVersionFlag(args []string, program string) bool {
	for _, a := range args {
		switch a {
		case "--version", "-version", "version":
			info := Get()
			fmt.Printf("%s %s\n", program, info)
			if !Release() {
				fmt.Println("note: this is not a released build")
			}
			return true
		}
		// Stop at the first non-flag argument so a subcommand named `version`
		// belonging to the program itself is not shadowed.
		if len(a) > 0 && a[0] != '-' {
			return false
		}
	}
	return false
}
