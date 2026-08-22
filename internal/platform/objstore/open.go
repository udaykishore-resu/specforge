package objstore

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// Providers lists the adapters this build actually contains.
//
// It is exported so the configuration validator can name them in an error
// rather than leaving an operator to discover by process of elimination which
// values are real. A provider that is configured but not built is a process
// that crash-loops at startup, and the message it crash-loops with is the only
// thing anyone gets to read.
var Providers = map[string]string{
	"db": "PostgreSQL. Write-once retention enforced by a database trigger. " +
		"Objects are bounded at 1 MiB.",
	"fs": "Local filesystem. Write-once retention enforced in application code. " +
		"Single node only.",
}

// ProviderNames returns the supported providers, sorted, for error messages.
func ProviderNames() []string {
	out := make([]string, 0, len(Providers))
	for name := range Providers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Supported reports whether this build contains the named adapter.
func Supported(provider string) bool {
	_, ok := Providers[provider]
	return ok
}

// Open builds the configured store.
//
// One store backs every bucket; the bucket name is the top-level directory or
// the bucket column, so content, evidence and anchors stay separated without
// needing three connections or three roots.
func Open(provider, root string, sdb *sql.DB) (Store, error) {
	switch provider {
	case "db", "postgres":
		if sdb == nil {
			return nil, fmt.Errorf("objstore: the %q provider needs a database handle", provider)
		}
		return NewPostgres(sdb), nil
	case "fs", "":
		return NewFS(root)
	default:
		return nil, fmt.Errorf(
			"objstore: provider %q is not available in this build; supported providers are %s",
			provider, strings.Join(ProviderNames(), ", "))
	}
}
