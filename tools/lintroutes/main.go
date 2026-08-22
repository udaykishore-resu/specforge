// Command lintroutes fails the build when an endpoint is registered without a
// permission, or when a route is public without being on the approved list.
//
// The API server performs the same check at startup and refuses to boot on a
// failure. Running it here as well moves the discovery from "production pod
// crash-loops" to "pull request goes red", which is where it belongs.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/specforge/specforge/internal/server"
)

// approvedPublic is the unauthenticated surface, listed explicitly.
//
// Health, readiness, metrics and discovery only. Adding to this list should be
// a visible, reviewed change, because every entry is an endpoint the internet
// can reach without a token.
var approvedPublic = map[string]bool{
	"GET /healthz":             true,
	"GET /readyz":              true,
	"GET /metrics":             true,
	"GET /api/v1/version":      true,
	"GET /api/v1/openapi.json": true,
}

func main() {
	routes := server.RouteTable()
	if len(routes) == 0 {
		fmt.Fprintln(os.Stderr, "lintroutes: no routes were registered; the linter is not seeing the router")
		os.Exit(1)
	}

	var problems []string
	for _, r := range routes {
		id := r.Method + " " + r.Pattern
		switch {
		case r.Public && !approvedPublic[id]:
			problems = append(problems, fmt.Sprintf(
				"%s is public but is not on the approved public list", id))
		case !r.Public && (r.Permission == "" || strings.HasPrefix(r.Permission, "permission(")):
			problems = append(problems, fmt.Sprintf(
				"%s declares no permission", id))
		}
	}

	registered := map[string]bool{}
	for _, r := range routes {
		if r.Public {
			registered[r.Method+" "+r.Pattern] = true
		}
	}
	for id := range approvedPublic {
		if !registered[id] {
			problems = append(problems, fmt.Sprintf(
				"%s is on the approved public list but is not registered", id))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		fmt.Fprintln(os.Stderr, "lintroutes: the API surface does not meet the authorization rules:")
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		os.Exit(1)
	}

	fmt.Printf("lintroutes: %d routes, all authorized\n", len(routes))
}
