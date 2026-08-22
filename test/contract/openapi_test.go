// Package contract checks that the published API document describes the API
// that is actually served.
//
// An OpenAPI file that has drifted from the code is worse than no file at all:
// clients are generated from it, reviewers reason about it, and auditors are
// shown it. These tests fail the build the moment the two disagree.
//
// The YAML is read with a small purpose-built scanner rather than a YAML
// library. The platform has no third-party dependencies, and the two things
// these tests need from the document — the path/method table and a handful of
// enum blocks — are extractable from its line structure without a general
// parser. The scanner is deliberately strict: anything it cannot interpret is
// a test failure, not a silent skip.
package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/specforge/specforge/internal/artifactgraph/domain"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/types"
	"github.com/specforge/specforge/internal/server"
	tenancydomain "github.com/specforge/specforge/internal/tenancy/domain"
)

const specPath = "../../api/openapi/specforge.v1.yaml"

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("reading the OpenAPI document: %v", err)
	}
	return string(b)
}

// specOperations extracts the method/path pairs declared in the document.
func specOperations(t *testing.T, doc string) map[string]bool {
	t.Helper()

	var (
		ops      = map[string]bool{}
		path     string
		inPaths  bool
		pathRe   = regexp.MustCompile(`^  (/\S*):\s*$`)
		methodRe = regexp.MustCompile(`^    (get|put|post|delete|patch|head|options):\s*$`)
	)
	for _, line := range strings.Split(doc, "\n") {
		switch {
		case line == "paths:":
			inPaths = true
			continue
		case !inPaths:
			continue
		// A top-level key ends the paths section.
		case len(line) > 0 && line[0] != ' ' && line[0] != '#':
			inPaths = false
			continue
		}
		if m := pathRe.FindStringSubmatch(line); m != nil {
			path = m[1]
			continue
		}
		if m := methodRe.FindStringSubmatch(line); m != nil {
			if path == "" {
				t.Fatalf("found the method %q before any path", m[1])
			}
			ops[strings.ToUpper(m[1])+" "+path] = true
		}
	}
	if len(ops) == 0 {
		t.Fatal("no operations were found in the OpenAPI document; the scanner or the document is broken")
	}
	return ops
}

// TestEveryRouteIsDocumented is the check that matters most: an endpoint that
// exists but is undocumented is an endpoint no reviewer sees.
func TestEveryRouteIsDocumented(t *testing.T) {
	doc := readSpec(t)
	documented := specOperations(t, doc)

	var missing []string
	for _, r := range server.RouteTable() {
		key := r.Method + " " + r.Pattern
		if !documented[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these routes are served but not documented in %s:\n  %s",
			specPath, strings.Join(missing, "\n  "))
	}
}

// TestEveryDocumentedOperationExists catches the opposite drift: a documented
// endpoint that was renamed or removed. A client generated from the document
// would call it and get a 404.
func TestEveryDocumentedOperationExists(t *testing.T) {
	doc := readSpec(t)
	documented := specOperations(t, doc)

	served := map[string]bool{}
	for _, r := range server.RouteTable() {
		served[r.Method+" "+r.Pattern] = true
	}

	var phantom []string
	for op := range documented {
		if !served[op] {
			phantom = append(phantom, op)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("these operations are documented but not served:\n  %s",
			strings.Join(phantom, "\n  "))
	}
}

// TestEveryRouteDeclaresAPermission repeats the server's own startup lint here
// so the guarantee is covered by the test suite as well as by the process
// refusing to boot.
func TestEveryRouteDeclaresAPermission(t *testing.T) {
	for _, r := range server.RouteTable() {
		if r.Public {
			continue
		}
		if r.Permission == "" || strings.HasPrefix(r.Permission, "permission(") {
			t.Errorf("%s %s declares no permission", r.Method, r.Pattern)
		}
	}
}

// TestPublicRoutesAreTheExpectedSet pins the unauthenticated surface.
//
// Adding a public route should be a deliberate act that updates this list, not
// something that happens in passing during a refactor.
func TestPublicRoutesAreTheExpectedSet(t *testing.T) {
	want := map[string]bool{
		"GET /healthz":             true,
		"GET /readyz":              true,
		"GET /metrics":             true,
		"GET /api/v1/version":      true,
		"GET /api/v1/openapi.json": true,
	}
	got := map[string]bool{}
	for _, r := range server.RouteTable() {
		if r.Public {
			got[r.Method+" "+r.Pattern] = true
		}
	}
	for op := range got {
		if !want[op] {
			t.Errorf("%s is public but is not in the approved public set; "+
				"if this is intended, add it here and say why in review", op)
		}
	}
	for op := range want {
		if !got[op] {
			t.Errorf("%s was expected to be public but is not registered", op)
		}
	}
}

// enumValues extracts one schema's enum list from the document.
//
// It handles both the block form used for long lists and the inline
// `enum: [A, B]` form, and fails if the named schema has no enum at all.
func enumValues(t *testing.T, doc, schema string) []string {
	t.Helper()

	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		if line == "    "+schema+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("the schema %q is not defined in the OpenAPI document", schema)
	}

	var (
		out      []string
		inEnum   bool
		itemRe   = regexp.MustCompile(`^\s+- (\S+)\s*$`)
		inlineRe = regexp.MustCompile(`^\s+enum:\s*\[(.+)\]\s*$`)
	)
	for _, line := range lines[start+1:] {
		// A new schema at the same indentation ends this one.
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") &&
			strings.HasSuffix(strings.TrimSpace(line), ":") {
			break
		}
		if m := inlineRe.FindStringSubmatch(line); m != nil {
			for _, v := range strings.Split(m[1], ",") {
				out = append(out, strings.TrimSpace(v))
			}
			break
		}
		if strings.TrimSpace(line) == "enum:" {
			inEnum = true
			continue
		}
		if inEnum {
			if m := itemRe.FindStringSubmatch(line); m != nil {
				out = append(out, m[1])
				continue
			}
			break
		}
	}
	if len(out) == 0 {
		t.Fatalf("the schema %q declares no enum values", schema)
	}
	return out
}

func assertSameSet(t *testing.T, schema string, documented, actual []string) {
	t.Helper()

	docSet := map[string]bool{}
	for _, v := range documented {
		docSet[v] = true
	}
	actualSet := map[string]bool{}
	for _, v := range actual {
		actualSet[v] = true
	}
	for _, v := range actual {
		if !docSet[v] {
			t.Errorf("%s: %q exists in the code but is missing from the OpenAPI document", schema, v)
		}
	}
	for _, v := range documented {
		if !actualSet[v] {
			t.Errorf("%s: %q is documented but does not exist in the code", schema, v)
		}
	}
}

// TestArtifactTypeEnumMatchesCode and the tests below stop the enums drifting.
// A client that trusts a stale enum will send a value the server rejects, and
// the failure will look like a client bug.
func TestArtifactTypeEnumMatchesCode(t *testing.T) {
	doc := readSpec(t)
	var actual []string
	for _, v := range types.AllArtifactTypes() {
		actual = append(actual, string(v))
	}
	assertSameSet(t, "ArtifactType", enumValues(t, doc, "ArtifactType"), actual)
}

func TestLinkTypeEnumMatchesCode(t *testing.T) {
	doc := readSpec(t)
	var actual []string
	for _, v := range types.AllLinkTypes() {
		actual = append(actual, string(v))
	}
	assertSameSet(t, "LinkType", enumValues(t, doc, "LinkType"), actual)
}

func TestRoleEnumMatchesCode(t *testing.T) {
	doc := readSpec(t)
	var actual []string
	for _, r := range authz.AllRoles() {
		actual = append(actual, string(r))
	}
	assertSameSet(t, "Role", enumValues(t, doc, "Role"), actual)
}

func TestArtifactStatusEnumMatchesCode(t *testing.T) {
	doc := readSpec(t)
	var actual []string
	for _, s := range domain.Machine.States() {
		actual = append(actual, string(s))
	}
	assertSameSet(t, "ArtifactStatus", enumValues(t, doc, "ArtifactStatus"), actual)
}

func TestLinkStatusEnumMatchesCode(t *testing.T) {
	doc := readSpec(t)
	var actual []string
	for _, s := range types.AllLinkStatuses() {
		actual = append(actual, string(s))
	}
	assertSameSet(t, "LinkStatus", enumValues(t, doc, "LinkStatus"), actual)
}

func TestPDLCPhaseEnumMatchesCode(t *testing.T) {
	doc := readSpec(t)
	var actual []string
	for _, p := range tenancydomain.AllPhases() {
		actual = append(actual, string(p))
	}

	// The phase list is inline in the Project schema rather than a named
	// schema, so it is read from that block.
	documented := inlineListUnder(t, doc, "    Project:", "        pdlc_phase:")
	assertSameSet(t, "Project.pdlc_phase", documented, actual)
}

// inlineListUnder reads a bracketed enum that is nested under a property,
// including the wrapped continuation lines the document uses for long lists.
func inlineListUnder(t *testing.T, doc, schemaLine, propertyLine string) []string {
	t.Helper()

	lines := strings.Split(doc, "\n")
	i := 0
	for ; i < len(lines); i++ {
		if lines[i] == schemaLine {
			break
		}
	}
	if i == len(lines) {
		t.Fatalf("%q was not found in the OpenAPI document", schemaLine)
	}
	for ; i < len(lines); i++ {
		if lines[i] == propertyLine {
			break
		}
	}
	if i == len(lines) {
		t.Fatalf("%q was not found in the OpenAPI document", propertyLine)
	}

	var buf strings.Builder
	for _, line := range lines[i+1:] {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "enum:") {
			buf.WriteString(strings.TrimPrefix(trimmed, "enum:"))
			continue
		}
		if buf.Len() == 0 {
			continue
		}
		buf.WriteString(" " + trimmed)
		if strings.Contains(trimmed, "]") {
			break
		}
	}
	raw := strings.Trim(strings.TrimSpace(buf.String()), "[]")
	if raw == "" {
		t.Fatalf("no inline enum was found under %q", propertyLine)
	}
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
