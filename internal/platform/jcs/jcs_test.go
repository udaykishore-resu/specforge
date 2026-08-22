package jcs_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/specforge/specforge/internal/platform/jcs"
)

func TestCanonicalizeRFC8785Examples(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// RFC 8785 §3.2.3 — the sorting example.
			name: "member ordering",
			in: `{
			  "\u20ac": "Euro Sign",
			  "\r": "Carriage Return",
			  "\ufb33": "Hebrew Letter Dalet With Dagesh",
			  "1": "One",
			  "\ud83d\ude00": "Emoji: Grinning Face",
			  "\u0080": "Control",
			  "\u00f6": "Latin Small Letter O With Diaeresis"
			}`,
			// U+0080 is a C1 control character but sits above U+001F, so RFC 8785
			// §3.2.2.2 emits it literally rather than as a \u escape.
			want: "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\"," +
				"\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\"," +
				"\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
		{
			name: "whitespace removed and keys sorted",
			in:   `{ "b": 1, "a": 2 }`,
			want: `{"a":2,"b":1}`,
		},
		{
			name: "nested structures",
			in:   `{"z":[3,2,{"y":1,"x":2}],"a":null}`,
			want: `{"a":null,"z":[3,2,{"x":2,"y":1}]}`,
		},
		{
			name: "arrays keep their order",
			in:   `[3,1,2]`,
			want: `[3,1,2]`,
		},
		{
			name: "literal escapes",
			in:   `{"k":"a\"b\\c\nd\te"}`,
			want: `{"k":"a\"b\\c\nd\te"}`,
		},
		{
			name: "control characters use \\u00xx",
			in:   `{"k":"\u0001\u001f"}`,
			want: `{"k":"\u0001\u001f"}`,
		},
		{
			name: "non-ASCII is not escaped",
			in:   `{"k":"\u00e9\u4e2d"}`,
			want: `{"k":"é中"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jcs.CanonicalizeJSON([]byte(tc.in))
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// Number formatting must follow ECMAScript Number::toString, not Go's %g.
func TestNumberSerialization(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{`0`, `0`},
		{`-0`, `0`},
		{`1`, `1`},
		{`-1`, `-1`},
		{`1.0`, `1`},
		{`1.5`, `1.5`},
		{`100`, `100`},
		{`1e2`, `100`},
		{`1e21`, `1e+21`},
		{`1e-7`, `1e-7`},
		{`0.000001`, `0.000001`},
		{`0.0000001`, `1e-7`},
		{`1e20`, `100000000000000000000`},
		{`333333333.33333329`, `333333333.3333333`},
		{`1.7976931348623157e308`, `1.7976931348623157e+308`},
		{`5e-324`, `5e-324`},
		{`-1.5e-10`, `-1.5e-10`},
		{`2.220446049250313e-16`, `2.220446049250313e-16`},
	}
	for _, tc := range tests {
		got, err := jcs.CanonicalizeJSON([]byte(`{"n":` + tc.in + `}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		want := `{"n":` + tc.want + `}`
		if string(got) != want {
			t.Errorf("%s:\n got %s\nwant %s", tc.in, got, want)
		}
	}
}

// The whole point of canonicalisation: input key order must not change output.
func TestKeyOrderIndependence(t *testing.T) {
	t.Parallel()
	a := `{"alpha":1,"beta":{"x":true,"y":[1,2]},"gamma":"z"}`
	b := `{"gamma":"z","beta":{"y":[1,2],"x":true},"alpha":1}`

	ca, err := jcs.CanonicalizeJSON([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := jcs.CanonicalizeJSON([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("key order changed the canonical form:\n%s\n%s", ca, cb)
	}
}

func TestCanonicalizeStructRoundTrip(t *testing.T) {
	t.Parallel()
	type inner struct {
		Zed  string `json:"zed"`
		Abel int    `json:"abel"`
	}
	type outer struct {
		Name  string   `json:"name"`
		Inner inner    `json:"inner"`
		Tags  []string `json:"tags"`
	}
	got, err := jcs.Canonicalize(outer{
		Name:  "spec",
		Inner: inner{Zed: "z", Abel: 1},
		Tags:  []string{"b", "a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"inner":{"abel":1,"zed":"z"},"name":"spec","tags":["b","a"]}`
	if string(got) != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}

	// The canonical form must still be valid JSON that parses to the same value.
	var back map[string]any
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v", err)
	}
}

func TestRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
	}{
		{"malformed", `{"a":}`},
		{"trailing content", `{"a":1}{"b":2}`},
		{"empty", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jcs.CanonicalizeJSON([]byte(tc.in)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestRejectsNonFiniteNumbers(t *testing.T) {
	t.Parallel()
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := jcs.Canonicalize(map[string]any{"n": v}); err == nil {
			t.Fatalf("expected an error for %v", v)
		}
	}
}

// Astral-plane keys are where UTF-16 and UTF-8 ordering disagree; a Go-native
// sort would place them differently from any JavaScript implementation.
func TestAstralPlaneKeyOrdering(t *testing.T) {
	t.Parallel()
	got, err := jcs.CanonicalizeJSON([]byte(`{"\ud83d\ude00":1,"\ue000":2}`))
	if err != nil {
		t.Fatal(err)
	}
	// U+1F600 encodes to surrogate D83D, which is below E000 in UTF-16 order.
	if !strings.HasPrefix(string(got), `{"😀":1`) {
		t.Fatalf("UTF-16 ordering not applied: %s", got)
	}
}

func BenchmarkCanonicalize(b *testing.B) {
	doc := []byte(`{"artifact_id":"SPEC-AUTH-001","version":3,"content":{"given":["a user exists"],` +
		`"when":["they authenticate"],"then":["a session is issued"],"criteria":[{"id":"AC-1",` +
		`"text":"MFA is required for privileged roles"}]},"labels":{"domain":"identity"}}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := jcs.CanonicalizeJSON(doc); err != nil {
			b.Fatal(err)
		}
	}
}
