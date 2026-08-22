// Package jcs implements RFC 8785, the JSON Canonicalization Scheme.
//
// Content addressing is the backbone of SpecForge's assurance model: an
// artifact version is pinned by SHA-256 over its canonical form. That only
// works if canonicalization is deterministic across languages, platforms and
// releases, which is exactly what JCS specifies:
//
//   - object members sorted by UTF-16 code unit order of their names
//   - no insignificant whitespace
//   - numbers rendered with the ECMAScript Number::toString algorithm
//   - strings escaped with the minimal JSON escape set
//
// The web application uses the same scheme, and both implementations are
// checked against the shared vectors in testdata/.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize marshals v and returns its canonical JSON form.
func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jcs: marshalling value: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalizeJSON returns the canonical form of an existing JSON document.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: parsing JSON: %w", err)
	}
	// Reject trailing content: two documents in one buffer would otherwise
	// canonicalize to only the first, silently.
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("jcs: trailing content after the JSON document")
	}

	var buf bytes.Buffer
	buf.Grow(len(raw) + 16)
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		s, err := formatNumber(t.String())
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case float64:
		s, err := formatFloat(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := write(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported value of type %T", v)
	}
	return nil
}

// sortUTF16 orders keys by UTF-16 code unit, as RFC 8785 §3.2.3 requires.
//
// This differs from ordinary Go string comparison for astral-plane characters:
// U+1F600 sorts before U+E000 in UTF-16 (surrogate D83D < E000) but after it
// byte-wise in UTF-8. Getting this wrong would produce hashes that disagree
// with any JavaScript implementation.
func sortUTF16(keys []string) {
	sort.SliceStable(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})
}

func lessUTF16(a, b string) bool {
	// Fast path: both pure ASCII, where UTF-8 and UTF-16 order agree.
	if isASCII(a) && isASCII(b) {
		return a < b
	}
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// writeString emits a JSON string with the minimal escape set from RFC 8785 §3.2.2.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u`)
				const hexdigits = "0123456789abcdef"
				buf.WriteByte('0')
				buf.WriteByte('0')
				buf.WriteByte(hexdigits[(r>>4)&0xF])
				buf.WriteByte(hexdigits[r&0xF])
				continue
			}
			if r == utf8.RuneError {
				// Invalid UTF-8 in the input. Canonicalization must be total and
				// lossless, so emit the replacement character explicitly rather
				// than let the byte sequence vary.
				buf.WriteRune(utf8.RuneError)
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

func formatNumber(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("jcs: number %q is not representable as a double: %w", lit, err)
	}
	return formatFloat(f)
}

// formatFloat implements ECMAScript Number::toString (ECMA-262 §6.1.6.1.20),
// which RFC 8785 §3.2.2.3 mandates for numeric serialisation.
func formatFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcs: %v is not a valid JSON number", f)
	}
	if f == 0 {
		// Negative zero canonicalises to "0": JCS treats -0 and 0 as equal.
		return "0", nil
	}

	neg := f < 0
	if neg {
		f = -f
	}

	// Shortest round-trip decimal, from which we recover the ES (s, k, n) triple.
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, expPart, _ := strings.Cut(sci, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	e10, err := strconv.Atoi(expPart)
	if err != nil {
		return "", fmt.Errorf("jcs: parsing exponent of %q: %w", sci, err)
	}

	k := len(digits) // number of significant digits
	n := e10 + 1     // value == 0.digits * 10^n

	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}

	switch {
	case k <= n && n <= 21:
		sb.WriteString(digits)
		sb.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		sb.WriteString(digits[:n])
		sb.WriteByte('.')
		sb.WriteString(digits[n:])
	case -6 < n && n <= 0:
		sb.WriteString("0.")
		sb.WriteString(strings.Repeat("0", -n))
		sb.WriteString(digits)
	default:
		if k == 1 {
			sb.WriteString(digits)
		} else {
			sb.WriteString(digits[:1])
			sb.WriteByte('.')
			sb.WriteString(digits[1:])
		}
		sb.WriteByte('e')
		if n-1 >= 0 {
			sb.WriteByte('+')
		} else {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(abs(n - 1)))
	}
	return sb.String(), nil
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}
