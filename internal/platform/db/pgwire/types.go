package pgwire

import (
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PostgreSQL type OIDs the driver decodes natively. Anything else is returned
// as a string, which database/sql converts on Scan.
const (
	oidBool        = 16
	oidBytea       = 17
	oidInt8        = 20
	oidInt2        = 21
	oidInt4        = 23
	oidText        = 25
	oidOID         = 26
	oidJSON        = 114
	oidFloat4      = 700
	oidFloat8      = 701
	oidBPChar      = 1042
	oidVarchar     = 1043
	oidDate        = 1082
	oidTime        = 1083
	oidTimestamp   = 1114
	oidTimestamptz = 1184
	oidInterval    = 1186
	oidNumeric     = 1700
	oidUUID        = 2950
	oidJSONB       = 3802
)

// timestamp layouts PostgreSQL emits in text format, most specific first.
var timestampLayouts = []string{
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999Z07",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02",
}

// decodeValue converts a text-format column value to a driver.Value.
//
// Timestamps are decoded to time.Time rather than left as bytes because
// database/sql cannot convert []byte to time.Time on Scan, and every audit and
// artifact row carries timestamps.
func decodeValue(oid int32, raw []byte) (driver.Value, error) {
	if raw == nil {
		return nil, nil
	}
	s := string(raw)
	switch oid {
	case oidBool:
		return s == "t" || s == "true" || s == "1", nil
	case oidInt2, oidInt4, oidInt8, oidOID:
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("pgwire: decoding integer %q: %w", s, err)
		}
		return v, nil
	case oidFloat4, oidFloat8:
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, fmt.Errorf("pgwire: decoding float %q: %w", s, err)
		}
		return v, nil
	case oidBytea:
		if strings.HasPrefix(s, `\x`) {
			b, err := hex.DecodeString(s[2:])
			if err != nil {
				return nil, fmt.Errorf("pgwire: decoding bytea: %w", err)
			}
			return b, nil
		}
		return []byte(s), nil
	case oidDate, oidTimestamp, oidTimestamptz:
		return parseTimestamp(s)
	case oidJSON, oidJSONB:
		// Returned as []byte so callers can json.Unmarshal without a copy and so
		// Scan into *[]byte, *string and *json.RawMessage all work.
		return append([]byte(nil), raw...), nil
	default:
		return s, nil
	}
}

func parseTimestamp(s string) (time.Time, error) {
	// PostgreSQL renders "+00" style offsets; pad to "+00:00" for time.Parse.
	norm := s
	if n := len(norm); n >= 3 {
		if c := norm[n-3]; (c == '+' || c == '-') && norm[n-6] != '-' {
			norm += ":00"
		}
	}
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, norm); err == nil {
			return t, nil
		}
	}
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("pgwire: cannot parse timestamp %q", s)
}

// encodeParam renders a driver.Value in PostgreSQL text format.
// Returns (nil, true) for SQL NULL.
func encodeParam(v driver.Value) ([]byte, bool, error) {
	switch t := v.(type) {
	case nil:
		return nil, true, nil
	case string:
		return []byte(t), false, nil
	case []byte:
		// Ambiguous by nature: []byte is both "bytes" and "raw JSON/text" in Go.
		// The repository layer passes strings for textual columns and []byte only
		// for genuine bytea, so hex encoding is the correct choice here.
		return []byte(`\x` + hex.EncodeToString(t)), false, nil
	case bool:
		if t {
			return []byte("t"), false, nil
		}
		return []byte("f"), false, nil
	case int64:
		return []byte(strconv.FormatInt(t, 10)), false, nil
	case float64:
		return []byte(strconv.FormatFloat(t, 'g', -1, 64)), false, nil
	case time.Time:
		return []byte(t.UTC().Format("2006-01-02 15:04:05.999999-07:00")), false, nil
	default:
		return nil, false, fmt.Errorf("pgwire: unsupported parameter type %T", v)
	}
}

// TextArray renders a Go string slice as a PostgreSQL text[] literal, escaping
// per the array input syntax. Used for text[] columns such as api_keys.permissions.
func TextArray(values []string) string {
	if len(values) == 0 {
		return "{}"
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, v := range values {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		for _, r := range v {
			if r == '"' || r == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteRune(r)
		}
		sb.WriteByte('"')
	}
	sb.WriteByte('}')
	return sb.String()
}

// ParseTextArray parses a PostgreSQL text[] literal back into a string slice.
func ParseTextArray(s string) []string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil
	}
	body := s[1 : len(s)-1]
	if body == "" {
		return nil
	}
	var (
		out     []string
		cur     strings.Builder
		inQuote bool
		escaped bool
	)
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}
