// Package id generates the identifiers the platform relies on.
//
// UUIDv7 is used for every database primary key because its leading 48-bit
// millisecond timestamp gives index locality on insert, which matters for the
// append-heavy tables (audit records, outbox events, artifact versions).
package id

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	mu       sync.Mutex
	lastMS   int64
	lastSeq  uint16
	randRead = rand.Read
)

// NewUUIDv7 returns a time-ordered UUID (RFC 9562 §5.7) in canonical form.
//
// Within a single millisecond a monotonic counter guarantees ordering, so two
// identifiers generated back to back always sort in creation order. This is
// what lets the audit and outbox tables be scanned in insertion order without a
// separate sequence.
func NewUUIDv7() string {
	var b [16]byte
	if _, err := randRead(b[:]); err != nil {
		// crypto/rand failing means the platform cannot generate identifiers,
		// audit sequences or nonces safely. Continuing would be worse.
		panic(fmt.Sprintf("id: crypto/rand unavailable: %v", err))
	}

	now := time.Now().UnixMilli()

	mu.Lock()
	if now == lastMS {
		lastSeq++
		if lastSeq > 0x0FFF {
			// Counter exhausted within this millisecond: advance the timestamp
			// rather than emit a duplicate.
			now++
			lastMS = now
			lastSeq = 0
		}
	} else {
		if now < lastMS {
			// Clock moved backwards (NTP step). Keep monotonicity.
			now = lastMS
			lastSeq++
		} else {
			lastMS = now
			lastSeq = uint16(binary.BigEndian.Uint16(b[6:8]) & 0x0FFF)
		}
	}
	seq := lastSeq
	mu.Unlock()

	// 48-bit big-endian timestamp
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)

	// version 7 in the high nibble of byte 6, 12-bit counter in the rest
	b[6] = 0x70 | byte(seq>>8)
	b[7] = byte(seq)
	// RFC 4122 variant
	b[8] = (b[8] & 0x3F) | 0x80

	return format(b)
}

func format(b [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}

// TimestampOf extracts the creation time from a UUIDv7. It returns the zero
// time for identifiers that are not version 7.
func TimestampOf(uuid string) (time.Time, bool) {
	raw, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(raw) != 16 {
		return time.Time{}, false
	}
	if raw[6]>>4 != 7 {
		return time.Time{}, false
	}
	ms := int64(raw[0])<<40 | int64(raw[1])<<32 | int64(raw[2])<<24 |
		int64(raw[3])<<16 | int64(raw[4])<<8 | int64(raw[5])
	return time.UnixMilli(ms).UTC(), true
}

// NewToken returns a URL-safe random token of n bytes, hex encoded.
// Used for request IDs, state/nonce values and API key secrets.
func NewToken(n int) string {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		panic(fmt.Sprintf("id: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}

// NewRequestID returns a short correlation identifier for a single request.
func NewRequestID() string { return "req_" + NewToken(12) }
