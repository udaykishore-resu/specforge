package pgwire

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// md5Auth implements the legacy MD5 authentication exchange.
//
// MD5 authentication is obsolete and disabled on modern servers; it is
// implemented only so the driver can connect to legacy instances during a
// migration. SCRAM-SHA-256 is the expected mechanism.
func md5Auth(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), salt...))
	return "md5" + hex.EncodeToString(outer[:])
}

// ---------------------------------------------------------------------------
// SCRAM-SHA-256 (RFC 5802 / RFC 7677)
// ---------------------------------------------------------------------------

type scramClient struct {
	user       string
	password   string
	nonce      string
	firstBare  string
	saltedPass []byte
	authMsg    string
}

func newSCRAMClient(user, password string) (*scramClient, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("pgwire: generating SCRAM nonce: %w", err)
	}
	return &scramClient{
		user:     user,
		password: password,
		nonce:    base64.StdEncoding.EncodeToString(raw),
	}, nil
}

// firstMessage returns the client-first message, GS2 header included.
func (c *scramClient) firstMessage() string {
	// The username is sent empty: PostgreSQL takes it from the startup packet,
	// and RFC 7677 requires SASLprep normalisation we deliberately avoid here.
	c.firstBare = "n=,r=" + c.nonce
	return "n,," + c.firstBare
}

// finalMessage consumes the server-first message and produces client-final.
func (c *scramClient) finalMessage(serverFirst string) (string, error) {
	attrs, err := parseSCRAMAttrs(serverFirst)
	if err != nil {
		return "", err
	}
	serverNonce := attrs["r"]
	if !strings.HasPrefix(serverNonce, c.nonce) {
		return "", fmt.Errorf("pgwire: SCRAM server nonce does not extend the client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil {
		return "", fmt.Errorf("pgwire: SCRAM salt: %w", err)
	}
	iters, err := strconv.Atoi(attrs["i"])
	if err != nil || iters < 1 {
		return "", fmt.Errorf("pgwire: SCRAM iteration count %q", attrs["i"])
	}
	if iters > 1_000_000 {
		return "", fmt.Errorf("pgwire: SCRAM iteration count %d exceeds the safety limit", iters)
	}

	c.saltedPass = pbkdf2SHA256([]byte(c.password), salt, iters, sha256.Size)

	clientKey := hmacSHA256(c.saltedPass, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	clientFinalNoProof := "c=biws,r=" + serverNonce // biws = base64("n,,")
	c.authMsg = c.firstBare + "," + serverFirst + "," + clientFinalNoProof

	clientSig := hmacSHA256(storedKey[:], []byte(c.authMsg))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	return clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// verifyServer checks the server-final signature, completing mutual authentication.
// Skipping this step would allow a man-in-the-middle to impersonate the server.
func (c *scramClient) verifyServer(serverFinal string) error {
	attrs, err := parseSCRAMAttrs(serverFinal)
	if err != nil {
		return err
	}
	if e, ok := attrs["e"]; ok {
		return fmt.Errorf("pgwire: SCRAM authentication failed: %s", e)
	}
	got, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil {
		return fmt.Errorf("pgwire: SCRAM server signature: %w", err)
	}
	serverKey := hmacSHA256(c.saltedPass, []byte("Server Key"))
	want := hmacSHA256(serverKey, []byte(c.authMsg))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("pgwire: SCRAM server signature mismatch; the server may be impersonated")
	}
	return nil
}

func parseSCRAMAttrs(s string) (map[string]string, error) {
	out := make(map[string]string, 4)
	for _, part := range strings.Split(s, ",") {
		if len(part) < 2 || part[1] != '=' {
			return nil, fmt.Errorf("pgwire: malformed SCRAM attribute %q", part)
		}
		out[part[:1]] = part[2:]
	}
	return out, nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// pbkdf2SHA256 implements PBKDF2 with HMAC-SHA-256 (RFC 8018 §5.2).
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)

	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(buf, uint32(block))
		u := hmacSHA256(password, append(append([]byte{}, salt...), buf...))
		t := make([]byte, hLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = hmacSHA256(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
