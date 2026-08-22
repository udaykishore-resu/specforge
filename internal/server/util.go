package server

import (
	"bytes"
	"encoding/json"
	"io"
)

// jsonMarshal encodes a response body for idempotent replay storage.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// readAll reads a bounded reader fully.
func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

// newBodyReader restores a consumed request body.
func newBodyReader(b []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(b)) }
