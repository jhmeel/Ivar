package main

import (
	"bytes"
	"io"
	"net/http"
)

// readAll reads a request body and puts it back, so the next reader sees it too.
func readAll(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return raw, err
}
