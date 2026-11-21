package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWSCredentials for the responder's scoped IAM user or role.
type AWSCredentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// SignV4 signs an AWS request with Signature Version 4.
func SignV4(req *http.Request, body []byte, c AWSCredentials, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	day := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	req.Header.Set("Host", req.URL.Host)
	var names []string
	for k := range req.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		fmt.Fprintf(&canonHeaders, "%s:%s\n", n, strings.TrimSpace(req.Header.Get(n)))
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{req.Method, path, req.URL.Query().Encode(), canonHeaders.String(), signed, sha256Hex(body)}, "\n")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", day, region, service)
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonical))}, "\n")
	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", c.AccessKeyID, scope, signed, sig))
}
