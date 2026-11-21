package cloud

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Responder carries out IAM actions: deactivate an AWS access key, disable
// a Google Cloud service account key, delete an Azure role assignment.
type Responder struct {
	HTTP  *http.Client
	AWS   AWSCredentials
	Token func(provider string) (string, error)
	// Endpoints, overridable for tests. EC2Endpoint takes the region.
	IAMEndpoint, GCPEndpoint, AzureEndpoint string
	EC2Endpoint                             func(region string) string
	// IsolationGroup is the security group that denies all traffic except
	// forensics access; isolating an instance replaces its groups with it.
	IsolationGroup string
}

// NewResponder reads scoped credentials from the plugin environment.
func NewResponder(env func(string) string) *Responder {
	return &Responder{
		HTTP:          &http.Client{Timeout: 10 * time.Second},
		AWS:           AWSCredentials{env("IVAR_SECRET_AWS_ACCESS_KEY_ID"), env("IVAR_SECRET_AWS_SECRET_ACCESS_KEY"), env("IVAR_SECRET_AWS_SESSION_TOKEN")},
		Token:         func(p string) (string, error) { return env("IVAR_SECRET_" + strings.ToUpper(p) + "_TOKEN"), nil },
		IAMEndpoint:   "https://iam.amazonaws.com/",
		GCPEndpoint:   "https://iam.googleapis.com/v1/",
		AzureEndpoint: "https://management.azure.com/",
		EC2Endpoint:   func(region string) string { return "https://ec2." + region + ".amazonaws.com/" },
	}
}

// Execute runs one action. target is "provider:identifier".
func (r *Responder) Execute(ctx context.Context, action, target string) (string, string) {
	provider, id, _ := strings.Cut(target, ":")
	var err error
	switch {
	case action == "api_key.suspend" && provider == "aws":
		user, key, _ := strings.Cut(id, "/")
		form := url.Values{"Action": {"UpdateAccessKey"}, "Version": {"2010-05-08"}, "AccessKeyId": {key}, "Status": {"Inactive"}, "UserName": {user}}
		body := []byte(form.Encode())
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.IAMEndpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		SignV4(req, body, r.AWS, "us-east-1", "iam", time.Now())
		err = r.do(req)
	case action == "host.isolate" && provider == "aws":
		// target is aws:<region>/<instance id>
		region, instance, _ := strings.Cut(id, "/")
		if r.IsolationGroup == "" || region == "" || instance == "" {
			return "failed", "host.isolate needs an isolation security group and a region/instance target"
		}
		form := url.Values{"Action": {"ModifyInstanceAttribute"}, "Version": {"2016-11-15"}, "InstanceId": {instance}, "GroupId.1": {r.IsolationGroup}}
		body := []byte(form.Encode())
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.EC2Endpoint(region), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		SignV4(req, body, r.AWS, region, "ec2", time.Now())
		err = r.do(req)
	case action == "api_key.suspend" && provider == "gcp":
		err = r.bearer(ctx, "gcp", http.MethodPost, r.GCPEndpoint+id+":disable", nil)
	case action == "trust_edge.narrow" && provider == "azure":
		err = r.bearer(ctx, "azure", http.MethodDelete, r.AzureEndpoint+strings.TrimPrefix(id, "/")+"?api-version=2022-04-01", nil)
	default:
		return "failed", fmt.Sprintf("cloud responder has no %s for %s", action, provider)
	}
	if err != nil {
		return "failed", err.Error()
	}
	return "done", fmt.Sprintf("%s applied to %s", action, target)
}

func (r *Responder) bearer(ctx context.Context, provider, method, u string, body []byte) error {
	tok, err := r.Token(provider)
	if err != nil || tok == "" {
		return fmt.Errorf("no %s credential", provider)
	}
	req, _ := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	return r.do(req)
}

func (r *Responder) do(req *http.Request) error {
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s returned %d: %s", req.URL.Host, resp.StatusCode, b)
	}
	return nil
}
