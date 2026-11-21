package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jhmeel/ivar/go/internal/coreclient"
)

func TestMappings(t *testing.T) {
	ct := map[string]any{"detail-type": "AWS API Call via CloudTrail", "detail": map[string]any{
		"eventName": "AttachRolePolicy", "eventTime": "2026-10-15T02:00:00Z", "sourceIPAddress": "203.0.113.4",
		"userIdentity":      map[string]any{"arn": "arn:aws:sts::1:assumed-role/backup-app/s1", "accessKeyId": "ASIAX"},
		"requestParameters": map[string]any{"roleName": "backup-app", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
	}}
	e := FromCloudTrail("aws-1", ct)
	attrs := e["ivar"].(map[string]any)["attributes"].(map[string]string)
	if e["activity_name"] != "iam.grant" || attrs["grantee"] != "arn:aws:sts::1:assumed-role/backup-app/s1" {
		t.Fatalf("self grant not mapped: %v %v", e["activity_name"], attrs)
	}
	snap := FromCloudTrail("aws-1", map[string]any{"detail": map[string]any{"eventName": "DeleteDBSnapshot", "userIdentity": map[string]any{"arn": "x"}}})
	if snap["ivar"].(map[string]any)["destructive"] != true {
		t.Fatal("snapshot delete must be destructive")
	}
	az := FromAzureActivity("az-1", map[string]any{"data": map[string]any{"operationName": "Microsoft.Compute/snapshots/delete", "caller": "ops@contoso"}})
	if az["activity_name"] != "snapshot.delete" {
		t.Fatal(az["activity_name"])
	}
	g := FromGCPAudit("gcp-1", map[string]any{"protoPayload": map[string]any{"methodName": "google.iam.admin.v1.CreateServiceAccountKey", "authenticationInfo": map[string]any{"principalEmail": "ci@p.iam"}}})
	if g["activity_name"] != "app.secret_create" {
		t.Fatal(g["activity_name"])
	}
}

func TestReceiverAuthAndValidation(t *testing.T) {
	core := coreclient.New("http://unused", "cloud-1", "cloud")
	r := &Receiver{Core: core, SensorID: "cloud-1", Token: "s3cret"}
	h := r.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/aws", strings.NewReader(`{"detail":{"eventName":"ConsoleLogin"}}`)))
	if w.Code != 401 {
		t.Fatal("unauthenticated push accepted")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/azure", strings.NewReader(`[{"eventType":"Microsoft.EventGrid.SubscriptionValidationEvent","data":{"validationCode":"abc"}}]`)))
	if !strings.Contains(w.Body.String(), "abc") {
		t.Fatal("event grid handshake failed")
	}
	entry, _ := json.Marshal(map[string]any{"protoPayload": map[string]any{"methodName": "SetIamPolicy"}})
	push, _ := json.Marshal(map[string]any{"message": map[string]any{"data": base64.StdEncoding.EncodeToString(entry)}})
	req := httptest.NewRequest("POST", "/gcp", strings.NewReader(string(push)))
	req.Header.Set("X-Ivar-Token", "s3cret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if n, _ := core.Pending(); w.Code != 204 || n != 1 {
		t.Fatalf("gcp push: %d pending=%d", w.Code, n)
	}
}

func TestResponderSignsAndCalls(t *testing.T) {
	var auth, form string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		form = r.Form.Encode()
	}))
	defer srv.Close()
	resp := NewResponder(func(k string) string { return map[string]string{"IVAR_SECRET_AWS_ACCESS_KEY_ID": "AKID", "IVAR_SECRET_AWS_SECRET_ACCESS_KEY": "secret", "IVAR_SECRET_GCP_TOKEN": "tok"}[k] })
	resp.IAMEndpoint = srv.URL + "/"
	resp.GCPEndpoint = srv.URL + "/v1/"
	if res, v := resp.Execute(context.Background(), "api_key.suspend", "aws:ci-user/AKIAOLD"); res != "done" {
		t.Fatal(v)
	}
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(form, "Status=Inactive") {
		t.Fatalf("bad request: %s %s", auth, form)
	}
	if res, _ := resp.Execute(context.Background(), "api_key.suspend", "gcp:projects/p/serviceAccounts/sa/keys/k1"); res != "done" || auth != "Bearer tok" {
		t.Fatal("gcp disable")
	}
	resp.EC2Endpoint = func(string) string { return srv.URL + "/" }
	if res, _ := resp.Execute(context.Background(), "host.isolate", "aws:eu-west-1/i-0abc"); res != "failed" {
		t.Fatal("isolation without a configured group must fail")
	}
	resp.IsolationGroup = "sg-quarantine"
	if res, v := resp.Execute(context.Background(), "host.isolate", "aws:eu-west-1/i-0abc"); res != "done" {
		t.Fatal(v)
	}
	if !strings.Contains(auth, "/eu-west-1/ec2/aws4_request") || !strings.Contains(form, "GroupId.1=sg-quarantine") || !strings.Contains(form, "InstanceId=i-0abc") {
		t.Fatalf("bad isolate request: %s %s", auth, form)
	}
	_ = time.Now()
}

// AWS documentation example: GET ?Action=ListUsers&Version=2010-05-08 at
// 20150830T123600Z with the example credentials.
func TestSigV4KnownVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	SignV4(req, nil, AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "iam", now)
	want := "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, want) {
		t.Fatalf("got %s", got)
	}
}
