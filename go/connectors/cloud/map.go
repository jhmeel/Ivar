// Package cloud is the cloud connector (section 8): AWS, Azure and Google
// Cloud audit events in through their event streams (CloudTrail through
// EventBridge, Azure Event Grid, Cloud Audit Logs through Pub/Sub push), and
// revocation out through the providers' IAM APIs.
package cloud

import (
	"strings"
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

// Activity names from the core's vocabulary.
const (
	actLogin        = "auth.login"
	actGrant        = "iam.grant"
	actSecretCreate = "app.secret_create"
	actSecretRead   = "secret.read"
	actSnapshotDel  = "snapshot.delete"
	actBackup       = "backup.change"
	actAudit        = "cloud.audit"
	actMassVM       = "vm.mass_action"
)

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

// classify maps a provider operation to an activity.
func classify(op string) (activity string, destructive bool) {
	o := strings.ToLower(op)
	switch {
	case strings.Contains(o, "consolelogin") || strings.HasSuffix(o, "signin"):
		return actLogin, false
	case strings.Contains(o, "createaccesskey") || strings.Contains(o, "createserviceaccountkey") || strings.Contains(o, "credentials/write") || strings.Contains(o, "addpassword"):
		return actSecretCreate, false
	case strings.Contains(o, "attachrolepolicy") || strings.Contains(o, "putrolepolicy") || strings.Contains(o, "attachuserpolicy") || strings.Contains(o, "putuserpolicy") || strings.Contains(o, "addusertogroup") || strings.Contains(o, "setiampolicy") || strings.Contains(o, "roleassignments/write"):
		return actGrant, false
	case strings.Contains(o, "getsecretvalue") || strings.Contains(o, "accesssecretversion") || strings.Contains(o, "secrets/read") || strings.Contains(o, "secrets/getsecret"):
		return actSecretRead, false
	case strings.Contains(o, "deletesnapshot") || strings.Contains(o, "deletedbsnapshot") || strings.Contains(o, "deleterecoverypoint") || strings.Contains(o, "snapshots/delete") || strings.Contains(o, "snapshots.delete"):
		return actSnapshotDel, true
	case strings.Contains(o, "deletebackupvault") || strings.Contains(o, "vaults/delete") || strings.Contains(o, "backupvaults/delete") || strings.Contains(o, "stoplogging") || strings.Contains(o, "deletetrail"):
		return actBackup, true
	case strings.Contains(o, "terminateinstances") || strings.Contains(o, "virtualmachines/delete") || strings.Contains(o, "instances.delete"):
		return actMassVM, true
	}
	return actAudit, false
}

// FromCloudTrail maps an EventBridge "AWS API Call via CloudTrail" event.
func FromCloudTrail(sensorID string, e map[string]any) ocsf.Event {
	d, _ := e["detail"].(map[string]any)
	if d == nil {
		d = e
	}
	name := str(d, "eventName")
	act, destructive := classify(name)
	t, _ := time.Parse(time.RFC3339, str(d, "eventTime"))
	who := str(d, "userIdentity", "arn")
	ev := ocsf.New(sensorID, "cloud", ocsf.ClassAPIActivity, act, t).User(who, "service").SrcIP(str(d, "sourceIPAddress")).Status(str(d, "errorCode") == "").
		Attr("operation", name).Attr("resource", str(d, "eventSource")).Attr("region", str(d, "awsRegion")).Attr("provider", "aws")
	if k := str(d, "userIdentity", "accessKeyId"); k != "" {
		ev.Attr("api_key", k)
	}
	if act == actGrant {
		grantee := str(d, "requestParameters", "roleName")
		if grantee == "" {
			grantee = str(d, "requestParameters", "userName")
		}
		ev.Attr("grantee", grantee).Attr("role", str(d, "requestParameters", "policyArn"))
		// A role that grants to itself: the session's role name is in the ARN.
		if grantee != "" && strings.Contains(who, "/"+grantee+"/") {
			ev.Attr("grantee", who)
		}
	}
	if destructive {
		ev.Destructive()
	}
	return ev
}

// FromAzureActivity maps an Event Grid activity log event.
func FromAzureActivity(sensorID string, e map[string]any) ocsf.Event {
	data, _ := e["data"].(map[string]any)
	if data == nil {
		data = e
	}
	op := str(data, "operationName")
	act, destructive := classify(op)
	t, _ := time.Parse(time.RFC3339, str(e, "eventTime"))
	caller := str(data, "caller")
	ev := ocsf.New(sensorID, "cloud", ocsf.ClassAPIActivity, act, t).User(caller, "service").SrcIP(str(data, "claims", "ipaddr")).
		Status(!strings.EqualFold(str(data, "status"), "Failed")).Attr("operation", op).Attr("resource", str(data, "resourceUri")).Attr("provider", "azure")
	if act == actGrant {
		ev.Attr("grantee", str(data, "authorization", "evidence", "principalId"))
	}
	if destructive {
		ev.Destructive()
	}
	return ev
}

// FromGCPAudit maps a Cloud Audit Logs LogEntry.
func FromGCPAudit(sensorID string, entry map[string]any) ocsf.Event {
	p, _ := entry["protoPayload"].(map[string]any)
	if p == nil {
		p = map[string]any{}
	}
	method := str(p, "methodName")
	act, destructive := classify(method)
	t, _ := time.Parse(time.RFC3339Nano, str(entry, "timestamp"))
	who := str(p, "authenticationInfo", "principalEmail")
	ok := true
	if st, has := p["status"].(map[string]any); has && st["code"] != nil {
		ok = false
	}
	ev := ocsf.New(sensorID, "cloud", ocsf.ClassAPIActivity, act, t).User(who, "service").SrcIP(str(p, "requestMetadata", "callerIp")).Status(ok).
		Attr("operation", method).Attr("resource", str(p, "resourceName")).Attr("provider", "gcp")
	if destructive {
		ev.Destructive()
	}
	return ev
}
