// Package k8s is the management plane sensor for Kubernetes control planes
// and secret managers (section 8.3): audit events in (Kubernetes audit
// webhook, Vault audit device), and an admission webhook that holds
// destructive actions pending two person approval and refuses deploys to
// protected namespaces without a deploy intent chain (section 6.2).
package k8s

import (
	"strings"
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

// AuditEvent is the subset of audit.k8s.io/v1 Event the sensor reads.
type AuditEvent struct {
	Verb           string `json:"verb"`
	RequestURI     string `json:"requestURI"`
	StageTimestamp string `json:"stageTimestamp"`
	SourceIPs      []string `json:"sourceIPs"`
	User           struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	ObjectRef struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		APIGroup    string `json:"apiGroup"`
	} `json:"objectRef"`
	ResponseStatus struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	Stage string `json:"stage"`
}

var destructiveResources = map[string]bool{"namespaces": true, "persistentvolumes": true, "persistentvolumeclaims": true, "volumesnapshots": true, "volumesnapshotcontents": true, "backups": true, "backupstoragelocations": true}

// FromAudit maps one Kubernetes audit event.
func FromAudit(sensorID string, e AuditEvent) ocsf.Event {
	t, _ := time.Parse(time.RFC3339Nano, e.StageTimestamp)
	r := e.ObjectRef
	act := "cloud.audit"
	destructive := false
	switch {
	case e.Verb == "delete" || e.Verb == "deletecollection":
		if destructiveResources[r.Resource] {
			act, destructive = "snapshot.delete", true
			if r.Resource == "namespaces" || e.Verb == "deletecollection" {
				act = "vm.mass_action"
			}
		}
	case r.Resource == "secrets" && (e.Verb == "get" || e.Verb == "list" || e.Verb == "watch"):
		act = "secret.read"
	case (r.Resource == "clusterrolebindings" || r.Resource == "rolebindings") && (e.Verb == "create" || e.Verb == "update" || e.Verb == "patch"):
		act = "iam.grant"
	case r.Resource == "pods" && (r.Subresource == "exec" || r.Subresource == "attach"):
		act = "remote.session"
	case r.Resource == "serviceaccounts" && r.Subresource == "token":
		act = "app.secret_create"
	}
	ip := ""
	if len(e.SourceIPs) > 0 {
		ip = e.SourceIPs[0]
	}
	kind := "human"
	if strings.HasPrefix(e.User.Username, "system:serviceaccount:") {
		kind = "service"
	}
	ev := ocsf.New(sensorID, "management_plane", ocsf.ClassAPIActivity, act, t).User(e.User.Username, kind).SrcIP(ip).Status(e.ResponseStatus.Code < 400).
		Attr("operation", e.Verb+" "+r.Resource).Attr("resource", "k8s:"+r.Namespace+"/"+r.Resource+"/"+r.Name).Attr("secret", r.Name).Attr("tool", "kubectl").Tenant(r.Namespace)
	if destructive {
		ev.Destructive()
	}
	if act == "iam.grant" {
		ev.Attr("grantee", r.Name)
	}
	return ev
}

// FromVault maps one Vault audit device record (request type).
func FromVault(sensorID string, e map[string]any) ocsf.Event {
	req, _ := e["request"].(map[string]any)
	auth, _ := e["auth"].(map[string]any)
	path, _ := req["path"].(string)
	op, _ := req["operation"].(string)
	who, _ := auth["display_name"].(string)
	ip, _ := req["remote_address"].(string)
	act := "cloud.audit"
	destructive := false
	switch {
	case (op == "read" || op == "list") && (strings.Contains(path, "/data/") || strings.HasPrefix(path, "secret/") || strings.HasPrefix(path, "kv/")):
		act = "secret.read"
	case strings.HasPrefix(path, "sys/policy") || strings.HasPrefix(path, "sys/policies") || strings.HasPrefix(path, "auth/token/create"):
		act = "iam.grant"
	case op == "delete" && (strings.HasPrefix(path, "sys/mounts") || strings.Contains(path, "/metadata/") || strings.HasPrefix(path, "sys/audit")):
		act, destructive = "backup.change", true
	}
	ev := ocsf.New(sensorID, "management_plane", ocsf.ClassAPIActivity, act, time.Now()).User(who, "service").SrcIP(ip).Attr("operation", op+" "+path).Attr("secret", path).Attr("tool", "vault")
	if destructive {
		ev.Destructive()
	}
	return ev
}
