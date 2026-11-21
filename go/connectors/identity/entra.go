package identity

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

// Entra reads Microsoft Graph sign ins and directory audits (Entra ID and
// Microsoft 365) and revokes sessions, disables users and removes OAuth grants.
type Entra struct {
	SensorID string
	API      api
}

func NewEntra(sensorID, bearer string) *Entra {
	return &Entra{SensorID: sensorID, API: api{base: "https://graph.microsoft.com/v1.0", auth: "Bearer " + bearer}}
}

func (g *Entra) Name() string { return "entra" }

func (g *Entra) MapSignIn(e map[string]any) ocsf.Event {
	t, _ := time.Parse(time.RFC3339, s(e, "createdDateTime"))
	ok := s(e, "status", "errorCode") == "0" || s(e, "status", "errorCode") == ""
	upn := s(e, "userPrincipalName")
	ev := ocsf.New(g.SensorID, "identity", ocsf.ClassAuthentication, "auth.login", t).SrcIP(s(e, "ipAddress")).Status(ok).
		Attr("app", s(e, "appDisplayName")).Attr("device_id", s(e, "deviceDetail", "deviceId")).Attr("idp_risk", s(e, "riskLevelDuringSignIn")).Attr("provider", "entra")
	if ok {
		ev.User(upn, "human").Session(s(e, "correlationId"))
	} else {
		ev.Target("user:" + upn)
	}
	return ev
}

func (g *Entra) MapAudit(e map[string]any) ocsf.Event {
	t, _ := time.Parse(time.RFC3339, s(e, "activityDateTime"))
	activity := s(e, "activityDisplayName")
	who := s(e, "initiatedBy", "user", "userPrincipalName")
	kind := "human"
	if who == "" {
		who = s(e, "initiatedBy", "app", "servicePrincipalId")
		kind = "service"
	}
	target := s(e, "targetResources", "id")
	a := strings.ToLower(activity)
	act := "cloud.audit"
	switch {
	case strings.Contains(a, "add app role assignment") || strings.Contains(a, "add member to role") || strings.Contains(a, "add eligible member to role"):
		act = "iam.grant"
	case strings.Contains(a, "consent to application") || strings.Contains(a, "add delegated permission grant"):
		act = "oauth.grant"
	case strings.Contains(a, "credentials") || strings.Contains(a, "add service principal credentials") || strings.Contains(a, "update application – certificates and secrets"):
		act = "app.secret_create"
	}
	ev := ocsf.New(g.SensorID, "saas_identity", ocsf.ClassAccountChange, act, t).User(who, kind).Status(s(e, "result") == "success").
		Attr("operation", activity).Attr("resource", "entra:"+target).Attr("provider", "entra")
	if act == "iam.grant" {
		ev.Attr("grantee", target)
	}
	return ev
}

func (g *Entra) Poll(ctx context.Context, since time.Time) ([]ocsf.Event, time.Time, error) {
	f := url.QueryEscape("createdDateTime ge " + since.UTC().Format(time.RFC3339))
	var signIns struct {
		Value []map[string]any `json:"value"`
	}
	if err := g.API.get(ctx, "/auditLogs/signIns?$filter="+f+"&$top=999", &signIns); err != nil {
		return nil, since, err
	}
	fa := url.QueryEscape("activityDateTime ge " + since.UTC().Format(time.RFC3339))
	var audits struct {
		Value []map[string]any `json:"value"`
	}
	if err := g.API.get(ctx, "/auditLogs/directoryAudits?$filter="+fa+"&$top=999", &audits); err != nil {
		return nil, since, err
	}
	var out []ocsf.Event
	next := since
	for _, e := range signIns.Value {
		out = append(out, g.MapSignIn(e))
		if t, err := time.Parse(time.RFC3339, s(e, "createdDateTime")); err == nil && t.After(next) {
			next = t
		}
	}
	for _, e := range audits.Value {
		out = append(out, g.MapAudit(e))
	}
	return out, next.Add(time.Second), nil
}

func (g *Entra) Execute(ctx context.Context, action, subject string) (string, string) {
	var err error
	switch action {
	case "session.revoke":
		err = g.API.send(ctx, "POST", "/users/"+url.PathEscape(subject)+"/revokeSignInSessions", nil)
	case "user.suspend", "user.lock":
		err = g.API.send(ctx, "PATCH", "/users/"+url.PathEscape(subject), map[string]any{"accountEnabled": false})
	case "user.unlock":
		err = g.API.send(ctx, "PATCH", "/users/"+url.PathEscape(subject), map[string]any{"accountEnabled": true})
	case "oauth_grant.revoke":
		err = g.API.send(ctx, "DELETE", "/oauth2PermissionGrants/"+url.PathEscape(subject), nil)
	default:
		return "failed", "entra responder does not perform " + action
	}
	if err != nil {
		return "failed", err.Error()
	}
	return "done", "entra " + action + " for " + subject
}
