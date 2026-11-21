package identity

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

// Workspace reads Google Workspace Reports (token, login and admin) and revokes OAuth tokens.
type Workspace struct {
	SensorID string
	API      api
	DirAPI   api
}

func NewWorkspace(sensorID, bearer string) *Workspace {
	return &Workspace{SensorID: sensorID, API: api{base: "https://admin.googleapis.com/admin/reports/v1", auth: "Bearer " + bearer}, DirAPI: api{base: "https://admin.googleapis.com/admin/directory/v1", auth: "Bearer " + bearer}}
}

func (w *Workspace) Name() string { return "google_workspace" }

func param(e map[string]any, name string) string {
	evs, _ := e["events"].([]any)
	for _, x := range evs {
		ps, _ := x.(map[string]any)["parameters"].([]any)
		for _, p := range ps {
			pm := p.(map[string]any)
			if pm["name"] == name {
				return s(pm, "value")
			}
		}
	}
	return ""
}

func (w *Workspace) Map(app string, e map[string]any) ocsf.Event {
	t, _ := time.Parse(time.RFC3339, s(e, "id", "time"))
	who := s(e, "actor", "email")
	name := s(e, "events", "name")
	act := "cloud.audit"
	switch {
	case app == "token" && name == "authorize":
		act = "oauth.grant"
	case app == "login" && (name == "login_success" || name == "login_failure"):
		act = "auth.login"
	case app == "admin" && (strings.Contains(name, "ASSIGN_ROLE") || strings.Contains(name, "GRANT_ADMIN_PRIVILEGE")):
		act = "iam.grant"
	case app == "admin" && strings.Contains(name, "DOWNLOAD"):
		act = "business.action"
	}
	ev := ocsf.New(w.SensorID, "saas_identity", ocsf.ClassAPIActivity, act, t).User(who, "human").SrcIP(s(e, "ipAddress")).Status(name != "login_failure").
		Attr("operation", name).Attr("provider", "google_workspace")
	if act == "oauth.grant" {
		ev.Attr("oauth_grant", param(e, "client_id")).Attr("app", param(e, "app_name")).Attr("scope", param(e, "scope"))
	}
	if act == "iam.grant" {
		ev.Attr("grantee", param(e, "USER_EMAIL")).Attr("role", param(e, "ROLE_NAME"))
	}
	return ev
}

func (w *Workspace) Poll(ctx context.Context, since time.Time) ([]ocsf.Event, time.Time, error) {
	var out []ocsf.Event
	for _, app := range []string{"token", "login", "admin"} {
		var r struct {
			Items []map[string]any `json:"items"`
		}
		if err := w.API.get(ctx, "/activity/users/all/applications/"+app+"?startTime="+url.QueryEscape(since.UTC().Format(time.RFC3339)), &r); err != nil {
			return nil, since, err
		}
		for _, e := range r.Items {
			out = append(out, w.Map(app, e))
		}
	}
	return out, time.Now().Add(-time.Minute), nil
}

// Execute revokes one OAuth grant: subject is "user@domain/clientId".
func (w *Workspace) Execute(ctx context.Context, action, subject string) (string, string) {
	if action != "oauth_grant.revoke" {
		return "failed", "workspace responder does not perform " + action
	}
	user, client, _ := strings.Cut(subject, "/")
	if err := w.DirAPI.send(ctx, "DELETE", "/users/"+url.PathEscape(user)+"/tokens/"+url.PathEscape(client), nil); err != nil {
		return "failed", err.Error()
	}
	return "done", "workspace token " + client + " revoked for " + user
}

// Salesforce reads SetupAuditTrail, LoginHistory and bulk API event logs, and freezes users.
type Salesforce struct {
	SensorID string
	API      api
}

func NewSalesforce(sensorID, instance, bearer string) *Salesforce {
	return &Salesforce{SensorID: sensorID, API: api{base: instance + "/services/data/v61.0", auth: "Bearer " + bearer}}
}

func (f *Salesforce) Name() string { return "salesforce" }

func (f *Salesforce) query(ctx context.Context, soql string) ([]map[string]any, error) {
	var r struct {
		Records []map[string]any `json:"records"`
	}
	err := f.API.get(ctx, "/query?q="+url.QueryEscape(soql), &r)
	return r.Records, err
}

func (f *Salesforce) Poll(ctx context.Context, since time.Time) ([]ocsf.Event, time.Time, error) {
	ts := since.UTC().Format("2006-01-02T15:04:05Z")
	var out []ocsf.Event
	logins, err := f.query(ctx, "SELECT UserId, LoginTime, SourceIp, Status, Application FROM LoginHistory WHERE LoginTime > "+ts)
	if err != nil {
		return nil, since, err
	}
	for _, l := range logins {
		t, _ := time.Parse("2006-01-02T15:04:05.000+0000", s(l, "LoginTime"))
		ok := s(l, "Status") == "Success"
		ev := ocsf.New(f.SensorID, "saas_identity", ocsf.ClassAuthentication, "auth.login", t).SrcIP(s(l, "SourceIp")).Status(ok).Attr("app", s(l, "Application")).Attr("provider", "salesforce")
		if ok {
			ev.User(s(l, "UserId"), "human")
		} else {
			ev.Target("user:" + s(l, "UserId"))
		}
		out = append(out, ev)
	}
	audits, err := f.query(ctx, "SELECT Action, Section, CreatedById, Display, CreatedDate FROM SetupAuditTrail WHERE CreatedDate > "+ts)
	if err != nil {
		return nil, since, err
	}
	for _, a := range audits {
		t, _ := time.Parse("2006-01-02T15:04:05.000+0000", s(a, "CreatedDate"))
		action := strings.ToLower(s(a, "Action"))
		act := "cloud.audit"
		if strings.Contains(action, "permset") || strings.Contains(action, "profile") || strings.Contains(action, "role") {
			act = "iam.grant"
		} else if strings.Contains(action, "connectedapp") || strings.Contains(action, "oauth") {
			act = "oauth.grant"
		}
		out = append(out, ocsf.New(f.SensorID, "saas_identity", ocsf.ClassAccountChange, act, t).User(s(a, "CreatedById"), "human").Attr("operation", s(a, "Action")).Attr("provider", "salesforce").Message(s(a, "Display")))
	}
	bulk, err := f.query(ctx, "SELECT Id, EventType, LogDate, LogFileLength FROM EventLogFile WHERE EventType IN ('BulkApi','BulkApi2','ReportExport') AND LogDate > "+ts)
	if err == nil {
		for _, b := range bulk {
			out = append(out, ocsf.New(f.SensorID, "saas_identity", ocsf.ClassDatastore, "business.action", time.Now()).Ext("business_action", "bulk_export").Attr("event_log", s(b, "Id")).Attr("provider", "salesforce"))
		}
	}
	return out, time.Now().Add(-time.Minute), nil
}

// Execute freezes or unfreezes a user (subject: UserLogin id).
func (f *Salesforce) Execute(ctx context.Context, action, subject string) (string, string) {
	frozen := map[string]bool{"user.suspend": true, "user.lock": true, "user.unlock": false}
	v, ok := frozen[action]
	if !ok {
		return "failed", "salesforce responder does not perform " + action
	}
	if err := f.API.send(ctx, "PATCH", "/sobjects/UserLogin/"+url.PathEscape(subject), map[string]any{"IsFrozen": v}); err != nil {
		return "failed", err.Error()
	}
	return "done", "salesforce " + action + " for " + subject
}

// GitHub reads the organisation audit log and removes credential authorisations.
type GitHub struct {
	SensorID, Org string
	API           api
}

func NewGitHub(sensorID, org, token string) *GitHub {
	return &GitHub{SensorID: sensorID, Org: org, API: api{base: "https://api.github.com", auth: "Bearer " + token, extra: map[string]string{"X-GitHub-Api-Version": "2022-11-28"}}}
}

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) Map(e map[string]any) ocsf.Event {
	ms, _ := e["@timestamp"].(float64)
	t := time.UnixMilli(int64(ms))
	action := s(e, "action")
	act := "cloud.audit"
	switch {
	case strings.HasPrefix(action, "oauth_authorization.create"), strings.HasPrefix(action, "integration_installation.create"), strings.HasPrefix(action, "oauth_application.create"):
		act = "oauth.grant"
	case strings.HasPrefix(action, "personal_access_token.") || strings.HasPrefix(action, "deploy_key.create") || strings.HasPrefix(action, "secret_scanning"):
		act = "app.secret_create"
	case action == "org.update_member" || action == "team.add_member" && strings.Contains(s(e, "team"), "admin") || action == "repo.add_member":
		act = "iam.grant"
	case action == "repo.download_zip" || action == "git.clone":
		act = "business.action"
	case strings.HasPrefix(action, "workflows.") || action == "repo.actions_enabled":
		act = "workflow.change"
	}
	ev := ocsf.New(g.SensorID, "saas_identity", ocsf.ClassAPIActivity, act, t).User(s(e, "actor"), "human").SrcIP(s(e, "actor_ip")).
		Attr("operation", action).Attr("resource", "github:"+s(e, "repo")).Attr("provider", "github")
	if act == "business.action" {
		ev.Ext("business_action", "bulk_export").Records(1)
	}
	if act == "iam.grant" {
		ev.Attr("grantee", s(e, "user"))
	}
	return ev
}

func (g *GitHub) Poll(ctx context.Context, since time.Time) ([]ocsf.Event, time.Time, error) {
	var entries []map[string]any
	phrase := url.QueryEscape("created:>=" + since.UTC().Format("2006-01-02T15:04:05Z"))
	if err := g.API.get(ctx, "/orgs/"+url.PathEscape(g.Org)+"/audit-log?per_page=100&order=asc&phrase="+phrase, &entries); err != nil {
		return nil, since, err
	}
	out := make([]ocsf.Event, 0, len(entries))
	next := since
	for _, e := range entries {
		out = append(out, g.Map(e))
		if ms, ok := e["@timestamp"].(float64); ok {
			if t := time.UnixMilli(int64(ms)); t.After(next) {
				next = t.Add(time.Millisecond)
			}
		}
	}
	return out, next, nil
}

// Execute removes a SAML SSO credential authorisation (subject: credential id).
func (g *GitHub) Execute(ctx context.Context, action, subject string) (string, string) {
	if action != "oauth_grant.revoke" && action != "api_key.suspend" {
		return "failed", "github responder does not perform " + action
	}
	if err := g.API.send(ctx, "DELETE", "/orgs/"+url.PathEscape(g.Org)+"/credential-authorizations/"+url.PathEscape(subject), nil); err != nil {
		return "failed", err.Error()
	}
	return "done", "github credential authorization " + subject + " removed"
}
