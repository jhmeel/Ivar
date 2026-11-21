package identity

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

// Okta reads the System Log (/api/v1/logs) and revokes sessions or suspends users.
type Okta struct {
	SensorID, Org, Token string
	API                  api
}

func NewOkta(sensorID, org, token string) *Okta {
	return &Okta{SensorID: sensorID, Org: org, Token: token, API: api{base: org, auth: "SSWS " + token}}
}

func (o *Okta) Name() string { return "okta" }

var oktaAdminGroups = []string{"admin", "super", "privileged"}

func (o *Okta) Map(e map[string]any) ocsf.Event {
	t, _ := time.Parse(time.RFC3339, s(e, "published"))
	typ := s(e, "eventType")
	actor := s(e, "actor", "alternateId")
	target := s(e, "target", "alternateId")
	ok := s(e, "outcome", "result") == "SUCCESS"
	act := "cloud.audit"
	switch {
	case typ == "user.session.start" || typ == "user.authentication.sso":
		act = "auth.login"
	case typ == "user.account.privilege.grant", strings.HasPrefix(typ, "group.user_membership.add") && containsAny(strings.ToLower(s(e, "target", "displayName")), oktaAdminGroups):
		act = "iam.grant"
	case typ == "app.oauth2.as.consent.grant", typ == "app.oauth2.consent.grant":
		act = "oauth.grant"
	case typ == "system.api_token.create", strings.HasPrefix(typ, "app.oauth2.client.secret"):
		act = "app.secret_create"
	case typ == "user.account.update_password", typ == "user.account.reset_password":
		act = "auth.password_reset"
	}
	ev := ocsf.New(o.SensorID, "identity", ocsf.ClassAuthentication, act, t).SrcIP(s(e, "client", "ipAddress")).Status(ok).
		Attr("operation", typ).Attr("resource", "okta:"+target).Attr("device_id", s(e, "client", "device")).Attr("provider", "okta")
	if act == "auth.login" && !ok {
		ev.Target("user:" + actor)
	} else {
		ev.User(actor, "human")
	}
	if risk := s(e, "debugContext", "debugData", "risk"); risk != "" {
		ev.Attr("idp_risk", risk)
	}
	if act == "iam.grant" {
		ev.Attr("grantee", target)
	}
	if sid := s(e, "authenticationContext", "externalSessionId"); sid != "" {
		ev.Session(sid)
	}
	return ev
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func (o *Okta) Poll(ctx context.Context, since time.Time) ([]ocsf.Event, time.Time, error) {
	var logs []map[string]any
	if err := o.API.get(ctx, "/api/v1/logs?limit=1000&sortOrder=ASCENDING&since="+url.QueryEscape(since.UTC().Format(time.RFC3339)), &logs); err != nil {
		return nil, since, err
	}
	out := make([]ocsf.Event, 0, len(logs))
	next := since
	for _, l := range logs {
		out = append(out, o.Map(l))
		if t, err := time.Parse(time.RFC3339, s(l, "published")); err == nil && t.After(next) {
			next = t.Add(time.Millisecond)
		}
	}
	return out, next, nil
}

// Execute: session.revoke clears all sessions; user.suspend suspends the user.
func (o *Okta) Execute(ctx context.Context, action, user string) (string, string) {
	var err error
	switch action {
	case "session.revoke":
		err = o.API.send(ctx, "DELETE", "/api/v1/users/"+url.PathEscape(user)+"/sessions?oauthTokens=true", nil)
	case "user.suspend", "user.lock":
		err = o.API.send(ctx, "POST", "/api/v1/users/"+url.PathEscape(user)+"/lifecycle/suspend", nil)
	case "user.unlock":
		err = o.API.send(ctx, "POST", "/api/v1/users/"+url.PathEscape(user)+"/lifecycle/unsuspend", nil)
	default:
		return "failed", "okta responder does not perform " + action
	}
	if err != nil {
		return "failed", err.Error()
	}
	return "done", "okta " + action + " for " + user
}
