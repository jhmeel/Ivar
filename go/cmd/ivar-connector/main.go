// ivar-connector runs the Go connectors and their responders.
//
//	ivar-connector cloud       receivers for CloudTrail (EventBridge), Azure Event Grid, GCP Pub/Sub push
//	ivar-connector okta|entra|workspace|salesforce|github   audit pollers
//	ivar-connector k8s         Kubernetes audit webhook, Vault audit socket and admission webhook
//	ivar-connector telco       SIM swap check service (TIRMS, MTN Chenosis)
//	ivar-connector indicators  the shared indicator network service
//	ivar-connector respond <provider>   responder plugin: JSON lines on stdin and stdout
//
// Configuration comes from the environment (IVAR_CORE_URL, IVAR_SENSOR_ID,
// provider credentials); responders receive only their declared secrets as
// IVAR_SECRET_* from the plugin host.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jhmeel/ivar/go/connectors/cloud"
	"github.com/jhmeel/ivar/go/connectors/identity"
	"github.com/jhmeel/ivar/go/connectors/indicators"
	"github.com/jhmeel/ivar/go/connectors/k8s"
	"github.com/jhmeel/ivar/go/connectors/telco"
	"github.com/jhmeel/ivar/go/internal/coreclient"
	ivar "github.com/jhmeel/ivar/sdk/go"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ivar-connector <cloud|okta|entra|workspace|salesforce|github|k8s|telco|indicators|respond>")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	kind := os.Args[1]
	sensorID := env("IVAR_SENSOR_ID", kind+"-1")
	core := coreclient.New(env("IVAR_CORE_URL", "http://ivar-core:8080"), sensorID, kind)
	go core.Run(ctx, 500*time.Millisecond)
	listen := env("IVAR_LISTEN", ":8085")
	var err error
	switch kind {
	case "cloud":
		r := &cloud.Receiver{Core: core, SensorID: sensorID, Token: os.Getenv("IVAR_PUSH_TOKEN")}
		err = serve(ctx, listen, r.Handler())
	case "okta":
		identity.Run(ctx, identity.NewOkta(sensorID, os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_API_TOKEN")), core, 30*time.Second, time.Now().Add(-time.Hour))
	case "entra":
		identity.Run(ctx, identity.NewEntra(sensorID, os.Getenv("GRAPH_TOKEN")), core, 60*time.Second, time.Now().Add(-time.Hour))
	case "workspace":
		identity.Run(ctx, identity.NewWorkspace(sensorID, os.Getenv("GOOGLE_TOKEN")), core, 60*time.Second, time.Now().Add(-time.Hour))
	case "salesforce":
		identity.Run(ctx, identity.NewSalesforce(sensorID, os.Getenv("SALESFORCE_INSTANCE_URL"), os.Getenv("SALESFORCE_TOKEN")), core, 60*time.Second, time.Now().Add(-time.Hour))
	case "github":
		identity.Run(ctx, identity.NewGitHub(sensorID, os.Getenv("GITHUB_ORG"), os.Getenv("GITHUB_TOKEN")), core, 60*time.Second, time.Now().Add(-time.Hour))
	case "k8s":
		err = runK8s(ctx, core, sensorID, listen)
	case "telco":
		var providers []telco.Provider
		for _, name := range []string{"TIRMS", "CHENOSIS"} {
			if u := os.Getenv(name + "_URL"); u != "" {
				p := &telco.HTTPProvider{ProviderName: name, URL: u, AuthHeader: "Authorization", AuthValue: os.Getenv(name + "_AUTH"), RequestTemplate: env(name+"_REQUEST", `{"msisdn":"{msisdn}"}`),
					SwappedAtField: os.Getenv(name + "_SWAPPED_AT_FIELD"), SwappedField: os.Getenv(name + "_SWAPPED_FIELD"), ReassignedField: os.Getenv(name + "_REASSIGNED_FIELD"), FlaggedField: os.Getenv(name + "_FLAGGED_FIELD")}
				providers = append(providers, p)
			}
		}
		c := &telco.Checker{Providers: providers, Core: core, SensorID: sensorID, KeyHex: os.Getenv("IVAR_REDACTION_KEY_HEX")}
		mux := http.NewServeMux()
		mux.Handle("POST /v1/sim-swap/check", c)
		err = serve(ctx, listen, mux)
	case "indicators":
		n := indicators.New()
		var parts []indicators.Participant
		if b, e := os.ReadFile(env("IVAR_PARTICIPANTS", "/etc/ivar/participants.json")); e == nil {
			_ = json.Unmarshal(b, &parts)
		}
		for _, p := range parts {
			if e := n.Join(p); e != nil {
				log.Printf("participant %s not admitted: %v", p.ID, e)
			}
		}
		err = serve(ctx, listen, n.Handler())
	case "respond":
		err = respond(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown connector %s", kind)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runK8s(ctx context.Context, core *coreclient.Client, sensorID, listen string) error {
	rt, err := ivar.Shared()
	if err != nil {
		return err
	}
	var stepKeys map[string]string
	_ = json.Unmarshal([]byte(env("IVAR_DEPLOY_STEP_KEYS", "{}")), &stepKeys)
	sink, err := ivar.NewSink(rt, os.Getenv("IVAR_INTENT_ROOT_KEY"), stepKeys, nil, env("IVAR_INTENT_BINDING", "observe"), nil)
	if err != nil {
		return err
	}
	var ops map[string]string
	_ = json.Unmarshal([]byte(env("IVAR_OPERATOR_KEYS", "{}")), &ops)
	protected := map[string]bool{}
	var ns []string
	_ = json.Unmarshal([]byte(env("IVAR_PROTECTED_NAMESPACES", "[]")), &ns)
	for _, n := range ns {
		protected[n] = true
	}
	wh := &k8s.Webhook{Operators: ops, Protected: protected, Mode: env("IVAR_MODE", "observe"), Sink: sink}
	mux := http.NewServeMux()
	mux.Handle("POST /admission", wh)
	mux.HandleFunc("POST /audit", func(w http.ResponseWriter, r *http.Request) {
		var list struct {
			Items []k8s.AuditEvent `json:"items"`
		}
		if json.NewDecoder(r.Body).Decode(&list) != nil {
			http.Error(w, "bad audit list", http.StatusBadRequest)
			return
		}
		for _, e := range list.Items {
			if e.Stage == "" || e.Stage == "ResponseComplete" {
				core.Emit(k8s.FromAudit(sensorID, e))
			}
		}
	})
	if sock := os.Getenv("IVAR_VAULT_AUDIT_SOCKET"); sock != "" {
		go func() {
			l, err := net.Listen("tcp", sock)
			if err != nil {
				log.Print(err)
				return
			}
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					sc := bufio.NewScanner(c)
					sc.Buffer(make([]byte, 1<<20), 1<<24)
					for sc.Scan() {
						var e map[string]any
						if json.Unmarshal(sc.Bytes(), &e) == nil && e["type"] == "request" {
							core.Emit(k8s.FromVault(sensorID, e))
						}
					}
				}(c)
			}
		}()
	}
	cert, key := os.Getenv("IVAR_TLS_CERT"), os.Getenv("IVAR_TLS_KEY")
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	if cert != "" {
		err = srv.ListenAndServeTLS(cert, key)
	} else {
		err = srv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// respond speaks the process plugin protocol: one JSON request per line,
// one JSON reply per line.
func respond(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("respond <aws|azure|gcp|okta|entra|workspace|salesforce|github>")
	}
	var r interface {
		Execute(context.Context, string, string) (string, string)
	}
	switch args[0] {
	case "aws", "azure", "gcp":
		c := cloud.NewResponder(os.Getenv)
		c.IsolationGroup = flagValue(args, "--isolation-group")
		r = c
	case "okta":
		// The org URL is configuration, not a secret, so it comes as a flag;
		// the manifest grants only okta_api_token.
		org := flagValue(args, "--org")
		if org == "" {
			org = os.Getenv("IVAR_SECRET_OKTA_ORG_URL")
		}
		r = identity.NewOkta("okta-responder", org, os.Getenv("IVAR_SECRET_OKTA_API_TOKEN"))
	case "entra":
		r = identity.NewEntra("entra-responder", os.Getenv("IVAR_SECRET_GRAPH_TOKEN"))
	case "workspace":
		r = identity.NewWorkspace("workspace-responder", os.Getenv("IVAR_SECRET_GOOGLE_TOKEN"))
	case "salesforce":
		r = identity.NewSalesforce("salesforce-responder", os.Getenv("IVAR_SECRET_SALESFORCE_INSTANCE_URL"), os.Getenv("IVAR_SECRET_SALESFORCE_TOKEN"))
	case "github":
		r = identity.NewGitHub("github-responder", os.Getenv("IVAR_SECRET_GITHUB_ORG"), os.Getenv("IVAR_SECRET_GITHUB_TOKEN"))
	default:
		return fmt.Errorf("unknown responder %s", args[0])
	}
	allowed := map[string]bool{}
	for _, a := range splitComma(os.Getenv("IVAR_PLUGIN_ACTIONS")) {
		allowed[a] = true
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var req struct {
			Request struct {
				Action string `json:"action"`
				Target struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"target"`
			} `json:"request"`
		}
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			_ = out.Encode(map[string]string{"result": "failed", "verification": "malformed request"})
			continue
		}
		a := req.Request.Action
		if !allowed[a] {
			_ = out.Encode(map[string]string{"result": "refused", "verification": a + " is not in this responder's manifest"})
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		res, ver := r.Execute(cctx, a, req.Request.Target.ID)
		cancel()
		_ = out.Encode(map[string]string{"result": res, "verification": ver})
	}
	return in.Err()
}

// flagValue returns the value after name in args, or "".
func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
