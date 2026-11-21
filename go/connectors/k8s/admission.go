package k8s

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	ivar "github.com/ivar/ivar/sdk/go"
)

// AdmissionReview v1, the fields the webhook reads and writes.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID       string          `json:"uid"`
	Operation string          `json:"operation"`
	Namespace string          `json:"namespace"`
	Name      string          `json:"name"`
	Resource  struct {
		Resource string `json:"resource"`
	} `json:"resource"`
	UserInfo struct {
		Username string `json:"username"`
	} `json:"userInfo"`
	Object    json.RawMessage `json:"object"`
	OldObject json.RawMessage `json:"oldObject"`
}

type AdmissionResponse struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	Status  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Approval is one operator's signature over "<resource>/<namespace>/<name>".
type Approval struct {
	Operator  string `json:"operator"`
	Signature string `json:"signature"`
}

// Webhook enforces destructive action approval and deploy intent.
type Webhook struct {
	// Operator public keys (hex ed25519) from the staff key registry.
	Operators map[string]string
	// Namespaces where deploys need an intent chain.
	Protected map[string]bool
	// Mode: observe returns warnings instead of denials.
	Mode string
	// Deploy intent verification through the core (wasm).
	Sink *ivar.Sink
}

func (w *Webhook) approved(resource, ns, name string, approvals []Approval) (int, []string) {
	msg := []byte(resource + "/" + ns + "/" + name)
	seen := map[string]bool{}
	var problems []string
	for _, a := range approvals {
		pk, err := hex.DecodeString(w.Operators[a.Operator])
		sig, err2 := base64.StdEncoding.DecodeString(a.Signature)
		if err != nil || err2 != nil || len(pk) != ed25519.PublicKeySize || !ed25519.Verify(pk, msg, sig) {
			problems = append(problems, "invalid approval from "+a.Operator)
			continue
		}
		seen[a.Operator] = true
	}
	return len(seen), problems
}

type objMeta struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Image string `json:"image"`
		} `json:"containers"`
		Template struct {
			Spec struct {
				Containers []struct {
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

// Review decides one admission request.
func (w *Webhook) Review(r *AdmissionRequest) *AdmissionResponse {
	deny := func(code int, msg string) *AdmissionResponse {
		if w.Mode != "enforce" {
			return &AdmissionResponse{UID: r.UID, Allowed: true, Warnings: []string{"ivar observe: would deny: " + msg}}
		}
		resp := &AdmissionResponse{UID: r.UID, Allowed: false}
		resp.Status = &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{code, msg}
		return resp
	}
	res := r.Resource.Resource
	if r.Operation == "DELETE" && destructiveResources[res] {
		var old objMeta
		_ = json.Unmarshal(r.OldObject, &old)
		var approvals []Approval
		_ = json.Unmarshal([]byte(old.Metadata.Annotations["ivar.dev/approvals"]), &approvals)
		n, problems := w.approved(res, r.Namespace, r.Name, approvals)
		if n < 2 {
			return deny(403, fmt.Sprintf("destructive delete of %s %s/%s needs two operator approvals (has %d) %s", res, r.Namespace, r.Name, n, strings.Join(problems, "; ")))
		}
		return &AdmissionResponse{UID: r.UID, Allowed: true}
	}
	if (r.Operation == "CREATE" || r.Operation == "UPDATE") && w.Protected[r.Namespace] && (res == "deployments" || res == "pods" || res == "statefulsets" || res == "daemonsets") {
		var obj objMeta
		_ = json.Unmarshal(r.Object, &obj)
		containers := obj.Spec.Containers
		if len(containers) == 0 {
			containers = obj.Spec.Template.Spec.Containers
		}
		for _, c := range containers {
			if !strings.Contains(c.Image, "@sha256:") {
				return deny(403, "image "+c.Image+" is not pinned by digest")
			}
		}
		token := obj.Metadata.Annotations["ivar.dev/deploy-intent"]
		if w.Sink == nil {
			return deny(503, "deploy intent verification unavailable")
		}
		req := ivar.SinkRequest{Action: "deploy", Subject: r.Namespace + "/" + obj.Metadata.Name, Identity: r.UserInfo.Username, Business: r.Namespace}
		if token != "" {
			req.IntentToken = &token
		}
		d, err := w.Sink.Guard(req, nowMs())
		if err != nil {
			return deny(503, "deploy intent verification failed closed: "+err.Error())
		}
		if d.Outcome.Outcome == "refused" {
			return deny(403, "no deploy intent chain (reviewed commit, approved change, build provenance): "+d.Outcome.Reason)
		}
	}
	return &AdmissionResponse{UID: r.UID, Allowed: true}
}

// ServeHTTP handles AdmissionReview requests.
func (w *Webhook) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var review AdmissionReview
	if json.NewDecoder(req.Body).Decode(&review) != nil || review.Request == nil {
		http.Error(rw, "bad admission review", http.StatusBadRequest)
		return
	}
	review.Response = w.Review(review.Request)
	review.Request = nil
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(review)
}
