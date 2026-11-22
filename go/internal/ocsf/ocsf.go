// Package ocsf builds OCSF SecurityEvents with the IVAR extension, in the
// JSON shape of the ivar.v1 contracts, for the Go connectors.
package ocsf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync/atomic"
	"time"
)

// Class uids used by the connectors.
const (
	ClassAuthentication = 3002
	ClassAccountChange  = 3001
	ClassAPIActivity    = 6003
	ClassDatastore      = 6005
	ClassAppLifecycle   = 6002
)

// Event is a SecurityEvent in its JSON form.
type Event map[string]any

var seq atomic.Uint64

// New starts an event for one connector.
func New(sensorID, sensorType string, classUID int, activity string, t time.Time) Event {
	return Event{
		"class_uid":     classUID,
		"category_uid":  classUID / 1000,
		"activity_id":   1,
		"type_uid":      classUID*100 + 1,
		"time":          t.UnixMilli(),
		"severity_id":   1,
		"status_id":     1,
		"activity_name": activity,
		"metadata": map[string]any{
			"version":    "1.3.0",
			"product":    map[string]any{"name": "ivar", "vendor_name": "ivar", "version": "0.1.1"},
			"extensions": []any{map[string]any{"name": "ivar", "uid": "999", "version": "1.0.0"}},
		},
		"ivar": map[string]any{
			"sensor_id":         sensorID,
			"sensor_type":       sensorType,
			"observation_point": sensorType,
			"sensor_seq":        seq.Add(1),
			"attributes":        map[string]string{},
		},
	}
}

func (e Event) ext() map[string]any { return e["ivar"].(map[string]any) }

// Attr sets one string attribute in the IVAR extension.
func (e Event) Attr(k, v string) Event {
	e.ext()["attributes"].(map[string]string)[k] = v
	return e
}

// Ext sets a field of the IVAR extension.
func (e Event) Ext(k string, v any) Event { e.ext()[k] = v; return e }

func (e Event) actor() map[string]any {
	a, ok := e["actor"].(map[string]any)
	if !ok {
		a = map[string]any{}
		e["actor"] = a
	}
	return a
}

// User sets the acting identity (human, service, agent).
func (e Event) User(uid, kind string) Event {
	if uid != "" {
		e.actor()["user"] = map[string]any{"uid": uid, "type": kind}
	}
	return e
}

// Session sets the session id.
func (e Event) Session(uid string) Event {
	if uid != "" {
		e.actor()["session"] = map[string]any{"uid": uid}
	}
	return e
}

// App sets the acting application.
func (e Event) App(name string) Event {
	if name != "" {
		e.actor()["app_name"] = name
	}
	return e
}

// SrcIP sets the source address.
func (e Event) SrcIP(ip string) Event {
	if ip != "" {
		e["src_endpoint"] = map[string]any{"ip": ip}
	}
	return e
}

// Status sets success or failure.
func (e Event) Status(ok bool) Event {
	if ok {
		e["status_id"] = 1
	} else {
		e["status_id"] = 2
	}
	return e
}

// Target names an entity that was only targeted ("user:alice").
func (e Event) Target(t string) Event { return e.Ext("target_entity", t) }

// Records sets records read, for consequence invariants.
func (e Event) Records(n uint64) Event { return e.Ext("records_read", n) }

// Destructive marks a destructive operation.
func (e Event) Destructive() Event { return e.Ext("destructive", true) }

// Tenant sets the business or tenant.
func (e Event) Tenant(t string) Event { return e.Ext("tenant", t) }

// Message sets the free text message.
func (e Event) Message(m string) Event {
	if len(m) > 1024 {
		m = m[:1024]
	}
	e["message"] = m
	return e
}

// KeyedHash matches ivar_core::redact::keyed_hash.
func KeyedHash(keyHex, v string) string {
	key, err := hex.DecodeString(keyHex)
	if v == "" || strings.HasPrefix(v, "kh_") || keyHex == "" || err != nil {
		return v
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(v))
	return "kh_" + hex.EncodeToString(m.Sum(nil))[:24]
}
