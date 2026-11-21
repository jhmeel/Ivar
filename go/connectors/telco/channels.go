package telco

import (
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

// USSD and agent network channels join like any other channel (section 17):
// they report session, agent and device.

// USSDSession builds an event for one USSD session step.
func USSDSession(sensorID, keyHex, sessionID, msisdn, serviceCode, menuPath, operator string, t time.Time) ocsf.Event {
	sub := ocsf.KeyedHash(keyHex, msisdn)
	return ocsf.New(sensorID, "app_sdk", ocsf.ClassAPIActivity, "business.action", t).
		User(sub, "human").Session(sessionID).Ext("business_action", "ussd_session").
		Attr("subscriber", sub).Attr("channel", "ussd").Attr("service_code", serviceCode).Attr("menu_path", menuPath).Attr("operator", operator)
}

// AgentTransaction builds an event for a cash in, cash out or transfer made
// through an agent network, with its value for consequence invariants.
func AgentTransaction(sensorID, keyHex, agentID, deviceIMEI, msisdn, kind string, value float64, t time.Time) ocsf.Event {
	action := "payout"
	if kind == "cash_in" {
		action = "deposit"
	}
	sub := ocsf.KeyedHash(keyHex, msisdn)
	return ocsf.New(sensorID, "app_sdk", ocsf.ClassAPIActivity, "business.action", t).
		User(agentID, "human").Ext("business_action", action).Ext("value_moved", value).Tenant(agentID).
		Attr("subscriber", sub).Attr("channel", "agent_network").Attr("transaction", kind).Attr("device_id", ocsf.KeyedHash(keyHex, deviceIMEI))
}
