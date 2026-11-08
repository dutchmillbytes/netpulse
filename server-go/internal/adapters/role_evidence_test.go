package adapters

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestAgentRoleEvidenceInRouter(t *testing.T) {
	now := time.Unix(1700000000, 0)
	reg := NewAgentRegistry(time.Minute)
	reg.SetClock(func() time.Time { return now })
	live := newLiveAgentTest(t, reg)
	cfg := live.routers[0]
	evidence := &probe.RoleEvidence{ObservedAtMs: now.UnixMilli(), Router: true, Config: &probe.RoleConfigState{Wireless: &probe.RoleWirelessState{Interfaces: []probe.RoleWirelessInterface{{Name: "wlan0", Mode: "AP"}}}}}
	reg.Ingest(&probe.Payload{Router: cfg.ID, Data: probe.PayloadData{Roles: evidence}})

	check := func(want bool) {
		t.Helper()
		payload, ok := reg.Fresh(cfg.ID)
		if !ok {
			t.Fatal("agent payload expired")
		}
		router := live.buildRouter(live.polledFromAgent(cfg, payload), nil)
		data, err := json.Marshal(router)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		value, present := decoded["roleEvidence"]
		if present != want {
			t.Fatalf("roleEvidence present=%v, want %v", present, want)
		}
		if present {
			var got probe.RoleEvidence
			if err := json.Unmarshal(value, &got); err != nil {
				t.Fatal(err)
			}
			if got.ObservedAtMs != evidence.ObservedAtMs || got.Router || got.Config == nil || got.Config.Wireless.Interfaces[0].Mode != "AP" {
				t.Fatalf("unexpected evidence: %+v", got)
			}
		}
	}
	check(true)
	now = now.Add(30 * time.Second)
	reg.Ingest(&probe.Payload{Router: cfg.ID}) // Event-only push.
	check(true)
	now = now.Add(31 * time.Second)
	check(false) // Event traffic did not extend the observation lifetime.
	reg.Ingest(&probe.Payload{Router: "older-agent"})
	older, _ := reg.Fresh("older-agent")
	if older.Data.Roles != nil {
		t.Fatal("older agent acquired evidence")
	}
}
