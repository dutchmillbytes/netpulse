package probe

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func roleFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/roles/" + name + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRoleConfigRealDevices(t *testing.T) {
	for _, name := range []string{"mt7621-router", "ipq40xx-ap", "gs108t-switch", "gs108t-routed"} {
		t.Run(name, func(t *testing.T) {
			got := ParseRoleEvidence(roleFixture(t, name))
			if got == nil || got.Config == nil || got.Config.Network == nil || got.Config.Wireless == nil || got.Config.Bridging == nil {
				t.Fatalf("missing configuration: %+v", got)
			}
			// The collector reports facts; role derivation belongs to the server.
			if got.Router || got.AP || got.Switch {
				t.Fatal("collector assigned operational roles")
			}
			if name == "gs108t-switch" || name == "gs108t-routed" {
				if len(got.Config.Bridging.Bridges) != 1 || len(got.Config.Bridging.Bridges[0].EthernetPorts) != 8 {
					t.Fatalf("missing eight-port bridge: %+v", got.Config.Bridging)
				}
				if len(got.Config.Wireless.Interfaces) != 0 {
					t.Fatal("wireless absence was not observed")
				}
				if name == "gs108t-routed" && (len(got.Config.Network.Forwardings) != 1 || !got.Config.Network.Forwardings[0].Enabled) {
					t.Fatal("configured inter-VLAN forwarding was hidden")
				}
				if name == "gs108t-switch" && (len(got.Config.Network.Forwardings) != 0 || *got.Config.Network.IPv4Forwarding || *got.Config.Network.IPv6Forwarding) {
					t.Fatal("updated switch-only configuration was not preserved")
				}
			}
			if name == "ipq40xx-ap" && len(got.Config.Wireless.Interfaces) != 3 {
				t.Fatalf("missing wireless modes: %+v", got.Config.Wireless)
			}
		})
	}
}

func TestRoleConfigUnavailableIsNotAbsent(t *testing.T) {
	base := roleFixture(t, "gs108t-switch")
	noInventory := strings.Replace(base, "==wireless-devices==\nknown\n", "==wireless-devices==\nunavailable\n", 1)
	if e := ParseRoleEvidence(noInventory); e.Config.Wireless != nil {
		t.Fatal("missing iw and failed inventory became wireless absence")
	}
	radios := strings.Replace(base, "==wireless-devices==\nknown\n", "==wireless-devices==\nknown\nphy0\n", 1)
	if e := ParseRoleEvidence(radios); e.Config.Wireless != nil {
		t.Fatal("present radio without mode evidence became wireless absence")
	}
	noPorts := strings.Replace(base, "==ethernet-ports==\nknown\n", "==ethernet-ports==\nunavailable\n", 1)
	if e := ParseRoleEvidence(noPorts); e.Config.Bridging != nil {
		t.Fatal("failed port inventory became valid bridge evidence")
	}
	noFirewall := strings.Replace(base, "==firewall==\n", "==firewall==\nunavailable\n", 1)
	if e := ParseRoleEvidence(noFirewall); e.Config.Network != nil {
		t.Fatal("failed firewall probe became no routing")
	}
	emptyWireless := strings.Replace(base, "==wireless==\nunavailable\n", "==wireless==\n", 1)
	if e := ParseRoleEvidence(emptyWireless); e.Config.Wireless == nil || len(e.Config.Wireless.Interfaces) != 0 {
		t.Fatal("successful empty iw output lost")
	}
	if ParseRoleEvidence("") != nil {
		t.Fatal("empty probe should be unavailable")
	}
}

func TestBuildIncludesRoleConfig(t *testing.T) {
	p := NewProber(fakeRunner{outs: map[string]string{CmdRoleEvidence: roleFixture(t, "gs108t-switch")}}, Options{ScanInterval: ScanDisabled})
	payload := p.Build(context.Background(), "arbitrary-name", "test")
	if payload.Data.Roles == nil || payload.Data.Roles.Config == nil || payload.Data.Roles.ObservedAtMs == 0 {
		t.Fatal("missing configuration payload")
	}
	encoded, err := json.Marshal(payload.Data.Roles)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RoleEvidence
	if err = json.Unmarshal(encoded, &decoded); err != nil || len(decoded.Config.Bridging.Bridges[0].EthernetPorts) != 8 {
		t.Fatalf("configuration did not round trip: %s", encoded)
	}
	p = NewProber(fakeRunner{outs: map[string]string{}}, Options{ScanInterval: ScanDisabled})
	if p.Build(context.Background(), "switch-in-name", "test").Data.Roles != nil {
		t.Fatal("failed probe inferred a role from name")
	}
}
