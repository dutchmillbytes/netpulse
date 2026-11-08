package probe

import (
	"encoding/json"
	"sort"
	"strings"
)

// The same bounded, read-only probe runs locally and through SSH. It reports
// configuration state; operational roles are derived by the server. Section
// markers keep independent command results separate, and "unavailable" marks
// failed sources so the parser does not mistake a failure for an empty result.
const CmdRoleEvidence = `# Interface and firewall configuration are collected separately from kernel flags.
printf '%s\n' '==network=='
ubus call network.interface dump 2>/dev/null || echo unavailable
printf '%s\n' '==firewall=='
uci -q show firewall 2>/dev/null || echo unavailable
printf '%s\n' '==forwarding=='
printf 'ipv4='; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unavailable
printf 'ipv6='; cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo unavailable
printf '%s\n' '==wireless=='
iw dev 2>/dev/null || echo unavailable
printf '%s\n' '==wireless-devices=='
# The kernel inventory can establish that no wireless device exists when iw fails.
if [ -r /sys/class/net ] && [ -x /sys/class/net ]; then
 echo known
 for d in /sys/class/ieee80211/*; do [ ! -e "$d" ] || echo "${d##*/}"; done
 for d in /sys/class/net/*; do
  if [ -d "$d/phy80211" ] || [ -d "$d/wireless" ]; then echo "${d##*/}"; fi
 done
else echo unavailable; fi
printf '%s\n' '==devices=='
ubus call network.device status 2>/dev/null || echo unavailable
printf '%s\n' '==ethernet-ports=='
# Keep physical Ethernet devices; exclude DSA masters and wireless interfaces.
if [ -r /sys/class/net ] && [ -x /sys/class/net ]; then
 echo known
 for d in /sys/class/net/*; do
  [ -e "$d/device" ] && [ ! -d "$d/dsa" ] && [ ! -d "$d/phy80211" ] && [ ! -d "$d/wireless" ] || continue
  t=$(cat "$d/type" 2>/dev/null) || { echo unavailable; continue; }
  [ "$t" != 1 ] || echo "${d##*/}"
 done
else echo unavailable; fi
`

type RoleInterface struct {
	Name        string `json:"name"`
	Device      string `json:"device,omitempty"`
	Up          bool   `json:"up"`
	DefaultIPv4 bool   `json:"defaultIPv4,omitempty"`
	DefaultIPv6 bool   `json:"defaultIPv6,omitempty"`
}

type RoleZone struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
}

type RoleForwarding struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Enabled     bool   `json:"enabled"`
}

type RoleNetworkState struct {
	Interfaces     []RoleInterface  `json:"interfaces"`
	Zones          []RoleZone       `json:"zones"`
	Forwardings    []RoleForwarding `json:"forwardings"`
	IPv4Forwarding *bool            `json:"ipv4Forwarding"`
	IPv6Forwarding *bool            `json:"ipv6Forwarding"`
}

type RoleWirelessInterface struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type RoleWirelessState struct {
	Interfaces []RoleWirelessInterface `json:"interfaces"`
}

type RoleBridge struct {
	Name          string   `json:"name"`
	EthernetPorts []string `json:"ethernetPorts"`
}

type RoleBridgeState struct {
	Bridges []RoleBridge `json:"bridges"`
}

// A nil source means unavailable, while an empty collection is an observed
// absence. The state omits addresses, credentials, wireless keys and hostnames.
type RoleConfigState struct {
	Network  *RoleNetworkState  `json:"network,omitempty"`
	Wireless *RoleWirelessState `json:"wireless,omitempty"`
	Bridging *RoleBridgeState   `json:"bridging,omitempty"`
}

// RoleEvidence carries the parsed configuration and its collection time. The
// raw command output can contain unrelated settings; only selected fields from
// RoleConfigState are sent in the payload.
type RoleEvidence struct {
	ObservedAtMs int64            `json:"observedAtMs,omitempty"`
	Config       *RoleConfigState `json:"config,omitempty"`
	// Derived fields are populated by the server, not the collector.
	NetworkKnown  bool `json:"networkKnown,omitempty"`
	WirelessKnown bool `json:"wirelessKnown,omitempty"`
	BridgingKnown bool `json:"bridgingKnown,omitempty"`
	Router        bool `json:"router,omitempty"`
	AP            bool `json:"ap,omitempty"`
	Mesh          bool `json:"mesh,omitempty"`
	Switch        bool `json:"switch,omitempty"`
}

func roleUnavailable(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "unavailable" {
			return true
		}
	}
	return false
}

// ParseRoleEvidence separates the probe output into independent network,
// wireless and bridge sources. Each source is omitted when it cannot be read
// reliably; successfully observed empty collections are retained.
func ParseRoleEvidence(raw string) *RoleEvidence {
	// Accumulate lines under their markers. Repeated markers append to the same
	// source, preserving any failure marker for the source-level checks below.
	sections := map[string]string{}
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "==") && strings.HasSuffix(line, "==") {
			section = strings.Trim(line, "=")
			if _, ok := sections[section]; !ok {
				sections[section] = ""
			}
		} else {
			sections[section] += line + "\n"
		}
	}
	_, hasNetwork := sections["network"]
	_, hasWireless := sections["wireless"]
	_, hasDevices := sections["devices"]
	if !hasNetwork && !hasWireless && !hasDevices {
		return nil
	}
	state := &RoleConfigState{}
	state.Network = parseRoleNetwork(sections)
	// iw emits an Interface line followed by its type. A partial interface
	// without a type makes the whole wireless observation inconclusive.
	if wireless, ok := sections["wireless"]; ok && !roleUnavailable(wireless) {
		state.Wireless = &RoleWirelessState{Interfaces: []RoleWirelessInterface{}}
		var current *RoleWirelessInterface
		for _, line := range strings.Split(wireless, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if fields[0] == "Interface" {
				state.Wireless.Interfaces = append(state.Wireless.Interfaces, RoleWirelessInterface{Name: fields[1]})
				current = &state.Wireless.Interfaces[len(state.Wireless.Interfaces)-1]
			} else if fields[0] == "type" && current != nil {
				current.Mode = strings.Join(fields[1:], " ")
			}
		}
		for _, iface := range state.Wireless.Interfaces {
			if iface.Mode == "" {
				state.Wireless = nil
				break
			}
		}
	} else if strings.TrimSpace(sections["wireless-devices"]) == "known" {
		// A failed/missing iw is not absence. A successful kernel inventory with
		// no registered wireless devices can establish absence independently.
		state.Wireless = &RoleWirelessState{Interfaces: []RoleWirelessInterface{}}
	}
	// Intersect bridge members with the physical Ethernet inventory so that
	// wireless and virtual bridge members do not count as Ethernet ports.
	var devices map[string]struct {
		Type    string   `json:"type"`
		Members []string `json:"bridge-members"`
	}
	physical := strings.Fields(sections["ethernet-ports"])
	// Both inventories must succeed before an empty bridge list means absence.
	if json.Unmarshal([]byte(sections["devices"]), &devices) == nil && devices != nil && len(physical) > 0 && physical[0] == "known" && !roleUnavailable(sections["ethernet-ports"]) {
		state.Bridging = &RoleBridgeState{Bridges: []RoleBridge{}}
		ports := map[string]bool{}
		for _, name := range physical[1:] {
			ports[name] = true
		}
		for name, device := range devices {
			if device.Type != "bridge" {
				continue
			}
			bridge := RoleBridge{Name: name, EthernetPorts: []string{}}
			seen := map[string]bool{}
			for _, member := range device.Members {
				if ports[member] && !seen[member] {
					bridge.EthernetPorts = append(bridge.EthernetPorts, member)
					seen[member] = true
				}
			}
			// Stable ordering avoids changes caused by map iteration order.
			sort.Strings(bridge.EthernetPorts)
			state.Bridging.Bridges = append(state.Bridging.Bridges, bridge)
		}
		sort.Slice(state.Bridging.Bridges, func(i, j int) bool { return state.Bridging.Bridges[i].Name < state.Bridging.Bridges[j].Name })
	}
	return &RoleEvidence{Config: state}
}

// parseRoleNetwork requires interface, firewall and IPv4 forwarding data to
// be available together. It retains interface state, default-route flags and
// zone forwarding relationships, rather than the complete command output.
func parseRoleNetwork(sections map[string]string) *RoleNetworkState {
	var dump struct {
		Interface []ifaceStatus `json:"interface"`
	}
	forwarding := sections["forwarding"]
	known := strings.Contains(forwarding, "ipv4=1\n") || strings.Contains(forwarding, "ipv4=0\n")
	firewall, hasFirewall := sections["firewall"]
	if json.Unmarshal([]byte(sections["network"]), &dump) != nil || dump.Interface == nil || !hasFirewall || roleUnavailable(firewall) || !known {
		return nil
	}
	state := &RoleNetworkState{
		Interfaces: []RoleInterface{}, Zones: []RoleZone{}, Forwardings: []RoleForwarding{},
		IPv4Forwarding: roleForwardingFlag(forwarding, "ipv4"), IPv6Forwarding: roleForwardingFlag(forwarding, "ipv6"),
	}
	for _, iface := range dump.Interface {
		item := RoleInterface{Name: iface.Interface, Device: iface.Device, Up: iface.Up}
		// Some interfaces expose only their layer-3 device.
		if item.Device == "" {
			item.Device = iface.L3Device
		}
		// A zero-length mask and an all-zero target identify a default route;
		// report its presence without retaining its gateway or addresses.
		for _, route := range iface.Route {
			if route.Mask == 0 {
				item.DefaultIPv4 = item.DefaultIPv4 || route.Target == "0.0.0.0"
				item.DefaultIPv6 = item.DefaultIPv6 || route.Target == "::"
			}
		}
		state.Interfaces = append(state.Interfaces, item)
	}
	zones := map[string]*RoleZone{}
	forwardings := map[string]*RoleForwarding{}
	// UCI emits each section declaration before its options. Keep only zone
	// membership and inter-zone forwarding; ignore unrelated firewall rules.
	for _, line := range strings.Split(firewall, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) < 2 || parts[0] != "firewall" {
			continue
		}
		id := parts[1]
		if len(parts) == 2 {
			switch value {
			case "zone":
				zones[id] = &RoleZone{Networks: []string{}}
			case "forwarding":
				// UCI forwarding sections are enabled unless explicitly disabled.
				forwardings[id] = &RoleForwarding{Enabled: true}
			}
			continue
		}
		values := strings.Fields(strings.ReplaceAll(value, "'", ""))
		if len(values) == 0 {
			continue
		}
		if zone := zones[id]; zone != nil {
			switch parts[2] {
			case "name":
				zone.Name = values[0]
			case "network":
				zone.Networks = values
			}
		}
		if forward := forwardings[id]; forward != nil {
			switch parts[2] {
			case "src":
				forward.Source = values[0]
			case "dest":
				forward.Destination = values[0]
			case "enabled":
				forward.Enabled = values[0] != "0"
			}
		}
	}
	for _, z := range zones {
		state.Zones = append(state.Zones, *z)
	}
	for _, f := range forwardings {
		state.Forwardings = append(state.Forwardings, *f)
	}
	// Maps do not preserve UCI order; sort the payload for consistent output.
	sort.Slice(state.Zones, func(i, j int) bool { return state.Zones[i].Name < state.Zones[j].Name })
	sort.Slice(state.Forwardings, func(i, j int) bool {
		a, b := state.Forwardings[i], state.Forwardings[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		return !a.Enabled && b.Enabled
	})
	return state
}

// roleForwardingFlag uses nil for an unreadable flag, distinct from false.
func roleForwardingFlag(raw, family string) *bool {
	for _, line := range strings.Split(raw, "\n") {
		if line == family+"=0" || line == family+"=1" {
			enabled := strings.HasSuffix(line, "=1")
			return &enabled
		}
	}
	return nil
}
