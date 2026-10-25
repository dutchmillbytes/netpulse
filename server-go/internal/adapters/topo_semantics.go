// topo_semantics.go — Builder del modelo SEMÁNTICO de topología (SPEC-65
// D65-3), compartido demo/live. Porta a Go la lógica de asignación de
// anillos y enlaces de app/src/components/topology/model.ts
// (buildTopologyModel), SIN geometría: nada de coordenadas, radios, paths
// SVG ni flujo de paquetes — eso queda en la app.
//
// Paridad con model.ts (canon demo fijada en topo_semantics_test.go):
//   - El switch gestionado existe como Device Y como distnode managed: se
//     excluye de chips/enlaces cualquier Device cuya MAC coincida con la
//     chassis-MAC de un distnode managed (D1).
//   - Anclaje al router que atribuye el cliente: sin puerto FDB no se inventa
//     un uplink de AP ni se cambia el sitio del dispositivo.
//   - Solo los distnodes inferred|managed son hubs de enlaces "dist"; el
//     hipervisor enlaza vía su Device host (sus CTs/VMs cuelgan del host).
//   - Peers WG: los activos que exceden las 4 coordenadas canónicas no
//     generan enlace (la app los agrupa en su chip "+N" de peers).
package adapters

import (
	"net"
	"strings"
)

// Capacidad de los anillos canónicos de model.ts (GATEWAY_RINGS 8+12+16+24,
// AP_RINGS 8+14+18): el límite de chips visibles por anillo que aplica la app.
// HiddenPeers = clientes del anillo - visibles con este mismo límite.
// (9-Ago-2026: subido desde 13/20 — el gateway con ~60 clientes ocultaba
// casi todo; el resolver de colisiones mantiene 0 solapes con anillos densos.)
const (
	topoGatewayRingCap = 60
	topoAPRingCap      = 40
)

// maxTopoPeerChips: coordenadas canónicas de peers WG en model.ts (4); los
// activos que exceden no se trazan como túnel propio.
const maxTopoPeerChips = 4

// BuildTopoSemantics deriva enlaces, anillos y peers ocultos del mismo bundle
// que hoy consume la app (routers, devices, wireguard, distributionNodes).
func BuildTopoSemantics(routers []Router, devices []Device, wg WireGuardStats, dists []DistributionNode) *TopoSemantics {
	return buildTopoSemantics(routers, devices, wg, nil, dists)
}

// BuildTopoSemanticsWithWireguards keeps each router's tunnel independent.
func BuildTopoSemanticsWithWireguards(routers []Router, devices []Device, wireguards []RouterWireGuard, dists []DistributionNode) *TopoSemantics {
	return buildTopoSemantics(routers, devices, WireGuardStats{}, wireguards, dists)
}

func buildTopoSemantics(routers []Router, devices []Device, wg WireGuardStats, wireguards []RouterWireGuard, dists []DistributionNode) *TopoSemantics {
	sem := &TopoSemantics{Links: []TopoLink{}, Rings: map[string][]string{}}
	if len(routers) == 0 {
		return sem
	}

	// Gateway y APs/switches como model.ts: roleBadge "Principal" → gateway
	// (si no, el primero); el resto son routers (APs y switches gestionados).
	// Sin límite de 3 APs — el frontend decide cuántos dibujar con coordenadas
	// canónicas y cuáles como "extra" (switches, APs adicionales).
	gateway := routers[0]
	for _, r := range routers {
		if r.RoleBadge == "Principal" {
			gateway = r
			break
		}
	}
	nonGateway := make([]Router, 0, len(routers)-1)
	for _, r := range routers {
		if r.ID != gateway.ID {
			nonGateway = append(nonGateway, r)
		}
	}
	routerNodes := append([]Router{gateway}, nonGateway...)
	sem.RouterParents = topologyRouterParents(routers, devices)
	inRouter := map[string]bool{}
	for _, r := range routerNodes {
		inRouter[r.ID] = true
	}

	// D1: los Devices cuya MAC es la chassis-MAC de un distnode managed se
	// representan SOLO como nodo managed (sin chip ni enlaces propios).
	managedMacs := map[string]bool{}
	for _, n := range dists {
		if n.Kind == "managed" && n.Mac != "" {
			managedMacs[strings.ToUpper(n.Mac)] = true
		}
	}
	online := make([]Device, 0, len(devices))
	for _, d := range devices {
		if !d.Online || managedMacs[strings.ToUpper(d.MAC)] {
			continue
		}
		online = append(online, d)
	}
	deviceByID := map[string]Device{}
	for _, d := range online {
		deviceByID[d.ID] = d
	}
	distByID := map[string]DistributionNode{}
	for _, n := range dists {
		distByID[n.ID] = n
	}

	// hubOf: attachTo (si resuelve a router/distnode/device conocido) o su
	// router. A client attribution is stronger than an absent FDB port.
	hubOf := func(d Device) string {
		if d.AttachTo != "" {
			if inRouter[d.AttachTo] {
				return d.AttachTo
			}
			if _, ok := distByID[d.AttachTo]; ok {
				return d.AttachTo
			}
			if _, ok := deviceByID[d.AttachTo]; ok {
				return d.AttachTo
			}
		}
		return d.RouterID
	}

	// deviceHubs: dispositivos con hijos propios (switch gestionado,
	// hipervisor), en orden de descubrimiento (orden del dataset, como el
	// Set de JS). hypervisorHosts: hosts con distnode kind=hypervisor.
	var deviceHubOrder []string
	deviceHubs := map[string]bool{}
	for _, d := range online {
		if d.AttachTo == "" || deviceHubs[d.AttachTo] {
			continue
		}
		if _, ok := deviceByID[d.AttachTo]; ok {
			deviceHubs[d.AttachTo] = true
			deviceHubOrder = append(deviceHubOrder, d.AttachTo)
		}
	}
	hypervisorHosts := map[string]bool{}
	for _, n := range dists {
		if n.Kind == "hypervisor" && n.HostDeviceID != "" {
			hypervisorHosts[n.HostDeviceID] = true
		}
	}

	wiredLink := func(from string, d Device) {
		sem.Links = append(sem.Links, TopoLink{From: from, To: d.ID, Kind: "wired", Port: d.Port})
	}

	// -- enlaces (mismo orden que model.ts) --------------------------------
	wanCount := 0
	rootCount := 0
	for _, rn := range routerNodes {
		if rn.RoleBadge == "Principal" || rn.RoleBadge == "Secondary" {
			rootCount++
		}
	}
	for _, rn := range routerNodes {
		if rn.RoleBadge == "Principal" || rn.RoleBadge == "Secondary" {
			internetID := "internet"
			if rootCount > 1 {
				internetID = "internet-" + rn.ID
			}
			sem.Links = append(sem.Links, TopoLink{From: internetID, To: rn.ID, Kind: "wan"})
			wanCount++
		}
	}
	if wanCount == 0 {
		sem.Links = append(sem.Links, TopoLink{From: "internet", To: gateway.ID, Kind: "wan"})
	}
	for _, ap := range nonGateway {
		parent := sem.RouterParents[ap.ID]
		if parent == "" {
			continue
		}
		l := TopoLink{From: parent, To: ap.ID, Kind: "uplink"}
		if ap.Lldp != nil {
			l.Port = ap.Lldp.PortDesc // puerto del uplink en el gateway (C2)
		}
		sem.Links = append(sem.Links, l)
	}
	// router → distnode (solo inferred|managed son hubs propios en el mapa).
	// En una cadena LLDP switch→switch (issue #300) el distnode cuelga de su
	// Parent (otro distnode) en vez del router.
	for _, rn := range routerNodes {
		for _, dn := range dists {
			if dn.RouterID != rn.ID || (dn.Kind != "inferred" && dn.Kind != "managed") {
				continue
			}
			from := rn.ID
			if dn.Parent != "" {
				from = dn.Parent
			}
			sem.Links = append(sem.Links, TopoLink{From: from, To: dn.ID, Kind: "dist", Port: dn.Port})
		}
	}
	// cableados directos del router (sin los device-hubs, que enlazan después)
	for _, rn := range routerNodes {
		for _, d := range online {
			if d.Band != "cable" || deviceHubs[d.ID] || hubOf(d) != rn.ID {
				continue
			}
			wiredLink(rn.ID, d)
		}
	}
	// hijos cableados de device-hubs NO hipervisor (los CTs van en su fase)
	for _, hubID := range deviceHubOrder {
		if hypervisorHosts[hubID] {
			continue
		}
		for _, d := range online {
			if d.Band != "cable" || hubOf(d) != hubID {
				continue
			}
			wiredLink(hubID, d)
		}
	}
	// el cable del propio hub (chip con hijos; el hipervisor entre ellos)
	for _, hubID := range deviceHubOrder {
		hub := deviceByID[hubID]
		h := hubOf(hub)
		// Si el hub cuelga de un distnode inferred|managed, su cable ya lo
		// genera el bucle de hijos de distnodes (más abajo): no duplicar.
		// (Caso issue #142: host con CTs anidados por override que cuelga de
		// un distnode inferred — el host es device-hub Y cliente del distnode.)
		if dn, ok := distByID[h]; ok && (dn.Kind == "inferred" || dn.Kind == "managed") {
			continue
		}
		wiredLink(h, hub)
	}
	// hijos cableados de distnodes (abanico alrededor del círculo)
	for _, rn := range routerNodes {
		for _, dn := range dists {
			if dn.RouterID != rn.ID || (dn.Kind != "inferred" && dn.Kind != "managed") {
				continue
			}
			for _, d := range online {
				if d.Band != "cable" || hubOf(d) != dn.ID {
					continue
				}
				wiredLink(dn.ID, d)
			}
		}
	}
	// CTs/VMs anidados bajo el host hipervisor (línea desde el host)
	for _, dn := range dists {
		if dn.Kind != "hypervisor" || dn.HostDeviceID == "" {
			continue
		}
		if _, ok := deviceByID[dn.HostDeviceID]; !ok {
			continue
		}
		for _, d := range online {
			if hubOf(d) != dn.HostDeviceID {
				continue
			}
			wiredLink(dn.HostDeviceID, d)
		}
	}
	// Legacy demo topology retains peer→Internet links. Live topology uses
	// one peer node per public key and one router→peer edge per tunnel.
	if wireguards == nil {
		n := 0
		for _, p := range wg.Peers {
			if p.Active && n < maxTopoPeerChips {
				sem.Links = append(sem.Links, TopoLink{From: "peer-" + p.ID, To: "internet", Kind: "wg"})
				n++
			}
		}
	} else {
		visible := map[string]bool{}
		for _, rw := range wireguards {
			for _, p := range rw.Stats.Peers {
				peerID := topologyPeerID(rw.RouterID, p)
				if !visible[peerID] && len(visible) >= maxTopoPeerChips {
					continue
				}
				visible[peerID] = true
				sem.Links = append(sem.Links, TopoLink{From: rw.RouterID, To: peerID, Kind: "wg", Interface: p.Interface})
			}
		}
	}

	// -- anillos por router --------------------------------------------------
	// Anillo = chips que cuelgan DIRECTAMENTE del router (cableados directos,
	// incluidos los device-hubs, y wifi). Orden SPEC-65: cableados primero,
	// luego por banda 5GHz/2.4GHz, estable (orden del dataset).
	for _, rn := range routerNodes {
		var wired, g5, g24, other []string
		for _, d := range online {
			if hubOf(d) != rn.ID {
				continue
			}
			switch d.Band {
			case "cable":
				wired = append(wired, d.ID)
			case "5 GHz":
				g5 = append(g5, d.ID)
			case "2.4 GHz":
				g24 = append(g24, d.ID)
			default:
				other = append(other, d.ID)
			}
		}
		ring := make([]string, 0, len(wired)+len(g5)+len(g24)+len(other))
		ring = append(ring, wired...)
		ring = append(ring, g5...)
		ring = append(ring, g24...)
		ring = append(ring, other...)
		if len(ring) == 0 {
			continue
		}
		sem.Rings[rn.ID] = ring
		cap := topoAPRingCap
		if rn.RoleBadge == "Principal" || rn.RoleBadge == "Secondary" {
			cap = topoGatewayRingCap
		}
		if hidden := len(ring) - cap; hidden > 0 {
			if sem.HiddenPeers == nil {
				sem.HiddenPeers = map[string]int{}
			}
			sem.HiddenPeers[rn.ID] = hidden
		}
	}
	return sem
}

func topologyPeerID(routerID string, peer WGPeer) string {
	if peer.KeyFingerprint != "" {
		return "peer-key-" + peer.KeyFingerprint
	}
	// Local IDs can repeat on different routers; never merge by name or IP.
	return "peer-" + routerID + "-" + peer.ID
}

// topologyRouterParents finds an AP/switch's upstream without assuming that
// every non-primary router belongs to the primary's LAN. Exact client/LLDP
// identity wins; a unique DNS site suffix is a fallback for routers whose
// management host is a FQDN but whose observed client name is shortened.
func topologyRouterParents(routers []Router, devices []Device) map[string]string {
	parents := map[string]string{}
	roots := make([]Router, 0, len(routers))
	for _, r := range routers {
		if r.RoleBadge == "Principal" || r.RoleBadge == "Secondary" {
			roots = append(roots, r)
		}
	}
	if len(roots) == 0 && len(routers) > 0 {
		roots = append(roots, routers[0])
	}
	rootIDs := map[string]bool{}
	for _, root := range roots {
		rootIDs[root.ID] = true
	}
	identity := func(a, b string) bool {
		return a != "" && b != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	suffix := func(s string) string {
		if net.ParseIP(strings.TrimSpace(s)) != nil {
			return ""
		}
		parts := strings.Split(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")), ".")
		if len(parts) < 3 {
			return ""
		}
		return strings.Join(parts[1:], ".")
	}
	for _, r := range routers {
		if rootIDs[r.ID] {
			continue
		}
		if r.Lldp != nil {
			for _, root := range roots {
				if identity(r.Lldp.Chassis, root.MAC) || identity(r.Lldp.Mgmt, root.IP) || identity(r.Lldp.Chassis, root.Name) {
					parents[r.ID] = root.ID
					break
				}
			}
		}
		if parents[r.ID] != "" {
			continue
		}
		matched := ""
		ambiguous := false
		for _, d := range devices {
			if !rootIDs[d.RouterID] {
				continue
			}
			if !(identity(r.MAC, d.MAC) || identity(r.IP, d.IP) || identity(r.IP, d.Name) || identity(r.Name, d.Name)) {
				continue
			}
			if matched != "" && matched != d.RouterID {
				ambiguous = true
				break
			}
			matched = d.RouterID
		}
		if matched != "" && !ambiguous {
			parents[r.ID] = matched
			continue
		}
		// Site-qualified hostnames outrank short DHCP client names: an AP
		// called ap-2 may be observed behind another site's router too.
		nameSuffix := suffix(r.IP)
		if nameSuffix == "" {
			nameSuffix = suffix(r.Name)
		}
		if nameSuffix != "" {
			candidate := ""
			for _, root := range roots {
				rootSuffix := suffix(root.IP)
				if rootSuffix == "" {
					rootSuffix = suffix(root.Name)
				}
				if rootSuffix != nameSuffix {
					continue
				}
				if candidate != "" {
					candidate = ""
					break
				}
				candidate = root.ID
			}
			if candidate != "" {
				parents[r.ID] = candidate
				continue
			}
		}
		// DHCP/device discovery often reports only the AP's short hostname.
		// Use it only when it identifies one root and the site is unresolved.
		shortName := strings.Split(strings.ToLower(r.IP), ".")[0]
		if suffix(r.IP) != "" && shortName != "" {
			matched, ambiguous = "", false
			for _, d := range devices {
				if !rootIDs[d.RouterID] || !strings.EqualFold(d.Name, shortName) {
					continue
				}
				if matched != "" && matched != d.RouterID {
					ambiguous = true
					break
				}
				matched = d.RouterID
			}
			if matched != "" && !ambiguous {
				parents[r.ID] = matched
				continue
			}
		}
		if len(roots) == 1 {
			parents[r.ID] = roots[0].ID
		}
	}
	return parents
}
