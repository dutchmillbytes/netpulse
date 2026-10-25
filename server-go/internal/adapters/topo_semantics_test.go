package adapters

import (
	"fmt"
	"reflect"
	"testing"
)

// Golden test de la topología semántica (SPEC-65 D65-3): para el canon demo,
// los links/rings/hiddenPeers del builder Go deben coincidir con lo que
// produce hoy buildTopologyModel de app/src/components/topology/model.ts
// (revisado a mano contra model.ts @ audit/v2-main):
//   - wan + 3 uplinks (living/estudio con puerto LLDP del gateway; patio wifi)
//   - 2 enlaces dist (switch inferido del gateway y GS308E managed del Salón)
//   - cableados directos: nas y pve en el gateway; mac-mini/hue-hub en
//     Estudio según su routerId aunque no tengan puerto FDB; ps5 en Salón
//   - 8 clientes tras el switch inferido + 3 tras el GS308E + 10 CTs del pve
//   - 2 túneles WG (los 2 peers activos)
//   - El GS308E (switch-netgear) NO genera chips/enlaces: su MAC es la
//     chassis-MAC del distnode managed (D1)
//   - Anillos: cableados primero, luego 5GHz, luego 2.4GHz (orden dataset)
//   - hiddenPeers ausente: todos los anillos bajo el límite de chips visibles
//     de la app (gateway 13, AP 20)
func TestTopoSemanticsGoldenCanon(t *testing.T) {
	sem := BuildTopoSemantics(canonRouters(), canonAllDevices(), canonWireguard(), canonDistributionNodes())

	wantLinks := []TopoLink{
		{From: "internet", To: "flint2", Kind: "wan"},
		{From: "flint2", To: "living", Kind: "uplink", Port: "lan1"},
		{From: "flint2", To: "estudio", Kind: "uplink", Port: "lan2"},
		{From: "flint2", To: "patio", Kind: "uplink"},
		{From: "flint2", To: "dist-flint2-lan3", Kind: "dist", Port: "lan3"},
		{From: "living", To: "dist-living-lan3", Kind: "dist", Port: "lan3"},
		{From: "flint2", To: "nas-synology", Kind: "wired", Port: "lan4"},
		{From: "living", To: "ps5", Kind: "wired", Port: "lan1"},
		{From: "estudio", To: "mac-mini", Kind: "wired"},
		{From: "estudio", To: "hue-hub", Kind: "wired"},
		{From: "flint2", To: "pve", Kind: "wired", Port: "lan5"},
		{From: "dist-flint2-lan3", To: "pc-sobremesa", Kind: "wired"},
		{From: "dist-flint2-lan3", To: "raspberry-pi", Kind: "wired"},
		{From: "dist-flint2-lan3", To: "tv-salon-cable", Kind: "wired"},
		{From: "dist-flint2-lan3", To: "impresora-hp", Kind: "wired"},
		{From: "dist-flint2-lan3", To: "xbox-one", Kind: "wired"},
		{From: "dist-flint2-lan3", To: "receptor-av", Kind: "wired"},
		{From: "dist-flint2-lan3", To: "deco-orange", Kind: "wired"},
		{From: "dist-flint2-lan3", To: "pc-invitado", Kind: "wired"},
		{From: "dist-living-lan3", To: "xbox-series-s", Kind: "wired"},
		{From: "dist-living-lan3", To: "apple-tv-4k", Kind: "wired"},
		{From: "dist-living-lan3", To: "receptor-denon", Kind: "wired"},
		{From: "pve", To: "ct-pihole", Kind: "wired"},
		{From: "pve", To: "ct-home-assistant", Kind: "wired"},
		{From: "pve", To: "ct-nextcloud", Kind: "wired"},
		{From: "pve", To: "ct-jellyfin", Kind: "wired"},
		{From: "pve", To: "ct-immich", Kind: "wired"},
		{From: "pve", To: "ct-gitea", Kind: "wired"},
		{From: "pve", To: "ct-uptime-kuma", Kind: "wired"},
		{From: "pve", To: "ct-adguard-sync", Kind: "wired"},
		{From: "pve", To: "ct-postgres", Kind: "wired"},
		{From: "pve", To: "ct-redis", Kind: "wired"},
		{From: "peer-pixel-8-pro", To: "internet", Kind: "wg"},
		{From: "peer-macbook-air", To: "internet", Kind: "wg"},
	}
	if !reflect.DeepEqual(sem.Links, wantLinks) {
		t.Fatalf("links:\n got: %+v\nwant: %+v", sem.Links, wantLinks)
	}

	wantRings := map[string][]string{
		"flint2": {"nas-synology", "pve",
			"pixel-8-pro", "iphone-ana", "macbook-pro", "pixel-7",
			"timbre-nest", "enchufe-lavadora"},
		"living": {"ps5",
			"imac-salon", "tv-samsung", "galaxy-tab-s9", "chromecast", "homepod-mini",
			"galaxy-s23", "nintendo-switch", "portatil-invitado",
			"bombilla-1", "bombilla-2", "bombilla-3", "bombilla-4", "bombilla-5",
			"bombilla-6", "echo-dot"},
		"estudio": {"mac-mini", "hue-hub", "macbook-air", "ipad-pro", "iphone-trabajo",
			"nest-mini", "enchufe-ventilador", "sonos-one"},
		"patio": {"robot-aspirador", "camara-porche", "camara-jardin",
			"sensor-riego", "enchufe-calefactor"},
	}
	if !reflect.DeepEqual(sem.Rings, wantRings) {
		t.Fatalf("rings:\n got: %+v\nwant: %+v", sem.Rings, wantRings)
	}

	// Todos los anillos bajo el límite de chips visibles → sin "+N".
	if len(sem.HiddenPeers) != 0 {
		t.Fatalf("hiddenPeers debería estar vacío en el canon: %+v", sem.HiddenPeers)
	}
}

// HiddenPeers: superado el límite de chips visibles del anillo (gateway 60,
// AP 40), el exceso se reporta como "+N" por router.
func TestTopoSemanticsHiddenPeers(t *testing.T) {
	routers := []Router{
		{ID: "gw", RoleBadge: "Principal"},
		{ID: "ap", RoleBadge: "AP"},
	}
	devices := make([]Device, 0, 62+42)
	for i := 0; i < 62; i++ {
		devices = append(devices, Device{
			ID: fmt.Sprintf("gw-%02d", i), MAC: fmt.Sprintf("00:00:00:00:01:%02d", i),
			RouterID: "gw", Band: "5 GHz", Online: true,
		})
	}
	for i := 0; i < 42; i++ {
		devices = append(devices, Device{
			ID: fmt.Sprintf("ap-%02d", i), MAC: fmt.Sprintf("00:00:00:00:02:%02d", i),
			RouterID: "ap", Band: "2.4 GHz", Online: true,
		})
	}
	sem := BuildTopoSemantics(routers, devices, WireGuardStats{}, nil)
	want := map[string]int{"gw": 2, "ap": 2} // 62-60 y 42-40
	if !reflect.DeepEqual(sem.HiddenPeers, want) {
		t.Fatalf("hiddenPeers: got %+v want %+v", sem.HiddenPeers, want)
	}
	if got := len(sem.Rings["gw"]); got != 62 {
		t.Fatalf("el anillo conserva TODOS los clientes (visibles+ocultos): %d", got)
	}
}

// El overview demo lleva topology y vm SIEMPRE (SPEC-65 D65-3/D65-4).
func TestDemoOverviewIncluyeTopologyYVM(t *testing.T) {
	d := NewDemo()
	ov, err := d.GetOverview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ov.VM != ViewModelVersion {
		t.Fatalf("overview.vm=%d, ViewModelVersion=%d", ov.VM, ViewModelVersion)
	}
	if ov.Topology == nil {
		t.Fatal("overview.Topology ausente en demo")
	}
	// Mismo resultado que el builder puro sobre el canon.
	want := BuildTopoSemantics(canonRouters(), canonAllDevices(), canonWireguard(), canonDistributionNodes())
	if !reflect.DeepEqual(ov.Topology, want) {
		t.Fatalf("overview.Topology != builder canon:\n got: %+v\nwant: %+v", ov.Topology, want)
	}
}

// Sin routers: semántica vacía pero no nil (la app cae a su cálculo propio).
func TestTopoSemanticsSinRouters(t *testing.T) {
	sem := BuildTopoSemantics(nil, nil, WireGuardStats{}, nil)
	if sem == nil || sem.Links == nil || sem.Rings == nil {
		t.Fatalf("semántica vacía debe tener links/rings no-nil: %+v", sem)
	}
	if len(sem.Links) != 0 || len(sem.Rings) != 0 {
		t.Fatalf("sin routers no hay links ni anillos: %+v", sem)
	}
}

// TestTopoSemanticsDeviceHubBajoDistnode: un device-hub (host con CTs
// anidados por override, issue #142) que cuelga de un distnode inferred NO
// debe duplicar su cable: lo genera solo el bucle de hijos de distnodes.
func TestTopoSemanticsDeviceHubBajoDistnode(t *testing.T) {
	devices := []Device{
		{RouterID: "gateway", Band: "cable", Port: "lan1", ID: "host", MAC: "c8:ff:bf:08:6f:ba", AttachTo: "dist-gateway-lan1", Online: true, Infra: "hypervisor"},
		{RouterID: "gateway", Band: "cable", Port: "lan1", ID: "ct1", MAC: "bc:24:11:00:00:01", AttachTo: "host", Online: true, Infra: "ct"},
		{RouterID: "gateway", Band: "cable", Port: "lan1", ID: "ct2", MAC: "bc:24:11:00:00:02", AttachTo: "host", Online: true, Infra: "ct"},
	}
	routers := []Router{{ID: "gateway", Name: "gateway", RoleBadge: "Principal", Status: "online"}}
	dists := []DistributionNode{{ID: "dist-gateway-lan1", Kind: "inferred", RouterID: "gateway", Port: "lan1"}}
	sem := BuildTopoSemantics(routers, devices, WireGuardStats{}, dists)

	var toHost []TopoLink
	for _, l := range sem.Links {
		if l.To == "host" {
			toHost = append(toHost, l)
		}
	}
	// Un solo cable host→su hub (dist-gateway-lan1), no duplicado.
	if len(toHost) != 1 {
		t.Fatalf("cable del device-hub duplicado (%d): %+v", len(toHost), toHost)
	}
	if toHost[0].From != "dist-gateway-lan1" {
		t.Errorf("host debe colgar de su distnode: %+v", toHost[0])
	}
	// Los CTs cuelgan del host exactamente una vez cada uno.
	ctLinks := map[string]int{}
	for _, l := range sem.Links {
		if l.From == "host" {
			ctLinks[l.To]++
		}
	}
	for _, ct := range []string{"ct1", "ct2"} {
		if ctLinks[ct] != 1 {
			t.Errorf("CT %s debe colgar del host una vez, got %d", ct, ctLinks[ct])
		}
	}
}

func TestTopoSemanticsSecondaryRouterSiteAndSharedPeer(t *testing.T) {
	routers := []Router{
		{ID: "router-a", Name: "router.nl.example.home", IP: "10.49.1.254", RoleBadge: "Principal"},
		{ID: "router-b", Name: "router.th.example.home", IP: "router.th.example.home", RoleBadge: "Secondary"},
		{ID: "ap-a", Name: "ap-2.nl.example.home", IP: "ap-2.nl.example.home", RoleBadge: "AP"},
		{ID: "ap-b", Name: "ap-2.th.example.home", IP: "ap-2.th.example.home", RoleBadge: "AP"},
		{ID: "ap-a3", Name: "ap-3.nl.example.home", IP: "ap-3.nl.example.home", RoleBadge: "AP"},
	}
	devices := []Device{
		{ID: "ap-b-client", Name: "ap-2", RouterID: "router-b", Band: "cable", Online: true},
		{ID: "ap-a-client", Name: "ap-2", RouterID: "router-a", Band: "cable", Online: true},
		{ID: "ap-a3-conflict", Name: "ap-3", RouterID: "router-b", Band: "cable", Online: true},
	}
	wg := []RouterWireGuard{
		{RouterID: "router-a", Stats: WireGuardStats{Status: "active", Peers: []WGPeer{{ID: "peer-1", Name: "VPS", KeyFingerprint: "samekey", Active: true}}}},
		{RouterID: "router-b", Stats: WireGuardStats{Status: "active", Peers: []WGPeer{{ID: "peer-1", Name: "VPS", KeyFingerprint: "samekey", Active: false}}}},
	}
	sem := BuildTopoSemanticsWithWireguards(routers, devices, wg, nil)
	if sem.RouterParents["ap-a"] != "router-a" || sem.RouterParents["ap-b"] != "router-b" || sem.RouterParents["ap-a3"] != "router-a" {
		t.Fatalf("AP parents: %+v", sem.RouterParents)
	}
	links := map[string]bool{}
	for _, link := range sem.Links {
		links[link.Kind+":"+link.From+":"+link.To] = true
	}
	for _, want := range []string{
		"wan:internet-router-a:router-a", "wan:internet-router-b:router-b",
		"uplink:router-a:ap-a", "uplink:router-b:ap-b",
		"wired:router-a:ap-a-client", "wired:router-b:ap-b-client",
		"wg:router-a:peer-key-samekey", "wg:router-b:peer-key-samekey",
	} {
		if !links[want] {
			t.Errorf("missing %s in %+v", want, sem.Links)
		}
	}
	if links["uplink:router-a:router-b"] || links["uplink:router-a:ap-b"] {
		t.Fatalf("fictional physical uplink: %+v", sem.Links)
	}
	if topologyPeerID("router-a", WGPeer{ID: "peer-1"}) == topologyPeerID("router-b", WGPeer{ID: "peer-1"}) {
		t.Fatal("router-local peer IDs must not merge without a public key")
	}
}
