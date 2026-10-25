package adapters

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
	"github.com/gnacho/netpulse/server-go/internal/alerts"
	"github.com/gnacho/netpulse/server-go/internal/config"
)

type secondaryWGRunner struct {
	mu     sync.Mutex
	active map[string]bool
	fail   map[string]bool
	calls  map[string]int
}

func (f *secondaryWGRunner) Run(host, cmd string, _ time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[host]++
	if f.fail[host] {
		return "", fmt.Errorf("router unavailable")
	}
	switch {
	case cmd == wgListCommand:
		return "wg0\n", nil
	case cmd == awgListCommand:
		return "", nil
	case strings.Contains(cmd, "wg show wg0 dump"):
		last := time.Now().Unix() - 600
		if f.active[host] {
			last = time.Now().Unix() - 10
		}
		return wgStatsOutput(wgPeerDump("wg0", wgPeerLine("SHARED-KEY", "10.0.0.2/32", fmt.Sprint(last))), ""), nil
	}
	return "", fmt.Errorf("unexpected command: %s", cmd)
}

func TestSecondaryRouterWireGuardIsolation(t *testing.T) {
	a := RouterConfig{ID: "router-a", Host: "192.0.2.1", Type: "openwrt", IsGateway: true}
	b := RouterConfig{ID: "router-b", Host: "192.0.2.2", Type: "openwrt", IsRouter: true}
	ap := RouterConfig{ID: "ap", Host: "192.0.2.3", Type: "openwrt"}
	runner := &secondaryWGRunner{
		active: map[string]bool{a.SSHAddr(): true, b.SSHAddr(): true},
		fail:   map[string]bool{}, calls: map[string]int{},
	}
	l := &Live{cfg: &config.Config{WGInterface: "auto"}, wgRunner: runner,
		engine: alerts.New(nil, nil), wgActive: map[string]map[string]bool{}, wgByRouter: map[string]WireGuardStats{}}
	if err := l.engine.SetConfig(map[string]string{"vpn": "all"}); err != nil {
		t.Fatal(err)
	}
	devices := []Device{
		{ID: "a-peer", IP: "10.0.0.2", Name: "Alice", RouterID: a.ID},
		{ID: "b-peer", IP: "10.0.0.2", Name: "Bob", RouterID: b.ID},
	}
	collect := func() map[string]WireGuardStats {
		t.Helper()
		return l.pollRouterWireGuard(context.Background(), []RouterConfig{a, b, ap}, a.ID, devices)
	}
	first := collect()
	if len(first) != 2 || first[a.ID].Peers[0].Name != "Alice" || first[b.ID].Peers[0].Name != "Bob" {
		t.Fatalf("cross-router peer data: %+v", first)
	}
	if len(l.engine.List()) != 0 {
		t.Fatal("initial active peers generated alerts")
	}
	runner.mu.Lock()
	runner.active[b.SSHAddr()] = false
	runner.mu.Unlock()
	collect()
	runner.mu.Lock()
	runner.active[b.SSHAddr()] = true
	runner.mu.Unlock()
	collect()
	items := l.engine.List()
	if len(items) != 1 || items[0].RouterID != b.ID || !strings.Contains(items[0].ID, b.ID) {
		t.Fatalf("handshake alert attributed incorrectly: %+v", items)
	}
	runner.mu.Lock()
	runner.fail[b.SSHAddr()] = true
	runner.mu.Unlock()
	failed := collect()
	if failed[a.ID].Status != "active" || failed[b.ID].Status != "inactive" {
		t.Fatalf("secondary failure changed primary: %+v", failed)
	}
	if l.wgByRouter[b.ID].Status != "inactive" {
		t.Fatal("failed secondary retained stale service status")
	}
	if runner.calls[ap.SSHAddr()] != 0 {
		t.Fatal("AP received router-only WireGuard probes")
	}
}

func TestSecondaryRouterRoleAfterOfflineAndSettingsChange(t *testing.T) {
	a := RouterConfig{ID: "router-a", Host: "192.0.2.1", Type: "openwrt", IsGateway: true}
	b := RouterConfig{ID: "router-b", Host: "192.0.2.2", Type: "openwrt", IsRouter: true}
	l := &Live{gatewayCfg: &a, lastGood: map[string]*Router{
		b.ID: {ID: b.ID, Role: "Punto de acceso", RoleBadge: "AP"},
	}}
	if r := l.offlineRouter(b); r.RoleBadge != "Secondary" {
		t.Fatalf("offline role = %q", r.RoleBadge)
	}
	b.IsRouter = false
	if r := l.offlineRouter(b); r.RoleBadge != "AP" {
		t.Fatalf("role after removal = %q", r.RoleBadge)
	}
	if r := l.offlineRouter(a); r.RoleBadge != "Principal" {
		t.Fatalf("primary role = %q", r.RoleBadge)
	}
}

func TestSecondaryRouterDetailHasOwnWANAndWireGuard(t *testing.T) {
	primary := RouterConfig{ID: "router-a", Host: "192.0.2.1", Type: "openwrt", IsGateway: true}
	secondary := RouterConfig{ID: "router-b", Host: "192.0.2.2", Type: "openwrt", IsRouter: true}
	latency, loss := 12.5, 0.0
	download, upload := 2000000.0, 1000000.0
	l := &Live{
		routers: []RouterConfig{primary, secondary}, gatewayCfg: &primary,
		lastPolled: map[string]*routerPolled{secondary.ID: {
			cfg: secondary, latencyMs: &latency, lossPct: &loss,
			net:     &NetDevBps{RxBps: &download, TxBps: &upload},
			wanInfo: probe.WanInfo{Proto: "pppoe", IP: "198.51.100.2", Gateway: "198.51.100.1"},
		}},
		wgByRouter: map[string]WireGuardStats{secondary.ID: {Status: "active", Interface: "wg0"}},
	}
	detail, err := l.GetRouterDetail(context.Background(), secondary.ID)
	if err != nil || detail == nil {
		t.Fatalf("secondary detail: %v", err)
	}
	if detail.Router.RoleBadge != "Secondary" || detail.WAN == nil || detail.WAN.LatencyMs == nil || *detail.WAN.LatencyMs != latency || detail.WAN.PublicIP != "198.51.100.2" || detail.Wireguard == nil || detail.Wireguard.Interface != "wg0" {
		t.Fatalf("missing router-scoped checks: role=%s wan=%+v wg=%+v", detail.Router.RoleBadge, detail.WAN, detail.Wireguard)
	}
	if primary.IsGateway != true || l.gatewayCfg.ID != primary.ID {
		t.Fatal("secondary detail changed the primary router")
	}
}

func TestSecondaryRouterOverviewListsEveryRouterWireGuard(t *testing.T) {
	routers := []RouterConfig{
		{ID: "router-a", IsGateway: true},
		{ID: "ap"},
		{ID: "router-b", IsRouter: true},
		{ID: "router-c", IsRouter: true},
	}
	byRouter := map[string]WireGuardStats{
		"router-a": {Interface: "wg-a", Status: "active"},
		"router-b": {Interface: "wg-b", Status: "active"},
	}
	got := routerWireGuardOverview(routers, "router-a", byRouter, "auto")
	if len(got) != 3 || got[0].RouterID != "router-a" || got[1].RouterID != "router-b" || got[1].Stats.Interface != "wg-b" || got[2].RouterID != "router-c" || got[2].Stats.Status != "inactive" {
		t.Fatalf("router wireguard overview: %+v", got)
	}
}
