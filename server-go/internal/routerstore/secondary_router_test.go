package routerstore

import (
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/adapters"
	"github.com/gnacho/netpulse/server-go/internal/db"
)

func TestSecondaryRouterRoles(t *testing.T) {
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	add := func(name string, primary, secondary bool) adapters.RouterConfig {
		t.Helper()
		r, err := AddRouter(d.DB, AddInput{Name: name, Host: name, IsGateway: primary, IsRouter: secondary})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	a := add("router-A", true, false)
	b := add("router-B", false, true)
	c := add("router-C", false, true)
	assertRoles := func(primary string, secondaryIDs ...string) {
		t.Helper()
		want := map[string]bool{}
		for _, id := range secondaryIDs {
			want[id] = true
		}
		for _, r := range ListRouters(d.DB) {
			if r.IsGateway != (r.ID == primary) || r.IsRouter != (r.ID == primary || want[r.ID]) {
				t.Fatalf("unexpected roles: %+v", r)
			}
		}
	}
	assertRoles(a.ID, b.ID, c.ID)
	name := "renamed"
	if _, err := UpdateRouter(d.DB, b.ID, UpdateInput{Name: &name}); err != nil {
		t.Fatal("rename failed")
	}
	assertRoles(a.ID, b.ID, c.ID)
	yes, no := true, false
	if _, err := UpdateRouter(d.DB, b.ID, UpdateInput{IsRouter: &no}); err != nil {
		t.Fatal("remove secondary failed")
	}
	assertRoles(a.ID, c.ID)
	if _, err := UpdateRouter(d.DB, b.ID, UpdateInput{IsRouter: &yes}); err != nil {
		t.Fatal("assign secondary failed")
	}
	if _, err := UpdateRouter(d.DB, b.ID, UpdateInput{IsGateway: &yes, IsRouter: &no}); err == nil {
		t.Fatal("accepted gateway without router role")
	}
	assertRoles(a.ID, b.ID, c.ID)
	if _, err := AddRouter(d.DB, AddInput{Name: "invalid", Host: "invalid", IsRouter: true, AgentOnly: true}); err == nil {
		t.Fatal("accepted unsupported router role")
	}
	assertRoles(a.ID, b.ID, c.ID)
	if _, err := UpdateRouter(d.DB, b.ID, UpdateInput{IsGateway: &yes}); err != nil {
		t.Fatal("promotion failed")
	}
	assertRoles(b.ID, a.ID, c.ID)
}

func TestSecondaryRouterValidation(t *testing.T) {
	for _, in := range []AddInput{
		{Type: "managed-switch"}, {Type: "external"}, {Type: "openwrt", AgentOnly: true}, {Type: "openwrt", SnmpEnabled: true},
	} {
		if err := ValidateRole(false, true, in.AgentOnly, in.SnmpEnabled, in.Type); err == nil {
			t.Fatalf("accepted unsupported secondary: %+v", in)
		}
	}
	for _, typ := range []string{"openwrt", "glinet"} {
		if err := ValidateRole(false, true, false, false, typ); err != nil {
			t.Fatal(err)
		}
	}
}
