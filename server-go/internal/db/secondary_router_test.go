package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestSecondaryRouterMigration(t *testing.T) {
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, databaseFile))
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE routers (id TEXT PRIMARY KEY, name TEXT, host TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'openwrt', is_gateway INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
	INSERT INTO routers VALUES ('router-a', 'router-A', '192.0.2.1', 'openwrt', 1, 123), ('router-b', 'router-B', '192.0.2.2', 'openwrt', 0, 456);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		d, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		var primary, secondary int
		var host string
		var created int64
		if err := d.QueryRow("SELECT is_gateway, is_secondary_router, host, created_at FROM routers WHERE id = 'router-a'").Scan(&primary, &secondary, &host, &created); err != nil {
			t.Fatal(err)
		}
		if primary != 1 || secondary != 0 || host != "192.0.2.1" || created != 123 {
			t.Fatalf("primary changed: %d %d %s %d", primary, secondary, host, created)
		}
		if err := d.QueryRow("SELECT is_secondary_router FROM routers WHERE id = 'router-b'").Scan(&secondary); err != nil {
			t.Fatal(err)
		}
		if secondary != pass {
			t.Fatalf("secondary after migration/reopen = %d, want %d", secondary, pass)
		}
		if _, err := d.Exec("UPDATE routers SET is_secondary_router = 1 WHERE id = 'router-a'"); err == nil {
			t.Fatal("database allowed primary and secondary on the same device")
		}
		if _, err := d.Exec("UPDATE routers SET is_secondary_router = 1 WHERE id = 'router-b'"); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
