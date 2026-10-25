package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/adapters"
	"github.com/gnacho/netpulse/server-go/internal/db"
	"github.com/gnacho/netpulse/server-go/internal/routerstore"
)

func TestSecondaryRouterConfigAPI(t *testing.T) {
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	s := &server{db: d}
	request := func(method, id, body string, status int) adapters.RouterConfig {
		t.Helper()
		r := httptest.NewRequest(method, "/api/config/routers/"+id, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		if method == http.MethodPost {
			s.handleAddConfigRouter(w, r)
		} else {
			s.handleUpdateConfigRouter(w, r)
		}
		if w.Code != status {
			t.Fatalf("%s %s: got %d, want %d: %s", method, body, w.Code, status, w.Body.String())
		}
		var out struct {
			Router adapters.RouterConfig `json:"router"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Router
	}
	a := request("POST", "", `{"name":"router-A","host":"192.0.2.1","gateway":true}`, 201)
	b := request("POST", "", `{"name":"router-B","host":"192.0.2.2","router":true}`, 201)
	if !b.IsRouter || b.IsGateway {
		t.Fatalf("wrong secondary role: %+v", b)
	}
	request("POST", "", `{"name":"router-C","host":"192.0.2.3","router":true}`, 201)
	if legacy := request("POST", "", `{"name":"router-D","host":"192.0.2.6","secondary_router":true}`, 201); !legacy.IsRouter {
		t.Fatal("legacy secondary-router request lost the router role")
	}
	for _, r := range routerstore.ListRouters(d.DB) {
		if r.IsGateway != (r.ID == a.ID) {
			t.Fatalf("secondary displaced primary: %+v", r)
		}
	}
	if r := request("PUT", a.ID, `{"name":"primary-renamed"}`, 200); !r.IsGateway {
		t.Fatal("name update cleared primary")
	}
	if r := request("PUT", b.ID, `{"ssh_port":2222}`, 200); !r.IsRouter || r.SSHPort != 2222 {
		t.Fatalf("partial update lost secondary: %+v", r)
	}
	request("PUT", b.ID, `{"gateway":true,"router":false}`, 400)
	request("PUT", b.ID, `{"agent_only":true}`, 400)
	request("PUT", b.ID, `{"type":"managed-switch"}`, 400)
	request("PUT", b.ID, `{"snmp_enabled":true}`, 400)
	request("POST", "", `{"host":"192.0.2.4","router":true,"agent_only":true}`, 400)
	request("POST", "", `{"host":"192.0.2.4","router":true,"type":"external"}`, 400)
	request("PUT", "missing", `{"router":true}`, 404)
	if r := request("PUT", b.ID, `{"router":false}`, 200); r.IsRouter {
		t.Fatal("secondary role not removed")
	}
	request("PUT", b.ID, `{"router":true}`, 200)
	if r := request("PUT", b.ID, `{"gateway":true}`, 200); !r.IsGateway || !r.IsRouter {
		t.Fatalf("promotion failed: %+v", r)
	}
	sw := request("POST", "", `{"host":"192.0.2.5","type":"external","agent_only":true}`, 201)
	if r := request("PUT", sw.ID, `{"name":"switch-renamed"}`, 200); !r.AgentOnly {
		t.Fatal("name update cleared agent_only")
	}
	w := httptest.NewRecorder()
	s.handleListConfigRouters(w, httptest.NewRequest("GET", "/api/config/routers", nil))
	if !strings.Contains(w.Body.String(), `"is_router":true`) {
		t.Fatalf("list missing secondary role: %s", w.Body.String())
	}
}
