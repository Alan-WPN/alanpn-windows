package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const link = "vless://00000000-0000-0000-0000-000000000001@awpn.alanpn.ru:443?encryption=none&type=ws&security=tls&sni=awpn.alanpn.ru&host=awpn.alanpn.ru&path=%2Fpreserved%2Fsocket&alpn=h2%2Chttp%2F1.1&fp=chrome"

type engine struct {
	alive, ready  bool
	starts, stops int
	err           error
}

func (e *engine) Start(context.Context, []byte) error { e.starts++; e.alive = true; return nil }
func (e *engine) Ready(context.Context) bool          { return e.ready }
func (e *engine) Alive() bool                         { return e.alive }
func (e *engine) Stop() error {
	if e.err != nil {
		return e.err
	}
	e.stops++
	e.alive = false
	return nil
}

type guard struct {
	on       bool
	offCount int
}

type diagnosedEngine struct {
	*engine
	reason string
}

type clientVerifiedEngine struct {
	*engine
	clientReady bool
}

func (e *clientVerifiedEngine) ClientReady(context.Context) bool { return e.clientReady }
func TestConnectedRequiresNonExemptApplicationTraffic(t *testing.T) {
	now := time.Now()
	e := &clientVerifiedEngine{engine: &engine{ready: true}}
	g := &guard{}
	c := Controller{Engine: e, Guard: g}
	c.Lease(30*time.Second, now)
	if err := c.Connect(context.Background(), 1, "subscription", link, now); err != nil {
		t.Fatal(err)
	}
	if err := c.Tick(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if c.State == Connected || c.LastError != "client_traffic_blocked" {
		t.Fatal("Service-only connectivity incorrectly marked successful")
	}
	e.clientReady = true
	if err := c.Tick(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if c.State != Connected {
		t.Fatal("Working application traffic was not accepted")
	}
}

func (e *diagnosedEngine) Diagnostic() string { return e.reason }
func (e *diagnosedEngine) Stop() error        { e.reason = ""; return e.engine.Stop() }

func TestReadinessReasonSurvivesIntentionalRestart(t *testing.T) {
	now := time.Now()
	e := &diagnosedEngine{engine: &engine{}, reason: "tunnel_probe_failed"}
	g := &guard{}
	c := Controller{Engine: e, Guard: g}
	c.Lease(30*time.Second, now)
	if err := c.Connect(context.Background(), 1, "subscription", link, now); err != nil {
		t.Fatal(err)
	}
	if err := c.Tick(context.Background(), now.Add(16*time.Second)); err != nil {
		t.Fatal(err)
	}
	if c.LastError != "tunnel_probe_failed" || c.State != Reconnecting {
		t.Fatal("Readiness reason lost")
	}
	if err := c.Tick(context.Background(), now.Add(17*time.Second)); err != nil {
		t.Fatal(err)
	}
	if c.LastError != "tunnel_probe_failed" {
		t.Fatal("Intentional restart overwrote diagnostic")
	}
}

func (g *guard) Enable() error      { g.on = true; return nil }
func (g *guard) AllowTunnel() error { return nil }
func (g *guard) Disable() error     { g.on = false; g.offCount++; return nil }
func TestProfilePreservesEndpointAndWS(t *testing.T) {
	b, e := BuildConfig(link)
	if e != nil {
		t.Fatal(e)
	}
	var c map[string]any
	if json.Unmarshal(b, &c) != nil {
		t.Fatal("invalid JSON")
	}
	out := c["outbounds"].([]any)[0].(map[string]any)
	ws := out["streamSettings"].(map[string]any)["wsSettings"].(map[string]any)
	if ws["path"] != "/preserved/socket" {
		t.Fatal("path changed")
	}
	v := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if v["address"] != "awpn.alanpn.ru" {
		t.Fatal("GeoDNS changed")
	}
	if out["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["domainStrategy"] != "UseIP" {
		t.Fatal("Xray must resolve its own endpoint")
	}
	dns := c["dns"].(map[string]any)
	if dns["queryStrategy"] != "UseIPv4" || out["targetStrategy"] != "ForceIPv4" {
		t.Fatal("Domain destination compatibility policy missing")
	}
	servers := dns["servers"].([]any)
	bootstrap := servers[0].(map[string]any)
	if bootstrap["address"] != "https+local://1.1.1.1/dns-query" || bootstrap["skipFallback"] != true || bootstrap["domains"].([]any)[0] != "full:awpn.alanpn.ru" {
		t.Fatal("Only the VPN endpoint may use bootstrap DNS")
	}
	if servers[1].(map[string]any)["address"] != "1.1.1.1" {
		t.Fatal("Tunnel DNS missing")
	}
}
func TestLifecycle(t *testing.T) {
	now := time.Now()
	e, g := &engine{}, &guard{}
	c := Controller{Engine: e, Guard: g}
	ctx := context.Background()
	if c.Connect(ctx, 1, "one", link, now) == nil {
		t.Fatal("expired lease accepted")
	}
	c.Lease(30*time.Second, now)
	if err := c.Connect(ctx, 1, "one", link, now); err != nil {
		t.Fatal(err)
	}
	if c.State == Connected {
		t.Fatal("connected before proof")
	}
	e.ready = true
	_ = c.Tick(ctx, now)
	if c.State != Connected {
		t.Fatal(c.State)
	}
	e.alive = false
	_ = c.Tick(ctx, now.Add(time.Second))
	if !g.on || c.State != Reconnecting {
		t.Fatal("kill switch released on crash")
	}
	_ = c.Tick(ctx, now.Add(2*time.Second))
	if e.starts != 2 {
		t.Fatal("did not retry")
	}
	_ = c.Tick(ctx, now.Add(31*time.Second))
	if g.on || c.State != Disconnected {
		t.Fatal("lease cleanup failed")
	}
}
func TestSwitchAndDuplicateCommand(t *testing.T) {
	n := time.Now()
	e, g := &engine{}, &guard{}
	c := Controller{Engine: e, Guard: g}
	c.Lease(time.Minute, n)
	ctx := context.Background()
	_ = c.Connect(ctx, 1, "one", link, n)
	_ = c.Connect(ctx, 1, "one", link, n)
	if e.starts != 1 {
		t.Fatal("duplicate executed")
	}
	_ = c.Connect(ctx, 2, "two", link, n)
	if e.stops != 1 || g.offCount != 0 {
		t.Fatal("switch dropped protection")
	}
	e.err = errors.New("cleanup failed")
	if c.Disconnect() == nil || !g.on {
		t.Fatal("released protection despite failed cleanup")
	}
}
