package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (fn roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestSubscriptionFetchRestrictsOriginAndNeverSendsDeviceSecret(t *testing.T) {
	client, _ := New("https://127.0.0.1:13002")
	client.Credentials = Credentials{DeviceID: "device", Token: strings.Repeat("a", 64)}
	requests := 0
	client.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-AlanPN-Device") != "" {
			t.Fatal("device secret forwarded to feed")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("test feed")), Header: make(http.Header)}, nil
	})
	for _, address := range []string{"http://awpn.alanpn.ru/subscriptions/panel/test", "https://untrusted.example/subscriptions/panel/test", "https://awpn.alanpn.ru:443/subscriptions/panel/test", "https://awpn.alanpn.ru/subscriptions/panel/test?secret=x", "https://awpn.alanpn.ru/subscriptions/panel/test/other"} {
		if _, err := client.FetchSubscription(context.Background(), address); err == nil {
			t.Fatal("accepted untrusted feed")
		}
	}
	if requests != 0 {
		t.Fatal("invalid URL reached network")
	}
	body, err := client.FetchSubscription(context.Background(), "https://awpn.alanpn.ru/subscriptions/panel/test")
	if err != nil || string(body) != "test feed" || requests != 1 {
		t.Fatal("valid feed rejected")
	}
}

func TestPairAndSyncOverTLS(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "POST" {
			t.Error("unexpected method")
		}
		if r.URL.Path == "/api/native/pairings/redeem" {
			_ = json.NewEncoder(w).Encode(Credentials{DeviceID: "test-device", Token: strings.Repeat("x", 64)})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 64) || r.Header.Get("X-AlanPN-Device") != "test-device" {
			t.Error("device authentication missing")
		}
		_ = json.NewEncoder(w).Encode(SyncResponse{LeaseRemainingMS: 600000, Command: &Command{Sequence: 1, Action: "disconnect"}})
	}))
	defer server.Close()
	client, e := New(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	client.HTTP = server.Client()
	if e = client.Pair(context.Background(), strings.Repeat("a", 64)); e != nil {
		t.Fatal(e)
	}
	response, e := client.Sync(context.Background(), SyncRequest{State: "disconnected"})
	if e != nil {
		t.Fatal(e)
	}
	if requests != 2 || response.LeaseRemainingMS != 300000 || response.Command.Sequence != 1 {
		t.Fatal("invalid sync/lease bound")
	}
}
func TestRejectInsecureOriginAndMalformedTicket(t *testing.T) {
	for _, origin := range []string{"http://alanpn.ru", "https://user:password@alanpn.ru", "https://alanpn.ru/unexpected", "https://alanpn.ru?token=x"} {
		if _, e := New(origin); e == nil {
			t.Fatalf("accepted unsafe origin %s", origin)
		}
	}
	client, _ := New("https://alanpn.local:13002")
	for _, ticket := range []string{"", strings.Repeat("g", 64), "https://example.com/sub"} {
		if client.Pair(context.Background(), ticket) == nil {
			t.Fatal("invalid ticket accepted")
		}
	}
}

func TestPairURIAllowsShellNormalizationOnly(t *testing.T) {
	ticket := strings.Repeat("a", 64)
	for _, address := range []string{"alanpn://pair?ticket=" + ticket, "alanpn://pair/?ticket=" + ticket} {
		if got, err := PairTicketFromURI(address); err != nil || got != ticket {
			t.Fatal("Shell pairing URI rejected")
		}
	}
	for _, address := range []string{"http://pair/?ticket=" + ticket, "alanpn://pair/unexpected?ticket=" + ticket, "alanpn://pair/?ticket=" + ticket + "&ticket=" + ticket, "alanpn://pair/?ticket=" + ticket + "&config=command", "alanpn://pair/?ticket=" + strings.Repeat("g", 64)} {
		if _, err := PairTicketFromURI(address); err == nil {
			t.Fatal("unsafe URI accepted")
		}
	}
}
