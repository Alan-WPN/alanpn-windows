package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlDenialIsNotTreatedAsTemporaryNetworkFailure(t *testing.T) {
	for _, status := range []int{401, 403, 503} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		client, _ := New(server.URL)
		client.HTTP = server.Client()
		_, err := client.Sync(context.Background(), SyncRequest{State: "disconnected"})
		server.Close()
		if errors.Is(err, ErrAuthorizationDenied) != (status != 503) {
			t.Fatal("authorization denial confused with network failure")
		}
	}
}

func TestOpenURIIsOnlyTrayLaunch(t *testing.T) {
	for _, uri := range []string{"alanpn://open", "alanpn://open/", "ALANPN://OPEN", "alanpn://open?launch=12345678-1234-4234-8234-123456789abc"} {
		if !IsOpenURI(uri) {
			t.Fatal("valid launch rejected")
		}
	}
	for _, uri := range []string{"https://open", "alanpn://open?connect=1", "alanpn://open?", "alanpn://open?launch=bad", "alanpn://open?launch=12345678-1234-4234-8234-123456789abc&launch=12345678-1234-4234-8234-123456789abc", "alanpn://open/path", "alanpn://user@open", "alanpn://open#pair", "alanpn:open", "alanpn://pair"} {
		if IsOpenURI(uri) {
			t.Fatal("untrusted launch accepted")
		}
	}
}
