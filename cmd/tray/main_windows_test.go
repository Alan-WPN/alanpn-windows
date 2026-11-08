//go:build windows

package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("ALANPN_TRAY_HELPER_TEST"); mode != "" && len(os.Args) == 2 && os.Args[1] == "--disconnect" {
		if mode == "success" {
			os.Exit(0)
		}
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestDisconnectAcknowledgesOnlySuccessfulOwnedHelper(t *testing.T) {
	// Child is this harmless test binary, never the installed client/service.
	t.Setenv("ALANPN_TRAY_HELPER_TEST", "success")
	if err := stopTunnel(os.Args[0]); err != nil {
		t.Fatal("successful helper rejected")
	}
	t.Setenv("ALANPN_TRAY_HELPER_TEST", "failure")
	if err := stopTunnel(os.Args[0]); err == nil {
		t.Fatal("failed cleanup reported successful")
	}
}
