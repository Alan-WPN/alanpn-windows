//go:build windows

package main

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestEmbeddedInstallerAndWin64Structure(t *testing.T) {
	if len(installer) < 1024 || string(installer[:2]) != "MZ" {
		t.Fatal("missing Windows installer")
	}
	if unsafe.Sizeof(shellExecuteInfo{}) != 112 {
		t.Fatal("incorrect ShellExecuteExW x64 structure")
	}
}

func TestTaskDialogUsesPackedWindowsLayoutAndSafeDefault(t *testing.T) {
	cfg, buttons := taskDialogConfiguration(nil, nil, nil, nil, nil, 320)
	if len(cfg) != 160 || len(buttons) != 12 {
		t.Fatal("incorrect packed TaskDialog size")
	}
	if binary.LittleEndian.Uint32(cfg[72:]) != 2 {
		t.Fatal("installation must not be the default keyboard action")
	}
	if binary.LittleEndian.Uint32(cfg[60:]) != 1 || binary.LittleEndian.Uint32(buttons) != 1001 {
		t.Fatal("expected one explicit install action")
	}
}

func TestServicePeerMustMatchProtectedRegistrationAndLivePID(t *testing.T) {
	exe := `C:\Program Files\AlanPN\alanpn-client.exe`
	registered := `"` + exe + `" --service`
	if !matchesTrustedService(exe, registered, 42, 42, true) {
		t.Fatal("trusted service rejected")
	}
	for _, c := range []struct {
		path      string
		peer, pid uint32
		running   bool
	}{
		{registered, 42, 43, true}, {registered, 0, 0, true}, {registered, 42, 42, false},
		{`"C:\Users\user\alanpn-client.exe" --service`, 42, 42, true},
		{registered + ` --unexpected`, 42, 42, true},
	} {
		if matchesTrustedService(exe, c.path, c.peer, c.pid, c.running) {
			t.Fatal("untrusted pipe server accepted")
		}
	}
}
