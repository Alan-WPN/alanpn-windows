//go:build windows

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Opening a SYSTEM process can require elevation even when the caller owns the
// pipe. SCM grants authenticated users read-only configuration/status queries.
// Check both the registered protected executable and the actual pipe server PID.
func trustedServicePeer(conn net.Conn) bool {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	var peerPID uint32
	if windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &peerPID) != nil {
		return false
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString("AlanPNClient")
	handle, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	service := mgr.Service{Name: "AlanPNClient", Handle: handle}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return false
	}
	cfg, err := service.Config()
	if err != nil {
		return false
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
	if err != nil {
		return false
	}
	return matchesTrustedService(filepath.Join(root, "AlanPN", "alanpn-client.exe"), cfg.BinaryPathName, peerPID, status.ProcessId, status.State == svc.Running) && strings.EqualFold(cfg.ServiceStartName, "LocalSystem")
}

func matchesTrustedService(exe, registered string, peerPID, servicePID uint32, running bool) bool {
	return running && peerPID != 0 && peerPID == servicePID && strings.EqualFold(strings.TrimSpace(registered), `"`+exe+`" --service`)
}

func verifyServicePeer() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, `\\.\pipe\AlanPNClient.v1`)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"pipeAvailable": false})
		return
	}
	defer conn.Close()
	result := map[string]any{"pipeAvailable": true, "serviceVerified": trustedServicePeer(conn)}
	if fd, ok := conn.(interface{ Fd() uintptr }); ok {
		var pid uint32
		if windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid) == nil {
			handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
			result["legacyProcessQueryAllowed"] = err == nil
			if err == nil {
				windows.CloseHandle(handle)
			}
		}
	}
	// Read-only: close without writing any pipe command or enrollment secret.
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
