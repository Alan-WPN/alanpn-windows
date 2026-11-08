//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"alanpn/windows/internal/tunnel"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func emergencyCleanup() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator required for recovery")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	core := filepath.Join(filepath.Dir(exe), "xray.exe")
	if manager, e := mgr.Connect(); e == nil {
		defer manager.Disconnect()
		if service, e := manager.OpenService(serviceName); e == nil {
			_, _ = service.Control(svc.Stop)
			service.Close()
		}
	}
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for e = windows.Process32First(snapshot, &entry); e == nil; e = windows.Process32Next(snapshot, &entry) {
		if !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "xray.exe") {
			continue
		}
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, entry.ProcessID)
		if err != nil {
			continue
		}
		path := make([]uint16, 32768)
		length := uint32(len(path))
		err = windows.QueryFullProcessImageName(process, 0, &path[0], &length)
		if err == nil && strings.EqualFold(windows.UTF16ToString(path[:length]), core) {
			_ = windows.TerminateProcess(process, 0)
		}
		windows.CloseHandle(process)
	}
	guard := &tunnel.Firewall{}
	defer guard.Close()
	return guard.Disable()
}
