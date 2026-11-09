//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

func networkTest() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator required")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	dir := filepath.Dir(exe)
	b, e := os.ReadFile(filepath.Join(dir, "client.json"))
	if e != nil {
		return e
	}
	var cfg config
	if json.Unmarshal(b, &cfg) != nil {
		return errors.New("missing lab config")
	}
	input, e := io.ReadAll(io.LimitReader(os.Stdin, 4*1024*1024+1))
	if e != nil {
		return e
	}
	link, e := tunnel.VLESSFromFeed(input)
	if e != nil {
		return e
	}
	// The elevated preparation script must arm independent recovery before entry.
	permit, e := os.ReadFile(filepath.Join(dir, "lab-permit.json"))
	if e != nil {
		return errors.New("recovery not armed")
	}
	var permission struct {
		Expires    time.Time `json:"expires"`
		KeepAccess []string  `json:"keepAccess"`
	}
	if json.Unmarshal(permit, &permission) != nil || time.Now().After(permission.Expires) || time.Until(permission.Expires) > time.Minute {
		return errors.New("expired lab permit")
	}
	_ = os.Remove(filepath.Join(dir, "lab-permit.json"))
	result := map[string]any{"connected": false, "guardIndependentOfEngine": false, "leaseCleanup": false, "controlExceptions": len(permission.KeepAccess)}
	defer func() {
		data, _ := json.MarshalIndent(result, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "network-test.json"), data, 0600)
	}()
	engine := &tunnel.Process{Directory: dir, ExpectedSHA256: cfg.XraySHA256}
	guard := &tunnel.Firewall{EnginePath: filepath.Join(dir, "xray.exe"), ServicePath: exe, LabKeepAccessPaths: permission.KeepAccess}
	defer guard.Close()
	ctl := &tunnel.Controller{Engine: engine, Guard: guard, State: tunnel.Disconnected}
	defer func() { result["cleanupOK"] = ctl.Disconnect() == nil }()
	now := time.Now()
	probe := filepath.Join(dir, "alanpn-probe.exe")
	if exec.Command(probe).Run() != nil {
		result["stage"] = "baseline-network-failed"
		return errors.New("baseline probe failed")
	}
	ctl.Lease(15*time.Second, now)
	if e = ctl.Connect(context.Background(), 1, "local-test", link, now); e != nil {
		result["stage"] = "start-failed"
		return e
	}
	for time.Since(now) < 17*time.Second {
		if e = ctl.Tick(context.Background(), time.Now()); e != nil {
			result["stage"] = "tick-failed"
			return e
		}
		if ctl.State == tunnel.Connected {
			result["connected"] = true
			if result["guardIndependentOfEngine"] == false {
				if e = engine.Stop(); e != nil {
					return e
				}
				result["guardIndependentOfEngine"] = exec.Command(probe).Run() != nil
				result["killSwitchTested"] = true
			}
		}
		if ctl.State == tunnel.Disconnected {
			result["leaseCleanup"] = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	result["finalState"] = ctl.State
	if ctl.State == tunnel.Disconnected {
		result["ordinaryInternetRestored"] = exec.Command(probe).Run() == nil
	}
	return nil
}
