//go:build windows

// The downloaded bootstrap runs as the interactive user. Only the embedded,
// fixed installer is elevated. Enrollment secrets never enter process arguments.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"alanpn/windows/internal/setupconfig"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

//go:embed payload/installer.exe
var installer []byte

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--verify-service" {
		verifyServicePeer()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--preview-installation" {
		// Pure UI preview: no enrollment file, network, elevation or service use.
		_, _ = confirmInstallation(true)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		notice()
		return
	}
	f, err := os.Open(exe)
	if err != nil {
		notice()
		return
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		notice()
		return
	}
	cfg, err := setupconfig.Read(f, info.Size(), time.Now())
	f.Close()
	if len(os.Args) == 2 && os.Args[1] == "--verify-package" {
		// Deliberately before networking, mutexes, extraction, UAC and pairing.
		// Used to verify Windows can load a personalized PE without installing.
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"format": "ALANPN_BOOTSTRAP_TEMPLATE_V1", "origin": setupconfig.Origin, "valid": err == nil, "bundlePE": len(installer) > 2 && string(installer[:2]) == "MZ", "bundleBytes": len(installer)})
		return
	}
	if err != nil {
		notice()
		return
	}
	mutexName, _ := windows.UTF16PtrFromString(`Local\AlanPN.Setup.` + cfg.SetupID)
	mutex, err := windows.CreateMutex(nil, false, mutexName)
	if err != nil {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return
	}
	defer windows.CloseHandle(mutex)
	ctx, cancel := context.WithDeadline(context.Background(), cfg.ExpiresAt)
	defer cancel()
	httpClient := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	progress := func(stage int, code string) bool {
		payload := map[string]any{"id": cfg.SetupID, "token": cfg.ProgressToken, "stage": stage}
		if code != "" {
			payload["errorCode"] = code
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, "POST", cfg.Origin+"/api/native/setup/progress", bytes.NewReader(body))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := httpClient.Do(req)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode == http.StatusOK
	}
	if !progress(1, "") {
		notice()
		return
	}
	// An installed idle service can enroll immediately: no elevation/reinstall.
	available, paired := false, false
	root, rootErr := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
	if rootErr == nil {
		if info, statErr := os.Stat(filepath.Join(root, "AlanPN", "alanpn-tray.exe")); statErr == nil && info.Mode().IsRegular() && supportsLifecycle(ctx) {
			available, paired = pair(ctx, cfg.Ticket)
		}
	}
	if available {
		if !paired {
			progress(3, "pairing_failed")
		} else {
			startTray()
		}
		return
	}
	approved, err := confirmInstallation(false)
	if err != nil {
		progress(3, "installation_failed")
		return
	}
	if !approved {
		progress(3, "installation_cancelled")
		return
	}
	if ctx.Err() != nil {
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		progress(3, "installation_failed")
		return
	}
	owner := user.User.Sid.String()
	if !strings.HasPrefix(owner, "S-1-5-21-") {
		progress(3, "installation_failed")
		return
	}
	directory, err := os.MkdirTemp("", "AlanPN-Setup-")
	if err != nil {
		progress(3, "installation_failed")
		return
	}
	// No recursive deletion or broad cleanup: only our exact file and empty dir.
	file := filepath.Join(directory, "AlanPN-Installer.exe")
	defer func() { _ = os.Remove(file); _ = os.Remove(directory) }()
	if os.WriteFile(file, installer, 0600) != nil {
		progress(3, "installation_failed")
		return
	}
	data, err := os.ReadFile(file)
	if err != nil || sha256.Sum256(data) != sha256.Sum256(installer) {
		progress(3, "installation_failed")
		return
	}
	if !progress(2, "") {
		return
	}
	code := elevate(file, owner)
	if code != "" {
		progress(3, code)
		return
	}
	if !progress(3, "") {
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		available, paired = pair(ctx, cfg.Ticket)
		if paired {
			startTray()
			return
		}
		if available {
			progress(3, "pairing_failed")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	progress(3, "service_unavailable")
}

func startTray() {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
	if err != nil {
		return
	}
	cmd := exec.Command(filepath.Join(root, "AlanPN", "alanpn-tray.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}

func supportsLifecycle(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, `\\.\pipe\AlanPNClient.v1`)
	if err != nil {
		return false
	}
	defer conn.Close()
	if !trustedServicePeer(conn) {
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if json.NewEncoder(conn).Encode(map[string]string{"action": "capabilities"}) != nil {
		return false
	}
	var reply struct {
		OK       bool   `json:"ok"`
		Protocol int    `json:"lifecycleProtocol"`
		Origin   string `json:"origin"`
	}
	return json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&reply) == nil && reply.OK && reply.Protocol >= 3 && reply.Origin == setupconfig.Origin
}

func pair(ctx context.Context, ticket string) (available, paired bool) {
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(requestCtx, `\\.\pipe\AlanPNClient.v1`)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	if !trustedServicePeer(conn) {
		return true, false
	}
	deadline, _ := requestCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	if json.NewEncoder(conn).Encode(map[string]string{"action": "pair", "ticket": ticket}) != nil {
		return true, false
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&result) != nil {
		return true, false
	}
	return true, result.OK
}

type shellExecuteInfo struct {
	Size       uint32
	Mask       uint32
	Window     uintptr
	Verb       *uint16
	File       *uint16
	Parameters *uint16
	Directory  *uint16
	Show       int32
	Instance   uintptr
	IDList     uintptr
	Class      *uint16
	ClassKey   uintptr
	HotKey     uint32
	Icon       uintptr
	Process    windows.Handle
}

func elevate(file, owner string) string {
	// Shell extensions may use COM; STA initialization is thread-local.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ole := windows.NewLazySystemDLL("ole32.dll")
	hr, _, _ := ole.NewProc("CoInitializeEx").Call(0, 0x2|0x4)
	if int32(hr) < 0 {
		return "installation_failed"
	}
	defer ole.NewProc("CoUninitialize").Call()
	verb, _ := windows.UTF16PtrFromString("runas")
	name, _ := windows.UTF16PtrFromString(file)
	args, _ := windows.UTF16PtrFromString("/S /OWNER_SID=" + owner)
	info := shellExecuteInfo{Mask: 0x40 | 0x100 | 0x400, Verb: verb, File: name, Parameters: args, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	result, _, err := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return "uac_cancelled"
		}
		return "installation_failed"
	}
	defer windows.CloseHandle(info.Process)
	wait, err := windows.WaitForSingleObject(info.Process, 10*60*1000)
	if err != nil || wait != windows.WAIT_OBJECT_0 {
		return "installation_timeout"
	}
	var exit uint32
	if windows.GetExitCodeProcess(info.Process, &exit) != nil || exit != 0 {
		return "installation_failed"
	}
	return ""
}

func notice() {
	message, _ := windows.UTF16PtrFromString("Откройте личный кабинет AlanPN и снова нажмите «Подключить», чтобы скачать актуальный файл. / Open your AlanPN account and click Connect to download a fresh setup.")
	title, _ := windows.UTF16PtrFromString("AlanPN")
	_, _, _ = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x10)
}
