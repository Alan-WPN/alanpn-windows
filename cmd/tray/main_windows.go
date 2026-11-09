//go:build windows

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
)

//go:embed alanpn.ico
var logo []byte

func main() {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return
	}
	name, _ := windows.UTF16PtrFromString(`Local\AlanPN.Tray.` + user.User.Sid.String())
	exitName, _ := windows.UTF16PtrFromString(`Local\AlanPN.Tray.Exiting.` + user.User.Sid.String())
	exiting, err := windows.CreateEvent(nil, 1, 0, exitName)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return
	}
	defer windows.CloseHandle(exiting)
	mutex, err := acquireTrayMutex(name, exiting, 25*time.Second)
	if err != nil {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return
	}
	defer windows.CloseHandle(mutex)
	_ = windows.ResetEvent(exiting)
	exe, err := os.Executable()
	if err != nil {
		return
	}
	client := filepath.Join(filepath.Dir(exe), "alanpn-client.exe")
	presenceCtx, stopPresence := context.WithCancel(context.Background())
	presenceDone := make(chan struct{})
	defer stopPresence()
	systray.Run(func() {
		systray.SetIcon(logo)
		systray.SetTooltip("AlanPN · управление VPN")
		status := systray.AddMenuItem("AlanPN · управление туннелем", "")
		status.Disable()
		systray.AddSeparator()
		disconnect := systray.AddMenuItem("Отключить VPN", "Остановить туннель AlanPN и снять его сетевую защиту")
		quit := systray.AddMenuItem("Отключить VPN и выйти", "Сначала отключить туннель, затем убрать значок из трея")
		go func() {
			defer close(presenceDone)
			timer := time.NewTicker(5 * time.Second)
			defer timer.Stop()
			for {
				_ = reportPresence(presenceCtx, `\\.\pipe\AlanPNClient.v1`, true)
				select {
				case <-presenceCtx.Done():
					return
				case <-timer.C:
				}
			}
		}()
		go func() {
			for {
				leave := false
				select {
				case <-disconnect.ClickedCh:
				case <-quit.ClickedCh:
					leave = true
				}
				disconnect.Disable()
				quit.Disable()
				status.SetTitle("Отключаем AlanPN…")
				if leave {
					_ = windows.SetEvent(exiting)
				}
				if stopTunnel(client) != nil {
					_ = windows.ResetEvent(exiting)
					status.SetTitle("Не удалось отключить · повторите")
					systray.SetTooltip("AlanPN · отключение не подтверждено")
				} else {
					status.SetTitle("Команда отключения выполнена")
					systray.SetTooltip("AlanPN · команда отключения выполнена")
					if leave {
						stopPresence()
						<-presenceDone
						_ = reportPresence(context.Background(), `\\.\pipe\AlanPNClient.v1`, false)
						systray.Quit()
						return
					}
				}
				disconnect.Enable()
				quit.Enable()
			}
		}()
	}, func() {})
}

func reportPresence(ctx context.Context, address string, present bool) error {
	return reportPresenceAck(ctx, address, present, "", true)
}

func reportPresenceAck(ctx context.Context, address string, present bool, launchID string, acknowledge bool) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err = json.NewEncoder(conn).Encode(map[string]any{"action": "presence", "present": present, "launchId": launchID}); err != nil {
		return err
	}
	var reply struct {
		OK       bool   `json:"ok"`
		LaunchID string `json:"launchId"`
	}
	if err = json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&reply); err != nil {
		return err
	}
	if !reply.OK {
		return errors.New("tray presence rejected")
	}
	// Only the initialized tray acknowledges the current wake request. The
	// protocol handler never claims that its detached child is already visible.
	if present && acknowledge && reply.LaunchID != "" {
		return reportPresenceAck(ctx, address, true, reply.LaunchID, false)
	}
	return nil
}

func acquireTrayMutex(name *uint16, exiting windows.Handle, timeout time.Duration) (windows.Handle, error) {
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateMutex(nil, false, name)
		if err == nil {
			return h, nil
		}
		if h != 0 {
			windows.CloseHandle(h)
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) || !time.Now().Before(deadline) {
			return 0, err
		}
		state, waitErr := windows.WaitForSingleObject(exiting, 0)
		if waitErr != nil || state != windows.WAIT_OBJECT_0 {
			return 0, err
		}
		// A prior instance may be finishing Disconnect-and-exit. Wait for its
		// handle to disappear rather than losing this launch or creating two icons.
		time.Sleep(100 * time.Millisecond)
	}
}

func stopTunnel(client string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, client, "--disconnect")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000, HideWindow: true}
	return cmd.Run()
}
