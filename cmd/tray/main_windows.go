//go:build windows

package main

import (
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

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
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return
	}
	defer windows.CloseHandle(mutex)
	exe, err := os.Executable()
	if err != nil {
		return
	}
	client := filepath.Join(filepath.Dir(exe), "alanpn-client.exe")
	systray.Run(func() {
		systray.SetIcon(logo)
		systray.SetTooltip("AlanPN · управление VPN")
		status := systray.AddMenuItem("AlanPN · управление туннелем", "")
		status.Disable()
		systray.AddSeparator()
		disconnect := systray.AddMenuItem("Отключить VPN", "Остановить туннель AlanPN и снять его сетевую защиту")
		quit := systray.AddMenuItem("Отключить VPN и выйти", "Сначала отключить туннель, затем убрать значок из трея")
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
				if stopTunnel(client) != nil {
					status.SetTitle("Не удалось отключить · повторите")
					systray.SetTooltip("AlanPN · отключение не подтверждено")
				} else {
					status.SetTitle("Команда отключения выполнена")
					systray.SetTooltip("AlanPN · команда отключения выполнена")
					if leave {
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

func stopTunnel(client string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, client, "--disconnect")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000, HideWindow: true}
	return cmd.Run()
}
