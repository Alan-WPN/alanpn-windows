//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TASKDIALOGCONFIG and TASKDIALOG_BUTTON are packed at byte alignment in the
// Windows headers. Explicit encoding avoids Go's natural 8-byte padding.
func taskDialogConfiguration(title, instruction, content, footer, button *uint16, width uint32) ([]byte, []byte) {
	buttons := make([]byte, 12)
	binary.LittleEndian.PutUint32(buttons, 1001)
	binary.LittleEndian.PutUint64(buttons[4:], uint64(uintptr(unsafe.Pointer(button))))
	cfg := make([]byte, 160)
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(cfg[offset:], value) }
	putPtr := func(offset int, value uintptr) { binary.LittleEndian.PutUint64(cfg[offset:], uint64(value)) }
	put32(0, 160)
	put32(20, 0x10|0x8|0x1000) // command links, cancel/close, relative to owner
	put32(24, 0x8)             // Cancel common button
	putPtr(28, uintptr(unsafe.Pointer(title)))
	putPtr(36, 65532) // TD_SHIELD_ICON
	putPtr(44, uintptr(unsafe.Pointer(instruction)))
	putPtr(52, uintptr(unsafe.Pointer(content)))
	put32(60, 1)
	putPtr(64, uintptr(unsafe.Pointer(&buttons[0])))
	put32(72, 2) // Cancellation is the safe initial keyboard default.
	putPtr(132, uintptr(unsafe.Pointer(footer)))
	put32(156, width)
	return cfg, buttons
}

func confirmInstallation(preview bool) (bool, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
	if err != nil {
		return false, err
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return false, err
	}
	title := "AlanPN для Windows"
	button := "Установить AlanPN\nЗатем подтвердите разрешение Windows"
	if preview {
		title = "AlanPN · Предпросмотр установки"
		button = "Установить AlanPN · предпросмотр\nВ этом режиме ничего не устанавливается"
	}
	content := "Установим фоновую службу AlanPN и сетевые компоненты Xray / Wintun, чтобы подключать VPN кнопкой в личном кабинете.\n\n" +
		"Программа: " + filepath.Join(programFiles, "AlanPN") + "\n" +
		"Защищённые данные: " + filepath.Join(programData, "AlanPN") + "\n\n" +
		"Права администратора нужны для службы Windows, виртуального сетевого адаптера и защиты соединения.\n\n" +
		"После установки компьютер привяжется автоматически. Дальнейший процесс будет показан на сайте."
	texts := []string{title, "VPN одним нажатием", content, "Локальная тестовая версия · Windows 10/11 x64 · Без мастера «Далее»", button}
	utf := make([]*uint16, len(texts))
	for i, text := range texts {
		utf[i], err = windows.UTF16PtrFromString(text)
		if err != nil {
			return false, err
		}
	}
	cfg, buttons := taskDialogConfiguration(utf[0], utf[1], utf[2], utf[3], utf[4], 320)
	// Common Controls v6 and asInvoker are embedded in bootstrap.manifest.
	proc := windows.NewLazySystemDLL("comctl32.dll").NewProc("TaskDialogIndirect")
	if proc.Find() != nil {
		return false, errors.New("installation dialog unavailable")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var selected int32
	result, _, _ := proc.Call(uintptr(unsafe.Pointer(&cfg[0])), uintptr(unsafe.Pointer(&selected)), 0, 0)
	runtime.KeepAlive(utf)
	runtime.KeepAlive(buttons)
	runtime.KeepAlive(cfg)
	if int32(result) < 0 {
		return false, errors.New("installation dialog failed")
	}
	return selected == 1001, nil
}
