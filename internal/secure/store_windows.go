//go:build windows

package secure

import (
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func blob(data []byte) windows.DataBlob {
	if len(data) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}
func Save(path string, data []byte) error {
	in := blob(data)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	if err := os.WriteFile(path+".tmp", unsafe.Slice(out.Data, out.Size), 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
func Load(path string) ([]byte, error) {
	encrypted, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	in := blob(encrypted)
	var out windows.DataBlob
	if e = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return nil, e
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
