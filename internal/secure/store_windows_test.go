//go:build windows

package secure

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIRoundTripAndNoPlaintext(t *testing.T) {
	file := filepath.Join(t.TempDir(), "credentials.bin")
	secret := []byte("test-only-not-a-real-credential")
	if e := Save(file, secret); e != nil {
		t.Fatal(e)
	}
	encrypted, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(encrypted, secret) {
		t.Fatal("plaintext persisted")
	}
	plain, e := Load(file)
	if e != nil || !bytes.Equal(plain, secret) {
		t.Fatal("decrypt failed")
	}
	encrypted[len(encrypted)/2] ^= 1
	if e = os.WriteFile(file, encrypted, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(file); e == nil {
		t.Fatal("tampered payload accepted")
	}
}
