// Package setupconfig reads an enrollment footer from the downloaded bootstrap.
// No subscription, account session or reusable device credential is embedded.
package setupconfig

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const Marker = "ALANPNSETUPv1"

// Release build selects this value; the downloaded footer cannot override it.
var Origin = "https://127.0.0.1:13002"

type Config struct {
	Version       int       `json:"version"`
	Origin        string    `json:"origin"`
	SetupID       string    `json:"setupId"`
	Ticket        string    `json:"ticket"`
	ProgressToken string    `json:"progressToken"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

func Read(file io.ReaderAt, size int64, now time.Time) (Config, error) {
	var cfg Config
	bad := errors.New("invalid or expired setup")
	footer := make([]byte, 4+len(Marker))
	if size < int64(len(footer)) {
		return cfg, bad
	}
	if _, err := file.ReadAt(footer, size-int64(len(footer))); err != nil || string(footer[4:]) != Marker {
		return cfg, bad
	}
	n := int64(binary.LittleEndian.Uint32(footer[:4]))
	if n < 1 || n > 4096 || n > size-int64(len(footer)) {
		return cfg, bad
	}
	data := make([]byte, n)
	if _, err := file.ReadAt(data, size-int64(len(footer))-n); err != nil {
		return cfg, bad
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		return Config{}, bad
	}
	if cfg.Version != 1 || cfg.Origin != Origin || !regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(cfg.SetupID) ||
		!secret(cfg.Ticket) || !secret(cfg.ProgressToken) || !cfg.ExpiresAt.After(now) || cfg.ExpiresAt.After(now.Add(16*time.Minute)) {
		return Config{}, bad
	}
	return cfg, nil
}

func secret(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
