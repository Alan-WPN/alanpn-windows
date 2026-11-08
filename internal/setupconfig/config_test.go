package setupconfig

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFooterBoundToLoopbackAndShortLived(t *testing.T) {
	now := time.Now().UTC()
	valid := Config{1, Origin, "00000000-0000-4000-8000-000000000001", strings.Repeat("a", 64), strings.Repeat("b", 64), now.Add(15 * time.Minute)}
	makeFile := func(cfg Config) []byte {
		data, _ := json.Marshal(cfg)
		length := make([]byte, 4)
		binary.LittleEndian.PutUint32(length, uint32(len(data)))
		return append(append(append([]byte("MZ-test-template"), data...), length...), []byte(Marker)...)
	}
	data := makeFile(valid)
	if _, err := Read(bytes.NewReader(data), int64(len(data)), now); err != nil {
		t.Fatal("valid footer rejected")
	}
	for _, mutation := range []func(*Config){
		func(c *Config) { c.Origin = "https://example.com" }, func(c *Config) { c.Ticket = "bad" },
		func(c *Config) { c.ExpiresAt = now.Add(-time.Second) }, func(c *Config) { c.ExpiresAt = now.Add(time.Hour) },
		func(c *Config) { c.SetupID = "../anything" }, func(c *Config) { c.Version = 2 },
	} {
		c := valid
		mutation(&c)
		data := makeFile(c)
		if _, err := Read(bytes.NewReader(data), int64(len(data)), now); err == nil {
			t.Fatal("unsafe footer accepted")
		}
	}
	for _, data := range [][]byte{nil, []byte("MZ"), []byte(Marker), data[:len(data)-1]} {
		if _, err := Read(bytes.NewReader(data), int64(len(data)), now); err == nil {
			t.Fatal("truncated footer accepted")
		}
	}
}
