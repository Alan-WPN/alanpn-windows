//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/go-winio"
	"os"
	"testing"
	"time"
)

func TestPresenceUsesOnlyOwnedFakePipeAndReportsExit(t *testing.T) {
	address := fmt.Sprintf(`\\.\pipe\AlanPN.Presence.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(address, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	messages := make(chan bool, 2)
	go func() {
		for n := 0; n < 2; n++ {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			var body struct {
				Action  string `json:"action"`
				Present bool   `json:"present"`
			}
			e = json.NewDecoder(conn).Decode(&body)
			if e == nil && body.Action == "presence" {
				messages <- body.Present
			}
			_ = json.NewEncoder(conn).Encode(map[string]bool{"ok": e == nil})
			conn.Close()
		}
	}()
	if err = reportPresence(context.Background(), address, true); err != nil {
		t.Fatal(err)
	}
	if err = reportPresence(context.Background(), address, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []bool{true, false} {
		select {
		case got := <-messages:
			if got != expected {
				t.Fatal("incorrect tray presence")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("presence timed out")
		}
	}
}
