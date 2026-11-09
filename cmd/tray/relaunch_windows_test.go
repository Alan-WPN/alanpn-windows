//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

func TestRelaunchWaitsForExitingInstance(t *testing.T) {
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`Local\AlanPN.Test.Relaunch.%d.%d`, os.Getpid(), time.Now().UnixNano()))
	held, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() { time.Sleep(150 * time.Millisecond); windows.CloseHandle(held); close(released) }()
	exiting, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(exiting)
	acquired, err := acquireTrayMutex(name, exiting, time.Second)
	<-released
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(acquired)
}

func TestRunningTrayDoesNotLeaveDelayedDuplicate(t *testing.T) {
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`Local\AlanPN.Test.Existing.%d.%d`, os.Getpid(), time.Now().UnixNano()))
	held, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(held)
	exiting, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(exiting)
	started := time.Now()
	h, err := acquireTrayMutex(name, exiting, time.Second)
	if h != 0 {
		windows.CloseHandle(h)
	}
	if err == nil || time.Since(started) > 500*time.Millisecond {
		t.Fatal("a running tray must reject a duplicate immediately")
	}
}

func TestVisibleTrayAcknowledgesFreshLaunch(t *testing.T) {
	address := fmt.Sprintf(`\\.\pipe\AlanPN.Ack.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(address, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	id := "12345678-1234-4234-8234-123456789abc"
	received := make(chan string, 2)
	go func() {
		for n := 0; n < 2; n++ {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			var body struct {
				LaunchID string `json:"launchId"`
			}
			if json.NewDecoder(conn).Decode(&body) == nil {
				received <- body.LaunchID
			}
			_ = json.NewEncoder(conn).Encode(map[string]any{"ok": true, "launchId": id})
			conn.Close()
		}
	}()
	if err = reportPresence(context.Background(), address, true); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"", id} {
		select {
		case actual := <-received:
			if actual != expected {
				t.Fatal("missing fresh acknowledgement")
			}
		case <-time.After(time.Second):
			t.Fatal("timed out")
		}
	}
}
