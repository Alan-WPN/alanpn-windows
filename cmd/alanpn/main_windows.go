//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"alanpn/windows/internal/agent"
	"alanpn/windows/internal/secure"
	"alanpn/windows/internal/setupconfig"
	"alanpn/windows/internal/tunnel"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

const serviceName = "AlanPNClient"
const pipeName = `\\.\pipe\AlanPNClient.v1`

type config struct {
	Origin     string `json:"origin"`
	XraySHA256 string `json:"xraySHA256"`
	OwnerSID   string `json:"ownerSID"`
}
type localCommand struct {
	LaunchID string `json:"launchId,omitempty"`
	Action   string `json:"action"`
	Ticket   string `json:"ticket,omitempty"`
	Present  bool   `json:"present,omitempty"`
}
type request struct {
	command localCommand
	reply   chan localReply
}
type localReply struct {
	OK       bool   `json:"ok"`
	LaunchID string `json:"launchId,omitempty"`
}
type service struct {
	directory, data string
	cfg             config
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("AlanPN prototype: --diagnose, --validate, --service, --disconnect, or alanpn://pair?ticket=...")
		return
	}
	arg := os.Args[1]
	if arg == "--update-origin" {
		exe, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		path := filepath.Join(filepath.Dir(exe), "client.json")
		b, err := os.ReadFile(path)
		if err != nil {
			os.Exit(2)
		}
		var cfg config
		if json.Unmarshal(b, &cfg) != nil || !validSID(cfg.OwnerSID) {
			os.Exit(2)
		}
		cfg.Origin = setupconfig.Origin
		b, _ = json.MarshalIndent(cfg, "", "  ")
		if os.WriteFile(path, b, 0600) != nil {
			os.Exit(2)
		}
		return
	}
	if arg == "--cleanup" {
		if emergencyCleanup() != nil {
			os.Exit(1)
		}
		return
	}
	if arg == "--network-test" {
		if networkTest() != nil {
			os.Exit(1)
		}
		return
	}
	if arg == "--preflight" {
		return
	}
	if arg == "--setup" || strings.HasPrefix(arg, "--setup-owner=") {
		exe, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		directory := filepath.Dir(exe)
		b, err := os.ReadFile(filepath.Join(directory, "payload-manifest.json"))
		if err != nil {
			os.Exit(2)
		}
		var manifest map[string]string
		if json.Unmarshal(b, &manifest) != nil {
			os.Exit(2)
		}
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			os.Exit(2)
		}
		ownerSID := user.User.Sid.String()
		if strings.HasPrefix(arg, "--setup-owner=") {
			ownerSID = strings.TrimPrefix(arg, "--setup-owner=")
			if !validSID(ownerSID) {
				os.Exit(2)
			}
		}
		cfg := config{Origin: setupconfig.Origin, XraySHA256: manifest["xray.exe"], OwnerSID: ownerSID}
		if len(cfg.XraySHA256) != 64 {
			os.Exit(2)
		}
		b, _ = json.MarshalIndent(cfg, "", "  ")
		if os.WriteFile(filepath.Join(directory, "client.json"), b, 0600) != nil {
			os.Exit(2)
		}
		return
	}
	if arg == "--diagnose" {
		fmt.Printf("AlanPN Windows prototype; VM eligible: %v\n", virtualMachine())
		return
	}
	if arg == "--validate" {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4*1024*1024+1))
		_, e := tunnel.VLESSFromFeed(b)
		if e != nil {
			fmt.Println("Profile validation failed")
			os.Exit(1)
		}
		fmt.Println("Profile accepted")
		return
	}
	if arg == "--service" {
		exe, e := os.Executable()
		if e != nil {
			os.Exit(2)
		}
		directory := filepath.Dir(exe)
		b, e := os.ReadFile(filepath.Join(directory, "client.json"))
		if e != nil {
			os.Exit(2)
		}
		var cfg config
		if json.Unmarshal(b, &cfg) != nil || !validSID(cfg.OwnerSID) {
			os.Exit(2)
		}
		data := filepath.Join(os.Getenv("ProgramData"), "AlanPN")
		if e = svc.Run(serviceName, &service{directory: directory, data: data, cfg: cfg}); e != nil {
			os.Exit(1)
		}
		return
	}
	cmd := localCommand{Action: "disconnect"}
	if agent.IsOpenURI(arg) {
		if startTray() != nil {
			os.Exit(1)
		}
		cmd.Action = "wake"
		cmd.LaunchID = agent.OpenLaunchID(arg)
	} else if arg == "--diagnostics" {
		cmd.Action = "diagnostics"
	} else if arg != "--disconnect" {
		ticket, e := agent.PairTicketFromURI(arg)
		if e != nil {
			handlerReport("invalid_uri")
			os.Exit(2)
		}
		cmd = localCommand{Action: "pair", Ticket: ticket}
		handlerReport("started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, e := winio.DialPipeContext(ctx, pipeName)
	if e != nil {
		handlerReport("pipe_unavailable")
		fmt.Println("AlanPN service unavailable")
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if json.NewEncoder(conn).Encode(cmd) != nil {
		handlerReport("pipe_write_failed")
		os.Exit(1)
	}
	var result struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	if json.NewDecoder(conn).Decode(&result) != nil {
		handlerReport("pipe_response_failed")
		os.Exit(1)
	}
	if !result.OK {
		handlerReport("service_rejected")
		os.Exit(1)
	}
	if cmd.Action == "pair" {
		handlerReport("paired")
		_ = startTray()
	}
	if cmd.Action == "diagnostics" {
		fmt.Println(result.Detail)
	}
}

// Called by the interactive protocol handler, never by the SYSTEM service.
func startTray() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(filepath.Dir(exe), "alanpn-tray.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err = cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
func handlerReport(code string) {
	// Diagnostic codes only: no URI, ticket, credentials or subscription data.
	directory := filepath.Join(os.Getenv("LOCALAPPDATA"), "AlanPN")
	if os.MkdirAll(directory, 0700) != nil {
		return
	}
	body, _ := json.Marshal(map[string]any{"code": code, "at": time.Now().UTC()})
	_ = os.WriteFile(filepath.Join(directory, "pairing-status.json"), body, 0600)
}
func validSID(s string) bool {
	_, e := windows.StringToSid(s)
	return e == nil && strings.HasPrefix(s, "S-1-5-21-")
}
func virtualMachine() bool {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if e != nil {
		return false
	}
	defer k.Close()
	model, _, _ := k.GetStringValue("SystemProductName")
	model = strings.ToLower(model)
	for _, s := range []string{"virtual machine", "virtualbox", "vmware", "kvm", "qemu"} {
		if strings.Contains(model, s) {
			return true
		}
	}
	return false
}
func (s *service) Execute(_ []string, changes <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, e := agent.New(s.cfg.Origin)
	if e != nil {
		return true, 2
	}
	credPath := filepath.Join(s.data, "credentials.bin")
	if b, e := secure.Load(credPath); e == nil {
		if json.Unmarshal(b, &client.Credentials) != nil {
			return true, 3
		}
	}
	exe, _ := os.Executable()
	engine := &tunnel.Process{Directory: s.directory, ExpectedSHA256: s.cfg.XraySHA256}
	guard := &tunnel.Firewall{EnginePath: filepath.Join(s.directory, "xray.exe"), ServicePath: exe}
	defer guard.Close()
	ctl := &tunnel.Controller{Engine: engine, Guard: guard, State: tunnel.Disconnected}
	// A service restart starts disconnected, without an old unattended connection.
	if guard.Disable() != nil {
		return true, 4
	}
	commands := make(chan request)
	listener, e := winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + s.cfg.OwnerSID + ")", MessageMode: false, InputBufferSize: 4096, OutputBufferSize: 4096})
	if e != nil {
		return true, 5
	}
	defer listener.Close()
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				var cmd localCommand
				if json.NewDecoder(io.LimitReader(bufio.NewReaderSize(conn, 2048), 4096)).Decode(&cmd) != nil {
					return
				}
				if cmd.Action == "diagnostics" {
					_ = json.NewEncoder(conn).Encode(map[string]any{"ok": true, "detail": engine.SafeFailureDetail()})
					return
				}
				if cmd.Action == "capabilities" {
					_ = json.NewEncoder(conn).Encode(map[string]any{"ok": true, "lifecycleProtocol": 3, "origin": s.cfg.Origin})
					return
				}
				if cmd.Action != "pair" && cmd.Action != "disconnect" && cmd.Action != "presence" && cmd.Action != "wake" {
					return
				}
				if cmd.LaunchID != "" && !agent.ValidLaunchID(cmd.LaunchID) {
					return
				}
				req := request{command: cmd, reply: make(chan localReply, 1)}
				select {
				case commands <- req:
				case <-ctx.Done():
					return
				}
				select {
				case reply := <-req.reply:
					_ = json.NewEncoder(conn).Encode(reply)
				case <-ctx.Done():
					return
				}
			}()
		}
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	next := time.Now()
	var seq uint64
	var emergency bool
	var traySeen time.Time
	var trayLaunchID, pendingLaunchID string
	// Network work must not block the local lease deadline or emergency pipe.
	type exchange struct {
		out        agent.SyncResponse
		err        error
		started    time.Time
		generation uint64
	}
	results := make(chan exchange, 1)
	var generation uint64
	var inFlight bool
	var stopExchange context.CancelFunc
	defer func() {
		if stopExchange != nil {
			stopExchange()
		}
	}()
	for {
		select {
		case change := <-changes:
			if change.Cmd == svc.Interrogate {
				status <- change.CurrentStatus
				continue
			}
			status <- svc.Status{State: svc.StopPending}
			if ctl.Disconnect() != nil {
				return true, 6
			}
			return false, 0
		case req := <-commands:
			if req.command.Action == "presence" || req.command.Action == "wake" {
				if req.command.Action == "wake" && req.command.LaunchID != "" {
					pendingLaunchID = req.command.LaunchID
				}
				if req.command.Action == "presence" {
					if req.command.Present {
						traySeen = time.Now()
						if req.command.LaunchID != "" && req.command.LaunchID == pendingLaunchID {
							trayLaunchID = pendingLaunchID
						}
					} else {
						traySeen = time.Time{}
						trayLaunchID = ""
					}
				}
				next = time.Now()
				req.reply <- localReply{OK: true, LaunchID: pendingLaunchID}
				continue
			}
			generation++
			if stopExchange != nil {
				stopExchange()
			}
			var err error
			if req.command.Action == "disconnect" {
				err = ctl.Disconnect()
				emergency = true
			} else {
				if ctl.SubscriptionID != "" {
					err = errors.New("disconnect before pairing")
				} else if err = client.Pair(ctx, req.command.Ticket); err == nil {
					var b []byte
					b, err = json.Marshal(client.Credentials)
					if err == nil {
						err = secure.Save(credPath, b)
						seq = 0
						ctl = &tunnel.Controller{Engine: engine, Guard: guard, State: tunnel.Disconnected}
						emergency = false
					}
				}
			}
			next = time.Now()
			req.reply <- localReply{OK: err == nil}
		case now := <-tick.C:
			_ = ctl.Tick(ctx, now)
			if inFlight || now.Before(next) || client.Credentials.Token == "" {
				continue
			}
			next = now.Add(2 * time.Second)
			if ctl.SubscriptionID == "" {
				next = now.Add(15 * time.Second)
			}
			inFlight = true
			requestCtx, cancelRequest := context.WithTimeout(ctx, 11*time.Second)
			stopExchange = cancelRequest
			copyClient := *client
			report := agent.SyncRequest{State: string(ctl.State), SubscriptionID: ctl.SubscriptionID, LastSequence: seq, ErrorCode: ctl.LastError, TrayRunning: !traySeen.IsZero() && time.Since(traySeen) < 12*time.Second, TrayLaunchID: trayLaunchID}
			currentGeneration := generation
			stopRemote := emergency
			go func() {
				defer cancelRequest()
				started := time.Now()
				if stopRemote {
					if err := copyClient.Disconnect(requestCtx); err != nil {
						select {
						case results <- exchange{err: err, generation: currentGeneration}:
						case <-ctx.Done():
						}
						return
					}
				}
				out, err := copyClient.Sync(requestCtx, report)
				if err == nil && out.Command != nil && out.Command.Action == "connect" {
					var feed []byte
					feed, err = copyClient.FetchSubscription(requestCtx, out.Command.SubscriptionURL)
					if err == nil {
						out.Command.VLESS, err = tunnel.VLESSFromFeed(feed)
					}
				}
				select {
				case results <- exchange{out, err, started, currentGeneration}:
				case <-ctx.Done():
				}
			}()
		case result := <-results:
			inFlight = false
			if result.generation != generation {
				continue
			}
			out, err := result.out, result.err
			if err != nil {
				if errors.Is(err, agent.ErrAuthorizationDenied) {
					_ = ctl.Disconnect()
					ctl.LastError = "device_authorization_denied"
					continue
				}
				if out.Command != nil && out.Command.Sequence > seq {
					seq = out.Command.Sequence
					// A failed switch must not report the previous tunnel as the new subscription.
					if ctl.Disconnect() == nil {
						ctl.State = tunnel.Failed
					}
				}
				continue
			}
			emergency = false
			remaining := time.Duration(out.LeaseRemainingMS)*time.Millisecond - time.Since(result.started)
			ctl.Lease(remaining, time.Now())
			if remaining <= 0 {
				_ = ctl.Disconnect()
			}
			if remaining > 0 {
				next = time.Now().Add(2 * time.Second)
			}
			if out.Command == nil || out.Command.Sequence <= seq {
				continue
			}
			command := out.Command
			if command.Action == "connect" {
				err = ctl.Connect(ctx, command.Sequence, command.SubscriptionID, command.VLESS, time.Now())
			} else if command.Action == "disconnect" {
				err = ctl.Disconnect()
			} else {
				err = errors.New("unsupported command")
			}
			// Acknowledge each attempt once; retrying the tunnel is the controller's job.
			seq = command.Sequence
			if err != nil && command.Action == "connect" && ctl.SubscriptionID != command.SubscriptionID {
				if ctl.Disconnect() == nil {
					ctl.State = tunnel.Failed
				}
			}
			if err != nil && ctl.SubscriptionID == "" {
				ctl.State = tunnel.Failed
			}
		}
	}
}
