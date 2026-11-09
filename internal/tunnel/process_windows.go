//go:build windows

package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Process struct {
	Directory      string
	ExpectedSHA256 string
	mu             sync.Mutex
	cmd            *exec.Cmd
	done           chan error
	diagnostic     string
	stopping       bool
	job            windows.Handle
	failureDetail  string
}

// Keep only a bounded startup buffer in memory, never log configuration/secrets.
type startupOutput struct {
	mu   sync.Mutex
	data []byte
}

func (b *startupOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) >= 16384 {
		b.data = append(b.data[:0], p[len(p)-16384:]...)
	} else {
		if len(b.data)+len(p) > 16384 {
			b.data = b.data[len(b.data)+len(p)-16384:]
		}
		b.data = append(b.data, p...)
	}
	return len(p), nil
}
func (b *startupOutput) code() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := strings.ToLower(string(b.data))
	if index := strings.LastIndex(text, "failed to start:"); index >= 0 {
		text = text[index:]
	}
	// Windows localizes errors. Export only an OS error number, never the
	// surrounding startup message, which can include private profile data.
	for _, number := range []int{2, 3, 5, 6, 8, 11, 13, 14, 31, 32, 50, 87, 109, 126, 127, 183, 216, 577, 1168, 1314, 1450} {
		message := strings.ToLower(syscall.Errno(number).Error())
		if len(message) > 12 && strings.Contains(text, message) {
			return fmt.Sprintf("xray_win32_%d", number)
		}
	}
	for _, entry := range []struct{ needle, code string }{
		{"access is denied", "permission_denied"}, {"wintun.dll", "wintun_load_failed"},
		{"create adapter", "tun_adapter_failed"}, {"createadapter", "tun_adapter_failed"},
		{"invalid parameter", "tun_invalid_parameter"}, {"route", "tun_route_failed"},
		{"dns", "tun_dns_failed"}, {"failed to start", "xray_startup_failed"},
	} {
		if strings.Contains(text, entry.needle) {
			return entry.code
		}
	}
	return "xray_exited"
}
func (p *Process) Diagnostic() string { p.mu.Lock(); defer p.mu.Unlock(); return p.diagnostic }
func (p *Process) SafeFailureDetail() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failureDetail
}

func (b *startupOutput) safeDetail(config []byte) string {
	b.mu.Lock()
	text := string(b.data)
	b.mu.Unlock()
	index := strings.LastIndex(strings.ToLower(text), "failed to start:")
	if index < 0 {
		return "No startup failure message was produced"
	}
	text = strings.Split(text[index:], "\n")[0]
	var value any
	var scrub func(any)
	scrub = func(v any) {
		switch x := v.(type) {
		case string:
			if len(x) >= 3 {
				text = strings.ReplaceAll(text, x, "[profile]")
			}
		case []any:
			for _, item := range x {
				scrub(item)
			}
		case map[string]any:
			for _, item := range x {
				scrub(item)
			}
		}
	}
	if json.Unmarshal(config, &value) != nil {
		return "Startup error (details unavailable)"
	}
	scrub(value)
	for _, pattern := range []string{`(?i)[a-z][a-z0-9+.-]*://[^\s<>]+`, `(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, `(?i)[a-f0-9]{16,}`, `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, `[A-Za-z]:\\[^\r\n<>]+`} {
		text = regexp.MustCompile(pattern).ReplaceAllString(text, "[redacted]")
	}
	if len(text) > 1000 {
		text = text[len(text)-1000:]
	}
	return text
}

func (p *Process) Start(_ context.Context, config []byte) error {
	if p.Alive() {
		return errors.New("engine already running")
	}
	file := filepath.Join(p.Directory, "xray.exe")
	data, err := os.ReadFile(file)
	if err != nil {
		return errors.New("engine missing")
	}
	sum := sha256.Sum256(data)
	if len(p.ExpectedSHA256) != 64 || hex.EncodeToString(sum[:]) != p.ExpectedSHA256 {
		return errors.New("engine integrity check failed")
	}
	// Credentials are supplied on stdin, never through arguments or log files.
	cmd := exec.Command(file, "run", "-format", "json", "-config", "stdin:")
	cmd.Dir = p.Directory
	cmd.Stdin = bytes.NewReader(config)
	output := &startupOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	job, err := startInJob(cmd)
	if err != nil {
		return errors.New("engine start failed")
	}
	done := make(chan error, 1)
	p.mu.Lock()
	p.cmd = cmd
	p.done = done
	p.diagnostic = ""
	p.failureDetail = ""
	p.stopping = false
	p.job = job
	p.mu.Unlock()
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		if p.job != 0 {
			windows.CloseHandle(p.job)
			p.job = 0
		}
		if !p.stopping {
			p.diagnostic = output.code()
			p.failureDetail = output.safeDetail(config)
		}
		p.mu.Unlock()
		done <- err
		close(done)
	}()
	return nil
}
func (p *Process) Alive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		p.cmd = nil
		return false
	default:
		return true
	}
}
func (p *Process) Stop() error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	if cmd != nil {
		p.stopping = true
		p.diagnostic = ""
	}
	p.mu.Unlock()
	if cmd == nil {
		return waitAdapterRemoved()
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return errors.New("engine stop failed")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return errors.New("engine did not stop")
	}
	p.mu.Lock()
	p.cmd = nil
	p.mu.Unlock()
	return waitAdapterRemoved()
}

func waitAdapterRemoved() error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		interfaces, err := net.Interfaces()
		if err != nil {
			return errors.New("cannot verify AlanPN adapter removal")
		}
		found := false
		for _, iface := range interfaces {
			if iface.Name == AdapterName {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("AlanPN adapter cleanup pending")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
func (p *Process) Ready(ctx context.Context) bool {
	setReason := func(code string) bool {
		p.mu.Lock()
		p.diagnostic = code
		p.failureDetail = "Readiness check: " + code
		p.mu.Unlock()
		return false
	}
	iface, err := net.InterfaceByName(AdapterName)
	if err != nil {
		return setReason("tun_interface_missing")
	}
	if iface.Flags&net.FlagUp == 0 {
		return setReason("tun_interface_down")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return setReason("tun_address_missing")
	}
	found := false
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip.Equal(net.ParseIP("198.18.0.1")) {
			found = true
		}
	}
	if !found {
		return setReason("tun_address_missing")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// Bind to the TUN address so a healthy direct uplink cannot be mistaken for VPN.
	dial := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.18.0.1")}, Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: dial.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(probeCtx, "GET", "https://1.1.1.1/cdn-cgi/trace", nil)
	response, err := client.Do(req)
	if err != nil {
		p.mu.Lock()
		p.diagnostic = "tunnel_probe_failed"
		p.failureDetail = "TUN HTTPS probe: " + safeProbeFailure(err)
		p.mu.Unlock()
		return false
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
	if response.StatusCode != 200 {
		p.mu.Lock()
		p.diagnostic = "tunnel_probe_failed"
		p.failureDetail = fmt.Sprintf("TUN HTTPS probe: HTTP %d", response.StatusCode)
		p.mu.Unlock()
		return false
	}
	p.mu.Lock()
	p.diagnostic = ""
	p.failureDetail = ""
	p.mu.Unlock()
	return true
}

// Export categories only; net/url errors can contain private targets.
func safeProbeFailure(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "TLS trust failure"
	}
	var certificate x509.CertificateInvalidError
	if errors.As(err, &certificate) {
		return "invalid TLS certificate"
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "TLS hostname mismatch"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	var number syscall.Errno
	if errors.As(err, &number) {
		return fmt.Sprintf("socket error %d", number)
	}
	return "transport failure"
}

func (p *Process) ClientReady(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, filepath.Join(p.Directory, "alanpn-netcheck.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err == nil {
		return true
	}
	code := "client_traffic_blocked"
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 2 {
		code = "client_dns_failed"
	}
	if errors.Is(err, os.ErrNotExist) {
		code = "client_probe_missing"
	}
	p.mu.Lock()
	p.diagnostic = code
	p.mu.Unlock()
	return false
}
