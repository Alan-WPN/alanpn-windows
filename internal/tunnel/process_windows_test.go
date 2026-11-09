//go:build windows

package tunnel

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBundledXrayAcceptsGeneratedConfigWithoutStartingTunnel(t *testing.T) {
	file, err := filepath.Abs(filepath.Join("..", "..", "vendor-assets", "xray.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(file); err != nil {
		t.Skip("Bundled engine not downloaded")
	}
	config, err := BuildConfig(link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, file, "run", "-test", "-format", "json", "-config", "stdin:")
	cmd.Stdin = bytes.NewReader(config)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Bundled Xray config validation failed: %v\n%s", err, output)
	}
}

func TestProbeFailureNeverExportsTargetOrRawError(t *testing.T) {
	for _, tc := range []struct {
		cause error
		want  string
	}{
		{context.DeadlineExceeded, "timeout"},
		{x509.UnknownAuthorityError{}, "TLS trust failure"},
		{syscall.Errno(10051), "socket error 10051"},
		{errors.New("secret UUID and private subscription URL"), "transport failure"},
	} {
		err := &url.Error{Op: "Get", URL: "https://private.example/secret", Err: tc.cause}
		if actual := safeProbeFailure(err); actual != tc.want {
			t.Fatalf("wrong safe error category: %q", actual)
		}
	}
}

func TestStartupDiagnosticNeverReturnsCapturedSecrets(t *testing.T) {
	output := &startupOutput{}
	_, _ = output.Write([]byte("Failed to start: tun route failed; secret-user-and-private-link"))
	if output.code() != "tun_route_failed" {
		t.Fatal("Incorrect diagnostic category")
	}
	_, _ = output.Write(bytes.Repeat([]byte("x"), 65536))
	if len(output.data) > 16384 {
		t.Fatal("Unbounded diagnostic buffer")
	}
}
func TestSafeFailureDetailRedactsProfileAndReadsLastFatal(t *testing.T) {
	output := &startupOutput{}
	_, _ = output.Write([]byte("early file error\nFailed to start: old error\nFailed to start: tun startup denied " + link + " private " + "00000000-0000-0000-0000-000000000001"))
	config, _ := BuildConfig(link)
	detail := output.safeDetail(config)
	if strings.Contains(detail, "00000000") || strings.Contains(detail, "vless://") || strings.Contains(detail, "awpn.alanpn.ru") {
		t.Fatal("Private profile leaked")
	}
	if !strings.Contains(detail, "startup denied") || strings.Contains(detail, "old error") {
		t.Fatal("Incorrect failure selected")
	}
}
