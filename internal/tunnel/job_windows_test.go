//go:build windows

package tunnel

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestJobChildHelper(t *testing.T) {
	if os.Getenv("ALANPN_TEST_JOB_CHILD") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}
func TestClosingJobKillsChildWithoutNetworkActivity(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestJobChildHelper$")
	cmd.Env = append(os.Environ(), "ALANPN_TEST_JOB_CHILD=1")
	job, err := startInJob(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if job != 0 {
			windows.CloseHandle(job)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if err = windows.CloseHandle(job); err != nil {
		t.Fatal(err)
	}
	job = 0
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("Job did not terminate child")
	}
}
