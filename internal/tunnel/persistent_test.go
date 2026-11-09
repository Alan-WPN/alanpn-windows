package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestEightHoursWithDeviceRenewalAndNoBrowser(t *testing.T) {
	now := time.Now()
	e, g := &engine{ready: true}, &guard{}
	c := Controller{Engine: e, Guard: g}
	c.Lease(5*time.Minute, now)
	if err := c.Connect(context.Background(), 1, "subscription", link, now); err != nil {
		t.Fatal(err)
	}
	for elapsed := time.Duration(0); elapsed < 8*time.Hour; elapsed += 2 * time.Second {
		at := now.Add(elapsed)
		c.Lease(5*time.Minute, at) // Authenticated device sync, no page heartbeat.
		if err := c.Tick(context.Background(), at); err != nil {
			t.Fatal(err)
		}
		if c.State != Connected || !g.on {
			t.Fatal("healthy connection dropped")
		}
	}
	if err := c.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if c.State != Disconnected || g.on {
		t.Fatal("manual cleanup failed")
	}
}

func TestDeviceControlOutageIsBoundedAndCrashRetries(t *testing.T) {
	now := time.Now()
	e, g := &engine{ready: true}, &guard{}
	c := Controller{Engine: e, Guard: g}
	c.Lease(24*time.Hour, now) // Untrusted TTL is capped at five minutes.
	if err := c.Connect(context.Background(), 1, "subscription", link, now); err != nil {
		t.Fatal(err)
	}
	_ = c.Tick(context.Background(), now)
	e.alive = false
	_ = c.Tick(context.Background(), now.Add(time.Minute))
	_ = c.Tick(context.Background(), now.Add(time.Minute+time.Second))
	_ = c.Tick(context.Background(), now.Add(time.Minute+2*time.Second))
	if c.State != Connected || e.starts != 2 || !g.on {
		t.Fatal("outage interrupted retry")
	}
	_ = c.Tick(context.Background(), now.Add(5*time.Minute))
	if c.State != Disconnected || g.on {
		t.Fatal("authorization expiry not enforced")
	}
}
