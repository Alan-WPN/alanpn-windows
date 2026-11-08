package tunnel

import (
	"context"
	"errors"
	"time"
)

type State string

const (
	Disconnected  State = "disconnected"
	Connecting    State = "connecting"
	Connected     State = "connected"
	Reconnecting  State = "reconnecting"
	Disconnecting State = "disconnecting"
	Failed        State = "error"
)

type Engine interface {
	Start(context.Context, []byte) error
	Ready(context.Context) bool
	Alive() bool
	Stop() error
}
type Guard interface {
	Enable() error
	AllowTunnel() error
	Disable() error
}
type Controller struct {
	Engine         Engine
	Guard          Guard
	State          State
	SubscriptionID string
	LastError      string
	deadline       time.Time
	retryAt        time.Time
	failures       int
	profile        []byte
	lastSequence   uint64
	startedAt      time.Time
}

// All calls belong to one service event loop. No parallel tunnel operations.
func (c *Controller) Lease(ttl time.Duration, now time.Time) {
	if ttl < 0 {
		ttl = 0
	}
	if ttl > 30*time.Second {
		ttl = 30 * time.Second
	}
	c.deadline = now.Add(ttl)
}
func (c *Controller) Connect(ctx context.Context, seq uint64, id, link string, now time.Time) error {
	if seq <= c.lastSequence {
		return nil
	}
	if !now.Before(c.deadline) {
		return errors.New("page lease expired")
	}
	profile, err := BuildConfig(link)
	if err != nil {
		c.LastError = "invalid_profile"
		return err
	}
	if err = c.Guard.Enable(); err != nil {
		c.LastError = "kill_switch_failed"
		return err
	}
	if c.SubscriptionID != "" {
		if err = c.Engine.Stop(); err != nil {
			return err
		}
	}
	c.lastSequence = seq
	c.SubscriptionID = id
	c.profile = profile
	c.State = Connecting
	c.failures = 0
	c.retryAt = time.Time{}
	return c.attempt(ctx, now)
}
func (c *Controller) attempt(ctx context.Context, now time.Time) error {
	if !now.Before(c.deadline) {
		return c.Disconnect()
	}
	if err := c.Engine.Start(ctx, c.profile); err != nil {
		c.LastError = "engine_launch_failed"
		c.failed(now)
		return err
	}
	c.startedAt = now
	// Startup is checked in Tick, never advertise connected merely on process start.
	return nil
}
func (c *Controller) failed(now time.Time) {
	c.State = Reconnecting
	delays := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	i := c.failures
	if i >= len(delays) {
		i = len(delays) - 1
	}
	c.retryAt = now.Add(delays[i])
	c.failures++
}
func (c *Controller) Tick(ctx context.Context, now time.Time) error {
	if c.SubscriptionID == "" {
		return nil
	}
	if !now.Before(c.deadline) {
		return c.Disconnect()
	}
	if !c.Engine.Alive() {
		if engine, ok := c.Engine.(interface{ Diagnostic() string }); ok {
			if code := engine.Diagnostic(); code != "" {
				c.LastError = code
			}
		}
		if c.State != Reconnecting {
			c.failed(now)
		}
		if !now.Before(c.retryAt) {
			return c.attempt(ctx, now)
		}
		return nil
	}
	if c.State == Connecting || c.State == Reconnecting {
		if !c.Engine.Ready(ctx) {
			if engine, ok := c.Engine.(interface{ Diagnostic() string }); ok {
				if code := engine.Diagnostic(); code != "" {
					c.LastError = code
				}
			}
			if now.Sub(c.startedAt) > 15*time.Second {
				if c.LastError == "" {
					c.LastError = "tunnel_ready_timeout"
				}
				if err := c.Engine.Stop(); err != nil {
					return err
				}
				c.failed(now)
			}
			return nil
		}
		if err := c.Guard.AllowTunnel(); err != nil {
			c.LastError = "tunnel_guard_failed"
			return err
		}
		if verifier, ok := c.Engine.(interface{ ClientReady(context.Context) bool }); ok {
			verifyCtx, cancel := context.WithDeadline(ctx, c.deadline)
			ready := verifier.ClientReady(verifyCtx)
			cancel()
			if !ready {
				c.LastError = "client_traffic_blocked"
				if engine, ok := c.Engine.(interface{ Diagnostic() string }); ok {
					c.LastError = engine.Diagnostic()
				}
				if time.Now().After(c.deadline) {
					return c.Disconnect()
				}
				if now.Sub(c.startedAt) > 15*time.Second {
					if err := c.Engine.Stop(); err != nil {
						return err
					}
					c.failed(now)
				}
				return nil
			}
		}
		c.State = Connected
		c.LastError = ""
		c.failures = 0
	}
	return nil
}
func (c *Controller) Disconnect() error {
	c.State = Disconnecting
	// Keep protection if cleanup failed; a later tick/emergency action can retry.
	if err := c.Engine.Stop(); err != nil {
		return err
	}
	if err := c.Guard.Disable(); err != nil {
		return err
	}
	c.profile = nil
	c.SubscriptionID = ""
	c.State = Disconnected
	c.LastError = ""
	c.deadline = time.Time{}
	return nil
}
