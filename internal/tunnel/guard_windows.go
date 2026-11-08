//go:build windows

package tunnel

import (
	"errors"
	"net"
	"path/filepath"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

var guardID = wf.SublayerID{Data1: 0x87674011, Data2: 0xca1a, Data3: 0x4051, Data4: [8]byte{0x8b, 0x91, 0x41, 0x4c, 0x41, 0x4e, 0x50, 0x4e}}

type Firewall struct {
	EnginePath, ServicePath string
	LabKeepAccessPaths      []string
	session                 *wf.Session
}

func (f *Firewall) open() error {
	if f.session != nil {
		return nil
	}
	s, e := wf.New(&wf.Options{Name: "AlanPN", Dynamic: false})
	if e != nil {
		return e
	}
	f.session = s
	return nil
}
func (f *Firewall) ownRules() ([]*wf.Rule, error) {
	all, e := f.session.Rules()
	if e != nil {
		return nil, e
	}
	var own []*wf.Rule
	for _, r := range all {
		if r.Sublayer == guardID {
			own = append(own, r)
		}
	}
	return own, nil
}
func (f *Firewall) add(layer wf.LayerID, weight uint64, action wf.Action, conditions ...*wf.Match) error {
	id, e := windows.GenerateGUID()
	if e != nil {
		return e
	}
	return f.session.AddRule(&wf.Rule{ID: wf.RuleID(id), Name: "AlanPN private tunnel guard", Layer: layer, Sublayer: guardID, Weight: weight, Action: action, Conditions: conditions, Persistent: true})
}
func (f *Firewall) Enable() error {
	if e := f.open(); e != nil {
		return e
	}
	existing, e := f.ownRules()
	if e != nil {
		return e
	}
	if len(existing) > 0 {
		blocks := 0
		for _, r := range existing {
			if r.Action == wf.ActionBlock {
				blocks++
			}
		}
		if blocks != 2 {
			return errors.New("incomplete kill-switch state; emergency cleanup required")
		}
		for _, r := range existing {
			if r.Weight == 95 {
				if e = f.session.DeleteRule(r.ID); e != nil {
					return e
				}
			}
		}
		return nil
	}
	subs, e := f.session.Sublayers()
	if e != nil {
		return e
	}
	found := false
	for _, s := range subs {
		if s.ID == guardID {
			found = true
		}
	}
	if !found {
		if e = f.session.AddSublayer(&wf.Sublayer{ID: guardID, Name: "AlanPN", Persistent: true, Weight: 65000}); e != nil {
			return e
		}
	}
	// All permits precede the final block in the same private sublayer.
	// No global firewall policy or another VPN's rules are edited.
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
		for _, path := range append([]string{f.EnginePath, f.ServicePath}, f.LabKeepAccessPaths...) {
			app, e := wf.AppID(filepath.Clean(path))
			if e != nil {
				return e
			}
			if e = f.add(layer, 100, wf.ActionPermit, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: app}); e != nil {
				return e
			}
		}
		if e = f.add(layer, 90, wf.ActionPermit, &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: uint32(1)}); e != nil {
			return e
		} // loopback
		// DHCP bootstrap, restricted to its UDP protocol and server ports.
		for _, port := range []uint16{67, 547} {
			if e = f.add(layer, 80, wf.ActionPermit, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: uint8(17)}, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: port}); e != nil {
				return e
			}
		}
		if e = f.add(layer, 1, wf.ActionBlock); e != nil {
			return e
		}
	}
	return nil
}
func (f *Firewall) AllowTunnel() error {
	iface, e := net.InterfaceByName(AdapterName)
	if e != nil {
		return e
	}
	var luid uint64
	fn := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceIndexToLuid")
	result, _, _ := fn.Call(uintptr(iface.Index), uintptr(unsafe.Pointer(&luid)))
	if result != 0 {
		return errors.New("TUN LUID unavailable")
	}
	rules, e := f.ownRules()
	if e != nil {
		return e
	}
	for _, r := range rules {
		if r.Weight == 95 {
			if e = f.session.DeleteRule(r.ID); e != nil {
				return e
			}
		}
	}
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
		// Match actual egress, not the interface associated with the socket's local IP.
		if e = f.add(layer, 95, wf.ActionPermit, &wf.Match{Field: wf.FieldIPNexthopInterface, Op: wf.MatchTypeEqual, Value: luid}); e != nil {
			return e
		}
	}
	return nil
}
func (f *Firewall) Disable() error {
	if e := f.open(); e != nil {
		return e
	}
	rules, e := f.ownRules()
	if e != nil {
		return e
	}
	for _, r := range rules {
		if e = f.session.DeleteRule(r.ID); e != nil {
			return e
		}
	}
	return nil
}
func (f *Firewall) Close() error {
	if f.session != nil {
		return f.session.Close()
	}
	return nil
}
