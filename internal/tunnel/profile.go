package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const AdapterName = "AlanPN"

// Only client-side generated settings are accepted, never arbitrary Xray JSON.
func BuildConfig(link string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "vless" || u.User == nil || u.Hostname() == "" {
		return nil, errors.New("invalid VLESS profile")
	}
	id := u.User.Username()
	if !validUUID(id) {
		return nil, errors.New("invalid VLESS identity")
	}
	if _, set := u.User.Password(); set {
		return nil, errors.New("unexpected credentials")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid endpoint port")
	}
	if net.ParseIP(u.Hostname()) == nil && strings.ContainsAny(u.Hostname(), " /\\\r\n") {
		return nil, errors.New("invalid endpoint")
	}
	q := u.Query()
	if q.Get("encryption") != "" && q.Get("encryption") != "none" {
		return nil, errors.New("unsupported VLESS encryption")
	}
	if q.Get("type") != "ws" || q.Get("security") != "tls" {
		return nil, errors.New("prototype supports VLESS WS TLS only")
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	host := q.Get("host")
	if host == "" {
		host = sni
	}
	path := q.Get("path")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(host+sni, "\r\n") {
		return nil, errors.New("invalid TLS or WS parameters")
	}
	tls := map[string]any{"serverName": sni, "allowInsecure": false}
	if fp := q.Get("fp"); fp != "" {
		tls["fingerprint"] = fp
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		// Resolve the GeoDNS hostname in Xray itself. Windows' DNS Client is
		// intentionally blocked outside TUN and cannot bootstrap the tunnel.
		"dns": map[string]any{"tag": "alanpn-resolver", "queryStrategy": "UseIPv4", "disableFallbackIfMatch": true, "servers": []any{
			map[string]any{"address": "localhost", "domains": []string{"full:" + u.Hostname()}, "skipFallback": true},
			map[string]any{"address": "1.1.1.1"},
		}},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"alanpn-resolver"}, "outboundTag": "vpn"},
			map[string]any{"type": "field", "inboundTag": []string{"alanpn-tun"}, "port": "53", "network": "tcp,udp", "outboundTag": "alanpn-dns"},
		}},
		"inbounds": []any{map[string]any{"tag": "alanpn-tun", "protocol": "tun", "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": false}, "settings": map[string]any{
			"name": AdapterName, "mtu": 1400, "gateway": []string{"198.18.0.1/30", "fd7a:115c:a1e0::1/126"},
			"dns": []string{"1.1.1.1", "1.0.0.1"}, "autoSystemRoutingTable": []string{"0.0.0.0/0", "::/0"}, "autoOutboundsInterface": "auto",
		}}},
		"outbounds": []any{map[string]any{"tag": "vpn", "protocol": "vless", "targetStrategy": "ForceIPv4", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": u.Hostname(), "port": port, "users": []any{map[string]any{"id": id, "encryption": "none"}},
		}}}, "streamSettings": map[string]any{"network": "ws", "security": "tls", "tlsSettings": tls, "sockopt": map[string]any{"domainStrategy": "UseIP"},
			"wsSettings": map[string]any{"path": path, "headers": map[string]string{"Host": host}}}}, map[string]any{"tag": "alanpn-dns", "protocol": "dns", "settings": map[string]any{}}},
	}
	// Refuse unsupported additions instead of silently changing the imported transport.
	for _, name := range []string{"flow", "pbk", "sid", "fragment", "noises", "dialerProxy"} {
		if q.Get(name) != "" {
			return nil, errors.New("profile requires an unsupported transport option")
		}
	}
	return json.Marshal(config)
}

func validUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

func VLESSFromFeed(body []byte) (string, error) {
	if len(body) > 4*1024*1024 {
		return "", errors.New("subscription too large")
	}
	text := strings.TrimSpace(string(body))
	if !strings.Contains(text, "vless://") {
		b, e := base64.StdEncoding.DecodeString(text)
		if e != nil {
			return "", errors.New("unsupported subscription format")
		}
		text = string(b)
	}
	var found []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "vless://") {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		return "", errors.New("subscription must contain exactly one VLESS profile")
	}
	if _, e := BuildConfig(found[0]); e != nil {
		return "", e
	}
	return found[0], nil
}
