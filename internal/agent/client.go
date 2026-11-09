package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Credentials struct {
	DeviceID string `json:"deviceId"`
	Token    string `json:"token"`
}

var ErrAuthorizationDenied = errors.New("device authorization denied")

type Command struct {
	Sequence        uint64 `json:"sequence"`
	Action          string `json:"action"`
	SubscriptionID  string `json:"subscriptionId"`
	VLESS           string `json:"vless"`
	SubscriptionURL string `json:"subscriptionUrl,omitempty"`
}
type SyncRequest struct {
	TrayLaunchID   string `json:"trayLaunchId,omitempty"`
	TrayRunning    bool   `json:"trayRunning"`
	State          string `json:"state"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	LastSequence   uint64 `json:"lastSequence"`
	ErrorCode      string `json:"errorCode,omitempty"`
}
type SyncResponse struct {
	LeaseRemainingMS int64    `json:"leaseRemainingMs"`
	Command          *Command `json:"command,omitempty"`
}
type Client struct {
	Origin      string
	Credentials Credentials
	HTTP        *http.Client
}

// Opening the installed tray carries no account or VPN configuration.
func IsOpenURI(address string) bool {
	u, err := url.Parse(address)
	if err != nil || !strings.EqualFold(u.Scheme, "alanpn") || !strings.EqualFold(u.Host, "open") || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.Fragment != "" {
		return false
	}
	if u.RawQuery == "" {
		return !u.ForceQuery
	}
	q, err := url.ParseQuery(u.RawQuery)
	return err == nil && len(q) == 1 && len(q["launch"]) == 1 && ValidLaunchID(q.Get("launch"))
}

// A correlation value only, never credentials or configuration.
func ValidLaunchID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func OpenLaunchID(address string) string {
	if !IsOpenURI(address) {
		return ""
	}
	u, _ := url.Parse(address)
	return u.Query().Get("launch")
}

// ShellExecute may normalize a hierarchical custom protocol to include '/'.
func PairTicketFromURI(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil || !strings.EqualFold(u.Scheme, "alanpn") || !strings.EqualFold(u.Host, "pair") || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.Fragment != "" {
		return "", errors.New("invalid pairing URI")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 1 || len(query["ticket"]) != 1 {
		return "", errors.New("invalid pairing ticket")
	}
	ticket := query.Get("ticket")
	if len(ticket) != 64 {
		return "", errors.New("invalid pairing ticket")
	}
	for _, char := range ticket {
		if !((char >= 'a' && char <= 'f') || (char >= '0' && char <= '9')) {
			return "", errors.New("invalid pairing ticket")
		}
	}
	return ticket, nil
}

func New(origin string) (*Client, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("HTTPS backend origin required")
	}
	return &Client{Origin: u.Scheme + "://" + u.Host, HTTP: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) post(ctx context.Context, path string, body, output any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return errors.New("request encoding failed")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.Origin+path, bytes.NewReader(b))
	if e != nil {
		return errors.New("invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Credentials.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credentials.Token)
		req.Header.Set("X-AlanPN-Device", c.Credentials.DeviceID)
	}
	res, e := c.HTTP.Do(req)
	if e != nil {
		return errors.New("control network unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return ErrAuthorizationDenied
	}
	if res.StatusCode != 200 && res.StatusCode != 201 {
		return errors.New("control request rejected")
	}
	d := json.NewDecoder(io.LimitReader(res.Body, 1024*1024))
	d.DisallowUnknownFields()
	if e = d.Decode(output); e != nil {
		return errors.New("invalid control response")
	}
	return nil
}
func (c *Client) Pair(ctx context.Context, ticket string) error {
	if len(ticket) != 64 {
		return errors.New("invalid pair ticket")
	}
	for _, x := range ticket {
		if !((x >= '0' && x <= '9') || (x >= 'a' && x <= 'f')) {
			return errors.New("invalid pair ticket")
		}
	}
	var out Credentials
	if e := c.post(ctx, "/api/native/pairings/redeem", map[string]string{"ticket": ticket}, &out); e != nil {
		return e
	}
	if out.DeviceID == "" || len(out.Token) < 32 {
		return errors.New("invalid device credentials")
	}
	c.Credentials = out
	return nil
}
func (c *Client) Sync(ctx context.Context, status SyncRequest) (SyncResponse, error) {
	var out SyncResponse
	e := c.post(ctx, "/api/native/agent/sync", status, &out)
	if out.LeaseRemainingMS < 0 {
		out.LeaseRemainingMS = 0
	}
	if out.LeaseRemainingMS > 300000 {
		out.LeaseRemainingMS = 300000
	}
	return out, e
}
func (c *Client) Disconnect(ctx context.Context) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return c.post(ctx, "/api/native/agent/disconnect", struct{}{}, &out)
}

// Device credentials are never forwarded to subscription URLs.
func (c *Client) FetchSubscription(ctx context.Context, address string) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host != "awpn.alanpn.ru" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/subscriptions/panel/") {
		return nil, errors.New("untrusted subscription URL")
	}
	token := strings.TrimPrefix(u.Path, "/subscriptions/panel/")
	if token == "" || strings.ContainsAny(token, "/\\%\r\n") {
		return nil, errors.New("invalid subscription path")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid subscription request")
	}
	req.Header.Set("User-Agent", "AlanPN-Windows/0.1")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("subscription unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("subscription rejected")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
	if err != nil || len(body) > 4*1024*1024 {
		return nil, errors.New("invalid subscription response")
	}
	return body, nil
}
