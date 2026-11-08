// A normal, non-exempt application must reach HTTPS and resolve DNS before the
// service may advertise connected. Runs only as part of a requested connection.
package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://1.1.1.1/cdn-cgi/trace", nil)
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		os.Exit(1)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		os.Exit(1)
	}
	if addresses, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err != nil || len(addresses) == 0 {
		os.Exit(2)
	}
}
