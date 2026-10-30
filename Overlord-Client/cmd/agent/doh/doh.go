// Package doh provides a DNS-over-HTTPS resolver that works when corporate
// proxies block or monitor standard DNS, routing queries through Cloudflare's
// or Google's HTTPS endpoint instead.
package doh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

// providers are tried in random order so traffic doesn't always go to one CDN.
var providers = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/resolve",
	"https://9.9.9.9:5053/dns-query",
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

var client = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
	},
}

// Resolve resolves hostname to IP addresses using DNS-over-HTTPS.
// Falls back to the next provider if one fails.
func Resolve(ctx context.Context, hostname string) ([]string, error) {
	if net.ParseIP(hostname) != nil {
		return []string{hostname}, nil
	}

	order := rand.Perm(len(providers))
	var lastErr error
	for _, idx := range order {
		addrs, err := query(ctx, providers[idx], hostname)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("doh: all providers failed for %s: %w", hostname, lastErr)
}

func query(ctx context.Context, endpoint, hostname string) ([]string, error) {
	url := fmt.Sprintf("%s?name=%s&type=A", endpoint, hostname)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	var result dohResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if result.Status != 0 {
		return nil, fmt.Errorf("dns status %d", result.Status)
	}

	var addrs []string
	for _, ans := range result.Answer {
		if ans.Type == 1 { // A record
			addr := strings.TrimSpace(ans.Data)
			if net.ParseIP(addr) != nil {
				addrs = append(addrs, addr)
			}
		}
	}
	return addrs, nil
}

// NewDialer returns a net.Dialer-compatible DialContext function that resolves
// hostnames via DoH before connecting. Drop it into an http.Transport.
//
// TCP keepalive at 15 s makes the OS send probes on idle connections so that
// silently-dropped NAT/firewall entries are detected within ~45 s rather than
// waiting for an application-level timeout.
func NewDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	inner := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return inner.DialContext(ctx, network, addr)
		}
		addrs, err := Resolve(ctx, host)
		if err != nil || len(addrs) == 0 {
			// Fall back to system DNS
			return inner.DialContext(ctx, network, addr)
		}
		// Try resolved IPs in random order
		rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
		for _, ip := range addrs {
			conn, err := inner.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
		}
		return inner.DialContext(ctx, network, addr)
	}
}
