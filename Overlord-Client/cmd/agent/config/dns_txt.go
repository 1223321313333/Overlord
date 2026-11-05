package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// dohEndpoints are queried in order until one succeeds.
// Using DoH avoids DNS traffic visible to network monitors.
var dohEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://9.9.9.9/dns-query",
}

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// LoadServerURLsFromDNSTxt resolves TXT records for domain via DoH, extracts
// WSS URLs, and verifies the HMAC-SHA256 signature using the rolling 60-second
// window format shared with the dead-drop server endpoint.
// LoadServerURLsFromDNSTxt resolves TXT records for domain via DoH, extracts
// WSS URLs, and verifies the HMAC-SHA256 signature. tlsCfg is applied to the
// DoH HTTP client; pass nil to use the system trust store.
func LoadServerURLsFromDNSTxt(domain, agentToken string, tlsCfg *tls.Config) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	txts, err := queryTXTDoH(domain, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("DoH query failed: %w", err)
	}

	var urls []string
	var sig string

	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		// Lines starting with "sig:" carry the HMAC signature.
		if strings.HasPrefix(txt, "sig:") {
			sig = strings.TrimPrefix(txt, "sig:")
			continue
		}
		// Lines that look like WSS URLs are server addresses.
		if strings.HasPrefix(txt, "wss://") || strings.HasPrefix(txt, "ws://") {
			urls = append(urls, txt)
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no WSS URLs found in TXT records for %s", domain)
	}

	if agentToken != "" {
		if sig == "" {
			return nil, fmt.Errorf("TXT dead-drop: signature record missing; refusing unsigned URLs")
		}
		if err := verifyDeadDropSig(urls, sig, agentToken); err != nil {
			return nil, fmt.Errorf("TXT signature verification failed: %w", err)
		}
	}

	return urls, nil
}

// verifyDeadDropSig checks the rolling-window HMAC using the same algorithm
// as the server's dead-drop endpoint (±1 window tolerance).
func verifyDeadDropSig(urls []string, sigB64url, agentToken string) error {
	sorted := make([]string, len(urls))
	copy(sorted, urls)
	sort.Strings(sorted)
	message := strings.Join(sorted, "\n")

	now := time.Now().Unix() / 60
	for _, window := range []int64{now - 1, now, now + 1} {
		msg := message + "\n" + fmt.Sprintf("%d", window)
		mac := hmac.New(sha256.New, []byte(agentToken))
		mac.Write([]byte(msg))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(expected), []byte(sigB64url)) {
			return nil
		}
	}
	return fmt.Errorf("HMAC mismatch")
}

func queryTXTDoH(domain string, tlsCfg *tls.Config) ([]string, error) {
	var transport http.RoundTripper
	if tlsCfg != nil {
		transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	var lastErr error

	for _, endpoint := range dohEndpoints {
		req, err := http.NewRequest("GET", endpoint+"?name="+domain+"&type=TXT", nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, endpoint)
			continue
		}

		var doh dohResponse
		if err := json.Unmarshal(body, &doh); err != nil {
			lastErr = err
			continue
		}

		var txts []string
		for _, ans := range doh.Answer {
			if ans.Type != 16 { // 16 = TXT
				continue
			}
			// DoH returns TXT data with surrounding quotes — strip them.
			data := strings.Trim(ans.Data, `"`)
			txts = append(txts, data)
		}
		return txts, nil
	}
	return nil, lastErr
}
