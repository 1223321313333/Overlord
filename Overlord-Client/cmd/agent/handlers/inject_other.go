//go:build !windows
// +build !windows

package handlers

import (
	"context"

	agentRuntime "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleInject(ctx context.Context, env *agentRuntime.Env, cmdID string, _ map[string]interface{}) error {
	return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
		Type: "command_result", CommandID: cmdID, OK: false,
		Message: "process injection not supported on this platform",
	})
}
