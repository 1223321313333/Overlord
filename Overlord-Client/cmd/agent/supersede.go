package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"overlord-client/cmd/agent/config"
	"overlord-client/cmd/agent/persistence"

	"nhooyr.io/websocket"
)

const supersededCloseCode = 4004

var exitProcess = os.Exit

func isSupersededError(err error) bool {
	if err == nil {
		return false
	}
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		return false
	}
	return closeErr.Code == supersededCloseCode || strings.EqualFold(strings.TrimSpace(closeErr.Reason), "superseded")
}

func handleSuperseded(cfg config.Config) {
	if !cfg.EnablePersistence || !builtWithPersistenceDefault() {
		return
	}

	currentExe, err := os.Executable()
	if err != nil {
		log.Printf("superseded: failed to resolve executable for cleanup: %v", err)
		return
	}
	if realPath, err := filepath.EvalSymlinks(currentExe); err == nil {
		currentExe = realPath
	}
	currentExe, err = filepath.Abs(currentExe)
	if err != nil {
		log.Printf("superseded: failed to resolve absolute executable path for cleanup: %v", err)
		return
	}

	// If the persistence target points to the same path we're running from,
	// a newer instance of this binary is already using that path — removing
	// persistence here would kill the new instance's ability to restart after
	// reboot.  Only clean up when we're running from a DIFFERENT location
	// (e.g. a path left over from before an agent_update moved us).
	if targetPath, err := persistence.TargetPath(); err == nil {
		if resolvedTarget, err2 := filepath.Abs(targetPath); err2 == nil {
			if strings.EqualFold(filepath.Clean(currentExe), filepath.Clean(resolvedTarget)) {
				log.Printf("superseded: skipping cleanup — new instance runs from same path")
				return
			}
		}
	}

	if err := persistence.RemoveCurrentInstall(currentExe); err != nil {
		log.Printf("superseded: current-install cleanup warning: %v", err)
	}
}

func builtWithPersistenceDefault() bool {
	return strings.EqualFold(strings.TrimSpace(config.DefaultPersistence), "true")
}
