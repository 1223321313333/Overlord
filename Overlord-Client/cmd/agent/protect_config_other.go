//go:build !windows
// +build !windows

package main

import "overlord-client/cmd/agent/config"

func protectSensitiveConfig(_ *config.Config) {}
