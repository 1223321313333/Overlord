//go:build windows
// +build windows

package harvest

import "syscall"

func hiddenSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}
