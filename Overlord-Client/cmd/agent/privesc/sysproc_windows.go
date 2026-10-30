//go:build windows
// +build windows

package privesc

import "syscall"

func syscallSysProcAttr() syscall.SysProcAttr {
	return syscall.SysProcAttr{HideWindow: true}
}
