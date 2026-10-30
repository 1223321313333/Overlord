//go:build !windows
// +build !windows

package privesc

func tryElevate() bool  { return false }
func isElevated() bool  { return false }
