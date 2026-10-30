//go:build !windows
// +build !windows

package harvest

func collect() []Credential { return nil }
