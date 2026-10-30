package privesc

// TryElevate attempts all available privilege escalation techniques for the
// current platform. Returns true if any technique succeeded.
func TryElevate() bool {
	return tryElevate()
}

// IsElevated returns true when the process is running as admin / SYSTEM.
func IsElevated() bool {
	return isElevated()
}
