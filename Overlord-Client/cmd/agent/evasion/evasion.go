package evasion

// Run applies all available evasion techniques for the current platform.
// Call once at process startup, before any other initialization.
func Run() {
	runEvasion()
}
