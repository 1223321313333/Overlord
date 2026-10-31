//go:build !crypt_build

package main

// Zero-value stubs used during development / non-server builds.
// The server replaces this file with payload_gen.go (tag: crypt_build)
// that contains the actual encrypted payload and key.

var encPayload []byte
var cryptKey = [32]byte{}
