package main

// malleable.go — browser-impersonation profiles used by the WebSocket dial and
// HTTP poll paths.  A malleableProfile ties a uTLS ClientHello spec to its
// matching User-Agent so both JA3/JA4 fingerprint and the HTTP User-Agent header
// always match a single consistent browser.

import (
	mrand "math/rand"

	utls "github.com/refraction-networking/utls"
)

// malleableProfile ties a TLS ClientHello spec to its matching User-Agent.
// Pick one with randomProfile() so JA3 and UA are always from the same browser.
type malleableProfile struct {
	HelloSpec utls.ClientHelloID
	UserAgent string
}

// malleableProfiles is the rotation pool.  Versions are current as of 2025-11.
// Three Chrome (136/135/134), one Edge (136), two Firefox (137/136).
var malleableProfiles = []malleableProfile{
	{
		utls.HelloChrome_Auto,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	},
	{
		utls.HelloChrome_Auto,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
	},
	{
		utls.HelloChrome_Auto,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	},
	{
		utls.HelloEdge_Auto,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
	},
	{
		utls.HelloFirefox_Auto,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
	},
	{
		utls.HelloFirefox_Auto,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
	},
}

// randomProfile returns a random browser profile.
func randomProfile() malleableProfile {
	return malleableProfiles[mrand.Intn(len(malleableProfiles))]
}

// malleableAcceptLanguages rotates locale strings to avoid a fixed fingerprint.
var malleableAcceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9,en-US;q=0.8",
	"en-US,en;q=0.8,fr;q=0.5",
	"en-US,en;q=0.9,de;q=0.7",
	"en-CA,en;q=0.9,fr-CA;q=0.8",
	"en-AU,en;q=0.9",
}

// malleableOrigins is a set of plausible Origin headers.
var malleableOrigins = []string{
	"https://teams.microsoft.com",
	"https://web.whatsapp.com",
	"https://discord.com",
	"https://slack.com",
	"https://meet.google.com",
}
