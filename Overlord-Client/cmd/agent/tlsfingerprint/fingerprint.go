// Package tlsfingerprint wraps net.Conn with a uTLS ClientHello so the agent's
// TLS handshake looks like Chrome instead of the distinctive Go runtime profile.
//
// Go's crypto/tls produces a unique JA3/JA4 fingerprint that network scanners
// and EDR products reliably use to flag C2 traffic. uTLS replaces the ClientHello
// with a hand-crafted spec that matches a real Chrome release, making the TLS
// layer indistinguishable from normal browser traffic.
package tlsfingerprint

import (
	"context"
	"crypto/tls"
	"net"

	utls "github.com/refraction-networking/utls"
)

// UTLSDialFunc returns a DialTLSContext function that wraps a raw TCP connection
// in a uTLS UConn configured to present a Chrome ClientHello.
//
// stdCfg is the original *tls.Config carrying pinning callbacks, root CAs,
// client certificates, and InsecureSkipVerify — all are forwarded verbatim.
// The underlying TCP dial is provided by baseDial.
func UTLSDialFunc(
	baseDial func(ctx context.Context, network, addr string) (net.Conn, error),
	stdCfg *tls.Config,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		rawConn, err := baseDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		uCfg := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: stdCfg.InsecureSkipVerify, //nolint:gosec
			RootCAs:            stdCfg.RootCAs,
		}
		for _, c := range stdCfg.Certificates {
			uCfg.Certificates = append(uCfg.Certificates, utls.Certificate{
				Certificate: c.Certificate,
				PrivateKey:  c.PrivateKey,
				OCSPStaple:  c.OCSPStaple,
				Leaf:        c.Leaf,
				SignedCertificateTimestamps: c.SignedCertificateTimestamps,
			})
		}

		// Forward SPKI-pinning or any other VerifyConnection callback.
		// utls.ConnectionState has the same PeerCertificates field that the
		// pinning verifier inspects.
		if stdCfg.VerifyConnection != nil {
			orig := stdCfg.VerifyConnection
			uCfg.VerifyConnection = func(cs utls.ConnectionState) error {
				return orig(tls.ConnectionState{
					Version:            cs.Version,
					HandshakeComplete:  cs.HandshakeComplete,
					DidResume:          cs.DidResume,
					CipherSuite:        cs.CipherSuite,
					NegotiatedProtocol: cs.NegotiatedProtocol,
					ServerName:         cs.ServerName,
					PeerCertificates:   cs.PeerCertificates,
					VerifiedChains:     cs.VerifiedChains,
					SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
					OCSPResponse:       cs.OCSPResponse,
					TLSUnique:          cs.TLSUnique,
				})
			}
		}

		// HelloChrome_Auto tracks the latest Chrome release (currently 133).
		// Rotate to HelloFirefox_Auto on a per-session basis if fingerprint
		// diversity is desired — both are common and trusted on corporate networks.
		uConn := utls.UClient(rawConn, uCfg, utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return uConn, nil
	}
}

