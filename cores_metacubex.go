package main

import (
	"net"

	mutls "github.com/metacubex/utls"
)

// sing-box and mihomo both use github.com/metacubex/utls, but at different
// versions, and one binary can link only one. The *_Auto aliases are what moves
// between versions, so the tables name the concrete profile each core resolves
// a fingerprint to at its pinned utls version (u_common.go of that version);
// the profiles themselves come from the newest utls, which has all of them.

// sing-box v1.14.4: metacubex/utls v1.8.7, common/tls/utls_client.go.
// Same utls version and mapping in sing-box v1.15.0-alpha.13 and in
// shtorm-7/sing-box-extended v1.14.3-extended-2.7.3 (its XHTTP transport
// handshakes through the same common/tls), so these rows cover them too.
var singboxProfiles = []namedHello[mutls.ClientHelloID]{
	{"chrome", mutls.HelloChrome_133},
	{"firefox", mutls.HelloFirefox_120},
	{"edge", mutls.HelloEdge_85},
	{"safari", mutls.HelloSafari_16_0},
	{"360", mutls.Hello360_7_5},
	{"qq", mutls.HelloQQ_11_1},
	{"ios", mutls.HelloIOS_14},
	{"android", mutls.HelloAndroid_11_OkHttp},
}

// "random" picks one of these per process (init in utls_client.go).
var singboxRandom = []string{"chrome", "firefox", "edge", "safari", "ios"}

// mihomo v1.19.34: metacubex/utls v1.9.0-alpha.1, component/tls/utls.go
// (the Alpha branch of 2026-11-15 has the same utls version).
var mihomoProfiles = []namedHello[mutls.ClientHelloID]{
	{"chrome", mutls.HelloChrome_133},
	{"firefox", mutls.HelloFirefox_148},
	{"safari", mutls.HelloSafari_26_3},
	{"ios", mutls.HelloIOS_14},
	{"android", mutls.HelloAndroid_11_OkHttp},
	{"edge", mutls.HelloEdge_85},
	{"360", mutls.Hello360_7_5},
	{"qq", mutls.HelloQQ_11_1},
	{"chrome120", mutls.HelloChrome_120},
	{"firefox120", mutls.HelloFirefox_120},
	{"safari16", mutls.HelloSafari_16_0},
}

// "random" picks per process, weighted: chrome 6, safari 3, ios 2, firefox 1.
var mihomoRandom = []string{"chrome", "safari", "ios", "firefox"}

type namedHello[T any] struct {
	Name string
	ID   T
}

// metacubexHello builds the ClientHello the way the cores do: UClient with the
// config's NextProtos, then BuildHandshakeState. rewriteALPN mirrors
// sing-box's utlsALPNWrapper, which puts the configured ALPN into the
// profile's ALPN extension (mihomo leaves the profile's own).
func metacubexHello(id mutls.ClientHelloID, sni string, alpn []string, rewriteALPN bool) ([]byte, error) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }() // also closed by the TLS conn; a second Close is a no-op
	defer func() { _ = c2.Close() }()
	uconn := mutls.UClient(c1, &mutls.Config{ServerName: sni, NextProtos: alpn, SessionTicketsDisabled: true}, id)
	defer func() { _ = uconn.Close() }()
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if rewriteALPN && len(alpn) > 0 {
		for _, ext := range uconn.Extensions {
			if a, ok := ext.(*mutls.ALPNExtension); ok {
				a.AlpnProtocols = alpn
				if err := uconn.BuildHandshakeState(); err != nil {
					return nil, err
				}
				break
			}
		}
	}
	return append([]byte(nil), uconn.HandshakeState.Hello.Raw...), nil
}
