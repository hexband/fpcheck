package main

import (
	"fmt"
	"os"
	"path/filepath"

	flag "github.com/spf13/pflag"
)

func usage() {
	prog := filepath.Base(os.Args[0])
	out := flag.CommandLine.Output()

	fmt.Fprintf(out, `fpcheck - HTTPS fingerprint checker using surf + uTLS

Usage:
  %[1]s [options] https://host[:port]/path [options]

Options can go before or after the URL. Use -- to end options.

Options:
`, prog)

	flag.PrintDefaults()

	fmt.Fprintf(out, `
Examples:
  %[1]s https://example.com/
  %[1]s --fp firefox https://example.com/
  %[1]s --fp hellochrome_155 https://example.com/
  %[1]s --fp randomized https://example.com/
  %[1]s --http2=false --fp firefox https://example.com/
  %[1]s --padding 200 --fp hellochrome_120 https://example.com/
  %[1]s --resolve "example.com:443:127.0.0.1" https://example.com/
  %[1]s --stall --resolve "example.com:443:1.2.3.4" https://example.com/assets/probe.bin
  %[1]s --request --fp firefox https://example.com/
  %[1]s --impersonate chrome https://example.com/
  %[1]s --impersonate firefox-macos https://example.com/
  %[1]s -X POST -H "Content-Type: application/json" -d '{"a":1}' https://example.com/api
  %[1]s --data-binary @payload.bin https://example.com/api
  %[1]s -I https://example.com/

Resolve:
  --resolve works like curl --resolve:
  TCP connects to the supplied IP, but SNI and HTTP host stay from the URL.

Modes:
  Default mode runs a TLS probe. It opens TCP, sends ClientHello, waits for server TLS bytes,
  and prints handshake diagnostics. It does not send an HTTP request.

  --padding overrides the length of an existing TLS padding extension in TLS probe mode.
  If the selected fingerprint does not contain a TLS padding extension, fpcheck returns an error
  instead of adding one and changing JA3/JA4.

  --stall adds a download test to the TLS probe. On the same connection and with the same
  fingerprint it requests the URL with Range: bytes=0-<max-bytes - 1> and watches the raw TCP
  bytes from the server. If they stop growing for --stall-timeout while the connection stays
  open (no RST, no FIN), it reports a freeze, the way some DPI stops passing data after N bytes.
  Use a URL that serves a large file.

  --request mode performs a real HTTP request through surf instead of the TLS-only probe. Response body preview is limited to 4096 bytes.
  -X, -H, -d, --data-binary, and -I automatically enable request mode.
  -d and --data-binary default the method to POST unless -X is set.
  --impersonate enables surf browser impersonation for request mode and cannot be combined with --fp.
  Supported profiles: chrome, firefox, with optional -windows, -macos, -linux, -android, -ios, -randomos suffix.

Output:
  * connection/debug metadata
  > outgoing request headers, only with --request
  < incoming response headers, only with --request

On errors, fpcheck still prints fingerprint, SNI, dial target, and protocol if known.
`, prog)
}
