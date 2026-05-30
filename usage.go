package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func usage() {
	prog := filepath.Base(os.Args[0])
	out := flag.CommandLine.Output()

	fmt.Fprintf(out, `fpcheck - HTTPS fingerprint checker using surf + uTLS

Usage:
  %[1]s [options] https://host[:port]/path

Options:
`, prog)

	flag.PrintDefaults()

	fmt.Fprintf(out, `
Examples:
  %[1]s https://example.com/
  %[1]s -fp firefox https://example.com/
  %[1]s -fp hellochrome_133 https://example.com/
  %[1]s -fp randomized https://example.com/
  %[1]s -http2=false -fp firefox https://example.com/
  %[1]s -padding 200 -fp firefox https://example.com/
  %[1]s -resolve "example.com:443:127.0.0.1" https://example.com/
  %[1]s -request -fp firefox https://example.com/

Resolve:
  -resolve works like curl --resolve:
  TCP connects to the supplied IP, but SNI and HTTP host stay from the URL.

Modes:
  Default mode runs a TLS probe. It opens TCP, sends ClientHello, waits for server TLS bytes,
  and prints handshake diagnostics. It does not send an HTTP request.

  -padding overrides the length of an existing TLS padding extension in TLS probe mode.
  If the selected fingerprint does not contain a TLS padding extension, fpcheck returns an error
  instead of adding one and changing JA3/JA4.

  -request mode performs a real HTTP request through surf instead of the TLS-only probe. Response body preview is limited to 4096 bytes.

Output:
  * connection/debug metadata
  > outgoing request headers, only with -request
  < incoming response headers, only with -request

On errors, fpcheck still prints fingerprint, SNI, dial target, and protocol if known.
`, prog)
}
