package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var runMeta runMetaState

type runMetaState struct {
	FingerprintName string
	FingerprintID   string
	SNI             string
	DialAddr        string
}

func printRunMeta(proto string) {
	fmt.Println("* Fingerprint:", runMeta.FingerprintName)
	fmt.Println("* uTLS ID:", runMeta.FingerprintID)
	fmt.Println("* SNI:", runMeta.SNI)
	fmt.Println("* Dial:", runMeta.DialAddr)

	if proto != "" {
		fmt.Println("* Proto:", proto)
	} else {
		fmt.Println("* Proto: unknown")
	}
}

func main() {
	flag.Usage = usage

	fingerprintName := flag.String("fp", "chrome", "fingerprint: chrome, firefox, safari, hellochrome_133, hellofirefox_148, randomized")
	resolveValue := flag.String("resolve", "", "curl-like DNS override: host:port:ipv4")
	useHTTP2 := flag.Bool("http2", true, "offer h2,http/1.1 via ALPN; set false to offer only HTTP/1.1")
	requestEnabled := flag.Bool("request", false, "perform real HTTP request through surf instead of TLS-only probe")
	list := flag.Bool("list", false, "list supported fingerprint names")
	timeout := flag.Duration("timeout", 2*time.Second, "request/probe timeout")

	flag.Parse()

	if *list {
		for _, name := range listFingerprints() {
			fmt.Println(name)
		}
		return
	}

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	fp, ok := getFingerprint(*fingerprintName)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown fingerprint %q\n\nknown fingerprints:\n", *fingerprintName)
		for _, name := range listFingerprints() {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		os.Exit(2)
	}

	rawURL := flag.Arg(0)
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if parsedURL.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "only https:// URLs are supported")
		os.Exit(2)
	}

	urlHost := parsedURL.Hostname()
	urlPort := parsedURL.Port()
	if urlPort == "" {
		urlPort = "443"
	}

	resolveHost, resolvePort, resolveIP, hasResolve, err := parseResolve(*resolveValue)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if hasResolve && (resolveHost != urlHost || resolvePort != urlPort) {
		fmt.Fprintf(os.Stderr, "--resolve %s:%s does not match URL host:port %s:%s\n", resolveHost, resolvePort, urlHost, urlPort)
		os.Exit(2)
	}

	dialAddr := net.JoinHostPort(urlHost, urlPort)
	if hasResolve {
		dialAddr = net.JoinHostPort(resolveIP, resolvePort)
	}

	runMeta = runMetaState{
		FingerprintName: strings.ToLower(strings.TrimSpace(*fingerprintName)),
		FingerprintID:   fp.Str(),
		SNI:             urlHost,
		DialAddr:        dialAddr,
	}

	if !*requestEnabled {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), *timeout)
		probe := runTLSProbe(probeCtx, fp, urlHost, dialAddr, *useHTTP2)
		probeCancel()

		printRunMeta(probe.NegotiatedProtocol)
		printTLSProbe(probe)
		return
	}

	err = runHTTPRequest(requestConfig{
		RawURL:      rawURL,
		ParsedHost:  parsedURL.Host,
		ResolveHost: resolveHost,
		ResolveIP:   resolveIP,
		HasResolve:  hasResolve,
		UseHTTP2:    *useHTTP2,
		Timeout:     *timeout,
		Fingerprint: fp,
	})
	if err != nil {
		printRequestError(err)
	}
}
