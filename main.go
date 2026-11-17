package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	flag "github.com/spf13/pflag"
)

var runMeta runMetaState

type runMetaState struct {
	FingerprintName  string
	FingerprintID    string
	FingerprintLabel string
	SNI              string
	DialAddr         string
}

type headerFlag []requestHeader

func (h *headerFlag) String() string {
	if h == nil {
		return ""
	}

	var values []string
	for _, header := range *h {
		values = append(values, header.Name+": "+header.Value)
	}

	return strings.Join(values, ", ")
}

func (h *headerFlag) Type() string {
	return "header"
}

func (h *headerFlag) Set(value string) error {
	name, headerValue, ok := strings.Cut(value, ":")
	if !ok {
		return fmt.Errorf("header must be in Name: value format")
	}

	name = strings.TrimSpace(name)
	headerValue = strings.TrimSpace(headerValue)
	if name == "" {
		return fmt.Errorf("header name cannot be empty")
	}
	if headerValue == "" {
		return fmt.Errorf("header value cannot be empty")
	}

	*h = append(*h, requestHeader{Name: name, Value: headerValue})
	return nil
}

func printRunMeta(proto string) {
	fingerprintLabel := runMeta.FingerprintLabel
	if fingerprintLabel == "" {
		fingerprintLabel = "uTLS ID"
	}

	fmt.Println("* Fingerprint:", runMeta.FingerprintName)
	fmt.Println("* "+fingerprintLabel+":", runMeta.FingerprintID)
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

	fingerprintName := flag.String("fp", "chrome", "fingerprint: chrome, firefox, safari, hellochrome_155, hellofirefox_148, randomized")
	impersonate := flag.String("impersonate", "", "surf browser impersonation profile; enables request mode and cannot be combined with explicit --fp")
	padding := flag.Int("padding", 0, "override TLS padding extension length (TLS probe only)")
	stallEnabled := flag.Bool("stall", false, "after the TLS probe, download the URL on the same connection and detect a DPI freeze (TLS probe only)")
	stallTimeout := flag.Duration("stall-timeout", 5*time.Second, "with --stall: no new server bytes for this long means the connection froze")
	maxBytesValue := flag.String("max-bytes", "256KB", "with --stall: bytes to download (sent as Range) before the test counts as passed")
	resolveValue := flag.String("resolve", "", "curl-like DNS override: host:port:ipv4")
	useHTTP2 := flag.Bool("http2", true, "offer h2,http/1.1 via ALPN; --http2=false offers only HTTP/1.1 (rewrites the fingerprint's ALPN, so JA3/JA4 change)")
	requestEnabled := flag.Bool("request", false, "perform real HTTP request through surf instead of TLS-only probe")
	list := flag.Bool("list", false, "list supported fingerprint names")
	dump := flag.Bool("dump", false, "print JA3/JA4 of every uTLS fingerprint of xray-core, sing-box and mihomo (offline, no URL)")
	dumpCore := flag.StringSlice("core", dumpCores, "with --dump: cores to dump (xray, sing-box, mihomo)")
	dumpALPN := flag.String("alpn", "h2,http/1.1", "with --dump: client ALPN (sing-box writes it into the profile; xray and mihomo profiles keep their own)")
	dumpSNI := flag.String("sni", "example.com", "with --dump: SNI in the ClientHello (only its presence enters JA4)")
	dumpRuns := flag.Int("runs", 5, "with --dump: builds per fingerprint, to catch profiles whose JA4 changes")
	dumpJSON := flag.Bool("json", false, "with --dump: JSON output")
	dumpPQOnly := flag.Bool("pq-only", false, "with --dump: only fingerprints with an X25519MLKEM768 key share (what REALITY accepts)")
	dumpProfiles := flag.StringSlice("profiles", nil, "with --dump: only these fingerprints (--fp names), e.g. hellochrome_155,hellofirefox_148,hellosafari_26_3")
	dumpYAML := flag.Bool("yaml", false, "with --dump: print ja4_allowlist (YAML) for the selected fingerprints")
	dumpNames := flag.Bool("names", false, "with --dump: print ja4_names (YAML, JA4 -> fingerprint name); implies --all")
	dumpAll := flag.Bool("all", false, "with --dump: also xray-core's old fingerprints (OtherFingerprints: hellochrome_58 ... hellochrome_120_pq, Golang)")
	timeout := flag.Duration("timeout", 2*time.Second, "request/probe timeout")
	method := flag.StringP("method", "X", "", "HTTP request method; enables request mode")
	head := flag.BoolP("head", "I", false, "perform a HEAD request; enables request mode")
	data := flag.StringP("data", "d", "", "HTTP request body; defaults method to POST and enables request mode")
	dataBinary := flag.String("data-binary", "", "HTTP request body or @file bytes; defaults method to POST and enables request mode")
	var headers headerFlag
	flag.VarP(&headers, "header", "H", "HTTP request header in Name: value format; may be repeated and enables request mode")

	flag.CommandLine.SortFlags = false
	flag.CommandLine.Init(filepath.Base(os.Args[0]), flag.ContinueOnError)
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return // pflag has already printed the usage
		}
		errf("fpcheck: %v\nRun 'fpcheck --help' for usage.\n", err)
		os.Exit(2)
	}

	specifiedFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		specifiedFlags[f.Name] = true
	})

	if *list {
		for _, name := range listFingerprints() {
			fmt.Println(name)
		}
		return
	}

	if *dump {
		os.Exit(runDump(dumpOptions{
			Cores:    *dumpCore,
			SNI:      *dumpSNI,
			ALPN:     strings.Split(*dumpALPN, ","),
			Runs:     *dumpRuns,
			JSON:     *dumpJSON,
			PQOnly:   *dumpPQOnly,
			Profiles: *dumpProfiles,
			YAML:     *dumpYAML,
			Names:    *dumpNames,
			All:      *dumpAll || *dumpNames,
		}))
	}

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	impersonationProfile, err := normalizeImpersonationProfile(*impersonate)
	if err != nil {
		errln(err)
		os.Exit(2)
	}
	if impersonationProfile != "" && specifiedFlags["fp"] {
		errln("--impersonate cannot be combined with --fp")
		os.Exit(2)
	}

	requestMethod := strings.ToUpper(strings.TrimSpace(*method))
	hasMethod := specifiedFlags["method"]
	hasData := specifiedFlags["data"]
	hasDataBinary := specifiedFlags["data-binary"]
	hasBody := hasData || hasDataBinary

	if hasMethod && requestMethod == "" {
		errln("-X/--method requires a method")
		os.Exit(2)
	}
	if *head && hasMethod {
		errln("-I/--head cannot be combined with -X/--method")
		os.Exit(2)
	}
	if hasData && hasDataBinary {
		errln("-d/--data cannot be combined with --data-binary")
		os.Exit(2)
	}

	if *head {
		requestMethod = "HEAD"
	} else if requestMethod == "" && hasBody {
		requestMethod = "POST"
	} else if requestMethod == "" {
		requestMethod = "GET"
	}

	var requestBody []byte
	if hasData {
		requestBody = []byte(*data)
	}
	if hasDataBinary {
		if after, ok := strings.CutPrefix(*dataBinary, "@"); ok {
			if after == "" {
				errln("--data-binary @ requires a file path")
				os.Exit(2)
			}

			requestBody, err = os.ReadFile(filepath.Clean(after))
			if err != nil {
				errln(err)
				os.Exit(2)
			}
		} else {
			requestBody = []byte(*dataBinary)
		}
	}

	autoRequestEnabled := impersonationProfile != "" || hasMethod || *head || hasBody || len(headers) > 0

	var maxBytes int64
	if *stallEnabled {
		if *requestEnabled || autoRequestEnabled {
			errln("--stall works only in TLS probe mode; it cannot be combined with --request, --impersonate, -X, -I, -H, -d or --data-binary")
			os.Exit(2)
		}
		if *stallTimeout <= 0 {
			errln("--stall-timeout must be positive")
			os.Exit(2)
		}
		maxBytes, err = parseByteSize(*maxBytesValue)
		if err != nil {
			errln("--max-bytes:", err)
			os.Exit(2)
		}
	}

	rawURL := flag.Arg(0)
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		errln(err)
		os.Exit(2)
	}
	if parsedURL.Scheme != "https" {
		errln("only https:// URLs are supported")
		os.Exit(2)
	}

	urlHost := parsedURL.Hostname()
	urlPort := parsedURL.Port()
	if urlPort == "" {
		urlPort = "443"
	}

	resolveHost, resolvePort, resolveIP, hasResolve, err := parseResolve(*resolveValue)
	if err != nil {
		errln(err)
		os.Exit(2)
	}
	if hasResolve && (resolveHost != urlHost || resolvePort != urlPort) {
		errf("--resolve %s:%s does not match URL host:port %s:%s\n", resolveHost, resolvePort, urlHost, urlPort)
		os.Exit(2)
	}

	dialAddr := net.JoinHostPort(urlHost, urlPort)
	if hasResolve {
		dialAddr = net.JoinHostPort(resolveIP, resolvePort)
	}

	var fp *utls.ClientHelloID
	if impersonationProfile == "" {
		var ok bool
		fp, ok = getFingerprint(*fingerprintName)
		if !ok {
			errf("unknown fingerprint %q\n\nknown fingerprints:\n", *fingerprintName)
			for _, name := range listFingerprints() {
				errf("  %s\n", name)
			}
			os.Exit(2)
		}

		runMeta = runMetaState{
			FingerprintName:  strings.ToLower(strings.TrimSpace(*fingerprintName)),
			FingerprintID:    fp.Str(),
			FingerprintLabel: "uTLS ID",
			SNI:              urlHost,
			DialAddr:         dialAddr,
		}
	} else {
		runMeta = runMetaState{
			FingerprintName:  "impersonate:" + impersonationProfile,
			FingerprintID:    "surf " + impersonationProfile,
			FingerprintLabel: "Profile",
			SNI:              urlHost,
			DialAddr:         dialAddr,
		}
	}

	if !*requestEnabled && !autoRequestEnabled {
		if fp == nil { // --impersonate always selects request mode
			errln("TLS probe needs a uTLS fingerprint (--fp)")
			os.Exit(2)
		}
		probeCtx, probeCancel := context.WithTimeout(context.Background(), *timeout)
		var stall *stallConfig
		if *stallEnabled {
			stall = &stallConfig{
				MaxBytes:    maxBytes,
				IdleTimeout: *stallTimeout,
				Host:        parsedURL.Host,
				RequestURI:  parsedURL.RequestURI(),
			}
		}
		probe := runTLSProbe(probeCtx, fp, urlHost, dialAddr, *useHTTP2, *padding, stall)
		probeCancel()

		printRunMeta(probe.NegotiatedProtocol)
		printTLSProbe(probe)
		if probe.Stall != nil && stall != nil {
			printStallResult(probe.Stall, stall)
		} else if stall != nil {
			fmt.Println()
			fmt.Println(cYellow("Download test skipped: TLS handshake did not complete"))
		}
		return
	}

	err = runHTTPRequest(requestConfig{
		RawURL:      rawURL,
		ParsedHost:  parsedURL.Host,
		Method:      requestMethod,
		Headers:     headers,
		Body:        requestBody,
		HasBody:     hasBody,
		Impersonate: impersonationProfile,
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

func normalizeImpersonationProfile(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}

	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return "", fmt.Errorf("unknown impersonation profile %q", value)
	}

	switch parts[0] {
	case "chrome", "firefox":
	default:
		return "", fmt.Errorf("unknown impersonation browser %q; supported browsers: chrome, firefox", parts[0])
	}

	if len(parts) == 2 {
		switch parts[1] {
		case "windows", "macos", "linux", "android", "ios", "randomos":
		default:
			return "", fmt.Errorf("unknown impersonation OS %q; supported OS values: windows, macos, linux, android, ios, randomos", parts[1])
		}
	}

	return value, nil
}
