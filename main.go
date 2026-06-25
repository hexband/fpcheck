package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	padding := flag.Int("padding", 0, "override TLS padding extension length (TLS probe only)")
	resolveValue := flag.String("resolve", "", "curl-like DNS override: host:port:ipv4")
	useHTTP2 := flag.Bool("http2", true, "offer h2,http/1.1 via ALPN; set false to offer only HTTP/1.1")
	requestEnabled := flag.Bool("request", false, "perform real HTTP request through surf instead of TLS-only probe")
	list := flag.Bool("list", false, "list supported fingerprint names")
	timeout := flag.Duration("timeout", 2*time.Second, "request/probe timeout")
	method := flag.String("X", "", "HTTP request method; enables request mode")
	head := flag.Bool("I", false, "perform a HEAD request; enables request mode")
	data := flag.String("d", "", "HTTP request body; defaults method to POST and enables request mode")
	dataBinary := flag.String("data-binary", "", "HTTP request body or @file bytes; defaults method to POST and enables request mode")
	var headers headerFlag
	flag.Var(&headers, "H", "HTTP request header in Name: value format; may be repeated and enables request mode")

	flag.Parse()

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

	requestMethod := strings.ToUpper(strings.TrimSpace(*method))
	hasMethod := specifiedFlags["X"]
	hasData := specifiedFlags["d"]
	hasDataBinary := specifiedFlags["data-binary"]
	hasBody := hasData || hasDataBinary

	if hasMethod && requestMethod == "" {
		fmt.Fprintln(os.Stderr, "-X requires a method")
		os.Exit(2)
	}
	if *head && hasMethod {
		fmt.Fprintln(os.Stderr, "-I cannot be combined with -X")
		os.Exit(2)
	}
	if hasData && hasDataBinary {
		fmt.Fprintln(os.Stderr, "-d cannot be combined with --data-binary")
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
	var err error
	if hasData {
		requestBody = []byte(*data)
	}
	if hasDataBinary {
		if after, ok := strings.CutPrefix(*dataBinary, "@"); ok {
			if after == "" {
				fmt.Fprintln(os.Stderr, "--data-binary @ requires a file path")
				os.Exit(2)
			}

			requestBody, err = os.ReadFile(filepath.Clean(after))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		} else {
			requestBody = []byte(*dataBinary)
		}
	}

	autoRequestEnabled := hasMethod || *head || hasBody || len(headers) > 0

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

	if !*requestEnabled && !autoRequestEnabled {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), *timeout)
		probe := runTLSProbe(probeCtx, fp, urlHost, dialAddr, *useHTTP2, *padding)
		probeCancel()

		printRunMeta(probe.NegotiatedProtocol)
		printTLSProbe(probe)
		return
	}

	err = runHTTPRequest(requestConfig{
		RawURL:      rawURL,
		ParsedHost:  parsedURL.Host,
		Method:      requestMethod,
		Headers:     headers,
		Body:        requestBody,
		HasBody:     hasBody,
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
