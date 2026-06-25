package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	utls "github.com/refraction-networking/utls"
)

func applyFingerprint(builder *surf.Builder, fp *utls.ClientHelloID) *surf.Builder {
	return builder.JA().SetHelloID(*fp)
}

type requestConfig struct {
	RawURL      string
	ParsedHost  string
	Method      string
	Headers     []requestHeader
	Body        []byte
	HasBody     bool
	ResolveHost string
	ResolveIP   string
	HasResolve  bool
	UseHTTP2    bool
	Timeout     time.Duration
	Fingerprint *utls.ClientHelloID
}

type requestHeader struct {
	Name  string
	Value string
}

func runHTTPRequest(cfg requestConfig) error {
	baseClient := surf.NewClient()
	defer baseClient.CloseIdleConnections()

	builder := baseClient.Builder().Timeout(cfg.Timeout).NotFollowRedirects()
	if !isGolangFingerprint(cfg.Fingerprint) {
		builder = applyFingerprint(builder, cfg.Fingerprint)
	}

	if cfg.UseHTTP2 {
		builder = builder.ForceHTTP2()
	} else {
		builder = builder.ForceHTTP1()
	}

	if cfg.HasResolve {
		dnsAddr, shutdown, err := startResolveDNS(cfg.ResolveHost, cfg.ResolveIP)
		if err != nil {
			return err
		}
		defer shutdown()
		builder = builder.DNS(g.String(dnsAddr))
	}

	client := builder.Build().Unwrap()
	defer client.CloseIdleConnections()

	request := newRequest(client, cfg.Method, cfg.RawURL)
	stdReq := request.GetRequest()
	stdReq.Host = cfg.ParsedHost
	stdReq.Header.Set("Accept", "*/*")

	if cfg.HasBody {
		request.Body(cfg.Body)
	}

	for _, header := range cfg.Headers {
		stdReq.Header.Set(header.Name, header.Value)
	}

	result := request.Do()
	if result.IsErr() {
		return result.Err()
	}

	response := result.Ok()
	stdResponse := response.GetResponse()
	if stdResponse.Body != nil {
		defer stdResponse.Body.Close()
	}
	body := response.Body.Limit(4096).String().Unwrap()

	printRunMeta(response.Proto.Std())

	requestProto := response.Proto.Std()
	if requestProto == "HTTP/2.0" {
		requestProto = "HTTP/2"
	}

	fmt.Printf("> %s %s %s\n", stdReq.Method, stdReq.URL.RequestURI(), requestProto)
	fmt.Printf("> Host: %s\n", stdReq.Host)

	for key, values := range stdReq.Header {
		for _, value := range values {
			fmt.Printf("> %s: %s\n", key, value)
		}
	}

	fmt.Println(">")
	fmt.Printf("< %s\n", stdResponse.Status)

	for key, values := range stdResponse.Header {
		for _, value := range values {
			fmt.Printf("< %s: %s\n", key, value)
		}
	}

	fmt.Println("<")
	fmt.Println()
	fmt.Print(strings.TrimRight(body.Std(), "\n"))
	fmt.Println()
	return nil
}

func newRequest(client *surf.Client, method string, rawURL string) *surf.Request {
	switch method {
	case "CONNECT":
		return client.Connect(g.String(rawURL))
	case "DELETE":
		return client.Delete(g.String(rawURL))
	case "GET":
		return client.Get(g.String(rawURL))
	case "HEAD":
		return client.Head(g.String(rawURL))
	case "OPTIONS":
		return client.Options(g.String(rawURL))
	case "PATCH":
		return client.Patch(g.String(rawURL))
	case "POST":
		return client.Post(g.String(rawURL))
	case "PUT":
		return client.Put(g.String(rawURL))
	case "TRACE":
		return client.Trace(g.String(rawURL))
	default:
		request := client.Get(g.String(rawURL))
		request.GetRequest().Method = method
		return request
	}
}

func printRequestError(err error) {
	printRunMeta("")
	fmt.Println("Error:")
	fmt.Println(err)
	os.Exit(1)
}
