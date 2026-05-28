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
	ResolveHost string
	ResolveIP   string
	HasResolve  bool
	UseHTTP2    bool
	Timeout     time.Duration
	Fingerprint *utls.ClientHelloID
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

	request := client.Get(g.String(cfg.RawURL))
	request.GetRequest().Host = cfg.ParsedHost
	request.GetRequest().Header.Set("Accept", "*/*")

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

	stdReq := request.GetRequest()
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

func printRequestError(err error) {
	printRunMeta("")
	fmt.Println("Error:")
	fmt.Println(err)
	os.Exit(1)
}
