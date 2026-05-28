package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	utls "github.com/refraction-networking/utls"
)

type countingConn struct {
	net.Conn
	bytesRead    int64
	bytesWritten int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		atomic.AddInt64(&c.bytesRead, int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		atomic.AddInt64(&c.bytesWritten, int64(n))
	}
	return n, err
}

type tlsProbeResult struct {
	TCPConnected       bool
	TCPError           error
	TLSHandshakeDone   bool
	TLSError           error
	BytesWritten       int64
	BytesRead          int64
	TLSVersion         uint16
	CipherSuite        uint16
	NegotiatedProtocol string
	StartedAt          time.Time
	TCPConnectedAt     time.Time
	TLSHandshakeStart  time.Time
	TLSHandshakeEnd    time.Time
	FinishedAt         time.Time
	PeerCertificates   []*x509.Certificate
}

func runTLSProbe(ctx context.Context, fp *utls.ClientHelloID, sni string, dialAddr string, useHTTP2 bool) *tlsProbeResult {
	result := &tlsProbeResult{StartedAt: time.Now()}
	defer func() {
		result.FinishedAt = time.Now()
	}()

	tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		result.TCPError = err
		return result
	}
	result.TCPConnected = true
	result.TCPConnectedAt = time.Now()
	defer tcpConn.Close()

	countedConn := &countingConn{Conn: tcpConn}

	nextProtos := []string{"http/1.1"}
	if useHTTP2 {
		nextProtos = []string{"h2", "http/1.1"}
	}

	result.TLSHandshakeStart = time.Now()
	if isGolangFingerprint(fp) {
		tlsConn := tls.Client(countedConn, &tls.Config{
			ServerName: sni,
			NextProtos: nextProtos,
		})
		err = tlsConn.HandshakeContext(ctx)
		state := tlsConn.ConnectionState()
		result.TLSVersion = state.Version
		result.CipherSuite = state.CipherSuite
		result.NegotiatedProtocol = state.NegotiatedProtocol
		result.PeerCertificates = state.PeerCertificates
	} else {
		utlsConn := utls.UClient(countedConn, &utls.Config{
			ServerName: sni,
			NextProtos: nextProtos,
		}, *fp)
		err = utlsConn.HandshakeContext(ctx)
		state := utlsConn.ConnectionState()
		result.TLSVersion = state.Version
		result.CipherSuite = state.CipherSuite
		result.NegotiatedProtocol = state.NegotiatedProtocol
		result.PeerCertificates = state.PeerCertificates
	}
	result.TLSHandshakeEnd = time.Now()

	result.BytesWritten = atomic.LoadInt64(&countedConn.bytesWritten)
	result.BytesRead = atomic.LoadInt64(&countedConn.bytesRead)
	result.TLSError = err
	result.TLSHandshakeDone = err == nil
	return result
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		if version == 0 {
			return "unknown"
		}
		return fmt.Sprintf("0x%04x", version)
	}
}

func cipherSuiteString(id uint16) string {
	if id == 0 {
		return "unknown"
	}
	if name := tls.CipherSuiteName(id); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}

func durationString(start time.Time, end time.Time) string {
	if start.IsZero() || end.IsZero() {
		return "unknown"
	}
	return end.Sub(start).Round(time.Millisecond).String()
}

func formatByteCount(n int64) string {
	formatted := formatThousands(n)

	if n == 0 {
		return cRed(formatted)
	}

	return cCyan(formatted)
}

func formatThousands(n int64) string {
	s := fmt.Sprintf("%d", n)

	if len(s) <= 3 {
		return s
	}

	negative := false
	if strings.HasPrefix(s, "-") {
		negative = true
		s = s[1:]
	}

	var parts []string

	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}

	parts = append([]string{s}, parts...)

	out := strings.Join(parts, " ")

	if negative {
		out = "-" + out
	}

	return out
}

var (
	cGreen  = color.New(color.FgGreen).SprintFunc()
	cYellow = color.New(color.FgYellow).SprintFunc()
	cRed    = color.New(color.FgRed).SprintFunc()
	cCyan   = color.New(color.FgCyan).SprintFunc()
	cBold   = color.New(color.Bold).SprintFunc()
)

func boolStatus(ok bool) string {
	if ok {
		return cGreen("YES")
	}
	return cRed("NO")
}

func tlsDiagnosis(result *tlsProbeResult) string {
	switch {
	case !result.TCPConnected:
		return cRed("TCP connect failed before TLS")

	case result.BytesWritten == 0:
		return cRed("TCP connected, but ClientHello was not written")

	case result.BytesWritten > 0 && result.BytesRead == 0:
		return cYellow("ClientHello sent, but no TLS bytes came back (possible DPI drop / blackhole)")

	case result.BytesRead > 0 && !result.TLSHandshakeDone:
		return cYellow("Server sent TLS bytes, but handshake failed")

	case result.TLSHandshakeDone:
		return cGreen("TLS handshake completed successfully")

	default:
		return cYellow("Inconclusive")
	}
}

func printCertificateInfo(result *tlsProbeResult) {
	if len(result.PeerCertificates) == 0 {
		fmt.Println("Certificate:         unknown")
		return
	}

	cert := result.PeerCertificates[0]

	fmt.Println("Certificate:")
	fmt.Println("  Subject:", cert.Subject.String())
	fmt.Println("  Issuer:", cert.Issuer.String())
	fmt.Println("  Serial:", cert.SerialNumber.String())
	fmt.Println("  Not before:", cert.NotBefore.Format(time.RFC3339))
	fmt.Println("  Not after:", cert.NotAfter.Format(time.RFC3339))

	if len(cert.DNSNames) > 0 {
		fmt.Println("  DNS names:", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.IPAddresses) > 0 {
		ips := make([]string, 0, len(cert.IPAddresses))
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		fmt.Println("  IP addresses:", strings.Join(ips, ", "))
	}
}

func printTLSProbe(result *tlsProbeResult) {
	fmt.Println()
	fmt.Println(cBold("TLS Probe"))
	fmt.Println(strings.Repeat("─", 50))

	fmt.Printf("TCP connected        %s\n", boolStatus(result.TCPConnected))
	fmt.Printf("TCP connect time     %s\n", cCyan(durationString(result.StartedAt, result.TCPConnectedAt)))

	if result.TCPError != nil {
		fmt.Printf("TCP error            %s\n", cRed(result.TCPError.Error()))
	}

	fmt.Printf("ClientHello bytes    %s\n", formatByteCount(result.BytesWritten))
	fmt.Printf("Server TLS bytes     %s\n", formatByteCount(result.BytesRead))
	fmt.Printf("TLS handshake        %s\n", boolStatus(result.TLSHandshakeDone))
	fmt.Printf("TLS handshake time   %s\n", cCyan(durationString(result.TLSHandshakeStart, result.TLSHandshakeEnd)))
	fmt.Printf("Total probe time     %s\n", cCyan(durationString(result.StartedAt, result.FinishedAt)))

	if result.TLSError != nil {
		fmt.Printf("TLS error            %s\n", cRed(result.TLSError.Error()))
	}

	version := tlsVersionString(result.TLSVersion)
	cipher := cipherSuiteString(result.CipherSuite)

	alpn := result.NegotiatedProtocol
	if alpn == "" {
		alpn = "unknown"
	}

	fmt.Printf("TLS version          %s\n", version)
	fmt.Printf("TLS cipher           %s\n", cipher)
	fmt.Printf("ALPN                 %s\n", alpn)

	printCertificateInfo(result)

	fmt.Println(strings.Repeat("─", 50))
	fmt.Printf("%s\n", tlsDiagnosis(result))
}
