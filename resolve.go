package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func parseResolve(value string) (host string, port string, ip string, ok bool, err error) {
	if value == "" {
		return "", "", "", false, nil
	}

	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return "", "", "", false, fmt.Errorf("bad --resolve format %q, expected host:port:ip", value)
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false, fmt.Errorf("bad --resolve format %q, expected host:port:ip", value)
	}

	return parts[0], parts[1], parts[2], true, nil
}

func startResolveDNS(host string, ip string) (addr string, closeFunc func() error, err error) {
	fqdn := dns.Fqdn(host)
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", nil, fmt.Errorf("bad resolve IP %q", ip)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)

		for _, q := range r.Question {
			if strings.EqualFold(q.Name, fqdn) && q.Qtype == dns.TypeA && parsedIP.To4() != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
					A:   parsedIP.To4(),
				})
			}
		}

		_ = w.WriteMsg(msg)
	})

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	server := &dns.Server{PacketConn: packetConn, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()

	return packetConn.LocalAddr().String(), server.Shutdown, nil
}
