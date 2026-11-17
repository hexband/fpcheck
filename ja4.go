package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// clientHelloFields are the parts of a ClientHello that JA3 and JA4 use.
type clientHelloFields struct {
	LegacyVersion     uint16
	CipherSuites      []uint16 // wire order, GREASE included
	Extensions        []uint16 // wire order, GREASE included
	SupportedVersions []uint16
	SupportedGroups   []uint16
	KeyShareGroups    []uint16
	PointFormats      []uint8
	SignatureAlgs     []uint16
	ALPN              []string
	HasSNI            bool
}

// isGREASE reports RFC 8701 values: 0x0a0a, 0x1a1a, ... 0xfafa.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// parseClientHello reads a ClientHello from a TLS record (as sent on the wire)
// or from a bare handshake message.
func parseClientHello(raw []byte) (*clientHelloFields, error) {
	b := raw
	if len(b) >= 5 && b[0] == 0x16 { // TLS record header
		b = b[5:]
	}
	if len(b) < 4 || b[0] != 0x01 {
		return nil, errors.New("not a ClientHello")
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if len(b) < n {
		return nil, errors.New("truncated ClientHello")
	}
	b = b[:n]
	r := reader{b: b}
	f := &clientHelloFields{}
	f.LegacyVersion = r.u16()
	r.skip(32) // random
	r.skip(int(r.u8()))
	cs := r.bytes(int(r.u16()))
	for i := 0; i+1 < len(cs); i += 2 {
		f.CipherSuites = append(f.CipherSuites, binary.BigEndian.Uint16(cs[i:]))
	}
	r.skip(int(r.u8())) // compression methods
	if r.err != nil {
		return nil, r.err
	}
	if r.left() == 0 {
		return f, nil
	}
	exts := reader{b: r.bytes(int(r.u16()))}
	for exts.left() > 0 && exts.err == nil {
		typ := exts.u16()
		data := reader{b: exts.bytes(int(exts.u16()))}
		f.Extensions = append(f.Extensions, typ)
		switch typ {
		case 0x0000:
			f.HasSNI = true
		case 0x000a:
			l := data.bytes(int(data.u16()))
			for i := 0; i+1 < len(l); i += 2 {
				f.SupportedGroups = append(f.SupportedGroups, binary.BigEndian.Uint16(l[i:]))
			}
		case 0x000b:
			f.PointFormats = append(f.PointFormats, data.bytes(int(data.u8()))...)
		case 0x000d:
			l := data.bytes(int(data.u16()))
			for i := 0; i+1 < len(l); i += 2 {
				f.SignatureAlgs = append(f.SignatureAlgs, binary.BigEndian.Uint16(l[i:]))
			}
		case 0x0010:
			l := reader{b: data.bytes(int(data.u16()))}
			for l.left() > 0 && l.err == nil {
				f.ALPN = append(f.ALPN, string(l.bytes(int(l.u8()))))
			}
		case 0x0033:
			l := reader{b: data.bytes(int(data.u16()))}
			for l.left() > 0 && l.err == nil {
				f.KeyShareGroups = append(f.KeyShareGroups, l.u16())
				l.skip(int(l.u16()))
			}
		case 0x002b:
			l := data.bytes(int(data.u8()))
			for i := 0; i+1 < len(l); i += 2 {
				f.SupportedVersions = append(f.SupportedVersions, binary.BigEndian.Uint16(l[i:]))
			}
		}
	}
	if exts.err != nil {
		return nil, exts.err
	}
	return f, nil
}

// x25519MLKEM768 is the hybrid post-quantum group (0x11ec).
const x25519MLKEM768 = 0x11ec

// PostQuantum reports an X25519MLKEM768 key share. REALITY servers from
// Xray-core v26.9.8 on reject Client Hellos without one (hexband/REALITY:
// unless XRAY_REALITY_NONPQ_CLIENTS allows them).
func (f *clientHelloFields) PostQuantum() bool {
	for _, g := range f.KeyShareGroups {
		if g == x25519MLKEM768 {
			return true
		}
	}
	return false
}

func dropGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinDec(vals []uint16) string {
	s := make([]string, len(vals))
	for i, v := range vals {
		s[i] = strconv.Itoa(int(v))
	}
	return strings.Join(s, "-")
}

func joinHex(vals []uint16) string {
	s := make([]string, len(vals))
	for i, v := range vals {
		s[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(s, ",")
}

// JA3 returns the JA3 string and its MD5, with the extensions sorted: Chrome
// shuffles its extension order per connection, so the classic wire-order JA3
// is not stable.
func (f *clientHelloFields) JA3() (string, string) {
	exts := dropGREASE(f.Extensions)
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	pf := make([]string, len(f.PointFormats))
	for i, v := range f.PointFormats {
		pf[i] = strconv.Itoa(int(v))
	}
	s := fmt.Sprintf("%d,%s,%s,%s,%s", f.LegacyVersion, joinDec(dropGREASE(f.CipherSuites)),
		joinDec(exts), joinDec(dropGREASE(f.SupportedGroups)), strings.Join(pf, "-"))
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// JA4 returns the JA4 fingerprint (FoxIO spec) and its raw form (JA4_r).
func (f *clientHelloFields) JA4() (string, string) {
	version := f.LegacyVersion
	if vs := dropGREASE(f.SupportedVersions); len(vs) > 0 {
		version = 0
		for _, v := range vs {
			if v > version && v < 0xfe00 { // DTLS versions count downwards
				version = v
			}
		}
	}
	sni := "i"
	if f.HasSNI {
		sni = "d"
	}
	ciphers := dropGREASE(f.CipherSuites)
	exts := dropGREASE(f.Extensions)
	alpn := "00"
	if len(f.ALPN) > 0 && f.ALPN[0] != "" {
		a := f.ALPN[0]
		first, last := a[0], a[len(a)-1]
		if isAlnum(first) && isAlnum(last) {
			alpn = string([]byte{first, last})
		} else {
			alpn = fmt.Sprintf("%c%c", hex.EncodeToString([]byte{first})[0], hex.EncodeToString([]byte{last})[1])
		}
	}
	part1 := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(version), sni, min(len(ciphers), 99), min(len(exts), 99), alpn)

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	var sortedExts []uint16
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			sortedExts = append(sortedExts, e)
		}
	}
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })

	cipherStr := joinHex(sortedCiphers)
	extStr := joinHex(sortedExts)
	if sigs := dropGREASE(f.SignatureAlgs); len(sigs) > 0 {
		extStr += "_" + joinHex(sigs)
	}
	ja4 := part1 + "_" + hash12(cipherStr) + "_" + hash12(extStr)
	ja4r := part1 + "_" + cipherStr + "_" + extStr
	return ja4, ja4r
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) left() int { return len(r.b) }

func (r *reader) bytes(n int) []byte {
	if r.err != nil || n > len(r.b) {
		r.err = errors.New("truncated ClientHello")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.bytes(n) }

func (r *reader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
