package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	xraycore "github.com/xtls/xray-core/core"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// --dump: the JA3/JA4 every uTLS fingerprint of xray-core, sing-box and
// mihomo produces, computed offline from the ClientHello each core would
// send. JA3 has its extensions sorted (see clientHelloFields.JA3).

type dumpRow struct {
	Core    string `json:"core"`
	Version string `json:"version"`
	Name    string `json:"fingerprint"`
	Profile string `json:"profile"`
	Random  bool   `json:"random_pool,omitempty"`
	PQ      bool   `json:"post_quantum"`
	JA4     string `json:"ja4"`
	// Variants: every distinct JA4 over the builds when they differ (profiles
	// with random parts). Such a row is not allowlistable.
	Variants []string `json:"ja4_variants,omitempty"`
	JA4R     string   `json:"ja4_r"`
	JA3      string   `json:"ja3"`
	JA3Hash  string   `json:"ja3_hash"`
	ALPN     string   `json:"alpn"`
	Error    string   `json:"error,omitempty"`
}

type dumpOptions struct {
	Cores    []string
	SNI      string
	ALPN     []string
	Runs     int
	JSON     bool
	PQOnly   bool
	Profiles []string // keep only these fingerprints (--fp names, e.g. hellochrome_155), in any core
	YAML     bool     // print ja4_allowlist (YAML) for the kept rows
	Names    bool     // print ja4_names (YAML, JA4 -> fingerprint name) for the kept rows
	All      bool     // xray: also OtherFingerprints (old profiles, Golang)
}

var dumpCores = []string{"xray", "sing-box", "mihomo"}

func runDump(opt dumpOptions) int {
	warnGoVersion()
	var rows []dumpRow
	for _, core := range opt.Cores {
		switch core {
		case "xray":
			rows = append(rows, dumpXray(opt)...)
		case "sing-box":
			for _, p := range singboxProfiles {
				rows = append(rows, helloRow("sing-box", "1.14.4 / 1.15.0-alpha.13 / extended 2.7.3 (metacubex/utls 1.8.7)", p.Name, p.ID.Str(),
					contains(singboxRandom, p.Name), opt, func() ([]byte, error) { return metacubexHello(p.ID, opt.SNI, opt.ALPN, true) }))
			}
		case "mihomo":
			for _, p := range mihomoProfiles {
				rows = append(rows, helloRow("mihomo", "1.19.34 / Alpha (metacubex/utls 1.9.0-alpha.1)", p.Name, p.ID.Str(),
					contains(mihomoRandom, p.Name), opt, func() ([]byte, error) { return metacubexHello(p.ID, opt.SNI, opt.ALPN, false) }))
			}
		default:
			errf("unknown core %q (known: %s)\n", core, strings.Join(dumpCores, ", "))
			return 2
		}
	}

	if len(opt.Profiles) > 0 {
		// Same names as --fp (xray-core's "fingerprint"): each resolves to a
		// uTLS profile, and every core's fingerprint building that profile
		// is kept (mihomo "firefox" for hellofirefox_148, say).
		want := map[string]string{} // profile -> name as given
		for _, name := range opt.Profiles {
			name = strings.ToLower(strings.TrimSpace(name))
			fp, ok := getFingerprint(name)
			if !ok || strings.HasPrefix(name, "random") {
				errf("--profiles: %q is not a fixed fingerprint (see fpcheck --list)\n", name)
				return 2
			}
			want[strings.ToLower(fp.Str())] = name
		}
		found := map[string]bool{}
		kept := rows[:0]
		for _, r := range rows {
			if key := strings.ToLower(r.Profile); want[key] != "" {
				kept = append(kept, r)
				found[key] = true
			}
		}
		rows = kept
		for profile, name := range want {
			if !found[profile] {
				errf("--profiles: %s (%s) is built by none of the selected cores\n", name, profile)
				return 2
			}
		}
	}

	if opt.PQOnly {
		kept := rows[:0]
		for _, r := range rows {
			if r.PQ {
				kept = append(kept, r)
			}
		}
		rows = kept
	}

	if opt.YAML {
		return printAllowlistYAML(rows)
	}
	if opt.Names {
		return printNamesYAML(rows)
	}

	if opt.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			errln(err)
			return 1
		}
		return 0
	}
	printDump(rows, opt.Runs)
	return 0
}

func dumpXray(opt dumpOptions) []dumpRow {
	var rows []dumpRow
	names := map[string]bool{} // name -> in the "random" pool
	for name, fp := range xraytls.PresetFingerprints {
		if fp != nil && name != "random" && name != "randomized" && name != "randomizednoalpn" {
			names[name] = false
		}
	}
	for name := range xraytls.ModernFingerprints {
		names[name] = true
	}
	if opt.All {
		// *_auto aliases, hellogolang and the old profiles xray still accepts
		// for TLS (REALITY refuses hellogolang and unsafe, TLS does not).
		for name, fp := range xraytls.OtherFingerprints {
			if fp != nil && !strings.HasPrefix(name, "hellorandomized") {
				if _, ok := names[name]; !ok {
					names[name] = false
				}
			}
		}
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fp := xraytls.GetFingerprint(name)
		rows = append(rows, helloRow("xray", xrayVersion(), name, fp.Str(), names[name], opt,
			func() ([]byte, error) { return xrayHello(fp, opt.SNI, opt.ALPN) }))
	}
	// "unsafe": no uTLS, xray dials with Go's crypto/tls. Its hello follows
	// the Go version the client was built with (fpcheck's own here).
	rows = append(rows, helloRow("xray", xrayVersion(), "unsafe", goTLSProfile(), false, opt,
		func() ([]byte, error) { return goTLSHello(opt.SNI, opt.ALPN) }))
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// xrayReleaseGo is the Go version the official Xray release of the bundled
// xray-core is built with ("xray version": go1.27.3). The crypto/tls hello
// ("unsafe", "hellogolang") depends on it, so fpcheck must be built with the
// same toolchain: go.mod "toolchain" go1.27.3, GOTOOLCHAIN=go1.27.3.
const xrayReleaseGo = "go1.27.3"

// warnGoVersion tells when this build's Go differs from xrayReleaseGo.
func warnGoVersion() {
	if runtime.Version() != xrayReleaseGo {
		errf("warning: fpcheck is built with %s, Xray %s with %s: the unsafe/hellogolang rows may differ; build with GOTOOLCHAIN=%s go build\n",
			runtime.Version(), xrayVersion(), xrayReleaseGo, xrayReleaseGo)
	}
}

// goTLSProfile names the crypto/tls hello of this build, e.g. GoTLS-go1.27.3.
func goTLSProfile() string {
	return "GoTLS-" + runtime.Version()
}

// goTLSHello captures the ClientHello crypto/tls sends with xray's defaults
// for a TLS stream (session resumption off).
func goTLSHello(sni string, alpn []string) ([]byte, error) {
	return captureClientHello(func(c net.Conn) error {
		return tls.Client(c, &tls.Config{ServerName: sni, NextProtos: alpn, SessionTicketsDisabled: true}).Handshake()
	})
}

// captureClientHello runs a client handshake over a pipe and returns the
// first TLS record it writes: the ClientHello. For hellos that uTLS does not
// expose before the handshake (crypto/tls, HelloGolang).
func captureClientHello(client func(net.Conn) error) ([]byte, error) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		_ = client(c1)
		_ = c1.Close()
	}()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(c2, header); err != nil {
		return nil, err
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

// xrayHello builds the ClientHello the way xray's xhttp/grpc dialers do:
// tls.UClient with the stream's tls.Config, BuildHandshakeState before the
// handshake. Fixed profiles keep their own ALPN; randomized ones follow
// NextProtos.
func xrayHello(fp *utls.ClientHelloID, sni string, alpn []string) ([]byte, error) {
	if fp.Client == utls.HelloGolang.Client {
		// uTLS builds the Go hello only inside the handshake.
		return captureClientHello(func(c net.Conn) error {
			return xraytls.UClient(c, &tls.Config{ServerName: sni, NextProtos: alpn, SessionTicketsDisabled: true}, fp).(*xraytls.UConn).Handshake()
		})
	}
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }() // also closed by the TLS conn; a second Close is a no-op
	defer func() { _ = c2.Close() }()
	conn := xraytls.UClient(c1, &tls.Config{ServerName: sni, NextProtos: alpn, SessionTicketsDisabled: true}, fp).(*xraytls.UConn)
	defer func() { _ = conn.Close() }()
	if err := conn.BuildHandshakeState(); err != nil {
		if errors.Is(err, utls.ErrEmptyPsk) || strings.Contains(err.Error(), "empty psk") {
			// xray does not set OmitEmptyPsk: without a session to resume
			// the handshake fails the same way, so the profile is unusable.
			return nil, errors.New("unusable in xray: PSK profile without a session (no OmitEmptyPsk)")
		}
		return nil, err
	}
	return append([]byte(nil), conn.HandshakeState.Hello.Raw...), nil
}

// xrayVersion is the version of the bundled xray-core, as "xray version"
// prints it (26.11.9), not the Go module pseudo-version.
func xrayVersion() string {
	return xraycore.Version()
}

// helloRow builds the ClientHello opt.Runs times: some profiles have random
// parts, and a JA4 that changes between connections cannot go into the
// allowlist.
func helloRow(core, version, name, profile string, random bool, opt dumpOptions, build func() ([]byte, error)) dumpRow {
	row := dumpRow{Core: core, Version: version, Name: name, Profile: profile, Random: random}
	counts := map[string]int{}
	for i := 0; i < max(opt.Runs, 1); i++ {
		raw, err := build()
		if err != nil {
			row.Error = err.Error()
			return row
		}
		f, err := parseClientHello(raw)
		if err != nil {
			row.Error = err.Error()
			return row
		}
		ja4, ja4r := f.JA4()
		counts[ja4]++
		if counts[ja4] > counts[row.JA4] {
			row.JA4, row.JA4R = ja4, ja4r
			row.JA3, row.JA3Hash = f.JA3()
			row.ALPN = strings.Join(f.ALPN, ",")
			row.PQ = f.PostQuantum()
		}
	}
	if len(counts) > 1 {
		for k := range counts {
			row.Variants = append(row.Variants, k)
		}
		sort.Strings(row.Variants)
	}
	return row
}

func printDump(rows []dumpRow, runs int) {
	fmt.Printf("%-9s %-18s %-26s %-3s %-38s %s\n", "CORE", "FINGERPRINT", "PROFILE", "PQ", "JA4", "JA3 (sorted ext)")
	for _, r := range rows {
		name := r.Name
		if r.Random {
			name += " *"
		}
		if r.Error != "" {
			fmt.Printf("%-9s %-18s %-26s error: %s\n", r.Core, name, r.Profile, r.Error)
			continue
		}
		if len(r.Variants) > 0 {
			fmt.Printf("%-9s %-18s %-26s %d different JA4 in %d builds\n", r.Core, name, r.Profile, len(r.Variants), max(runs, 1))
			continue
		}
		fmt.Printf("%-9s %-18s %-26s %-3s %-38s %s\n", r.Core, name, r.Profile, yesNo(r.PQ), r.JA4, r.JA3Hash)
	}
	fmt.Println("\n* in the core's \"random\" pool (one is picked per process start)")
	fmt.Println("PQ: X25519MLKEM768 key share; REALITY (Xray-core >= v26.9.8) rejects hellos without it")

	// Allowlist candidates: deterministic, post-quantum and current. Current
	// means a profile xray-core's own presets (chrome, firefox, safari, ...)
	// resolve to in this version; older profiles such as Chrome 131/133 still
	// carry X25519MLKEM768 but are not suggested.
	current := currentProfiles()
	labels := map[string][]string{}
	group := map[string]int{} // 0 candidate, 1 PQ but not current, 2 no PQ
	for _, r := range rows {
		if r.Error != "" || len(r.Variants) > 0 {
			continue
		}
		labels[r.JA4] = append(labels[r.JA4], r.Core+":"+r.Name)
		g := 2
		if r.PQ {
			g = 1
			if current[strings.ToLower(r.Profile)] {
				g = 0
			}
		}
		if prev, ok := group[r.JA4]; !ok || g < prev {
			group[r.JA4] = g
		}
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	titles := []string{
		"ja4_allowlist candidates (post-quantum, current xray-core presets):",
		"post-quantum, not suggested (older profiles, Go crypto/tls):",
		"without X25519MLKEM768 (rejected by REALITY):",
	}
	for g, title := range titles {
		printed := false
		for _, k := range keys {
			if group[k] != g {
				continue
			}
			if !printed {
				fmt.Println("\n" + title)
				printed = true
			}
			fmt.Printf("  - \"%s\"  # %s\n", k, strings.Join(labels[k], ", "))
		}
	}
}

// currentProfiles: the uTLS profiles xray-core's named presets resolve to in
// the bundled version ("chrome" -> Chrome-155, ...), lower-cased. "random" is
// skipped: xray's init() fills it with one profile of the random pool, picked
// anew on every run.
func currentProfiles() map[string]bool {
	out := map[string]bool{}
	for name, fp := range xraytls.PresetFingerprints {
		if strings.HasPrefix(name, "random") || name == "unsafe" {
			continue
		}
		if fp != nil {
			out[strings.ToLower(fp.Str())] = true
		}
	}
	return out
}

// printAllowlistYAML prints the kept rows as a YAML list (ja4_allowlist), one
// JA4 per line with the profile and the core settings that send it.
func printAllowlistYAML(rows []dumpRow) int {
	type entry struct {
		profiles map[string]bool
		labels   []string
		pq       bool
	}
	entries := map[string]*entry{}
	for _, r := range rows {
		if r.Error != "" {
			errf("%s:%s (%s) left out: %s\n", r.Core, r.Name, r.Profile, r.Error)
			continue
		}
		if len(r.Variants) > 0 {
			errf("%s:%s (%s) left out: no stable JA4\n", r.Core, r.Name, r.Profile)
			continue
		}
		e := entries[r.JA4]
		if e == nil {
			e = &entry{profiles: map[string]bool{}, pq: r.PQ}
			entries[r.JA4] = e
		}
		e.profiles[r.Profile] = true
		e.labels = append(e.labels, r.Core+":"+r.Name)
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("# fpcheck --dump (Xray %s, %s)\n", xrayVersion(), runtime.Version())
	fmt.Println("ja4_allowlist:")
	for _, k := range keys {
		e := entries[k]
		profiles := make([]string, 0, len(e.profiles))
		for p := range e.profiles {
			profiles = append(profiles, p)
		}
		sort.Strings(profiles)
		note := ""
		if !e.pq {
			note = ", no X25519MLKEM768"
		}
		fmt.Printf("  - \"%s\"  # %s%s: %s\n", k, strings.Join(profiles, ", "), note, strings.Join(e.labels, ", "))
	}
	return 0
}

// fpNameForProfile returns the --fp / xray "fingerprint" name of a uTLS
// profile ("Chrome-133" -> "hellochrome_133"), so --names uses the same names
// as --fp and xray. Profiles xray has no name for keep their profile string.
func fpNameForProfile(profile string) string {
	if strings.HasPrefix(profile, "GoTLS-") {
		return "unsafe"
	}
	best := ""
	for _, m := range []map[string]*utls.ClientHelloID{xraytls.ModernFingerprints, xraytls.OtherFingerprints} {
		for name, fp := range m {
			if fp == nil || !strings.HasPrefix(name, "hello") || strings.HasSuffix(name, "_auto") || strings.HasPrefix(name, "hellorandomized") {
				continue
			}
			if strings.EqualFold(fp.Str(), profile) && (best == "" || name < best) {
				best = name
			}
		}
	}
	if best == "" {
		return profile
	}
	return best
}

// printNamesYAML prints ja4_names: every stable JA4 of the kept rows with the
// fingerprint name(s) behind it (see fpNameForProfile).
func printNamesYAML(rows []dumpRow) int {
	profiles := map[string]map[string]bool{}
	labels := map[string][]string{}
	for _, r := range rows {
		if r.Error != "" || len(r.Variants) > 0 {
			continue
		}
		if profiles[r.JA4] == nil {
			profiles[r.JA4] = map[string]bool{}
		}
		profiles[r.JA4][fpNameForProfile(r.Profile)] = true
		labels[r.JA4] = append(labels[r.JA4], r.Core+":"+r.Name)
	}
	keys := make([]string, 0, len(profiles))
	for k := range profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("# fpcheck --dump --names (Xray %s, %s)\n", xrayVersion(), runtime.Version())
	fmt.Println("# value: --fp / xray fingerprint name(s); comment: who sends it")
	fmt.Println("ja4_names:")
	for _, k := range keys {
		names := make([]string, 0, len(profiles[k]))
		for p := range profiles[k] {
			names = append(names, p)
		}
		sort.Strings(names)
		fmt.Printf("  \"%s\": \"%s\"  # %s\n", k, strings.Join(names, "/"), strings.Join(labels[k], ", "))
	}
	return 0
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
