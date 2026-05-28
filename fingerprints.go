package main

import (
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

var extraFingerprints = map[string]*utls.ClientHelloID{
	// Overlay for uTLS fingerprints that may exist before xray-core updates its registry.
	"hellofirefox_148": &utls.HelloFirefox_148,
	"hellochrome_133":  &utls.HelloChrome_133,
	"hellosafari_26_3": &utls.HelloSafari_26_3,
}

func getFingerprint(name string) (*utls.ClientHelloID, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "chrome"
	}

	if fp := xraytls.GetFingerprint(name); fp != nil {
		return fp, true
	}
	if fp := extraFingerprints[name]; fp != nil {
		return fp, true
	}
	return nil, false
}

func listFingerprints() []string {
	seen := make(map[string]struct{})

	for key, fp := range xraytls.PresetFingerprints {
		if fp != nil {
			seen[key] = struct{}{}
		}
	}
	for key := range xraytls.ModernFingerprints {
		seen[key] = struct{}{}
	}
	for key := range xraytls.OtherFingerprints {
		seen[key] = struct{}{}
	}
	for key := range extraFingerprints {
		seen[key] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func isGolangFingerprint(fp *utls.ClientHelloID) bool {
	return fp != nil && fp.Str() == utls.HelloGolang.Str()
}
