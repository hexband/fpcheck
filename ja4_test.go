package main

import (
	"os"
	"testing"
)

// testdata: ClientHellos captured from curl (h2; http/1.1 with TLS 1.2; to an
// IP, no SNI), Python ssl, and xray 26.11.9-nonpq with fingerprint firefox /
// chrome. Expected values: computed for the same ClientHellos by an
// independent JA3/JA4 implementation.
func TestJA4Reference(t *testing.T) {
	cases := []struct{ file, ja4, ja3hash string }{
		{"testdata/curl_h2.bin", "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6", "22441e3edb4a151c17462a438c7a10a5"},
		{"testdata/curl_h1_12.bin", "t12d2807h1_d943125447b4_a44c6288192a", "3aa15ce9d3688b3180ad303598bf225c"},
		{"testdata/py.bin", "t13d171100_ab0a1bf427ad_8e6e362c5eac", ""},
		{"testdata/curl_ip.bin", "t13i3111h2_e8f1e7e78f70_b26ce05bbdd6", ""},
		{"testdata/xray_firefox.bin", "t13d1715h2_5b57614c22b0_a54fffd0eb61", ""},
		{"testdata/xray_chrome.bin", "t13d1517h2_8daaf6152771_cb7bf5808d99", ""},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parseClientHello(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if got, _ := f.JA4(); got != c.ja4 {
			t.Errorf("%s: JA4 %s, want %s", c.file, got, c.ja4)
		}
		if c.ja3hash != "" {
			if _, got := f.JA3(); got != c.ja3hash {
				t.Errorf("%s: JA3 hash %s, want %s", c.file, got, c.ja3hash)
			}
		}
	}
}
