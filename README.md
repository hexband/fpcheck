

# fpcheck

`fpcheck` is a small HTTPS fingerprint checker built on top of `surf` and `uTLS`.

It can run a TLS-only probe or perform a real HTTP request with a selected uTLS fingerprint.

Useful for debugging:

- TLS fingerprints
- uTLS profiles
- CDN / WAF behavior
- DPI filtering

## Features

- TLS probe mode without sending an HTTP request
- real HTTP request mode
- curl-like request method, headers, and body flags
- uTLS fingerprint selection
- surf browser impersonation profiles
- HTTP/2 enable/disable switch
- curl-like `--resolve` override
- handshake timing diagnostics
- ClientHello and server TLS byte counters
- certificate inspection
- ALPN reporting
- download test for DPI that stops passing data after N bytes (`--stall`)

## Build

Requires Go 1.27 or newer.

```bash
go build -o fpcheck .
```

## Usage

```bash
fpcheck [options] https://host[:port]/path [options]
```

## Examples

Basic TLS probe:

```bash
fpcheck https://example.com/
```

Firefox fingerprint:

```bash
fpcheck --fp firefox https://example.com/
```

Specific Chrome fingerprint:

```bash
fpcheck --fp hellochrome_155 https://example.com/
```

Randomized fingerprint:

```bash
fpcheck --fp randomized https://example.com/
```

Disable HTTP/2 ALPN (the fingerprint's ALPN extension is rewritten to `http/1.1`, so JA3/JA4 change):

```bash
fpcheck --http2=false --fp firefox https://example.com/
```

curl-like resolve override:

```bash
fpcheck --resolve "example.com:443:127.0.0.1" https://example.com/
```

Download test (detect a DPI freeze after N bytes):

```bash
fpcheck --stall --resolve "example.com:443:1.2.3.4" https://example.com/assets/probe.bin
```

Real HTTP request:

```bash
fpcheck --request --fp firefox https://example.com/
```

Surf browser impersonation:

```bash
fpcheck --impersonate chrome https://example.com/
fpcheck --impersonate firefox-macos https://example.com/
```

POST JSON request:

```bash
fpcheck -X POST -H "Content-Type: application/json" -d '{"a":1}' https://example.com/api
```

Binary request body from a file:

```bash
fpcheck --data-binary @payload.bin https://example.com/api
```

HEAD request:

```bash
fpcheck -I https://example.com/
```

## Options

Options can go before or after the URL. Use `--` to end options.

```text
    --fp string                fingerprint: chrome, firefox, safari, hellochrome_155, hellofirefox_148, randomized (default "chrome")
    --impersonate string       surf browser impersonation profile; enables request mode and cannot be combined with explicit --fp
    --padding int              override TLS padding extension length (TLS probe only)
    --stall                    after the TLS probe, download the URL on the same connection and detect a DPI freeze (TLS probe only)
    --stall-timeout duration   with --stall: no new server bytes for this long means the connection froze (default 5s)
    --max-bytes string         with --stall: bytes to download (sent as Range) before the test counts as passed (default "256KB")
    --resolve string           curl-like DNS override: host:port:ipv4
    --http2                    offer h2,http/1.1 via ALPN; --http2=false offers only HTTP/1.1 (rewrites the fingerprint's ALPN, so JA3/JA4 change) (default true)
    --request                  perform real HTTP request through surf instead of TLS-only probe
    --list                     list supported fingerprint names
    --timeout duration         request/probe timeout (default 2s)
-X, --method string            HTTP request method; enables request mode
-I, --head                     perform a HEAD request; enables request mode
-d, --data string              HTTP request body; defaults method to POST and enables request mode
    --data-binary string       HTTP request body or @file bytes; defaults method to POST and enables request mode
-H, --header header            HTTP request header in Name: value format; may be repeated and enables request mode
```

## TLS probe mode

Default mode performs a TLS-only probe.

It:

1. opens TCP
2. sends ClientHello
3. waits for server TLS bytes
4. completes the TLS handshake if possible
5. prints diagnostics

No HTTP request is sent.

Example output:

```text
* Fingerprint: chrome
* uTLS ID: Chrome-155
* SNI: www.example.com
* Dial: www.example.com:443
* Proto: h2

TLS Probe
──────────────────────────────────────────────────
TCP connected        YES
TCP connect time     52ms
ClientHello bytes    1 950
Server TLS bytes     7 534
TLS handshake        YES
TLS handshake time   74ms
Total probe time     127ms
TLS version          TLS1.3
TLS cipher           TLS_AES_128_GCM_SHA256
ALPN                 h2
Certificate:
  Subject: CN=example.com
  Issuer: CN=Example CA
  Serial: 123456789
  Not before: 2026-01-01T00:00:00Z
  Not after: 2027-01-01T00:00:00Z
  DNS names: example.com, www.example.com
──────────────────────────────────────────────────
TLS handshake completed successfully
```

## Download test

`--stall` adds a download test to the TLS probe. It catches DPI that lets the TCP and TLS handshakes through and then silently stops passing data after some amount, often reported around 14-20 KB from the server: no RST, no FIN, the connection just goes quiet.

After the handshake, on the same connection and with the same fingerprint and ALPN, fpcheck requests the URL with `Range: bytes=0-<max-bytes - 1>` (HTTP/1.1 or h2, whichever was negotiated) and watches the raw TCP bytes coming from the server, handshake included. If the counter stops growing for `--stall-timeout` while the connection is still open, the test reports a freeze.

Outcomes:

- download completed: `--max-bytes` received without a stall
- freeze: data stopped at N bytes from the server, no RST/FIN
- reset: RST at N bytes
- closed early: EOF before the expected body length
- too small to tell: the response ended before 32 KB from the server; use a larger file
- the server answered a non-2xx status: check the URL

The URL must serve a file larger than `--max-bytes`, and the server should support `Range` (Caddy's `file_server` does). Random content is best, so that compression cannot shrink the response below the threshold. `--stall` cannot be combined with request mode.

Example output:

```text
Download Test
──────────────────────────────────────────────────
Request              GET /assets/probe.bin (h2, bytes=0-262143)
Status               206 Partial Content
Body bytes           0 of 262 144
Server bytes (TCP)   16 384 (handshake 1 985)
Last data at         +31ms
Idle                 5s (connection still open)
Download time        5.101s
──────────────────────────────────────────────────
Data stopped at 16 384 bytes from the server, no RST/FIN: looks like a DPI freeze
```

`Body bytes` can be 0 even though data came in: when the stream stops in the middle of a TLS record, nothing of that record can be decrypted. `Server bytes (TCP)` is the number to compare with DPI thresholds.

## Request mode

`--request` performs a real HTTP request through `surf` instead of the TLS-only probe. Response body preview is limited to 4096 bytes.

The request flags `-X`, `-H`, `-d`, `--data-binary`, and `-I` automatically enable request mode. If a body is provided with `-d` or `--data-binary` and no explicit `-X` method is set, the request method defaults to `POST`. Otherwise request mode defaults to `GET`.

`--impersonate` enables surf browser impersonation for request mode and cannot be combined with explicit `--fp`. Supported profiles are `chrome` and `firefox`, with optional OS suffixes: `-windows`, `-macos`, `-linux`, `-android`, `-ios`, and `-randomos`. The bundled surf v1.0.209 impersonates Chrome 156 (Chrome 157 on iOS) and Firefox 159.

The tool prints:

- connection metadata
- request line
- outgoing request headers
- response status
- incoming response headers
- response body preview

Example:

```bash
fpcheck --request --fp safari https://example.com/
```

## Fingerprints

List supported fingerprints:

```bash
fpcheck --list
```

The exact list depends on the bundled `uTLS` and `xray-core` versions. Names follow xray-core's `fingerprint` setting: `chrome` is uTLS `HelloChrome_Auto` (currently Chrome 155), `firefox` is Firefox 148, `safari` is Safari 26.3, `edge` is Edge 85.

## Resolve override

`--resolve` works similarly to `curl --resolve`.

Example:

```bash
fpcheck --resolve "example.com:443:1.2.3.4" https://example.com/
```

Behavior:

- TCP connects to `1.2.3.4`
- SNI remains `example.com`
- HTTP Host remains `example.com`

Current format:

```text
host:port:ipv4
```

IPv6 is not currently supported by `--resolve`.

## Notes

- `ClientHello bytes` and `Server TLS bytes` are raw TLS byte counters during the handshake.
- `Server TLS bytes` are not limited to `ServerHello`; they may include certificates and other handshake records.
- `--padding` only works with fingerprints that already have a padding extension, such as `hellochrome_120`. Chrome 131+, Firefox 148 and Safari 26.3 have none, and adding one would change JA3/JA4.

## License

Mozilla Public License 2.0. See LICENSE for the full text.
