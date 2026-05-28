

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
- uTLS fingerprint selection
- HTTP/2 enable/disable switch
- curl-like `--resolve` override
- handshake timing diagnostics
- ClientHello and server TLS byte counters
- certificate inspection
- ALPN reporting

## Build

```bash
go build -o fpcheck .
```

## Usage

```bash
fpcheck [options] https://host[:port]/path
```

## Examples

Basic TLS probe:

```bash
fpcheck https://example.com/
```

Firefox fingerprint:

```bash
fpcheck -fp firefox https://example.com/
```

Specific Chrome fingerprint:

```bash
fpcheck -fp hellochrome_133 https://example.com/
```

Randomized fingerprint:

```bash
fpcheck -fp randomized https://example.com/
```

Disable HTTP/2 ALPN:

```bash
fpcheck -http2=false -fp firefox https://example.com/
```

curl-like resolve override:

```bash
fpcheck -resolve "example.com:443:127.0.0.1" https://example.com/
```

Real HTTP request:

```bash
fpcheck -request -fp firefox https://example.com/
```

## Options

```text
-fp string
      fingerprint: chrome, firefox, safari, hellochrome_133, hellofirefox_148, randomized (default "chrome")
-http2
      offer h2,http/1.1 via ALPN; set false to offer only HTTP/1.1 (default true)
-list
      list supported fingerprint names
-request
      perform real HTTP request through surf instead of TLS-only probe
-resolve string
      curl-like DNS override: host:port:ipv4
-timeout duration
      request/probe timeout (default 2s)
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
* Fingerprint: hellochrome_96
* uTLS ID: Chrome-96
* SNI: www.example.com
* Dial: www.example.com:443
* Proto: h2

TLS Probe
──────────────────────────────────────────────────
TCP connected        YES
TCP connect time     52ms
ClientHello bytes    581
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

## Request mode

`-request` performs a real HTTP request through `surf` instead of the TLS-only probe. Response body preview is limited to 4096 bytes.

The tool prints:

- connection metadata
- request line
- outgoing request headers
- response status
- incoming response headers
- response body preview

Example:

```bash
fpcheck -request -fp safari https://example.com/
```

## Fingerprints

List supported fingerprints:

```bash
fpcheck -list
```

The exact list depends on the bundled `uTLS` and `xray-core` versions.

## Resolve override

`-resolve` works similarly to `curl --resolve`.

Example:

```bash
fpcheck -resolve "example.com:443:1.2.3.4" https://example.com/
```

Behavior:

- TCP connects to `1.2.3.4`
- SNI remains `example.com`
- HTTP Host remains `example.com`

Current format:

```text
host:port:ipv4
```

IPv6 is not currently supported by `-resolve`.

## Notes

- `ClientHello bytes` and `Server TLS bytes` are raw TLS byte counters during the handshake.
- `Server TLS bytes` are not limited to `ServerHello`; they may include certificates and other handshake records.

## License

Mozilla Public License 2.0. See LICENSE for the full text.
