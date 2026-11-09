package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// Download test: after the TLS handshake, request a resource on the same
// connection and watch the raw TCP bytes coming from the server. Some DPI
// boxes let the handshake and the first kilobytes through and then silently
// stop passing data: no RST, no FIN, the connection just goes quiet.

const (
	stallPollInterval = 100 * time.Millisecond
	stallMaxDuration  = 60 * time.Second
	stallSmallBytes   = 32 * 1024
	stallUserAgent    = "fpcheck"
)

type stallConfig struct {
	MaxBytes    int64
	IdleTimeout time.Duration
	Host        string
	RequestURI  string
}

type stallOutcome int

const (
	stallOK stallOutcome = iota
	stallFrozen
	stallReset
	stallClosedEarly
	stallTimeLimit
	stallRequestFailed
	stallTooSmall
)

type stallResult struct {
	Proto            string
	Status           string
	StatusCode       int
	ContentRange     string
	ExpectedBody     int64
	BodyBytes        int64
	ServerBytesStart int64
	ServerBytesEnd   int64
	StartedAt        time.Time
	FirstBodyAt      time.Time
	LastDataAt       time.Time
	FinishedAt       time.Time
	IdleFor          time.Duration
	Outcome          stallOutcome
	Err              error
}

// stallWatchdog closes the connection when the server byte counter stops
// growing for longer than the idle timeout, or when the phase runs too long.
type stallWatchdog struct {
	counted     *countingConn
	idleTimeout time.Duration
	conn        net.Conn

	mu         sync.Mutex
	lastBytes  int64
	lastChange time.Time
	frozen     bool
	timedOut   bool
	idleFor    time.Duration

	stop chan struct{}
	done chan struct{}
}

func newStallWatchdog(conn net.Conn, counted *countingConn, idleTimeout time.Duration, started time.Time) *stallWatchdog {
	return &stallWatchdog{
		counted:     counted,
		idleTimeout: idleTimeout,
		conn:        conn,
		lastBytes:   atomic.LoadInt64(&counted.bytesRead),
		lastChange:  started,
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
}

func (w *stallWatchdog) run(started time.Time) {
	defer close(w.done)
	ticker := time.NewTicker(stallPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case now := <-ticker.C:
			current := atomic.LoadInt64(&w.counted.bytesRead)

			w.mu.Lock()
			if current != w.lastBytes {
				w.lastBytes = current
				w.lastChange = now
			}
			idle := now.Sub(w.lastChange)
			if idle >= w.idleTimeout {
				w.frozen = true
				w.idleFor = idle
			} else if now.Sub(started) >= stallMaxDuration {
				w.timedOut = true
			}
			fire := w.frozen || w.timedOut
			w.mu.Unlock()

			if fire {
				_ = w.conn.Close()
				return
			}
		}
	}
}

func (w *stallWatchdog) finish() {
	close(w.stop)
	<-w.done
}

func (w *stallWatchdog) state() (frozen, timedOut bool, idleFor time.Duration, lastChange time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.frozen, w.timedOut, w.idleFor, w.lastChange
}

// countingWriter counts response body bytes and records when the first one came.
type countingWriter struct {
	n       int64
	firstAt time.Time
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if len(p) > 0 && c.firstAt.IsZero() {
		c.firstAt = time.Now()
	}
	c.n += int64(len(p))
	return len(p), nil
}

func runStallTest(conn net.Conn, counted *countingConn, negotiatedProto string, cfg *stallConfig) *stallResult {
	result := &stallResult{
		ExpectedBody:     -1,
		ServerBytesStart: atomic.LoadInt64(&counted.bytesRead),
		StartedAt:        time.Now(),
	}

	watchdog := newStallWatchdog(conn, counted, cfg.IdleTimeout, result.StartedAt)
	go watchdog.run(result.StartedAt)

	body := &countingWriter{}
	var err error
	if negotiatedProto == "h2" {
		result.Proto = "h2"
		err = stallRequestH2(conn, cfg, result, body)
	} else {
		result.Proto = "HTTP/1.1"
		err = stallRequestH1(conn, cfg, result, body)
	}

	watchdog.finish()
	_ = conn.Close()

	frozen, timedOut, idleFor, _ := watchdog.state()
	result.FinishedAt = time.Now()
	result.ServerBytesEnd = atomic.LoadInt64(&counted.bytesRead)
	result.BodyBytes = body.n
	result.FirstBodyAt = body.firstAt
	if last := atomic.LoadInt64(&counted.lastReadNano); last > 0 {
		result.LastDataAt = time.Unix(0, last)
	}
	result.IdleFor = idleFor

	switch {
	case frozen:
		result.Outcome = stallFrozen
	case timedOut:
		result.Outcome = stallTimeLimit
	case err != nil && isConnReset(err):
		result.Outcome = stallReset
		result.Err = err
	case err != nil && result.StatusCode == 0:
		result.Outcome = stallRequestFailed
		result.Err = err
	case err != nil:
		result.Outcome = stallClosedEarly
		result.Err = err
	case result.ExpectedBody >= 0 && result.BodyBytes < result.ExpectedBody && result.BodyBytes < cfg.MaxBytes:
		result.Outcome = stallClosedEarly
	case result.ServerBytesEnd < stallSmallBytes:
		result.Outcome = stallTooSmall
	default:
		result.Outcome = stallOK
	}
	return result
}

func stallRangeHeader(maxBytes int64) string {
	return fmt.Sprintf("bytes=0-%d", maxBytes-1)
}

func stallRequestH1(conn net.Conn, cfg *stallConfig, result *stallResult, body *countingWriter) error {
	request := "GET " + cfg.RequestURI + " HTTP/1.1\r\n" +
		"Host: " + cfg.Host + "\r\n" +
		"User-Agent: " + stallUserAgent + "\r\n" +
		"Accept: */*\r\n" +
		"Range: " + stallRangeHeader(cfg.MaxBytes) + "\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return stallReadBody(resp, cfg, result, body)
}

func stallRequestH2(conn net.Conn, cfg *stallConfig, result *stallResult, body *countingWriter) error {
	transport := &http2.Transport{}
	clientConn, err := transport.NewClientConn(conn)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+cfg.Host+cfg.RequestURI, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", stallUserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Range", stallRangeHeader(cfg.MaxBytes))

	resp, err := clientConn.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return stallReadBody(resp, cfg, result, body)
}

func stallReadBody(resp *http.Response, cfg *stallConfig, result *stallResult, body *countingWriter) error {
	result.Status = resp.Status
	result.StatusCode = resp.StatusCode
	result.ContentRange = resp.Header.Get("Content-Range")
	result.ExpectedBody = expectedBodyBytes(resp)

	// A server that ignores Range sends the whole resource: stop at MaxBytes.
	_, err := io.Copy(body, io.LimitReader(resp.Body, cfg.MaxBytes))
	return err
}

func expectedBodyBytes(resp *http.Response) int64 {
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		// bytes 0-262143/1048576
		spec, _, _ := strings.Cut(strings.TrimPrefix(cr, "bytes "), "/")
		startStr, endStr, ok := strings.Cut(spec, "-")
		if ok {
			start, err1 := strconv.ParseInt(startStr, 10, 64)
			end, err2 := strconv.ParseInt(endStr, 10, 64)
			if err1 == nil && err2 == nil && end >= start {
				return end - start + 1
			}
		}
	}
	return resp.ContentLength
}

func isConnReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(err.Error(), "connection reset")
}

func parseByteSize(value string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(value))
	multiplier := int64(1)
	for _, unit := range []struct {
		suffix string
		mult   int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
		{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
		{"B", 1},
	} {
		if strings.HasSuffix(s, unit.suffix) {
			s = strings.TrimSpace(strings.TrimSuffix(s, unit.suffix))
			multiplier = unit.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q: want a positive number with an optional KB, MB or GB suffix", value)
	}
	return n * multiplier, nil
}

func stallDiagnosis(r *stallResult) string {
	got := formatThousands(r.ServerBytesEnd)
	badStatus := r.StatusCode != 0 && (r.StatusCode < 200 || r.StatusCode > 299)
	if badStatus && (r.Outcome == stallOK || r.Outcome == stallTooSmall) {
		return cYellow(fmt.Sprintf("Server answered %s instead of the file: check the URL", r.Status))
	}
	switch r.Outcome {
	case stallOK:
		return cGreen("Download completed, no stall")
	case stallFrozen:
		return cRed(fmt.Sprintf("Data stopped at %s bytes from the server, no RST/FIN: looks like a DPI freeze", got))
	case stallReset:
		return cRed(fmt.Sprintf("Connection reset at %s bytes from the server", got))
	case stallClosedEarly:
		return cYellow(fmt.Sprintf("Connection closed early at %s bytes from the server", got))
	case stallTimeLimit:
		return cYellow(fmt.Sprintf("Still downloading after %s: very slow or throttled", stallMaxDuration))
	case stallRequestFailed:
		return cYellow("Request failed before a response arrived")
	case stallTooSmall:
		return cYellow(fmt.Sprintf("Response ended at %s bytes from the server: too small to tell, use a larger resource", got))
	default:
		return cYellow("Inconclusive")
	}
}

func printStallResult(r *stallResult, cfg *stallConfig) {
	fmt.Println()
	fmt.Println(cBold("Download Test"))
	fmt.Println(strings.Repeat("─", 50))

	fmt.Printf("Request              GET %s (%s, %s)\n", cfg.RequestURI, r.Proto, stallRangeHeader(cfg.MaxBytes))
	if r.Status != "" {
		status := r.Status
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			status = cGreen(status)
		} else {
			status = cYellow(status)
		}
		fmt.Printf("Status               %s\n", status)
	}

	expected := "unknown"
	if r.ExpectedBody >= 0 {
		expected = formatThousands(min(r.ExpectedBody, cfg.MaxBytes))
	}
	fmt.Printf("Body bytes           %s of %s\n", formatByteCount(r.BodyBytes), expected)
	fmt.Printf("Server bytes (TCP)   %s (handshake %s)\n", formatByteCount(r.ServerBytesEnd), formatThousands(r.ServerBytesStart))

	if !r.LastDataAt.IsZero() && r.LastDataAt.After(r.StartedAt) {
		fmt.Printf("Last data at         %s\n", cCyan("+"+r.LastDataAt.Sub(r.StartedAt).Round(time.Millisecond).String()))
	}
	if r.Outcome == stallFrozen {
		fmt.Printf("Idle                 %s (connection still open)\n", cRed(r.IdleFor.Round(100*time.Millisecond).String()))
	}
	if r.Outcome == stallOK && r.BodyBytes > 0 && !r.FirstBodyAt.IsZero() && r.LastDataAt.After(r.FirstBodyAt) {
		seconds := r.LastDataAt.Sub(r.FirstBodyAt).Seconds()
		fmt.Printf("Throughput           %s KB/s\n", cCyan(formatThousands(int64(float64(r.BodyBytes)/1024/seconds))))
	}
	fmt.Printf("Download time        %s\n", cCyan(durationString(r.StartedAt, r.FinishedAt)))

	if r.Err != nil && r.Outcome != stallFrozen && r.Outcome != stallTimeLimit {
		fmt.Printf("Error                %s\n", cRed(r.Err.Error()))
	}

	fmt.Println(strings.Repeat("─", 50))
	fmt.Println(stallDiagnosis(r))
}
