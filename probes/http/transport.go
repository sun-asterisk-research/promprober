package http

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// roundTripTrace holds timings for a single HTTP roundtrip.
type roundTripTrace struct {
	tls           bool
	start         time.Time
	dnsDone       time.Time
	connectDone   time.Time
	gotConn       time.Time
	responseStart time.Time
	end           time.Time
	tlsStart      time.Time
	tlsDone       time.Time
}

// https://github.com/prometheus/blackbox_exporter/blob/master/prober/http.go#L131-L221
// transport is a custom transport keeping traces for each HTTP roundtrip.
type transport struct {
	Transport             http.RoundTripper
	NoServerNameTransport http.RoundTripper
	firstHost             string
	logger                *logrus.Entry
	mu                    sync.Mutex
	traces                []*roundTripTrace
	current               *roundTripTrace
}

func newTransport(httpTransport *http.Transport, logger *logrus.Entry) *transport {
	noServerNameTransport := httpTransport.Clone()
	noServerNameTransport.TLSClientConfig.ServerName = ""

	return &transport{
		Transport:             httpTransport,
		NoServerNameTransport: noServerNameTransport,
		logger:                logger,
		traces:                []*roundTripTrace{},
	}
}

// NewTraceContext creates new context for tracing a request using this transport.
func (t *transport) NewTraceContext(parent context.Context) context.Context {
	trace := &httptrace.ClientTrace{
		DNSStart:             t.DNSStart,
		DNSDone:              t.DNSDone,
		ConnectStart:         t.ConnectStart,
		ConnectDone:          t.ConnectDone,
		GotConn:              t.GotConn,
		GotFirstResponseByte: t.GotFirstResponseByte,
		TLSHandshakeStart:    t.TLSHandshakeStart,
		TLSHandshakeDone:     t.TLSHandshakeDone,
	}

	return httptrace.WithClientTrace(parent, trace)
}

// RoundTrip switches to a new trace, then runs embedded RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	logrus.WithFields(logrus.Fields{"url": req.URL.String(), "host": req.Host}).Debug("Making HTTP request")

	trace := &roundTripTrace{}
	if req.URL.Scheme == "https" {
		trace.tls = true
	}
	t.current = trace
	t.traces = append(t.traces, trace)

	if t.firstHost == "" {
		t.firstHost = req.URL.Host
	}

	if t.firstHost != req.URL.Host {
		// This is a redirect to something other than the initial host,
		// so TLS ServerName should not be set.
		t.logger.WithFields(logrus.Fields{
			"first":   t.firstHost,
			"address": req.URL.Host,
		}).Debug("Address does not match first address, not sending TLS ServerName")

		return t.NoServerNameTransport.RoundTrip(req)
	}

	return t.Transport.RoundTrip(req)
}

func (t *transport) DNSStart(_ httptrace.DNSStartInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.start = time.Now()
}

func (t *transport) DNSDone(_ httptrace.DNSDoneInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.dnsDone = time.Now()
}

func (ts *transport) ConnectStart(_, _ string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := ts.current
	// No DNS resolution because we connected to IP directly.
	if t.dnsDone.IsZero() {
		t.start = time.Now()
		t.dnsDone = t.start
	}
}

func (t *transport) ConnectDone(net, addr string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.connectDone = time.Now()
}

func (t *transport) GotConn(_ httptrace.GotConnInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.gotConn = time.Now()
}

func (t *transport) GotFirstResponseByte() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.responseStart = time.Now()
}

func (t *transport) TLSHandshakeStart() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.tlsStart = time.Now()
}

func (t *transport) TLSHandshakeDone(_ tls.ConnectionState, _ error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current.tlsDone = time.Now()
}
