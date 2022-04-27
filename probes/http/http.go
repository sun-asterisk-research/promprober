package http

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/units"
	"github.com/cloudprober/cloudprober/metrics"
	"github.com/cloudprober/cloudprober/probes/options"
	"github.com/cloudprober/cloudprober/targets/endpoint"
	"github.com/sirupsen/logrus"
	"github.com/sun-asterisk-research/promprober/common"
	"github.com/sun-asterisk-research/promprober/common/tls"
	"github.com/sun-asterisk-research/promprober/probes"
	configpb "github.com/sun-asterisk-research/promprober/probes/http/proto"
	// "github.com/cloudprober/cloudprober/validators"
)

// DefaultTargetsUpdateInterval defines default frequency for target updates.
// Actual targets update interval is:
// max(DefaultTargetsUpdateInterval, probe_interval)
var DefaultTargetsUpdateInterval = 1 * time.Minute

// Probe holds aggregate information about all probe runs, per-target.
type Probe struct {
	name   string
	opts   *options.Options
	config *configpb.ProbeConf
	logger *logrus.Entry

	// book-keeping params
	targets   []endpoint.Endpoint
	scheme    string
	resolveFn func(context.Context, string) (common.ResolveResult, error)

	// How often to resolve targets (in probe counts), it's the minimum of
	targetsUpdateInterval time.Duration

	// Cancel functions for per-target probe loop
	cancelFuncs map[string]context.CancelFunc
	waitGroup   sync.WaitGroup

	requestBody []byte
}

// Init initializes the probe with the given params.
func (p *Probe) Init(name string, opts *options.Options) error {
	httpConfig, ok := opts.ProbeConf.(*configpb.ProbeConf)
	if !ok {
		return fmt.Errorf("not http config")
	}

	p.name = name
	p.opts = opts
	p.config = httpConfig

	p.logger = logrus.WithFields(logrus.Fields{
		"name":  p.name,
		"probe": "http",
	})

	p.requestBody = []byte(httpConfig.GetBody())

	p.targets = p.opts.Targets.ListEndpoints()
	p.cancelFuncs = make(map[string]context.CancelFunc, len(p.targets))

	resolver := common.NewResolver(httpConfig.GetPreferredIpProtocol().String(), p.logger)
	if httpConfig.GetIpProtocolFallback() {
		p.resolveFn = resolver.ResolveTarget
	} else {
		p.resolveFn = resolver.ResolveTargetStrict
	}

	if httpConfig.GetSecure() {
		p.scheme = "https"
	} else {
		p.scheme = "http"
	}

	p.targetsUpdateInterval = DefaultTargetsUpdateInterval
	// There is no point refreshing targets before probe interval.
	if p.targetsUpdateInterval < p.opts.Interval {
		p.targetsUpdateInterval = p.opts.Interval
	}

	p.logger.Infof("Targets update interval: %v", p.targetsUpdateInterval)

	return nil
}

func (p *Probe) GetName() string {
	return p.name
}

func (p *Probe) GetOpts() *options.Options {
	return p.opts
}

func (p *Probe) GetType() string {
	return "http"
}

func (p *Probe) Logger() *logrus.Entry {
	return p.logger
}

func relURLForTarget(path string) string {
	if path != "" {
		return path
	}

	return ""
}

func (p *Probe) Run(ctx context.Context, target endpoint.Endpoint, em *metrics.EventMetrics) (success bool, err error) {
	durationSeconds := metrics.NewMap("phase", metrics.NewFloat(0))
	contentLength := metrics.NewInt(0)
	uncompressedBodyLength := metrics.NewInt(0)
	redirects := metrics.NewInt(0)
	isSSL := metrics.NewInt(0)
	statusCode := metrics.NewInt(0)
	httpVersion := metrics.NewFloat(0)

	em.AddMetric("probe_http_duration_seconds", durationSeconds)
	em.AddMetric("probe_http_content_length", contentLength)
	em.AddMetric("probe_http_uncompressed_body_length", uncompressedBodyLength)
	em.AddMetric("probe_http_redirects", redirects)
	em.AddMetric("probe_http_ssl", isSSL)
	em.AddMetric("probe_http_status_code", statusCode)
	em.AddMetric("probe_http_version", httpVersion)

	logger := p.logger.WithField("target", target.Name)

	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)

	defer cancel()

	var baseURL string
	if target.Port != 0 {
		baseURL = fmt.Sprintf("%s://%s:%d", p.scheme, target.Name, target.Port)
	} else {
		baseURL = fmt.Sprintf("%s://%s", p.scheme, target.Name)
	}

	path := p.config.GetPath()
	if len(path) > 0 && path[0] != '/' {
		logger.Debugf("invalid path: %s, must begin with '/'", path)
		return
	}

	baseURL = fmt.Sprintf("%s%s", baseURL, relURLForTarget(p.config.GetPath()))

	em.AddLabel("url", baseURL)

	targetURL, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	targetHost := targetURL.Hostname()
	targetPort := targetURL.Port()

	resolved, err := p.resolveFn(ctx, targetHost)
	if err != nil {
		return
	}

	resolved.PopulateMetrics(em)
	resolvedIP := resolved.IP.String()
	durationSeconds.IncKeyBy("resolve", metrics.NewFloat(resolved.LookupTime))

	// Replace the host field in the URL with the IP we resolved.
	origHost := targetURL.Host

	if targetPort == "" {
		if strings.Contains(resolvedIP, ":") {
			targetURL.Host = "[" + resolvedIP + "]"
		} else {
			targetURL.Host = resolvedIP
		}
	} else {
		targetURL.Host = net.JoinHostPort(resolvedIP, targetPort)
	}

	req, err := newRequest(targetURL.String(), p.config)
	if err != nil {
		return
	}

	hostHeader, hasHostHeader := p.config.Headers["Host"]
	if !hasHostHeader {
		req.Host = origHost
	}

	transport, err := newHttpTransport(p.config)
	if err != nil {
		return
	}

	if transport.TLSClientConfig.ServerName == "" {
		if !hasHostHeader {
			// If there is no `server_name` in tls_config, use
			// the hostname of the target.
			transport.TLSClientConfig.ServerName = targetHost
		} else {
			// However, if there is a Host header it is better to use
			// its value instead. This helps avoid TLS handshake error
			// if targetHost is an IP address.
			transport.TLSClientConfig.ServerName = hostHeader
		}
	}

	traceableTransport := newTransport(transport, logger)

	client, err := newHttpClient(traceableTransport, p.config)
	if err != nil {
		return
	}

	traceCtx := traceableTransport.NewTraceContext(ctx)

	for _, phase := range []string{"connect", "tls", "processing", "transfer"} {
		durationSeconds.IncKeyBy(phase, metrics.NewFloat(0))
	}

	resp, err := client.Do(req.WithContext(traceCtx))
	// https://github.com/prometheus/blackbox_exporter/blob/master/prober/http.go#L454-L458
	// This is different from the usual err != nil you'd expect here because err won't be nil if redirects were
	// turned off. See https://github.com/golang/go/issues/3795
	//
	// If err == nil there should never be a case where resp is also nil, but better be safe than sorry, so check if
	// resp == nil first, and then check if there was an error.
	if resp == nil {
		resp = &http.Response{}
		if err != nil {
			logger.Debugf("HTTP request error: %v", err)
		}
	} else {
		requestErrored := (err != nil)

		logger.WithField("status_code", resp.StatusCode).Debug("Received HTTP response")

		// TODO add status code validation
		if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		}

		// TODO decompress if compression algorithm is specified

		bodySizeLimit, _ := units.ParseBase2Bytes(p.config.GetBodySizeLimit())
		if bodySizeLimit > 0 {
			resp.Body = http.MaxBytesReader(nil, resp.Body, int64(bodySizeLimit))
		}

		byteCounter := &byteCounter{ReadCloser: resp.Body}

		if !requestErrored {
			_, err = io.Copy(ioutil.Discard, byteCounter)
			if err != nil {
				logger.Debugf("Failed to read HTTP response body: %v", err)
				success = false
			}

			em.AddMetric("probe_http_uncompressed_body_length", metrics.NewInt(byteCounter.n))

			if err := byteCounter.Close(); err != nil {
				// We have already read everything we could from the server, maybe even uncompressed the
				// body. The error here might be either a decompression error or a TCP error. Log it in
				// case it contains useful information as to what's the problem.
				logger.Infof("Error while closing response from server: %v", err)
			}
		}

		// At this point body is fully read and we can write end time.
		traceableTransport.current.end = time.Now()

		// Check if there is a Last-Modified HTTP response header.
		if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err != nil {
			em.AddMetric("probe_http_last_modified_timestamp_seconds", metrics.NewInt(t.Unix()))
		}

		var httpVersionNumber float64
		httpVersionNumber, err = strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
		if err != nil {
			logger.Errorf("Cannot parse HTTP version: %v", err)
		}

		em.AddMetric("probe_http_version", metrics.NewFloat(httpVersionNumber))
	}

	traceableTransport.mu.Lock()
	defer traceableTransport.mu.Unlock()
	for i, trace := range traceableTransport.traces {
		if i != 0 {
			durationSeconds.IncKeyBy("resolve", metrics.NewFloat(trace.dnsDone.Sub(trace.start).Seconds()))
		}

		// Continue here if we never got a connection because a request failed.
		if trace.gotConn.IsZero() {
			continue
		}

		if trace.tls {
			// dnsDone must be set if gotConn was set.
			durationSeconds.IncKeyBy("connect", metrics.NewFloat(trace.connectDone.Sub(trace.dnsDone).Seconds()))
			durationSeconds.IncKeyBy("tls", metrics.NewFloat(trace.tlsDone.Sub(trace.tlsStart).Seconds()))
		} else {
			durationSeconds.IncKeyBy("connect", metrics.NewFloat(trace.gotConn.Sub(trace.dnsDone).Seconds()))
		}

		// Continue here if we never got a response from the server.
		if trace.responseStart.IsZero() {
			continue
		}

		durationSeconds.IncKeyBy("processing", metrics.NewFloat(trace.responseStart.Sub(trace.gotConn).Seconds()))

		// Continue here if we never read the full response from the server.
		// Usually this means that request either failed or was redirected.
		if trace.end.IsZero() {
			continue
		}

		durationSeconds.IncKeyBy("transfer", metrics.NewFloat(trace.end.Sub(trace.responseStart).Seconds()))
	}

	if resp.TLS != nil {
		tlsVersionInfo := metrics.NewMap("version", metrics.NewInt(0))
		tlsVersionInfo.IncKey(tls.GetTLSVersion(resp.TLS))

		sslLastChainInfo := metrics.NewMap("fingerprint_sha_256", metrics.NewInt(0))
		sslLastChainInfo.IncKey(tls.GetFingerprint(resp.TLS))

		isSSL.Inc()

		em.AddMetric("probe_ssl_earliest_cert_expiry", metrics.NewInt(tls.GetEarliestCertExpiry(resp.TLS).Unix()))
		em.AddMetric("probe_tls_version_info", tlsVersionInfo)
		em.AddMetric("probe_ssl_last_chain_expiry_timestamp_seconds", metrics.NewInt(tls.GetLastChainExpiry(resp.TLS).Unix()))
		em.AddMetric("probe_ssl_last_chain_info", sslLastChainInfo)
	}

	statusCode.IncBy(metrics.NewInt(int64(resp.StatusCode)))
	contentLength.IncBy(metrics.NewInt(resp.ContentLength))

	if !success {
		em.AddMetric("probe_error_message", metrics.NewString(resp.Status))
	}

	return
}

// updateTargetsAndStartProbes refreshes targets and starts probe loop for
// new targets and cancels probe loops for targets that are no longer active.
// Note that this function is not concurrency safe. It is never called
// concurrently by Start().
func (p *Probe) updateTargetsAndStartProbes(ctx context.Context, dataChan chan *metrics.EventMetrics) {
	p.targets = p.opts.Targets.ListEndpoints()

	p.logger.Debugf("Probe(%s) got %d targets", p.name, len(p.targets))

	// updatedTargets is used only for logging.
	updatedTargets := make(map[string]string)
	defer func() {
		if len(updatedTargets) > 0 {
			p.logger.Infof("Probe(%s) targets updated: %v", p.name, updatedTargets)
		}
	}()

	activeTargets := make(map[string]endpoint.Endpoint)
	for _, target := range p.targets {
		key := target.Key()
		activeTargets[key] = target
	}

	// Stop probing for deleted targets by invoking cancelFunc.
	for targetKey, cancelF := range p.cancelFuncs {
		if _, ok := activeTargets[targetKey]; ok {
			continue
		}
		cancelF()
		updatedTargets[targetKey] = "DELETE"
		delete(p.cancelFuncs, targetKey)
	}

	gapBetweenTargets := 10 * time.Millisecond
	var startWaitTime time.Duration

	// Start probe loop for new targets.
	for key, target := range activeTargets {
		// This target is already initialized.
		if _, ok := p.cancelFuncs[key]; ok {
			continue
		}
		updatedTargets[key] = "ADD"

		probeCtx, cancelF := context.WithCancel(ctx)
		p.waitGroup.Add(1)

		go func(target endpoint.Endpoint, waitTime time.Duration) {
			defer p.waitGroup.Done()
			// Wait for wait time + some jitter before starting this probe loop.
			time.Sleep(waitTime + time.Duration(rand.Int63n(gapBetweenTargets.Microseconds()/10))*time.Microsecond)
			probes.RunProbe(probeCtx, p, target, dataChan)
		}(target, startWaitTime)

		startWaitTime += gapBetweenTargets

		p.cancelFuncs[key] = cancelF
	}
}

// wait waits for child go-routines (one per target) to clean up.
func (p *Probe) wait() {
	p.waitGroup.Wait()
}

// Start starts and runs the probe indefinitely.
func (p *Probe) Start(ctx context.Context, dataChan chan *metrics.EventMetrics) {
	defer p.wait()

	p.updateTargetsAndStartProbes(ctx, dataChan)

	// Do more frequent listing of targets until we get a non-zero list of
	// targets.
	initialRefreshInterval := p.opts.Interval
	// Don't wait too long if p.opts.Interval is large.
	if initialRefreshInterval > time.Second {
		initialRefreshInterval = time.Second
	}

	for {
		if common.IsCtxDone(ctx) {
			return
		}
		if len(p.targets) != 0 {
			break
		}
		p.updateTargetsAndStartProbes(ctx, dataChan)
		time.Sleep(initialRefreshInterval)
	}

	targetsUpdateTicker := time.NewTicker(p.targetsUpdateInterval)
	defer targetsUpdateTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-targetsUpdateTicker.C:
			p.updateTargetsAndStartProbes(ctx, dataChan)
		}
	}
}
