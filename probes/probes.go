package probes

import (
	"context"
	"strconv"
	"time"

	"github.com/cloudprober/cloudprober/metrics"
	"github.com/cloudprober/cloudprober/probes/options"
	"github.com/cloudprober/cloudprober/targets/endpoint"
	"github.com/sirupsen/logrus"
	"github.com/sun-asterisk-research/promprober/common"
)

type Probe interface {
	GetName() string
	GetOpts() *options.Options
	GetType() string
	Logger() *logrus.Entry
	Run(ctx context.Context, target endpoint.Endpoint, em *metrics.EventMetrics) (success bool, err error)
}

func RunProbe(ctx context.Context, p Probe, target endpoint.Endpoint, dataChan chan *metrics.EventMetrics) {
	opts := p.GetOpts()
	logger := p.Logger()

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	var latencyDist metrics.Value
	if opts.LatencyDist != nil {
		latencyDist = opts.LatencyDist.Clone()
	}

	for ts := time.Now(); true; ts = <-ticker.C {
		// Don't run another probe if context is canceled already.
		if common.IsCtxDone(ctx) {
			return
		}

		em := metrics.NewEventMetrics(ts)

		em.Kind = metrics.GAUGE
		em.LatencyUnit = opts.LatencyUnit
		em.AddLabel("probe", p.GetType())
		em.AddLabel("target", p.GetName())

		var apdexT float64

		for _, label := range opts.AdditionalLabels {
			label, value := label.KeyValueForTarget(target.Name)
			if label == "apdex_t" {
				apdexT, _ = strconv.ParseFloat(value, 64)
			}

			em.AddLabel(label, value)
		}

		logger.Debug("Starting probe")

		start := time.Now()

		success, err := p.Run(ctx, target, em)
		if err == nil {
			if success {
				em.AddMetric("probe_success", metrics.NewInt(1))
				logger.Info("Probe succeeded")
			} else {
				em.AddMetric("probe_success", metrics.NewInt(0))
				logger.Info("Probe failed")
			}
		} else {
			em.AddMetric("probe_success", metrics.NewInt(0))
			logger.Infof("Probe failed: %v", err)
		}

		em.AddMetric("probe_duration_seconds", metrics.NewFloat(time.Since(start).Seconds()))

		if latencyDist != nil {
			em.AddMetric("latency", latencyDist)
			latencyDist.AddFloat64(time.Since(start).Seconds())

			if apdexT > 0 {
				addMetricsApdex(apdexT, latencyDist.String(), em)
			}
		}

		opts.LogMetrics(em)

		dataChan <- em
	}
}

func addMetricsApdex(apdexT float64, latencyDist string, em *metrics.EventMetrics) {
	var parseLatencyDist *metrics.Distribution
	parseLatencyDist, err := metrics.ParseDistFromString(latencyDist)
	if err != nil {
		return
	}

	var satisfied int64
	var tolerating int64

	bucketCounts := parseLatencyDist.Data().BucketCounts
	lowerBounds := parseLatencyDist.Data().LowerBounds

	for i, value := range bucketCounts {
		if i != (len(bucketCounts)-1) && lowerBounds[i+1] <= apdexT {
			satisfied += value
			tolerating = satisfied
		}
		if i != (len(bucketCounts)-1) && lowerBounds[i+1] > apdexT && lowerBounds[i+1] <= 4*apdexT {
			tolerating += value
		}
	}

	em.AddMetric("probe_latency_satisfied", metrics.NewInt(satisfied))
	em.AddMetric("probe_latency_tolerating", metrics.NewInt(tolerating))
}
