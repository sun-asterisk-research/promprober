package common

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"time"

	"github.com/cloudprober/cloudprober/metrics"
	"github.com/sirupsen/logrus"
)

var protocolVersions = map[string]int64{
	"ip4": 4,
	"ip6": 6,
}

type ResolveResult struct {
	IP              *net.IPAddr
	IPHash          float64
	ProtocolVersion int64
	LookupTime      float64
}

func (r *ResolveResult) PopulateMetrics(em *metrics.EventMetrics) {
	em.AddMetric("probe_dns_lookup_time_seconds", metrics.NewFloat(r.LookupTime))
	em.AddMetric("probe_ip_protocol", metrics.NewInt(r.ProtocolVersion))
	em.AddMetric("probe_ip_addr_hash", metrics.NewFloat(r.IPHash))
}

type Resolver struct {
	ipProtocol       string
	fallbackProtocol string
	logger           *logrus.Entry
}

func NewResolver(protocol string, logger *logrus.Entry) Resolver {
	resolver := Resolver{}

	if protocol == "ip6" || protocol == "" {
		resolver.ipProtocol = "ip6"
		resolver.fallbackProtocol = "ip4"
	} else {
		resolver.ipProtocol = "ip4"
		resolver.fallbackProtocol = "ip6"
	}

	if logger == nil {
		logger = logrus.NewEntry(logrus.StandardLogger())
	}

	resolver.logger = logger.WithField("protocol", resolver.ipProtocol)

	return resolver
}

func (r *Resolver) ResolveTarget(ctx context.Context, target string) (result ResolveResult, err error) {
	resolveStart := time.Now()

	defer func() {
		result.LookupTime = time.Since(resolveStart).Seconds()
	}()

	resolver := &net.Resolver{}
	logger := r.logger.WithFields(logrus.Fields{
		"target": target,
		"strict": false,
	})

	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		logger.Error("Could not resolve target")
		return
	}

	// Return the IP in the requested protocol.
	var fallback *net.IPAddr
	for _, ip := range ips {
		switch r.ipProtocol {
		case "ip4":
			if ip.IP.To4() != nil {
				result.IP = &ip
				result.IPHash = ipHash(ip.IP)
				result.ProtocolVersion = 4

				logger.Debugf("Resolved IP: %s", ip.String())

				return
			}

			// ip4 as fallback
			fallback = &ip

		case "ip6":
			if ip.IP.To4() == nil {
				result.IP = &ip
				result.IPHash = ipHash(ip.IP)
				result.ProtocolVersion = 6

				logger.Debugf("Resolved IP: %s", ip.String())

				return
			}

			// ip6 as fallback
			fallback = &ip
		}
	}

	// Unable to find ip and no fallback set.
	if fallback == nil {
		err = fmt.Errorf("unable to resolve IP, no fallback available")

		return
	}

	// Use fallback ip protocol.
	if r.fallbackProtocol == "ip4" {
		result.ProtocolVersion = 4
	} else {
		result.ProtocolVersion = 6
	}

	result.IPHash = ipHash(fallback.IP)

	return
}

func (r *Resolver) ResolveTargetStrict(ctx context.Context, target string) (result ResolveResult, err error) {
	resolveStart := time.Now()

	resolver := &net.Resolver{}
	logger := r.logger.WithFields(logrus.Fields{
		"target": target,
		"strict": true,
	})

	ips, err := resolver.LookupIP(ctx, r.ipProtocol, target)
	if err == nil {
		for _, ip := range ips {
			result.IP = &net.IPAddr{IP: ip}
			result.IPHash = ipHash(ip)
			result.ProtocolVersion = protocolVersions[r.ipProtocol]
			result.LookupTime = time.Since(resolveStart).Seconds()

			logger.Debugf("Resolved IP: %s", ip.String())

			return
		}
	}

	r.logger.Error("Could not resolve target")

	return
}

func ipHash(ip net.IP) float64 {
	h := fnv.New32a()
	if ip.To4() != nil {
		h.Write(ip.To4())
	} else {
		h.Write(ip.To16())
	}
	return float64(h.Sum32())
}
