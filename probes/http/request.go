package http

import (
	"io"
	"net/http"
	"strings"

	configpb "github.com/sun-asterisk-research/cloudprober/probes/http/proto"
)

// byteCounter implements an io.ReadCloser that keeps track of the total
// number of bytes it has read.
type byteCounter struct {
	io.ReadCloser
	n int64
}

func (bc *byteCounter) Read(p []byte) (int, error) {
	n, err := bc.ReadCloser.Read(p)
	bc.n += int64(n)
	return n, err
}

var userAgentDefaultHeader = "Cloudprober"

// https://github.com/prometheus/blackbox_exporter/blob/master/prober/http.go#L395-L405
func newRequest(target string, httpConfig *configpb.ProbeConf) (*http.Request, error) {
	body := strings.NewReader(httpConfig.GetBody())

	req, err := http.NewRequest(httpConfig.GetMethod().String(), target, body)
	if err != nil {
		return nil, err
	}

	for key, value := range httpConfig.Headers {
		if strings.Title(key) == "Host" {
			req.Host = value
		} else {
			req.Header.Set(key, value)
		}
	}

	_, hasUserAgent := req.Header["User-Agent"]
	if !hasUserAgent {
		req.Header.Set("User-Agent", userAgentDefaultHeader)
	}

	return req, nil
}
