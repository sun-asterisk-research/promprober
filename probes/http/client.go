package http

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/sun-asterisk-research/cloudprober/common/tls"
	configpb "github.com/sun-asterisk-research/cloudprober/probes/http/proto"
	"golang.org/x/net/http2"
	"golang.org/x/net/publicsuffix"
)

func newHttpClient(transport http.RoundTripper, httpConfig *configpb.ProbeConf) (*http.Client, error) {
	client := &http.Client{
		Transport: transport,
	}

	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if !httpConfig.GetFollowRedirects() || len(via) > 10 {
			return http.ErrUseLastResponse
		}

		return nil
	}

	// cookiejar for redirects that require cookies
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	client.Jar = jar

	return client, nil
}

func newHttpTransport(httpConfig *configpb.ProbeConf) (*http.Transport, error) {
	tlsConfig, err := tls.NewTLSConfig(httpConfig.TlsConfig)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		MaxIdleConns:          20000,
		MaxIdleConnsPerHost:   1000,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	proxyUrl := httpConfig.GetProxyUrl()
	if proxyUrl != "" {
		url, err := url.Parse(proxyUrl)
		if err != nil {
			return nil, fmt.Errorf("error parsing proxy URL (%s): %v", proxyUrl, err)
		}
		transport.Proxy = http.ProxyURL(url)
	}

	if httpConfig.GetEnableHttp2() {
		http2t, err := http2.ConfigureTransports(transport)
		if err != nil {
			return nil, err
		}

		http2t.ReadIdleTimeout = time.Minute
	}

	return transport, nil
}
