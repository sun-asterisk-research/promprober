package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"time"

	configpb "github.com/sun-asterisk-research/promprober/common/tls/proto"
)

func NewTLSConfig(cfg *configpb.TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.GetInsecureSkipVerify(),
	}

	caFile := cfg.GetCaFile()
	certFile := cfg.GetCertFile()
	keyFile := cfg.GetKeyFile()
	serverName := cfg.GetServerName()

	// If a CA cert is provided then let's read it in so we can validate the scrape target's certificate properly.
	if caFile != "" {
		data, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("unable to load specified CA cert %s: %s", caFile, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("unable to use specified CA cert %s", caFile)
		}

		tlsConfig.RootCAs = caCertPool
	}

	if serverName != "" {
		tlsConfig.ServerName = serverName
	}

	// If a client cert & key is provided then configure TLS config accordingly.
	if len(certFile) > 0 && len(keyFile) == 0 {
		return nil, fmt.Errorf("client cert file %q specified without client key file", certFile)
	} else if len(keyFile) > 0 && len(certFile) == 0 {
		return nil, fmt.Errorf("client key file %q specified without client cert file", keyFile)
	} else if len(certFile) > 0 && len(keyFile) > 0 {
		getClientCertificate := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				return &cert, nil
			} else {
				return nil, fmt.Errorf("unable to use specified client cert (%s) & key (%s): %s", certFile, keyFile, err)
			}
		}

		// Verify that client cert and key are valid.
		if _, err := getClientCertificate(nil); err != nil {
			return nil, err
		}

		tlsConfig.GetClientCertificate = getClientCertificate
	}

	return tlsConfig, nil
}

func GetEarliestCertExpiry(state *tls.ConnectionState) time.Time {
	earliest := time.Time{}
	for _, cert := range state.PeerCertificates {
		if (earliest.IsZero() || cert.NotAfter.Before(earliest)) && !cert.NotAfter.IsZero() {
			earliest = cert.NotAfter
		}
	}
	return earliest
}

func GetFingerprint(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

func GetLastChainExpiry(state *tls.ConnectionState) time.Time {
	lastChainExpiry := time.Time{}
	for _, chain := range state.VerifiedChains {
		earliestCertExpiry := time.Time{}
		for _, cert := range chain {
			if (earliestCertExpiry.IsZero() || cert.NotAfter.Before(earliestCertExpiry)) && !cert.NotAfter.IsZero() {
				earliestCertExpiry = cert.NotAfter
			}
		}
		if lastChainExpiry.IsZero() || lastChainExpiry.Before(earliestCertExpiry) {
			lastChainExpiry = earliestCertExpiry
		}

	}
	return lastChainExpiry
}

func GetTLSVersion(state *tls.ConnectionState) string {
	switch state.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
