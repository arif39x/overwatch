package scannerengine

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
)

// InsecureTransport returns an HTTP client that skips TLS verification.
// Used only for development environments with self-signed certificates.
func InsecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// CertsTransport returns an HTTP transport configured with the given CA cert.
func CertsTransport(caCertPath string) (*http.Transport, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}, nil
}
