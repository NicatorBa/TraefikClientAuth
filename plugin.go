package clientauth

import (
	"context"
	"crypto/x509"
	"net/http"
	"os"
	"time"
)

type Config struct {
	CAFiles []string `json:"caFiles"`
}

func CreateConfig() *Config {
	return &Config{}
}

type ClientAuth struct {
	next      http.Handler
	name      string
	clientCAs *x509.CertPool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	ca := &ClientAuth{
		next:      next,
		name:      name,
		clientCAs: x509.NewCertPool(),
	}

	for _, caFile := range config.CAFiles {
		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}

		ca.clientCAs.AppendCertsFromPEM(caBytes)
	}

	return ca, nil
}

func (ca *ClientAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate is required for authentication.", http.StatusUnauthorized)
		return
	}

	clientCert := r.TLS.PeerCertificates[0]

	opts := x509.VerifyOptions{
		Roots:         ca.clientCAs,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, cert := range r.TLS.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	chains, err := clientCert.Verify(opts)
	if err != nil {
		http.Error(w, "Failed to verify client certificate.", http.StatusUnauthorized)
		return
	}

	r.TLS.VerifiedChains = chains

	ca.next.ServeHTTP(w, r)
}
