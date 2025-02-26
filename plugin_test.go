package clientauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWithoutClientCertificate(t *testing.T) {
	certs, err := createCerts(time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	ca := &ClientAuth{
		next:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		clientCAs: x509.NewCertPool(),
	}

	svr := httptest.NewUnstartedServer(ca)
	svr.TLS = certs.serverTlsConfig
	svr.StartTLS()

	defer svr.Close()

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certs.cas,
			},
		},
	}
	resp, err := client.Get(svr.URL)
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status code to be %d got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	msgBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	expectedMsg := "Client certificate is required for authentication."
	msg := strings.TrimSpace(string(msgBytes))
	if msg != expectedMsg {
		t.Errorf("expected body to be '%s' got '%s'", expectedMsg, msg)
	}
}

func TestWithClientCertificate(t *testing.T) {
	certs, err := createCerts(time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	ca := &ClientAuth{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		clientCAs: certs.cas,
	}

	svr := httptest.NewUnstartedServer(ca)
	svr.TLS = certs.serverTlsConfig
	svr.StartTLS()

	defer svr.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      certs.cas,
			Certificates: []tls.Certificate{certs.clientKeyPair},
		},
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{certs.clientKeyPair}
	client := http.Client{
		Transport: transport,
	}
	resp, err := client.Get(svr.URL)
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code to be %d got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestWithInvalidClientCertificate(t *testing.T) {
	certs, err := createCerts(time.Now().AddDate(-1, 0, 0))
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	ca := &ClientAuth{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		clientCAs: certs.cas,
	}

	svr := httptest.NewUnstartedServer(ca)
	svr.TLS = certs.serverTlsConfig
	svr.StartTLS()

	defer svr.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      certs.cas,
			Certificates: []tls.Certificate{certs.clientKeyPair},
		},
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{certs.clientKeyPair}
	client := http.Client{
		Transport: transport,
	}
	resp, err := client.Get(svr.URL)
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status code to be %d got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	msgBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("expected err to be nil got %v", err)
	}

	expectedMsg := "Failed to verify client certificate."
	msg := strings.TrimSpace(string(msgBytes))
	if msg != expectedMsg {
		t.Errorf("expected body to be '%s' got '%s'", expectedMsg, msg)
	}
}

type certs struct {
	cas             *x509.CertPool
	serverTlsConfig *tls.Config
	clientKeyPair   tls.Certificate
}

func createCerts(clientNotAfter time.Time) (*certs, error) {
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now().AddDate(-5, 0, 0),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Server Cert",
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now().AddDate(-4, 0, 0),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	serverBytes, err := x509.CreateCertificate(rand.Reader, serverCert, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	serverPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})

	serverPEM := new(bytes.Buffer)
	pem.Encode(serverPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverBytes,
	})

	serverKeyPair, err := tls.X509KeyPair(serverPEM.Bytes(), serverPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Client Cert",
		},
		NotBefore:   time.Now().AddDate(-2, 0, 0),
		NotAfter:    clientNotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, clientCert, caCert, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	clientPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(clientPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey),
	})

	clientPEM := new(bytes.Buffer)
	pem.Encode(clientPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientBytes,
	})

	clientKeyPair, err := tls.X509KeyPair(clientPEM.Bytes(), clientPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	cas := x509.NewCertPool()
	cas.AppendCertsFromPEM(caPEM.Bytes())

	serverTlsConfig := &tls.Config{
		ClientAuth:   tls.RequestClientCert,
		Certificates: []tls.Certificate{serverKeyPair},
	}

	return &certs{
		cas:             cas,
		serverTlsConfig: serverTlsConfig,
		clientKeyPair:   clientKeyPair,
	}, nil
}
