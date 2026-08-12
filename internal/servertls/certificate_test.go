// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package servertls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestInitialLoad validates good, malformed, and mismatched initial pairs.
func TestInitialLoad(t *testing.T) {
	dir := t.TempDir()
	cert1, key1 := writeCertificatePair(t, dir, 1)
	_, key2 := writeCertificatePair(t, t.TempDir(), 2)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := Load(t.Context(), cert1, key1, logger); err != nil {
		t.Fatalf("load valid pair: %v", err)
	}
	if _, err := Load(t.Context(), cert1, key2, logger); err == nil {
		t.Fatal("accepted mismatched pair")
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(t.Context(), bad, key1, logger); err == nil {
		t.Fatal("accepted malformed certificate")
	}
}

// TestReload verifies replacement and last-known-good behavior through a TLS listener.
func TestReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertificatePair(t, dir, 1)
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[tls.Certificate]
	current.Store(&certificate)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return current.Load(), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ticks := make(chan time.Time)
	go reload(ctx, ticks, certPath, keyPath, slog.New(slog.NewTextHandler(io.Discard, nil)), &current)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go acceptTLSConnections(listener)
	if serial := presentedSerial(t, listener.Addr().String()); serial != 1 {
		t.Fatalf("initial serial = %d", serial)
	}
	replacementCert, replacementKey := writeCertificatePair(t, t.TempDir(), 2)
	copyFile(t, replacementCert, certPath)
	copyFile(t, replacementKey, keyPath)
	ticks <- time.Now()
	waitForSerial(t, listener.Addr().String(), 2)
	if err := os.WriteFile(keyPath, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	ticks <- time.Now()
	time.Sleep(10 * time.Millisecond)
	if serial := presentedSerial(t, listener.Addr().String()); serial != 2 {
		t.Fatalf("serial after invalid replacement = %d, want 2", serial)
	}
}

// acceptTLSConnections completes handshakes until the listener closes.
func acceptTLSConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}()
	}
}

// presentedSerial returns the certificate serial currently served by address.
func presentedSerial(t *testing.T, address string) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // Test inspects self-signed certificates.
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

// waitForSerial waits for the periodic reloader to present serial.
func waitForSerial(t *testing.T, address string, serial int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if presentedSerial(t, address) == serial {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("certificate serial did not become %d", serial)
}

// writeCertificatePair generates and writes a self-signed certificate pair.
func writeCertificatePair(t *testing.T, dir string, serial int64) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// copyFile replaces dst with the contents of src.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatal(err)
	}
}
