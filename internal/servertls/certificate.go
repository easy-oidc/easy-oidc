// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package servertls

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"
)

const reloadInterval = time.Minute

// Load loads a TLS certificate and reloads it until ctx is cancelled.
func Load(ctx context.Context, certificateFile, privateKeyFile string, logger *slog.Logger) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load serving certificate: %w", err)
	}

	var current atomic.Pointer[tls.Certificate]
	current.Store(&certificate)

	go func() {
		ticker := time.NewTicker(reloadInterval)
		defer ticker.Stop()
		reload(ctx, ticker.C, certificateFile, privateKeyFile, logger, &current)
	}()

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return current.Load(), nil
		},
	}, nil
}

// reload replaces the current certificate whenever the files contain a new valid pair.
func reload(ctx context.Context, ticks <-chan time.Time, certificateFile, privateKeyFile string, logger *slog.Logger, current *atomic.Pointer[tls.Certificate]) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			replacement, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
			if err != nil {
				logger.Error("failed to reload serving certificate; retaining last valid certificate", "error", err)
				continue
			}
			if slices.EqualFunc(current.Load().Certificate, replacement.Certificate, bytes.Equal) {
				continue
			}
			current.Store(&replacement)
			logger.Info("reloaded serving certificate")
		}
	}
}
