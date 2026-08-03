// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0
package oidc

import (
	"context"
	"log/slog"

	"github.com/easy-oidc/easy-oidc/internal/authpolicy"
	"github.com/easy-oidc/easy-oidc/internal/challenge"
	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/email"
	"github.com/easy-oidc/easy-oidc/internal/refresh"
	"github.com/easy-oidc/easy-oidc/internal/statedb"
	"github.com/easy-oidc/easy-oidc/internal/templates"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/easy-oidc/easy-oidc/internal/trust"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
)

// policyResolver defines the policy decisions consumed by the OIDC server and its services.
type policyResolver interface {
	ResolveClient(context.Context, string, bool) (authpolicy.ResolvedClient, error)
	ResolveUser(context.Context, authpolicy.ResolvedClient, string) (authpolicy.ResolvedUser, error)
	ResolveTrust(context.Context, authpolicy.ResolvedClient, string) ([]config.EffectiveTrustBinding, error)
}

type Server struct {
	config         *config.Config
	connectors     map[string]upstream.Connector
	authCodeMgr    *AuthCodeManager
	signer         *tokens.Signer
	jwksData       []byte
	logger         *slog.Logger
	store          *statedb.Store
	templates      *templates.Manager
	mailer         email.Sender
	challenge      challenge.Verifier
	otpSecret      []byte
	selectionKey   []byte
	encryptionKey  []byte
	refresh        *refresh.Service
	trust          *trust.Service
	policyResolver policyResolver
}

// NewServer creates an OIDC server with the provided dependencies.
func NewServer(cfg *config.Config, connectors map[string]upstream.Connector, authCodeMgr *AuthCodeManager, signer *tokens.Signer, jwksData []byte, logger *slog.Logger, store *statedb.Store, tm *templates.Manager, mailer email.Sender, challengeVerifier challenge.Verifier, otpSecret, selectionKey, encryptionKey []byte, resolver policyResolver) *Server {
	if resolver == nil {
		resolver = authpolicy.NewResolver(cfg, nil)
	}
	return &Server{config: cfg, connectors: connectors, authCodeMgr: authCodeMgr, signer: signer, jwksData: jwksData, logger: logger, store: store, templates: tm, mailer: mailer, challenge: challengeVerifier, otpSecret: otpSecret, selectionKey: selectionKey, encryptionKey: encryptionKey, policyResolver: resolver, refresh: refresh.NewService(cfg, store, signer, connectors, logger, resolver), trust: trust.NewService(cfg, resolver)}
}
func (s *Server) isValidRedirectURI(uri string, client config.ClientConfig) bool {
	uris := client.RedirectURIs
	if len(uris) == 0 {
		uris = s.config.DefaultRedirectURIs
	}
	for _, allowed := range uris {
		if uri == allowed {
			return true
		}
	}
	return false
}
