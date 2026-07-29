// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0
package oidc

import (
	"github.com/easy-oidc/easy-oidc/internal/challenge"
	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/email"
	"github.com/easy-oidc/easy-oidc/internal/refresh"
	"github.com/easy-oidc/easy-oidc/internal/storage"
	"github.com/easy-oidc/easy-oidc/internal/templates"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/easy-oidc/easy-oidc/internal/trust"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
	"log/slog"
)

type Server struct {
	config        *config.Config
	connectors    map[string]upstream.Connector
	authCodeMgr   *AuthCodeManager
	signer        *tokens.Signer
	groupResolver *tokens.GroupResolver
	jwksData      []byte
	logger        *slog.Logger
	store         *storage.Store
	templates     *templates.Manager
	mailer        email.Sender
	challenge     challenge.Verifier
	otpSecret     []byte
	selectionKey  []byte
	encryptionKey []byte
	refresh       *refresh.Service
	trust         *trust.Service
}

// NewServer creates an OIDC server with the provided dependencies.
func NewServer(cfg *config.Config, connectors map[string]upstream.Connector, authCodeMgr *AuthCodeManager, signer *tokens.Signer, groupResolver *tokens.GroupResolver, jwksData []byte, logger *slog.Logger, store *storage.Store, tm *templates.Manager, mailer email.Sender, challengeVerifier challenge.Verifier, otpSecret, selectionKey, encryptionKey []byte) *Server {
	return &Server{config: cfg, connectors: connectors, authCodeMgr: authCodeMgr, signer: signer, groupResolver: groupResolver, jwksData: jwksData, logger: logger, store: store, templates: tm, mailer: mailer, challenge: challengeVerifier, otpSecret: otpSecret, selectionKey: selectionKey, encryptionKey: encryptionKey, refresh: refresh.NewService(cfg, store, signer, groupResolver, connectors, logger), trust: trust.NewService(cfg)}
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
