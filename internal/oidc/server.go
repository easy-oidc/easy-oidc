// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0
package oidc

import (
	"github.com/easy-oidc/easy-oidc/internal/challenge"
	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/email"
	"github.com/easy-oidc/easy-oidc/internal/storage"
	"github.com/easy-oidc/easy-oidc/internal/templates"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
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
}

// NewServer creates an OIDC server with the provided dependencies.
func NewServer(cfg *config.Config, connectors map[string]upstream.Connector, authCodeMgr *AuthCodeManager, signer *tokens.Signer, groupResolver *tokens.GroupResolver, jwksData []byte, logger *slog.Logger, store *storage.Store, tm *templates.Manager, mailer email.Sender, challengeVerifier challenge.Verifier, otpSecret, selectionKey []byte) *Server {
	return &Server{cfg, connectors, authCodeMgr, signer, groupResolver, jwksData, logger, store, tm, mailer, challengeVerifier, otpSecret, selectionKey}
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
