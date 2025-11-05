// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"log/slog"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
)

// Server implements the OpenID Connect server endpoints.
type Server struct {
	config        *config.Config
	connector     upstream.Connector
	authCodeMgr   *AuthCodeManager
	signer        *tokens.Signer
	groupResolver *tokens.GroupResolver
	jwksData      []byte
	logger        *slog.Logger
}

// NewServer creates a new OIDC server with the provided dependencies.
func NewServer(
	cfg *config.Config,
	connector upstream.Connector,
	authCodeMgr *AuthCodeManager,
	signer *tokens.Signer,
	groupResolver *tokens.GroupResolver,
	jwksData []byte,
	logger *slog.Logger,
) *Server {
	return &Server{
		config:        cfg,
		connector:     connector,
		authCodeMgr:   authCodeMgr,
		signer:        signer,
		groupResolver: groupResolver,
		jwksData:      jwksData,
		logger:        logger,
	}
}

func (s *Server) isValidRedirectURI(uri string, client config.ClientConfig) bool {
	redirectURIs := client.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = s.config.DefaultRedirectURIs
	}

	for _, allowed := range redirectURIs {
		if uri == allowed {
			return true
		}
	}

	return false
}
