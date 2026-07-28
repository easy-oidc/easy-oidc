// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/storage"
)

// OAuthState represents the OAuth2 state parameter data.
// It contains client information and PKCE details that need to be preserved across the OAuth flow.
type OAuthState struct {
	ConnectorID   string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Nonce         string
	OIDCState     string
}

// EncodeState creates a new random state token and stores the OAuth state data.
// The token expires in 10 minutes and is used to prevent CSRF attacks.
func (m *AuthCodeManager) EncodeState(state OAuthState) (string, error) {
	stateToken, err := storage.GenerateStateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	now := time.Now()
	oauthState := &storage.OAuthState{
		StateToken:    stateToken,
		ClientID:      state.ClientID,
		RedirectURI:   state.RedirectURI,
		CodeChallenge: state.CodeChallenge,
		Nonce:         state.Nonce,
		OIDCState:     state.OIDCState,
		CreatedAt:     now,
		ExpiresAt:     now.Add(10 * time.Minute),
		ConnectorID:   state.ConnectorID,
	}

	if err := m.store.SaveState(oauthState); err != nil {
		return "", fmt.Errorf("failed to save state: %w", err)
	}

	return stateToken, nil
}

// DecodeState validates and retrieves a state token, extracting the OAuth state data.
// The state token is atomically retrieved and deleted to enforce single-use and prevent replay attacks.
func (m *AuthCodeManager) DecodeState(stateToken string) (*OAuthState, error) {
	storedState, err := m.store.GetAndDeleteState(stateToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state token: %w", err)
	}
	return oauthStateFromStored(storedState), nil
}

// PeekState validates and retrieves a state token without consuming it.
func (m *AuthCodeManager) PeekState(stateToken string) (*OAuthState, error) {
	storedState, err := m.store.PeekState(stateToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state token: %w", err)
	}
	return oauthStateFromStored(storedState), nil
}

// oauthStateFromStored converts a persisted state to its OIDC representation.
func oauthStateFromStored(storedState *storage.OAuthState) *OAuthState {
	return &OAuthState{ClientID: storedState.ClientID, RedirectURI: storedState.RedirectURI, CodeChallenge: storedState.CodeChallenge, Nonce: storedState.Nonce, OIDCState: storedState.OIDCState, ConnectorID: storedState.ConnectorID}
}
