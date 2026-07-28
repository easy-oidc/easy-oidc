// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/storage"
)

// AuthCodeManager handles the creation and validation of authorization codes using SQLite storage.
// It provides replay protection through single-use enforcement and automatic cleanup of expired codes.
type AuthCodeManager struct {
	store *storage.Store
}

// AuthCodePayload contains the information embedded in an authorization code.
type AuthCodePayload struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Email         string
	EmailVerified bool
	Nonce         string
}

// NewAuthCodeManager creates and initializes a new authorization code manager with SQLite storage.
func NewAuthCodeManager(store *storage.Store) (*AuthCodeManager, error) {
	mgr := &AuthCodeManager{
		store: store,
	}

	return mgr, nil
}

// GenerateCode creates a new authorization code containing the provided payload.
// The code is a cryptographically secure random token that expires in 5 minutes.
func (m *AuthCodeManager) GenerateCode(payload AuthCodePayload) (string, error) {
	code, err := storage.GenerateAuthCode()
	if err != nil {
		return "", fmt.Errorf("failed to generate auth code: %w", err)
	}

	now := time.Now()
	authCode := &storage.AuthCode{
		Code:          code,
		ClientID:      payload.ClientID,
		RedirectURI:   payload.RedirectURI,
		CodeChallenge: payload.CodeChallenge,
		Email:         payload.Email,
		EmailVerified: payload.EmailVerified,
		Nonce:         payload.Nonce,
		CreatedAt:     now,
		ExpiresAt:     now.Add(5 * time.Minute),
	}

	if err := m.store.SaveAuthCode(authCode); err != nil {
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}

	return code, nil
}

// ValidateAndExtract validates an authorization code and extracts its payload.
// The code is atomically retrieved and deleted to enforce single-use.
func (m *AuthCodeManager) ValidateAndExtract(code string) (*AuthCodePayload, error) {
	authCode, err := m.store.GetAndDeleteAuthCode(code)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired authorization code: %w", err)
	}

	payload := &AuthCodePayload{
		ClientID:      authCode.ClientID,
		RedirectURI:   authCode.RedirectURI,
		CodeChallenge: authCode.CodeChallenge,
		Email:         authCode.Email,
		EmailVerified: authCode.EmailVerified,
		Nonce:         authCode.Nonce,
	}

	return payload, nil
}
