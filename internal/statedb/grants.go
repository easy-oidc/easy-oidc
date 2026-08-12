// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/truster-dev/truster/internal/upstream"
)

const grantActionBatchSize = 5000

// ManagedGrant is non-secret grant metadata shown to its owner.
type ManagedGrant struct {
	SID, ClientID, Mode              string
	CreatedAt, LastUsedAt, ExpiresAt time.Time
}

// GrantAction binds a plaintext action token to one grant.
type GrantAction struct {
	Token string
	SID   string
}

// ListActiveGrants returns only active and unexpired grants for an exact normalized email.
func (s *Store) ListActiveGrants(email string, now time.Time) ([]ManagedGrant, error) {
	rows, err := s.db.Query(`SELECT sid,client_id,mode,created_at,last_used_at,idle_expires_at,absolute_expires_at FROM refresh_grants WHERE email=? AND revoked_at IS NULL AND idle_expires_at>? AND absolute_expires_at>? ORDER BY last_used_at DESC`, strings.ToLower(email), now, now)
	if err != nil {
		return nil, fmt.Errorf("list active grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var result []ManagedGrant
	for rows.Next() {
		var g ManagedGrant
		var idleExpiry, absoluteExpiry time.Time
		if err = rows.Scan(&g.SID, &g.ClientID, &g.Mode, &g.CreatedAt, &g.LastUsedAt, &idleExpiry, &absoluteExpiry); err != nil {
			return nil, fmt.Errorf("scan active grant: %w", err)
		}
		g.ExpiresAt = idleExpiry
		if absoluteExpiry.Before(g.ExpiresAt) {
			g.ExpiresAt = absoluteExpiry
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

// CreateGrantAction stores only a hash of a short-lived action token.
func (s *Store) CreateGrantAction(token, email, sid, action string, now, expiry time.Time) error {
	return s.CreateGrantActions([]GrantAction{{Token: token, SID: sid}}, email, action, now, expiry)
}

// CreateGrantActions stores hashes of short-lived action tokens in one operation.
func (s *Store) CreateGrantActions(actions []GrantAction, email, action string, now, expiry time.Time) error {
	email = strings.ToLower(email)
	for len(actions) != 0 {
		batch := min(len(actions), grantActionBatchSize)
		values := make([]string, batch)
		args := make([]any, 0, batch*6)
		for i, grant := range actions[:batch] {
			h := sha256.Sum256([]byte(grant.Token))
			values[i] = "(?,?,?,?,?,?)"
			args = append(args, h[:], email, grant.SID, action, now, expiry)
		}
		if _, err := s.db.Exec(`INSERT INTO grant_actions(action_hash,email,sid,action,created_at,expires_at) VALUES `+strings.Join(values, ","), args...); err != nil {
			return fmt.Errorf("create grant actions: %w", err)
		}
		actions = actions[batch:]
	}
	return nil
}

// ConsumeGrantActionAndRevoke atomically consumes a matching action and revokes its exact active grant.
func (s *Store) ConsumeGrantActionAndRevoke(token, email, sid, action string, now time.Time) error {
	h := sha256.Sum256([]byte(token))
	email = strings.ToLower(email)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin grant action: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	r, err := tx.Exec(`UPDATE refresh_grants SET revoked_at=?,revoke_reason='self_service'
		WHERE sid=? AND email=? AND revoked_at IS NULL AND idle_expires_at>? AND absolute_expires_at>?
		AND EXISTS (SELECT 1 FROM grant_actions WHERE action_hash=? AND email=? AND sid=? AND action=? AND expires_at>?)`,
		now, sid, email, now, now, h[:], email, sid, action, now)
	if err != nil {
		return fmt.Errorf("revoke managed grant: %w", err)
	}
	if affected, rowsErr := r.RowsAffected(); rowsErr != nil || affected != 1 {
		return ErrInvalidGrant
	}
	r, err = tx.Exec(`DELETE FROM grant_actions WHERE action_hash=?`, h[:])
	if err != nil {
		return fmt.Errorf("consume grant action: %w", err)
	}
	if affected, rowsErr := r.RowsAffected(); rowsErr != nil || affected != 1 {
		return ErrInvalidGrant
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit grant action: %w", err)
	}
	return nil
}

// CreateIdentitySelection stores identity assertions server-side behind an opaque token.
func (s *Store) CreateIdentitySelection(token, state, connector, subject string, emails []upstream.Email, expiry time.Time) error {
	h := sha256.Sum256([]byte(token))
	data, err := json.Marshal(emails)
	if err != nil {
		return fmt.Errorf("encode identity selection: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO identity_selections(token_hash,state_token,connector_id,subject,emails_json,expires_at) VALUES(?,?,?,?,?,?)`, h[:], state, connector, subject, data, expiry)
	if err != nil {
		return fmt.Errorf("create identity selection: %w", err)
	}
	return nil
}

// ConsumeIdentitySelection atomically consumes an unexpired opaque selection reference.
func (s *Store) ConsumeIdentitySelection(token string, now time.Time) (string, string, string, []upstream.Email, error) {
	h := sha256.Sum256([]byte(token))
	var state, connector, subject string
	var data []byte
	err := s.db.QueryRow(`DELETE FROM identity_selections WHERE token_hash=? AND expires_at>? RETURNING state_token,connector_id,subject,emails_json`, h[:], now).Scan(&state, &connector, &subject, &data)
	if err == sql.ErrNoRows {
		return "", "", "", nil, ErrInvalidGrant
	}
	if err != nil {
		return "", "", "", nil, fmt.Errorf("consume identity selection: %w", err)
	}
	var emails []upstream.Email
	if json.Unmarshal(data, &emails) != nil {
		return "", "", "", nil, ErrInvalidGrant
	}
	return state, connector, subject, emails, nil
}
