// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkPostgreSQLAuthorizationCodeGrant measures code consumption and initial grant creation.
func BenchmarkPostgreSQLAuthorizationCodeGrant(b *testing.B) {
	store, _ := postgreSQLStores(b)
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		now := time.Now().UTC()
		id := fmt.Sprintf("bench-code-%d", i)
		code := AuthCode{Code: id, ClientID: "bench-client", RedirectURI: "https://client.example/cb", CodeChallenge: "challenge", Email: "bench@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Scopes: "openid offline_access", RefreshMode: "session", AuthTime: now}
		material, err := GenerateRefreshMaterial()
		if err != nil {
			b.Fatal(err)
		}
		grant := RefreshGrant{SID: id, ClientID: code.ClientID, Email: code.Email, Scopes: code.Scopes, Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(24 * time.Hour)}
		if err = store.SaveAuthCode(&code); err != nil {
			b.Fatal(err)
		}
		expected, err := store.PeekAuthCode(code.Code, now)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		err = store.ConsumeAuthCode(*expected, AuthCodeBinding{ClientID: code.ClientID, RedirectURI: code.RedirectURI, CodeChallenge: code.CodeChallenge}, &grant, material, now)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPostgreSQLDirectRefreshRotation measures atomic downstream token rotation.
func BenchmarkPostgreSQLDirectRefreshRotation(b *testing.B) {
	store, _ := postgreSQLStores(b)
	b.StopTimer()
	now := time.Now().UTC()
	current, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "bench-direct", ClientID: "bench-client", Email: "bench@example.com", Scopes: "openid", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(24 * time.Hour)}
	if err := store.CreateRefreshGrant(grant, current, nil, nil, now); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		next, err := GenerateRefreshMaterial()
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		_, _, err = store.RotateRefreshToken(current, next, grant.ClientID, now.Add(time.Duration(i+1)*time.Millisecond))
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		current = next
	}
}

// BenchmarkPostgreSQLClaimedRefreshCompletion measures claim fencing and completion.
func BenchmarkPostgreSQLClaimedRefreshCompletion(b *testing.B) {
	store, _ := postgreSQLStores(b)
	b.StopTimer()
	now := time.Now().UTC()
	current, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "bench-claimed", ClientID: "bench-client", Email: "bench@example.com", Scopes: "openid", ConnectorID: "provider", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(24 * time.Hour)}
	if err := store.CreateRefreshGrant(grant, current, []byte{1}, []byte{2}, now); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		at := now.Add(time.Duration(i+1) * time.Millisecond)
		claimed, claim, _, err := store.ClaimRefresh(current, grant.ClientID, at, time.Minute)
		if err != nil {
			b.Fatal(err)
		}
		next, _ := GenerateRefreshMaterial()
		b.StartTimer()
		_, err = store.CompleteClaimedRefresh(current, next, claimed, claim, []byte{3}, []byte{4}, grant.AbsoluteExpiry, at)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		current = next
	}
}

// BenchmarkPostgreSQLBoundedCleanup measures one bounded expired-row cleanup pass.
func BenchmarkPostgreSQLBoundedCleanup(b *testing.B) {
	store, _ := postgreSQLStores(b)
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		now := time.Now().UTC()
		for j := 0; j < 500; j++ {
			state := OAuthState{StateToken: fmt.Sprintf("bench-cleanup-%d-%d", i, j), ClientID: "client", RedirectURI: "https://client.example", CodeChallenge: "challenge", OIDCState: "state", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), Scopes: "openid", AuthTime: now}
			if err := store.SaveState(&state); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		store.cleanupExpiredAt(now)
		b.StopTimer()
	}
}
