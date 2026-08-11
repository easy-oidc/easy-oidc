// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// TestReplayCacheRejectsReplaysAndExpiresEntries verifies same-process replay protection.
func TestReplayCacheRejectsReplaysAndExpiresEntries(t *testing.T) {
	cache := NewReplayCache(2)
	now := time.Unix(100, 0)
	first := [32]byte{1}
	if err := cache.Reserve(first, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Reserve(first, now.Add(time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v", err)
	}
	if err := cache.Reserve(first, now.Add(replayRetention)); err != nil {
		t.Fatalf("post-expiry reservation = %v", err)
	}
}

// TestReplayCacheCapacityIsBounded verifies unexpired entries are never evicted.
func TestReplayCacheCapacityIsBounded(t *testing.T) {
	cache := NewReplayCache(2)
	now := time.Unix(100, 0)
	if err := cache.Reserve([32]byte{1}, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Reserve([32]byte{2}, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Reserve([32]byte{3}, now); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("capacity error = %v", err)
	}
	if len(cache.entries) != 2 || cache.expiries.Len() != 2 {
		t.Fatalf("entries=%d expiries=%d", len(cache.entries), cache.expiries.Len())
	}
	if err := cache.Reserve([32]byte{3}, now.Add(replayRetention)); err != nil {
		t.Fatalf("reservation after cleanup = %v", err)
	}
}

// TestReplayCacheConcurrentReservationHasOneWinner verifies duplicate checks are atomic.
func TestReplayCacheConcurrentReservationHasOneWinner(t *testing.T) {
	cache := NewReplayCache(2)
	now := time.Unix(100, 0)
	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			<-start
			errorsSeen <- cache.Reserve([32]byte{1}, now)
		})
	}
	close(start)
	workers.Wait()
	close(errorsSeen)
	succeeded, replayed := 0, 0
	for err := range errorsSeen {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrReplay) {
			replayed++
		}
	}
	if succeeded != 1 || replayed != 1 {
		t.Fatalf("succeeded=%d replayed=%d", succeeded, replayed)
	}
}
