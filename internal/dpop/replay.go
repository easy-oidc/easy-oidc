// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

const replayRetention = 15 * time.Second

var (
	// ErrReplay identifies a proof already accepted by this process.
	ErrReplay = errors.New("DPoP proof replay")
	// ErrReplayCacheFull identifies a cache whose unexpired entries reached its bound.
	ErrReplayCacheFull = errors.New("DPoP replay cache full")
)

// replayExpiry associates a replay hash with its expiration time.
type replayExpiry struct {
	hash      [32]byte
	expiresAt time.Time
}

// replayExpiryHeap orders replay entries by expiration time.
type replayExpiryHeap []replayExpiry

// Len returns the number of queued expirations.
func (h replayExpiryHeap) Len() int { return len(h) }

// Less orders the earliest expiration first.
func (h replayExpiryHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }

// Swap exchanges two queued expirations.
func (h replayExpiryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

// Push appends an expiration to the heap.
func (h *replayExpiryHeap) Push(value any) { *h = append(*h, value.(replayExpiry)) }

// Pop removes the latest slice element after heap reordering.
func (h *replayExpiryHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

// ReplayCache is a process-local, capacity-bounded DPoP replay cache.
type ReplayCache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[[32]byte]time.Time
	expiries   replayExpiryHeap
}

// NewReplayCache creates a replay cache with the supplied hard entry limit.
func NewReplayCache(maxEntries int) *ReplayCache {
	if maxEntries < 1 {
		panic("DPoP replay cache capacity must be positive")
	}
	return &ReplayCache{maxEntries: maxEntries, entries: make(map[[32]byte]time.Time, maxEntries)}
}

// Reserve records a proof for the full acceptance window or rejects its replay.
func (c *ReplayCache) Reserve(hash [32]byte, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeExpired(now)
	if _, exists := c.entries[hash]; exists {
		return ErrReplay
	}
	if len(c.entries) >= c.maxEntries {
		return ErrReplayCacheFull
	}
	expiresAt := now.Add(replayRetention)
	c.entries[hash] = expiresAt
	heap.Push(&c.expiries, replayExpiry{hash: hash, expiresAt: expiresAt})
	return nil
}

// removeExpired discards entries that can no longer represent accepted proofs.
func (c *ReplayCache) removeExpired(now time.Time) {
	for c.expiries.Len() != 0 && !c.expiries[0].expiresAt.After(now) {
		expired := heap.Pop(&c.expiries).(replayExpiry)
		if current, exists := c.entries[expired.hash]; exists && current.Equal(expired.expiresAt) {
			delete(c.entries, expired.hash)
		}
	}
}
