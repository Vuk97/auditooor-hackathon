// Pattern 39 — NEGATIVE fixture: every exported method either takes
// a lock or routes through atomic helpers. Detector must NOT fire.
package fixture

import (
	"sync"
	"sync/atomic"
)

type SessionCache struct {
	mu      sync.Mutex
	entries map[string][]byte
	hits    int
}

type Stream struct {
	pos    int64
	closed atomic.Bool
}

type ConfigStore struct {
	rw    sync.RWMutex
	value string
	dirty bool
}

// SAFE: explicit `s.mu.Lock()` before mutation.
func (s *SessionCache) Put(key string, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = value
	s.hits = s.hits + 1
}

// SAFE: writes routed through atomic helpers.
func (t *Stream) AdvanceAndMaybeClose(n int64, eof bool) {
	atomic.AddInt64(&t.pos, n)
	if eof {
		t.closed.Store(true)
	}
}

// SAFE: takes a write lock.
func (c *ConfigStore) Set(v string) {
	c.rw.Lock()
	defer c.rw.Unlock()
	c.value = v
	c.dirty = true
}
