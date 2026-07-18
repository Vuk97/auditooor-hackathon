// Pattern 39 — POSITIVE fixture for
//   go.crypto.race.unsynchronized_concurrent_access
//
// Mirrors Swival #008 / #022 / #027 — TLS / x509 wrappers mutating
// shared state inside an exported method without internal locking.
package fixture

type SessionCache struct {
	entries map[string][]byte
	hits    int
}

type Stream struct {
	pos    int64
	closed bool
}

type ConfigStore struct {
	value string
	dirty bool
}

// BUG: exported method mutates `s.entries` and `s.hits` without any
// lock / atomic helper. Concurrent calls race on both fields.
func (s *SessionCache) Put(key string, value []byte) {
	s.entries[key] = value
	s.hits = s.hits + 1
}

// BUG: exported method writes `t.pos += n` and toggles `t.closed`
// without any synchronisation primitive.
func (t *Stream) AdvanceAndMaybeClose(n int64, eof bool) {
	t.pos += n
	if eof {
		t.closed = true
	}
}

// BUG: exported method reassigns the receiver's `value` field with no
// lock. `c.dirty++` racy under concurrent callers.
func (c *ConfigStore) Set(v string) {
	c.value = v
	c.dirty = true
}
