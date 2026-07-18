#!/usr/bin/env python3
"""tests for goroutine-shared-state-race.py - the lock-set-difference race reasoner.

Covers: a genuine survivor (map written from 2 goroutine contexts, no common lock),
the two NON-VACUOUS mutation pairs (wrap both in the same mu.Lock() -> survivor
disappears ; make the field goroutine-local -> disappears), a common-lock-protected
struct that must NOT survive, and the honest substrate/vacuity + CLI plumbing.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "goroutine-shared-state-race.py"
_spec = importlib.util.spec_from_file_location("gssr", _TOOL)
gssr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gssr)


def _write(root, name, text):
    p = Path(root) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


# --- Go fixtures ------------------------------------------------------------
# a shared map field written from two goroutine contexts with NO common lock
SURVIVOR = """package worker

type Registry struct {
	entries map[string]int
}

func (r *Registry) Run() {
	go r.consume()
	r.entries["a"] = 1
}

func (r *Registry) consume() {
	r.entries["b"] = 2
}
"""

# mutation A (vacuous-kill): wrap BOTH accesses in the same mu.Lock() -> protected
MUT_LOCKED = """package worker

import "sync"

type Registry struct {
	mu      sync.Mutex
	entries map[string]int
}

func (r *Registry) Run() {
	go r.consume()
	r.mu.Lock()
	r.entries["a"] = 1
	r.mu.Unlock()
}

func (r *Registry) consume() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries["b"] = 2
}
"""

# mutation B (goroutine-local): only ONE context touches the field -> not multi-goroutine
MUT_LOCAL = """package worker

type Registry struct {
	entries map[string]int
}

func (r *Registry) Run() {
	go r.consume()
	r.entries["a"] = 1
}

func (r *Registry) consume() {
	x := 5
	_ = x
}
"""

# a properly guarded cache (mirrors axelar latestFinalizedBlockCache): common RWMutex
GUARDED = """package evm

import "sync"

type cache struct {
	m    map[string]int
	lock sync.RWMutex
}

func (c *cache) Get(k string) int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.m[k]
}

func (c *cache) Set(k string, v int) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.m[k] = v
}

func (c *cache) start() {
	go c.Set("x", 1)
	c.Get("x")
}
"""


class SurvivorTest(unittest.TestCase):
    def test_genuine_survivor_kept(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "worker.go", SURVIVOR)
            res = gssr.analyze(Path(d))
            self.assertEqual(len(res["survivors"]), 1, res)
            s = res["survivors"][0]
            self.assertEqual(s["shared_state"]["name"], "entries")
            self.assertTrue(s["advisory"])
            self.assertFalse(s["auto_credit"])
            self.assertTrue(s["needs_source"])
            self.assertEqual(s["common_lock_set"], [])

    def test_mutation_common_lock_disappears(self):
        """NON-VACUOUS mutation: wrap both accesses in the same mu.Lock()."""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "worker.go", MUT_LOCKED)
            res = gssr.analyze(Path(d))
            self.assertEqual(len(res["survivors"]), 0, res)
            self.assertGreaterEqual(res["n_multi"], 1)      # still multi-goroutine
            self.assertGreaterEqual(res["n_protected"], 1)  # but now common-lock protected

    def test_mutation_goroutine_local_disappears(self):
        """NON-VACUOUS mutation: make the field goroutine-local (one context)."""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "worker.go", MUT_LOCAL)
            res = gssr.analyze(Path(d))
            self.assertEqual(len(res["survivors"]), 0, res)
            self.assertEqual(res["n_multi"], 0)

    def test_guarded_cache_not_survivor(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "cache.go", GUARDED)
            res = gssr.analyze(Path(d))
            names = [s["shared_state"]["name"] for s in res["survivors"]]
            self.assertNotIn("m", names, res)

    def test_lock_token_normalization(self):
        self.assertEqual(gssr._strip_lock_token("c.lock"), "lock")
        self.assertEqual(gssr._strip_lock_token("mu"), "mu")
        self.assertEqual(gssr._strip_lock_token("s.mu.inner"), "inner")


class SubstrateAndCliTest(unittest.TestCase):
    def test_substrate_vacuous_on_no_go(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "readme.md", "no go here")
            summ = gssr._summary(gssr.analyze(Path(d)), "substrate_vacuous")
            self.assertEqual(summ["verdict"], "substrate_vacuous")
            self.assertEqual(summ["survivors"], 0)

    def test_cited_empty_on_present_no_survivor(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "cache.go", GUARDED)
            summ = gssr._summary(gssr.analyze(Path(d)), "substrate_present")
            self.assertEqual(summ["verdict"], "cited-empty")

    def test_cli_src_root_and_failclosed(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "worker.go", SURVIVOR)
            r = subprocess.run(
                [sys.executable, str(_TOOL), "--src-root", d, "--fail-closed"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)  # survivor -> elevated
            out = json.loads(r.stdout)
            self.assertEqual(out["summary"]["schema"], gssr.SCHEMA)
            self.assertEqual(out["summary"]["survivors"], 1)

    def test_cli_emit_sidecar_and_check(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "worker.go", SURVIVOR)
            r = subprocess.run(
                [sys.executable, str(_TOOL), "--workspace", d, "--emit", "--json"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            side = Path(d) / ".auditooor" / "goroutine_shared_state_race_hypotheses.jsonl"
            self.assertTrue(side.exists())
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["schema"], gssr.SCHEMA)
            chk = subprocess.run(
                [sys.executable, str(_TOOL), "--workspace", d, "--check"],
                capture_output=True, text=True)
            self.assertEqual(json.loads(chk.stdout)["survivors"], 1)


if __name__ == "__main__":
    unittest.main()
