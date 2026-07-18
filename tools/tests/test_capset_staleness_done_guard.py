#!/usr/bin/env python3
"""test_capset_staleness_done_guard.py - T1 (stale-done-on-capability-set-hash-change).

Regression coverage for the loop's own T1 machinery gap: audit-completeness-check
wrote the ``audit_complete_last_result.json`` done-marker WITHOUT recording the
capability_set_hash the pass was produced under, and audit-done-guard never
compared it - so a ``pass-audit-complete`` verdict survived unchanged after new
detectors/screens were wired, even though that pass never had a chance to surface
what the new capabilities find.

The fix stamps ``capability_set_hash`` into the marker (via the ONE shared source
capability-wiring-integrity-check.current_capability_set_hash) and re-compares it
in audit-done-guard.evaluate():
  - marker hash present AND differs from live => STALE, hard NOT-DONE under
    AUDITOOOR_CAPSET_STALENESS_STRICT=1 (opt-in ramp), advisory-WARN otherwise.
  - marker hash absent (legacy pass) OR live hash uncomputable => grandfather,
    never a spurious stale.

Cases (all reach the staleness branch by giving the ws a fresh STRICT pass marker):
  (A) strict + hash mismatch => NOT-DONE with the capability-set-stale reason.
  (B) advisory (no env) + mismatch => does NOT hard-fail on staleness; the soft
      capset_stale_warn is set (still surfaced, never silently trusted).
  (C) strict + hash MATCH => staleness branch does NOT fire (no warn, no stale reason).
  (D) strict + marker has NO capability_set_hash (legacy) => grandfather, no stale.
  (E) shared-source roundtrip: the gate's _live_capability_set_hash() ==
      the guard's _current_capability_set_hash() == compute over load_inventory(),
      proving the written hash matches the read hash byte-for-byte.

Stdlib-only; loads the real tools by path and monkeypatches the live-hash source
so the test does not depend on the repo's current inventory contents.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GUARD_PATH = REPO / "tools" / "audit-done-guard.py"
GATE_PATH = REPO / "tools" / "audit-completeness-check.py"
INTEGRITY_PATH = REPO / "tools" / "capability-wiring-integrity-check.py"

_STRICT_ENV = "AUDITOOOR_CAPSET_STALENESS_STRICT"
_SCHEMA = "auditooor.audit_completeness.v1"


def _load(mod_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass field() introspection (Python 3.14) can
    # resolve the module dict for default_factory fields (mirrors the gate tool's
    # own _load_hunt_completeness_module idiom).
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class CapsetStalenessTest(unittest.TestCase):
    def setUp(self):
        self.guard = _load("_guard_capset_test", GUARD_PATH)
        self._env_saved = os.environ.get(_STRICT_ENV)
        os.environ.pop(_STRICT_ENV, None)

    def tearDown(self):
        if self._env_saved is None:
            os.environ.pop(_STRICT_ENV, None)
        else:
            os.environ[_STRICT_ENV] = self._env_saved
        # restore the real live-hash source
        importlib.reload  # no-op; we monkeypatch per-test on the fresh module

    def _make_ws(self, tmp: Path, *, marker_hash) -> Path:
        """A workspace whose ONLY content is a fresh STRICT pass marker plus a
        paste_ready finding, so evaluate() reaches (and can pass) the staleness
        branch. marker_hash=None omits the field (legacy marker)."""
        ws = tmp
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        blob = {
            "schema": _SCHEMA,
            "gate": "audit-complete",
            "verdict": "pass-audit-complete",
            "strict": True,
            "failures": [],
            "rebutted": [],
            "workspace": str(ws),
        }
        if marker_hash is not None:
            blob["capability_set_hash"] = marker_hash
        marker = ws / ".auditooor" / "audit_complete_last_result.json"
        marker.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        # keep the marker fresh (well within TTL)
        os.utime(marker, (time.time(), time.time()))
        # paste-ready-or-nothing: give it one paste_ready file so the downstream
        # gate is not the thing that flips done (isolates the staleness axis).
        pr = ws / "submissions" / "paste_ready"
        pr.mkdir(parents=True, exist_ok=True)
        (pr / "finding.md").write_text("# finding\nPoC pass.\n", encoding="utf-8")
        return ws

    def _patch_live_hash(self, value):
        self.guard._current_capability_set_hash = lambda: value  # type: ignore[assignment]

    # -- (A) strict + mismatch => hard NOT-DONE on staleness -------------------
    def test_A_strict_mismatch_not_done(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td), marker_hash="a" * 64)
            self._patch_live_hash("b" * 64)  # live differs
            os.environ[_STRICT_ENV] = "1"
            r = self.guard.evaluate(ws, ttl_hours=6.0)
            self.assertFalse(r["done"], f"strict+mismatch must be NOT-DONE: {r}")
            self.assertIn("STALE against the current capability set", r["reason"])

    # -- (B) advisory + mismatch => not a staleness hard-fail; warn set --------
    def test_B_advisory_mismatch_warns_not_stalefail(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td), marker_hash="a" * 64)
            self._patch_live_hash("b" * 64)
            # no strict env
            r = self.guard.evaluate(ws, ttl_hours=6.0)
            # the soft warn is recorded either way
            self.assertIn("capset_stale_warn", r, f"advisory warn must be set: {r}")
            self.assertIn("capability set changed since this pass", r["capset_stale_warn"])
            # and it did NOT hard-fail on staleness (that reason is strict-only)
            self.assertNotIn("STALE against the current capability set", r.get("reason", ""))

    # -- (C) strict + hash MATCH => staleness branch does not fire -------------
    def test_C_strict_match_no_stale(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td), marker_hash="c" * 64)
            self._patch_live_hash("c" * 64)  # identical
            os.environ[_STRICT_ENV] = "1"
            r = self.guard.evaluate(ws, ttl_hours=6.0)
            self.assertNotIn("capset_stale_warn", r,
                             f"matching hash must not warn: {r}")
            self.assertNotIn("STALE against the current capability set", r.get("reason", ""))

    # -- (D) strict + legacy marker (no hash) => grandfather -------------------
    def test_D_strict_legacy_marker_grandfathered(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td), marker_hash=None)  # no field
            self._patch_live_hash("d" * 64)
            os.environ[_STRICT_ENV] = "1"
            r = self.guard.evaluate(ws, ttl_hours=6.0)
            self.assertNotIn("capset_stale_warn", r,
                             f"legacy marker must be grandfathered: {r}")
            self.assertNotIn("STALE against the current capability set", r.get("reason", ""))

    # -- (D2) strict + mismatch but live-hash UNCOMPUTABLE (None) => grandfather
    def test_D2_strict_uncomputable_live_grandfathered(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td), marker_hash="a" * 64)
            self._patch_live_hash(None)  # cannot compute live => cannot stale
            os.environ[_STRICT_ENV] = "1"
            r = self.guard.evaluate(ws, ttl_hours=6.0)
            self.assertNotIn("capset_stale_warn", r,
                             f"uncomputable live hash must not stale: {r}")
            self.assertNotIn("STALE against the current capability set", r.get("reason", ""))

    # -- (E) shared-source roundtrip: gate write-hash == guard read-hash -------
    def test_E_shared_source_roundtrip(self):
        gate = _load("_gate_capset_test", GATE_PATH)
        integ = _load("_integ_capset_test", INTEGRITY_PATH)
        # all three must agree on the SAME live inventory
        h_gate = gate._live_capability_set_hash()
        h_guard = self.guard._current_capability_set_hash()
        h_integ = integ.current_capability_set_hash()
        self.assertIsNotNone(h_integ, "live inventory must be readable in-repo")
        self.assertEqual(h_gate, h_integ,
                         "gate write-hash must equal the shared source hash")
        self.assertEqual(h_guard, h_integ,
                         "guard read-hash must equal the shared source hash")
        # and it must equal a hand-computed hash over load_inventory (no drift)
        rows = integ.load_inventory(REPO)
        self.assertEqual(h_integ, integ.compute_capability_set_hash(rows))


if __name__ == "__main__":
    unittest.main()
