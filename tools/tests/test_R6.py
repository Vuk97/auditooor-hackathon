#!/usr/bin/env python3
"""R6 - async-cancel coupled-state screen (tools/async-cancel-coupled-state-screen.py).

GENERAL trust-enforcement class (NOT a bug shape): the delegated-trusted invariant is
"a must-move-together state set is committed atomically"; its private invariant is
"a cancel/drop at an `.await` between two writes of the set is unwound (Drop / scopeguard
/ explicit rollback)"; the attack is a caller/timeout/select!-branch-loss drop at that
interior await leaving a partial commit with no rollback. Advisory-first: every emitted
row carries verdict='needs-fuzz', advisory=True, auto_credit=False, and default mode
never fail-closes.

NON-VACUOUS contract - every case below breaks if a load-bearing predicate is neutralized:
  1. planted POSITIVE fires (pub async fn, 2 distinct coupled writes straddling an await,
     no unwind, drivable).
  2. NEUTRALIZE the core predicate (remove the interior `.await`) -> the positive STOPS
     firing (proves the interior-await-straddle predicate is load-bearing, not vacuous).
  3. NEUTRALIZE the second distinct write (collapse to one field) -> stops firing (proves
     the must-move-together >=2-slot predicate is load-bearing).
  4. guarded NEGATIVE silent x3 (impl Drop / scopeguard / explicit rollback).
  5. not-drivable NEGATIVE silent (private fn, no select!/timeout/spawn/abort surface).
  6. comment-mask precision: a `reset`/`restore` mentioned ONLY in a comment is NOT a
     guard (still fires); a `self.x = ..` in a comment is NOT a write (no phantom slot).
  7. advisory-first contract on the emitted row + on the strict exit-code (default 0).
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_TOOL = _TOOLS / "async-cancel-coupled-state-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("acs_r6", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["acs_r6"] = m
    spec.loader.exec_module(m)
    return m


ACS = _load()


# --- fixtures (Rust source strings) ----------------------------------------

# POSITIVE: pub async fn, writes self.a BEFORE an interior await and self.b AFTER;
# no Drop/scopeguard/rollback anywhere -> partial commit survives a drop = fires.
POSITIVE = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        self.a = 1;
        let fetched = client.fetch_remote().await?;
        self.b = fetched;
        Ok(())
    }
}
"""

# NEUTRALIZE the interior await (core predicate): both writes now precede the only await.
NO_INTERIOR_AWAIT = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        self.a = 1;
        self.b = 2;
        let _fetched = client.fetch_remote().await?;
        Ok(())
    }
}
"""

# NEUTRALIZE the second distinct slot: only one field is written (no coupled set).
ONE_SLOT = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        self.a = 1;
        let fetched = client.fetch_remote().await?;
        self.a = fetched;
        Ok(())
    }
}
"""

# GUARDED (impl Drop for the type): a Drop re-establishes the invariant -> silent.
GUARDED_DROP = """
struct Ledger { a: u64, b: u64 }

impl Drop for Ledger {
    fn drop(&mut self) { self.a = 0; self.b = 0; }
}

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        self.a = 1;
        let fetched = client.fetch_remote().await?;
        self.b = fetched;
        Ok(())
    }
}
"""

# GUARDED (scopeguard drop-guard object in the body) -> silent.
GUARDED_SCOPEGUARD = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        let _guard = scopeguard::guard((), |_| { /* revert on drop */ });
        self.a = 1;
        let fetched = client.fetch_remote().await?;
        self.b = fetched;
        Ok(())
    }
}
"""

# GUARDED (explicit rollback call in the body) -> silent.
GUARDED_ROLLBACK = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        self.a = 1;
        let fetched = match client.fetch_remote().await {
            Ok(v) => v,
            Err(e) => { self.rollback(); return Err(e); }
        };
        self.b = fetched;
        Ok(())
    }
}
"""

# NOT DRIVABLE: private (non-pub) async fn, file has NO select!/timeout/spawn/abort
# cancellation surface -> the caller cannot externally drop this future -> silent.
NOT_DRIVABLE = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    async fn commit(&mut self, client: &Client) -> Result<()> {
        self.a = 1;
        let fetched = client.fetch_remote().await?;
        self.b = fetched;
        Ok(())
    }
}
"""

# COMMENT-ONLY "guard": rollback words appear ONLY in a comment (not real code) -> the
# masking pass must NOT credit them; the point still fires.
COMMENT_ONLY_GUARD = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        // on failure we would rollback / restore / reset the ledger by hand
        self.a = 1;
        let fetched = client.fetch_remote().await?;
        self.b = fetched;
        Ok(())
    }
}
"""

# COMMENT-ONLY second write: the only real write is self.a; `self.b = ..` is in a comment
# -> no phantom coupled slot -> not a coupled set -> silent.
COMMENT_ONLY_WRITE = """
struct Ledger { a: u64, b: u64 }

impl Ledger {
    pub async fn commit(&mut self, client: &Client) -> Result<()> {
        self.a = 1;
        let fetched = client.fetch_remote().await?;
        // self.b = fetched;
        let _ = fetched;
        Ok(())
    }
}
"""


def _rows(src):
    return ACS.scan_file(Path("mem.rs"), "mem.rs", file_text=src)


def _fired(src):
    return [r for r in _rows(src) if r["fires"]]


class TestR6Positive(unittest.TestCase):
    def test_1_positive_fires(self):
        f = _fired(POSITIVE)
        self.assertEqual(len(f), 1, f"expected 1 fired point, got {f}")
        r = f[0]
        self.assertEqual(r["function"], "commit")
        self.assertEqual(sorted(r["coupled_set"]), ["a", "b"])
        self.assertFalse(r["has_unwind"])
        self.assertTrue(r["cancel_externally_drivable"])

    def test_2_await_line_is_source_accurate(self):
        # the interior await is on source line 6 (1-indexed) of POSITIVE
        r = _fired(POSITIVE)[0]
        self.assertEqual(POSITIVE.split("\n")[r["await_line"] - 1].strip(),
                         "let fetched = client.fetch_remote().await?;")


class TestR6NonVacuous(unittest.TestCase):
    """Neutralizing each load-bearing predicate makes the positive STOP firing."""

    def test_3_neutralize_interior_await_kills_fire(self):
        self.assertEqual(_fired(NO_INTERIOR_AWAIT), [],
                         "removing the interior await must silence the screen")

    def test_4_neutralize_second_slot_kills_fire(self):
        self.assertEqual(_fired(ONE_SLOT), [],
                         "collapsing to one coupled slot must silence the screen")

    def test_5_predicate_toggle_is_the_only_difference(self):
        # POSITIVE fires, its await-removed twin does not: the interior-await straddle
        # is the sole toggled predicate (proves non-vacuity of that predicate).
        self.assertTrue(_fired(POSITIVE))
        self.assertFalse(_fired(NO_INTERIOR_AWAIT))


class TestR6GuardedNegatives(unittest.TestCase):
    def test_6_impl_drop_silent(self):
        f = _fired(GUARDED_DROP)
        self.assertEqual(f, [], "impl Drop unwind must silence the point")
        # the enforcement point is still ENUMERATED (advisory completeness), just silent
        rows = [r for r in _rows(GUARDED_DROP) if r["function"] == "commit"]
        self.assertTrue(rows and rows[0]["has_unwind"])
        self.assertEqual(rows[0]["unwind_kind"], "impl_drop")

    def test_7_scopeguard_silent(self):
        f = _fired(GUARDED_SCOPEGUARD)
        self.assertEqual(f, [])
        rows = [r for r in _rows(GUARDED_SCOPEGUARD) if r["function"] == "commit"]
        self.assertEqual(rows[0]["unwind_kind"], "scopeguard")

    def test_8_explicit_rollback_silent(self):
        f = _fired(GUARDED_ROLLBACK)
        self.assertEqual(f, [])
        rows = [r for r in _rows(GUARDED_ROLLBACK) if r["function"] == "commit"]
        self.assertEqual(rows[0]["unwind_kind"], "explicit_rollback")

    def test_9_not_drivable_silent(self):
        f = _fired(NOT_DRIVABLE)
        self.assertEqual(f, [], "no external cancellation surface -> not drivable -> silent")
        rows = [r for r in _rows(NOT_DRIVABLE) if r["function"] == "commit"]
        self.assertTrue(rows)
        self.assertFalse(rows[0]["cancel_externally_drivable"])


class TestR6CommentMaskPrecision(unittest.TestCase):
    def test_10_comment_only_guard_still_fires(self):
        # rollback/restore/reset only in a comment is NOT a guard
        f = _fired(COMMENT_ONLY_GUARD)
        self.assertEqual(len(f), 1, "a commented rollback must not suppress the fire")
        self.assertFalse(f[0]["has_unwind"])

    def test_11_comment_only_write_is_not_a_slot(self):
        # `self.b = ..` in a comment must not create a phantom second coupled slot
        self.assertEqual(_fired(COMMENT_ONLY_WRITE), [])

    def test_12_mask_preserves_line_indices(self):
        # masking replaces comment chars with spaces but keeps newlines -> line count stable
        masked = ACS._mask_comments(COMMENT_ONLY_GUARD)
        self.assertEqual(masked.count("\n"), COMMENT_ONLY_GUARD.count("\n"))
        self.assertNotIn("rollback", masked)  # the comment text is gone


class TestR6AdvisoryContract(unittest.TestCase):
    def test_13_row_carries_advisory_first_fields(self):
        r = _fired(POSITIVE)[0]
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        self.assertEqual(r["schema"], ACS.HYP_SCHEMA)

    def test_14_default_mode_never_failcloses_strict_opt_in_elevates(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "m.rs").write_text(POSITIVE)
            env = dict(os.environ)
            env.pop("AUDITOOOR_RUST_ASYNC_CANCEL_STRICT", None)
            # default: emits sidecar + summary, exit 0 even though a point fired
            r1 = subprocess.run([sys.executable, str(_TOOL), "--workspace", str(ws)],
                                capture_output=True, text=True, env=env)
            self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
            summ = json.loads(r1.stdout)
            self.assertEqual(summ["fired"], 1)
            self.assertTrue(summ["advisory"])
            self.assertFalse(summ["auto_credit"])
            # sidecar was written
            side = ws / ".auditooor" / ACS._SIDE_NAME
            self.assertTrue(side.exists())
            # strict opt-in elevates the exit code on a fired point (still no credit)
            env["AUDITOOOR_RUST_ASYNC_CANCEL_STRICT"] = "1"
            r2 = subprocess.run([sys.executable, str(_TOOL), "--workspace", str(ws), "--check"],
                                capture_output=True, text=True, env=env)
            self.assertEqual(r2.returncode, 1, "strict must elevate exit code when a point fired")
            self.assertFalse(json.loads(r2.stdout)["auto_credit"])

    def test_15_check_without_sidecar_is_clean_advisory(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, str(_TOOL), "--workspace", d, "--check"],
                               capture_output=True, text=True,
                               env={k: v for k, v in os.environ.items()
                                    if k != "AUDITOOOR_RUST_ASYNC_CANCEL_STRICT"})
            self.assertEqual(r.returncode, 0)
            self.assertEqual(json.loads(r.stdout)["verdict"], "clean-advisory")


if __name__ == "__main__":
    unittest.main(verbosity=2)
