#!/usr/bin/env python3
# <!-- r36-rebuttal: lane W3b-honest-zero-bank registered via agent-pathspec-register.py -->
"""Guard: honest-zero-bank banks the REUSABLE residue of a clean honest-0, and
honest-zero-verify REQUIRES >=1 reusable record banked (recomputed from disk, not
trusting a written flag).

THE FIX UNDER TEST: a clean honest-0 banked NOTHING reusable, so the next re-pin
re-resolved fork bases + re-hunted the same dead-ends from scratch. Now:
  1. honest-zero-bank --workspace <ws> with dead-ends + fork_bases writes one
     engagement-level seed record with per-drop_class counts + resolved fork bases
     + per-fork unmodified-upstream OOS counts; idempotent (upsert by workspace).
  2. honest-zero-verify's banked_reusable check FAILS with 0 bankable residue and
     PASSES with >=1 - recomputed from disk, un-fakeable by a written bank file.
  3. The existing honest-zero checks stay intact (the genuine fixture still passes).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name: str, fname: str):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


bank = _load("hzb_test", "honest-zero-bank.py")
hzv = _load("hzv_bank_test", "honest-zero-verify.py")


def _ws_with_dead_ends(tmp: Path) -> Path:
    """A workspace with 2 ruled-out units (different drop_classes) + a resolved
    fork base, but NO findings - the clean-0 shape."""
    ws = tmp / "ws"
    aud = ws / ".auditooor"
    sidecar_dir = aud / "hunt_findings_sidecars"
    sidecar_dir.mkdir(parents=True)
    # privileged-only drop
    (sidecar_dir / "batch_0000.jsonl").write_text(
        json.dumps({
            "unit_id": "Foo.setAdmin",
            "file_line": "src/bor/Foo.go:10",
            "verdict": "REJECTED",
            "rebuttal_or_guard": "onlyOwner gate; unprivileged cannot reach",
            "code_excerpt": "function setAdmin() onlyOwner {",
        }) + "\n"
        # upstream-unmodified drop
        + json.dumps({
            "unit_id": "Bar.decode",
            "file_line": "src/bor/Bar.go:42",
            "verdict": "OOS",
            "ruled_out_reason": "unmodified upstream go-ethereum library",
        }) + "\n",
        encoding="utf-8",
    )
    # a resolved fork base + a fork checkout with one modified + one unmodified file
    (aud / "fork_bases.json").write_text(json.dumps([
        {"local_name": "bor", "upstream_repo": "ethereum/go-ethereum",
         "base_ref": "v1.13.0", "resolved_via": "git-history"},
    ]), encoding="utf-8")
    fork = ws / "src" / "bor"
    fork.mkdir(parents=True)
    (fork / "modified.go").write_text("package bor\nfunc A() {}\n")
    (fork / "vanilla.go").write_text("package bor\nfunc B() {}\n")
    # fork-scope sidecar: bor has 1 modified file (so 1 of the 2 src files is OOS)
    (ws / "inscope_units.fork_scope.json").write_text(json.dumps({
        "schema": "auditooor.inscope_fork_scope.v1",
        "applied": True,
        "forks": [{"local_name": "bor", "verdict": "scoped", "modified_file_count": 1}],
    }), encoding="utf-8")
    return ws


class TestBankRecord(unittest.TestCase):
    def test_record_has_per_class_counts_and_fork_bases(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws_with_dead_ends(Path(td))
            rec = bank.build_record(ws)
            # per-drop_class dead-end counts
            self.assertEqual(rec["dead_end_total"], 2)
            self.assertEqual(rec["dead_end_class_counts"].get("privileged-only-R24"), 1)
            self.assertEqual(
                rec["dead_end_class_counts"].get("oos-unmodified-upstream"), 1
            )
            # resolved fork bases captured
            self.assertEqual(rec["fork_base_count"], 1)
            fb = rec["fork_bases"][0]
            self.assertEqual(fb["local_name"], "bor")
            self.assertEqual(fb["base_ref"], "v1.13.0")
            self.assertEqual(fb["upstream_repo"], "ethereum/go-ethereum")
            # per-fork unmodified-upstream OOS count: 2 src files - 1 modified = 1 OOS
            self.assertEqual(fb["in_scope_source_files"], 2)
            self.assertEqual(fb["modified_file_count"], 1)
            self.assertEqual(fb["unmodified_upstream_oos_file_count"], 1)
            # reusable residue present
            self.assertGreaterEqual(rec["reusable_record_count"], 3)

    def test_cli_writes_seed_jsonl_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws_with_dead_ends(Path(td))
            bank_file = Path(td) / "honest_zero_bank.jsonl"
            rc = bank.main(["--workspace", str(ws), "--bank-file", str(bank_file), "--quiet"])
            self.assertEqual(rc, 0)
            self.assertTrue(bank_file.exists())
            rows = [json.loads(l) for l in bank_file.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["schema"], "auditooor.honest_zero_bank.v1")
            self.assertEqual(rows[0]["workspace"], "ws")
            # re-run: upsert, not append (idempotent)
            bank.main(["--workspace", str(ws), "--bank-file", str(bank_file), "--quiet"])
            rows2 = [json.loads(l) for l in bank_file.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows2), 1)

    def test_empty_ws_degrades_gracefully_no_crash(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty"
            (ws / ".auditooor").mkdir(parents=True)
            rec = bank.build_record(ws)
            self.assertEqual(rec["dead_end_total"], 0)
            self.assertEqual(rec["fork_base_count"], 0)
            self.assertEqual(rec["reusable_record_count"], 0)
            self.assertTrue(rec["degraded"])
            self.assertTrue(any("fork_bases" in r for r in rec["degraded_reasons"]))

    def test_fork_base_without_sidecar_records_none_oos(self):
        """Resolved fork base but no fork-scope sidecar => modified unknown, OOS
        count None (never a false OOS claim), but the base is still banked."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws2"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            (aud / "fork_bases.json").write_text(json.dumps([
                {"local_name": "bor", "upstream_repo": "ethereum/go-ethereum",
                 "base_ref": "v1.13.0", "resolved_via": "git-history"},
            ]), encoding="utf-8")
            fork = ws / "src" / "bor"
            fork.mkdir(parents=True)
            (fork / "a.go").write_text("package bor\n")
            rec = bank.build_record(ws)
            self.assertEqual(rec["fork_base_count"], 1)
            fb = rec["fork_bases"][0]
            self.assertIsNone(fb["modified_file_count"])
            self.assertIsNone(fb["unmodified_upstream_oos_file_count"])
            self.assertEqual(fb["in_scope_source_files"], 1)


class TestVerifyBankedReusableCheck(unittest.TestCase):
    def test_zero_banked_fails_check(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty"
            (ws / ".auditooor").mkdir(parents=True)
            ok, detail, fp = hzv._check_banked_reusable(ws)
            self.assertFalse(ok, "0 reusable residue must fail banked_reusable")
            self.assertEqual(fp, "")
            self.assertIn("0 reusable", detail)

    def test_dead_ends_or_fork_bases_pass_check(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws_with_dead_ends(Path(td))
            ok, detail, fp = hzv._check_banked_reusable(ws)
            self.assertTrue(ok, detail)
            self.assertTrue(fp.startswith("bank:"))

    def test_written_bank_file_does_not_fake_check(self):
        """A hand-written reports bank file must NOT make the check pass when the
        on-disk residue is empty - the check recomputes from disk."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty"
            (ws / ".auditooor").mkdir(parents=True)
            # write a fake bank record claiming reusable residue
            fake = ws / ".auditooor" / "honest_zero_bank.jsonl"
            fake.write_text(json.dumps({
                "schema": "auditooor.honest_zero_bank.v1",
                "workspace": "empty", "reusable_record_count": 99,
            }) + "\n", encoding="utf-8")
            ok, _detail, _fp = hzv._check_banked_reusable(ws)
            self.assertFalse(ok, "a written bank file must not fake the check")

    def test_l37_rebuttal_escape(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty"
            a = ws / ".auditooor"
            a.mkdir(parents=True)
            (a / "l37-rebuttal").write_text("other-gate\nbanked_reusable\n")
            ok, detail, fp = hzv._check_banked_reusable(ws)
            self.assertTrue(ok, "rebuttal escape must flip to pass")
            self.assertIn("ok-rebuttal", detail)
            self.assertEqual(fp, "bank:rebuttal")

    def test_check_wired_into_verify(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws_with_dead_ends(Path(td))
            r = hzv.verify(ws)
            self.assertIn("banked_reusable", r["checks"])
            self.assertTrue(r["checks"]["banked_reusable"]["ok"], r["checks"]["banked_reusable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
