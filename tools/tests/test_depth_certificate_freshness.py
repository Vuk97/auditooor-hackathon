#!/usr/bin/env python3
"""Regression tests for the depth-certificate FRESHNESS check (K2 lane).

A cert built at T1 over depth inputs replaced at T2>T1 is STALE and must NOT be
certified. The gate (tools/depth-certificate-check.py) compares the cert's mtime
against every existing depth input and fails ``fail-depth-stale`` (or marks
ok-rebuttal) when any input is newer. Completeness-safe: missing inputs are
reported, never crash, and never on their own mark the cert stale.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "depth-certificate-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("_depth_cert_fresh_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _complete_cert(**overrides) -> dict:
    cert = {
        "schema": "auditooor.depth_certificate.v1",
        "workspace": "ws",
        "negative_space_ran": True,
        "guards_enumerated": 12,
        "incomplete_guard_deltas": [
            {
                "guard": "validateNotExited",
                "file_line": "x.go:42",
                "delta": "claim path missing check",
                "exploitation_attempt_artifact": "poc/claim_after_exit_test.go",
            }
        ],
        "sibling_diff_ran": True,
        "sibling_pairs_enumerated": 4,
        "sibling_asymmetries": [
            {
                "pair": "claim/finalize",
                "ruled_out_reason": "claim is admin-only, see acl.go:5",
            }
        ],
        "findings_count": 2,
        "zero_findings_smell_cleared": False,
    }
    cert.update(overrides)
    return cert


def _set_mtime(p: Path, mtime: float) -> None:
    os.utime(p, (mtime, mtime))


class TestDepthCertificateFreshness(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.ws = Path(self._td.name)
        self.aud = self.ws / ".auditooor"
        self.aud.mkdir(parents=True, exist_ok=True)
        self.cert_path = self.aud / "depth_certificate.json"

    def tearDown(self):
        self._td.cleanup()

    def _write_cert(self, cert: dict, mtime: float | None = None) -> None:
        self.cert_path.write_text(json.dumps(cert), encoding="utf-8")
        if mtime is not None:
            _set_mtime(self.cert_path, mtime)

    def _write_input(self, name: str, mtime: float | None = None) -> Path:
        p = self.aud / name
        p.write_text("{}\n", encoding="utf-8")
        if mtime is not None:
            _set_mtime(p, mtime)
        return p

    # --- (1) stale cert: an input is NEWER than the cert -> fail-depth-stale ---
    def test_input_newer_than_cert_is_stale(self):
        base = time.time()
        self._write_cert(_complete_cert(), mtime=base)
        # input regenerated AFTER the cert was built
        self._write_input("negative_space_gaps.jsonl", mtime=base + 1000)
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_STALE, r)
        self.assertIn("negative_space_gaps.jsonl", r["freshness"]["newer_inputs"])
        self.assertIn("audit-depth", r["reason"])

    # --- (2) fresh cert: cert NEWER than all inputs -> normal pass ---
    def test_cert_newer_than_inputs_passes(self):
        base = time.time()
        self._write_input("negative_space_gaps.jsonl", mtime=base)
        self._write_input("sibling_guard_asymmetries.jsonl", mtime=base)
        self._write_input("inscope_units.jsonl", mtime=base)
        # cert built AFTER the inputs
        self._write_cert(_complete_cert(), mtime=base + 1000)
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.PASS, r)

    # --- (3) directory input newer than cert -> stale ---
    def test_probe_dir_member_newer_than_cert_is_stale(self):
        base = time.time()
        self._write_cert(_complete_cert(), mtime=base)
        pdir = self.aud / "asymmetry_probes"
        pdir.mkdir()
        member = pdir / "batch_0.jsonl"
        member.write_text("{}\n", encoding="utf-8")
        _set_mtime(member, base + 1000)
        _set_mtime(pdir, base + 1000)
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_STALE, r)
        self.assertIn("asymmetry_probes/", r["freshness"]["newer_inputs"])

    # --- (4) glob batch dir (depth_probes_*) newer than cert -> stale ---
    def test_depth_probes_glob_dir_newer_is_stale(self):
        base = time.time()
        self._write_cert(_complete_cert(), mtime=base)
        pdir = self.aud / "depth_probes_batch3"
        pdir.mkdir()
        member = pdir / "b.jsonl"
        member.write_text("{}\n", encoding="utf-8")
        _set_mtime(member, base + 1000)
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_STALE, r)

    # --- (5) completeness-safe: NO inputs -> not stale, does not crash ---
    def test_no_inputs_not_stale_and_no_crash(self):
        # No input files at all (the existing-tests scenario). Freshness cannot be
        # verified -> keep-all (not stale), gate proceeds to normal verdict logic.
        self._write_cert(_complete_cert())
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.PASS, r)

    # --- (6) missing input reported, present input compared (graceful) ---
    def test_missing_input_reported_not_fatal(self):
        base = time.time()
        self._write_input("negative_space_gaps.jsonl", mtime=base)
        self._write_cert(_complete_cert(), mtime=base + 1000)
        r = MOD.check_depth(self.ws)
        # On a non-stale path the freshness report rides in the detail block.
        fresh = r["detail"]["freshness"]
        self.assertIn("negative_space_gaps.jsonl", fresh["checked_inputs"])
        # an input that does not exist is reported as missing, not a crash
        self.assertIn("inscope_units.jsonl", fresh["missing_inputs"])
        self.assertEqual(r["verdict"], MOD.PASS, r)

    # --- (7) same-second rebuild is NOT mis-flagged stale (strict ">") ---
    def test_same_mtime_not_stale(self):
        base = time.time()
        self._write_input("negative_space_gaps.jsonl", mtime=base)
        self._write_cert(_complete_cert(), mtime=base)  # exactly equal
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.PASS, r)

    # --- (8) stale cert + rebuttal -> ok-rebuttal with would_be=fail-depth-stale
    def test_stale_with_rebuttal_is_ok_rebuttal(self):
        base = time.time()
        self._write_cert(_complete_cert(), mtime=base)
        self._write_input("negative_space_gaps.jsonl", mtime=base + 1000)
        (self.aud / "depth_certificate_rebuttal.txt").write_text(
            "r81-rebuttal: depth N/A on this target", encoding="utf-8"
        )
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.OK_REBUTTAL, r)
        self.assertEqual(r["would_be_verdict"], MOD.FAIL_STALE)

    # --- (9) producer depth-audited cert that is STALE still fails freshness ---
    def test_stale_beats_producer_audited_verdict(self):
        base = time.time()
        cert = _complete_cert(
            verdict="depth-audited",
            build_schema="auditooor.depth_certificate_build.v1",
            zero_findings_smell_cleared=True,
        )
        self._write_cert(cert, mtime=base)
        # An input regenerated after the audited cert was written.
        self._write_input("asymmetry_probes.jsonl", mtime=base + 1000)
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_STALE, r)

    # --- (10) main() returns exit 1 on a stale cert ---
    def test_main_exit_code_on_stale(self):
        base = time.time()
        self._write_cert(_complete_cert(), mtime=base)
        self._write_input("negative_space_gaps.jsonl", mtime=base + 1000)
        rc = MOD.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 1)

    # --- (11) FAIL_STALE constant exists + is non-pass ---
    def test_fail_stale_constant(self):
        self.assertEqual(MOD.FAIL_STALE, "fail-depth-stale")
        self.assertNotIn(MOD.FAIL_STALE, MOD._PASS_VERDICTS)


if __name__ == "__main__":
    unittest.main()
