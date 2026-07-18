#!/usr/bin/env python3
"""Tests for tools/depth-certificate-check.py (R81 depth-certificate gate)."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "depth-certificate-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("_depth_cert_for_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_cert(ws: Path, cert: dict) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "depth_certificate.json").write_text(json.dumps(cert), encoding="utf-8")


def _write_rebuttal(ws: Path, text: str) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "depth_certificate_rebuttal.txt").write_text(text, encoding="utf-8")


def _complete_cert(**overrides) -> dict:
    cert = {
        "schema": "auditooor.depth_certificate.v1",
        "workspace": "ws",
        "run_id": "run-1",
        "generated_at_utc": "2026-06-04T00:00:00Z",
        "source_tree_hash": "abc123",
        "negative_space_ran": True,
        "negative_space_artifact": ".auditooor/depth/negative_space.jsonl",
        "guards_enumerated": 12,
        "incomplete_guard_deltas": [
            {
                "guard": "validateNotExited",
                "file_line": "x.go:42",
                "checks_what": "exit flag",
                "invariant_requires": "no-claim-after-exit",
                "delta": "claim path missing check",
                "exploitation_attempt_artifact": "poc/claim_after_exit_test.go",
            }
        ],
        "sibling_diff_ran": True,
        "sibling_diff_artifact": ".auditooor/depth/sibling_guard_diff.jsonl",
        "sibling_pairs_enumerated": 4,
        "sibling_asymmetries": [
            {
                "pair": "claim/finalize",
                "guarded_file_line": "finalize.go:10",
                "unguarded_file_line": "claim.go:20",
                "ruled_out_reason": "claim is admin-only, see acl.go:5",
            }
        ],
        "survivors_validated": True,
        "findings_count": 2,
        "zero_findings_smell_cleared": False,
        "verdict": "pass-depth-complete",
    }
    cert.update(overrides)
    return cert


class TestDepthCertificateCheck(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.ws = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    # Case 1: no cert -> fail-no-depth-certificate (NOT a pass).
    def test_no_cert_fails(self):
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_NO_CERT)

    # Case 2: complete cert -> pass-depth-audited.
    def test_complete_cert_passes(self):
        _write_cert(self.ws, _complete_cert())
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.PASS, r)

    # Case 3: cert with an un-probed guard (delta lacks artifact AND ruled_out).
    def test_unvalidated_survivor_fails(self):
        cert = _complete_cert(
            incomplete_guard_deltas=[
                {"guard": "g1", "file_line": "a:1", "delta": "missing"}
            ]
        )
        _write_cert(self.ws, cert)
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_SURVIVORS, r)

    # Case 4: negative-space not run -> fail.
    def test_negative_space_not_run(self):
        _write_cert(self.ws, _complete_cert(negative_space_ran=False))
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_NEG_SPACE, r)

    # Case 5: sibling-diff not run -> fail.
    def test_sibling_diff_not_run(self):
        _write_cert(self.ws, _complete_cert(sibling_diff_ran=False))
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_SIBLING, r)

    # Case 6: 0 findings but smell not cleared -> fail-zero-findings-smell.
    def test_zero_findings_smell_not_cleared(self):
        _write_cert(
            self.ws,
            _complete_cert(findings_count=0, zero_findings_smell_cleared=False),
        )
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_ZERO_SMELL, r)

    # Case 7: 0 findings WITH depth evidence + smell cleared -> pass.
    def test_zero_findings_smell_cleared_passes(self):
        _write_cert(
            self.ws,
            _complete_cert(findings_count=0, zero_findings_smell_cleared=True),
        )
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.PASS, r)

    # Case 8: rebuttal honored on a missing cert.
    def test_rebuttal_honored_no_cert(self):
        _write_rebuttal(self.ws, "r81-rebuttal: no guard surface on this target")
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.OK_REBUTTAL, r)

    # Case 9: rebuttal honored on a failing cert.
    def test_rebuttal_honored_failing_cert(self):
        _write_cert(self.ws, _complete_cert(negative_space_ran=False))
        _write_rebuttal(self.ws, "r81-rebuttal: depth N/A; greenfield workspace")
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.OK_REBUTTAL, r)
        self.assertEqual(r["would_be_verdict"], MOD.FAIL_NEG_SPACE)

    # Case 10: oversized rebuttal ignored -> original fail stands.
    def test_oversized_rebuttal_ignored(self):
        _write_cert(self.ws, _complete_cert(sibling_diff_ran=False))
        _write_rebuttal(self.ws, "r81-rebuttal: " + "x" * 250)
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_SIBLING, r)

    # Case 11: HTML-comment rebuttal form honored.
    def test_html_comment_rebuttal(self):
        _write_rebuttal(self.ws, "<!-- r81-rebuttal: out of scope here -->")
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.OK_REBUTTAL, r)

    # Case 12: schema mismatch -> error.
    def test_schema_mismatch_error(self):
        _write_cert(self.ws, _complete_cert(schema="auditooor.wrong.v9"))
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.ERROR, r)

    # Case 13: guards_enumerated==0 fails negative-space even if ran=True.
    def test_zero_guards_fails(self):
        _write_cert(self.ws, _complete_cert(guards_enumerated=0))
        r = MOD.check_depth(self.ws)
        self.assertEqual(r["verdict"], MOD.FAIL_NEG_SPACE, r)

    # Case 14: schema constant + reusable function importable.
    def test_schema_and_callable(self):
        self.assertEqual(MOD.SCHEMA, "auditooor.depth_certificate_check.v1")
        self.assertTrue(callable(MOD.check_depth))

    # Case 15: main() exit codes via JSON path.
    def test_main_exit_codes(self):
        # no cert -> exit 1
        rc = MOD.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 1)
        _write_cert(self.ws, _complete_cert())
        rc = MOD.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
