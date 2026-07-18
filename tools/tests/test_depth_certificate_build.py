#!/usr/bin/env python3
"""Tests for tools/depth-certificate-build.py (R81 depth-certificate PRODUCER).

Also verifies the round-trip contract with tools/depth-certificate-check.py:
- a depth-pending cert FAILS the gate;
- a depth-audited cert PASSES the gate.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
BUILD_TOOL = TOOLS / "depth-certificate-build.py"
CHECK_TOOL = TOOLS / "depth-certificate-check.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


BUILD = _load("_depth_cert_build_for_test", BUILD_TOOL)
CHECK = _load("_depth_cert_check_for_test", CHECK_TOOL)


def _jsonl(p: Path, rows: list[dict]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _worklist_row(gid: str, fl: str = "src/x.go:10") -> dict:
    return {
        "schema": "auditooor.guard_negative_space.v1",
        "guard_id": gid,
        "file_line": fl,
        "kinds": ["require"],
        "checks": "require(x > 0)",
        "invariant_hint": "amount bound",
        "question": "what does this guard NOT check",
    }


def _gap_row(gid: str, gap_found: bool, art: str = "", ruled: str = "") -> dict:
    row = {
        "schema": "auditooor.guard_negative_space.v1",
        "guard_id": gid,
        "file_line": "src/x.go:10",
        "gap_found": gap_found,
        "kind": "missing-bound" if gap_found else "",
    }
    if art:
        row["exploitation_attempt_artifact"] = art
    if ruled:
        row["ruled_out_reason"] = ruled
    return row


def _asym_row(pair: str, art: str = "", ruled: str = "") -> dict:
    row = {
        "schema": "auditooor.sibling_path_guard_diff.v1",
        "candidate_gap_id": f"ASYM-{pair.replace('|', '-')}",
        "pair": pair,
        "pair_kind": "naming-convention",
        "file_lines": ["src/a.go:1", "src/b.go:2"],
        "verdict": "asymmetry-candidate",
    }
    if art:
        row["exploitation_attempt_artifact"] = art
    if ruled:
        row["ruled_out_reason"] = ruled
    return row


class TestDepthCertificateBuild(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        self.aud = self.ws / ".auditooor"
        self.aud.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _cert(self) -> dict:
        return json.loads((self.aud / "depth_certificate.json").read_text())

    # Case 1: empty workspace -> depth-not-run.
    def test_empty_workspace_is_not_run(self):
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_NOT_RUN, cert)
        self.assertEqual(cert["guards_analyzed"], 0)
        self.assertFalse(cert["negative_space_ran"])
        self.assertFalse(cert["sibling_diff_ran"])

    # Case 2: worklist + asymmetries only (mechanical-only) -> depth-pending.
    def test_mechanical_only_is_pending(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl",
               [_worklist_row("NS-a"), _worklist_row("NS-b", "src/y.go:5")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl",
               [_asym_row("deposit|withdraw")])
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)
        self.assertEqual(cert["guards_analyzed"], 2)
        self.assertEqual(cert["sibling_pairs_diffed"], 1)
        self.assertTrue(cert["negative_space_ran"])
        self.assertTrue(cert["sibling_diff_ran"])
        # No guards adjudicated yet.
        self.assertEqual(cert["guards_adjudicated"], 0)

    # Case 3: full gaps for every guard + all candidates disposed + survivors ->
    # depth-audited.
    def test_full_adjudication_is_audited(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl",
               [_worklist_row("NS-a"), _worklist_row("NS-b", "src/y.go:5")])
        # both guards probed; one found a gap (disposed via artifact), one ruled out.
        _jsonl(self.aud / "negative_space_gaps.jsonl", [
            _gap_row("NS-a", True, art="poc/a_test.go"),
            _gap_row("NS-b", False, ruled="bounded by caller src/y.go:3"),
        ])
        # sibling asymmetry disposed via ruled-out reason.
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl",
               [_asym_row("deposit|withdraw", ruled="symmetric via shared modifier")])
        survivors = self.ws / "surv.json"
        survivors.write_text(json.dumps({
            "survivors": [{"id": "F1"}],
            "drops": [{"id": "D1", "ruled_out_reason": "OOS"}],
            "findings_drafted": [{"id": "F1", "slug": "claim-after-exit"}],
        }), encoding="utf-8")
        cert = BUILD.build_certificate(self.ws, json.loads(survivors.read_text()))
        self.assertEqual(cert["verdict"], BUILD.VERDICT_AUDITED, cert)
        self.assertEqual(cert["guards_adjudicated"], 2)
        self.assertEqual(cert["candidate_gaps_undisposed"], 0)
        self.assertEqual(cert["findings_count"], 1)
        self.assertTrue(cert["zero_findings_smell_cleared"])

    # Case 4: guards enumerated but only PARTIALLY adjudicated -> depth-pending.
    def test_partial_adjudication_is_pending(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl",
               [_worklist_row("NS-a"), _worklist_row("NS-b", "src/y.go:5")])
        # only NS-a probed.
        _jsonl(self.aud / "negative_space_gaps.jsonl",
               [_gap_row("NS-a", False, ruled="bounded")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl", [])
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)
        self.assertEqual(cert["guards_adjudicated"], 1)
        self.assertLess(cert["guards_adjudicated"], cert["guards_analyzed"])

    # Case 5: all guards probed but a candidate gap is UNDISPOSED -> depth-pending.
    def test_undisposed_candidate_is_pending(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        # guard probed (found a gap, with artifact => adjudicated) BUT a sibling
        # asymmetry has no disposition.
        _jsonl(self.aud / "negative_space_gaps.jsonl",
               [_gap_row("NS-a", True, art="poc/a_test.go")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl",
               [_asym_row("mint|burn")])  # no art, no ruled-out
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)
        self.assertGreaterEqual(cert["candidate_gaps_undisposed"], 1)
        # the undisposed sibling asymmetry is surfaced for the gate.
        self.assertTrue(cert["sibling_asymmetries"])

    # Case 6: gate treats a depth-pending cert as FAIL.
    def test_gate_fails_on_pending(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl",
               [_asym_row("deposit|withdraw")])
        BUILD.write_certificate(self.ws, BUILD.build_certificate(self.ws, None))
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.FAIL_DEPTH_PENDING, res)
        # exit code is non-zero (fail).
        rc = CHECK.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 1)

    # Case 7: gate treats a depth-audited cert as PASS.
    def test_gate_passes_on_audited(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        _jsonl(self.aud / "negative_space_gaps.jsonl",
               [_gap_row("NS-a", True, art="poc/a_test.go")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl",
               [_asym_row("deposit|withdraw", ruled="symmetric")])
        survivors = {"findings_drafted": [{"id": "F1"}], "drops": []}
        BUILD.write_certificate(
            self.ws, BUILD.build_certificate(self.ws, survivors))
        cert = self._cert()
        self.assertEqual(cert["verdict"], BUILD.VERDICT_AUDITED, cert)
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.PASS, res)
        rc = CHECK.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)

    def test_empty_sibling_asymmetry_file_can_pass_when_guards_are_adjudicated(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        _jsonl(self.aud / "negative_space_gaps.jsonl",
               [_gap_row("NS-a", False,
                         ruled="`require(x > 0)` at src/x.go:10 rules out the gap")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl", [])
        BUILD.write_certificate(self.ws, BUILD.build_certificate(self.ws, None))
        cert = self._cert()
        self.assertEqual(cert["verdict"], BUILD.VERDICT_AUDITED, cert)
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.PASS, res)

    def test_duplicate_probe_rows_do_not_cover_missing_guard_id(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl",
               [_worklist_row("NS-a"), _worklist_row("NS-b", "src/y.go:5")])
        _jsonl(self.aud / "negative_space_gaps.jsonl", [
            _gap_row("NS-a", False,
                     ruled="`require(x > 0)` at src/x.go:10 rules out the gap"),
            _gap_row("NS-a", False,
                     ruled="`require(x > 0)` at src/x.go:10 rules out duplicate path"),
        ])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl", [])
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)
        self.assertIn("NS-b", json.dumps(cert["incomplete_guard_deltas"]))

    def test_rust_source_matched_excerpt_makes_reason_substantive(self):
        rows = [{
            "guard_id": "NS-rs",
            "ruled_out_reason": (
                "return Err(MyError::BadInput); | Result error propagation "
                "prevents the invalid state from continuing"
            ),
        }]
        genuine = BUILD.adjudication_genuineness(rows)
        self.assertEqual(genuine["genuine_adjudicated"], 1, genuine)

    def test_asymmetry_probe_disposes_current_candidate(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        _jsonl(self.aud / "negative_space_gaps.jsonl",
               [_gap_row("NS-a", False,
                         ruled="`require(x > 0)` at src/x.go:10 rules out the gap")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl",
               [_asym_row("mint|burn")])
        _jsonl(self.aud / "asymmetry_probes.jsonl", [{
            "candidate_gap_id": "ASYM-mint-burn",
            "gap_found": False,
            "ruled_out_reason": (
                "src/a.go:1 and src/b.go:2 are different role surfaces; "
                "`onlyMinter` is intentionally one-sided here"
            ),
        }])
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_AUDITED, cert)
        self.assertEqual(cert["candidate_gaps_undisposed"], 0)

    def test_generic_asymmetry_probe_does_not_dispose_candidate(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        _jsonl(self.aud / "negative_space_gaps.jsonl",
               [_gap_row("NS-a", False,
                         ruled="`require(x > 0)` at src/x.go:10 rules out the gap")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl",
               [_asym_row("mint|burn")])
        _jsonl(self.aud / "asymmetry_probes.jsonl", [{
            "candidate_gap_id": "ASYM-mint-burn",
            "gap_found": False,
            "ruled_out_reason": "not a bug",
        }])
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)
        self.assertEqual(cert["candidate_gaps_undisposed"], 1)

    # Case 8: gate treats a depth-not-run cert as FAIL (distinct verdict).
    def test_gate_fails_on_not_run(self):
        BUILD.write_certificate(self.ws, BUILD.build_certificate(self.ws, None))
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.FAIL_DEPTH_NOT_RUN, res)

    # Case 9: main() writes the cert and returns 0 regardless of verdict.
    def test_main_writes_cert_returns_zero(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl", [])
        rc = BUILD.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)
        cert = self._cert()
        self.assertEqual(cert["schema"], "auditooor.depth_certificate.v1")
        self.assertEqual(cert["build_schema"], "auditooor.depth_certificate_build.v1")
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)

    # Case 10: a flat-list survivors json (disposition rows) is accepted.
    def test_flat_survivors_list(self):
        _jsonl(self.aud / "negative_space_worklist.jsonl", [_worklist_row("NS-a")])
        _jsonl(self.aud / "negative_space_gaps.jsonl",
               [_gap_row("NS-a", False,
                         ruled="bounded by caller require(x>0) at src/x.go:10")])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl", [])
        flat = [
            {"disposition": "draft", "id": "F1"},
            {"disposition": "drop", "id": "D1", "ruled_out_reason": "OOS"},
        ]
        cert = BUILD.build_certificate(self.ws, flat)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_AUDITED, cert)
        self.assertEqual(cert["findings_count"], 1)
        self.assertEqual(len(cert["drops"]), 1)

    # Case 10b: Go receiver-method sink fn yields a bare-name key so a coverage
    # verdict keyed by the plain method name can join (NUVA 2026-07-09:
    # "(github.com/provlabs/vault/keeper.msgServer).BridgeBurnShares" starts with
    # '(' and the old split-on-'(' produced an empty bare name -> uncoverable).
    def test_go_receiver_method_sink_fn_yields_bare_key(self):
        sink = {
            "fn": "(github.com/provlabs/vault/keeper.msgServer).BridgeBurnShares",
            "file": "/root/audits/nuva/src/vault/keeper/msg_server.go",
        }
        keys = BUILD._sink_fn_keys(sink)
        self.assertIn("bridgeburnshares", keys)
        self.assertIn("msg_server.go::bridgeburnshares", keys)

    def test_solidity_sink_fn_key_extraction_unchanged(self):
        sink = {"fn": "Vault.withdraw(uint256,address)", "file": "src/Vault.sol"}
        keys = BUILD._sink_fn_keys(sink)
        self.assertIn("withdraw", keys)
        self.assertIn("vault.withdraw", keys)
        self.assertIn("vault.sol::withdraw", keys)

    # Case 11: schema constants are stable.
    def test_schema_constants(self):
        self.assertEqual(BUILD.SCHEMA, "auditooor.depth_certificate_build.v1")
        self.assertEqual(BUILD.CERT_SCHEMA, "auditooor.depth_certificate.v1")
        self.assertTrue(callable(BUILD.build_certificate))
        self.assertTrue(callable(BUILD.write_certificate))


if __name__ == "__main__":
    unittest.main()
