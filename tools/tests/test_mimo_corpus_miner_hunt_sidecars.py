#!/usr/bin/env python3
"""Guard: mimo-corpus-miner consumes the BRIDGED hunt verdict sidecars.

Adversarial-verify gap (L7): the miner's sidecar glob only matched the DERIVED
mimo_harness_/haiku_harness_ dirs and parse_sidecar only accepted the MIMO-API
wrapper schema {"status":"ok","result":"```json...```"}. The real per-fn hunt
verdicts live FLAT at <ws>/.auditooor/hunt_findings_sidecars/*.json
({"unit":..., "verdict":"NEGATIVE", "analysis":[...]}), so a per-workspace mine
scanned 0 of them.

This test feeds N flat hunt_findings_sidecars/*.json and asserts:
  - parse_sidecar accepts the flat schema (returns the dict as the verdict obj),
  - a --workspace mine scans/parses all N (sidecars_scanned == N),
  - non-zero signal is emitted,
  - false-green-safe: a dict with no verdict signal still parses to None,
  - the legacy MIMO-API wrapper schema still parses.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "mimo_corpus_miner", str(_TOOLS / "mimo-corpus-miner.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["mimo_corpus_miner"] = m
spec.loader.exec_module(m)


def _flat_sidecar(unit: str, verdict: str = "NEGATIVE") -> dict:
    return {
        "unit": unit,
        "file_line": "src/contracts/Tranche.sol:209",
        "verdict": verdict,
        "analysis": ["atomic rollback protects partial state"],
        "attack_classes_checked": ["reentrancy", "erc4626-share-inflation"],
    }


class FlatHuntSidecarParse(unittest.TestCase):
    def test_flat_schema_parses_to_verdict_object(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Tranche_deposit_mint.json"
            p.write_text(json.dumps(_flat_sidecar("Tranche.deposit/mint")))
            parsed = m.parse_sidecar(p)
            self.assertIsNotNone(parsed)
            # the flat dict itself IS the verdict object
            self.assertEqual(parsed["verdict"]["unit"], "Tranche.deposit/mint")
            # NEGATIVE normalizes to the "no" applies_to_target token
            self.assertEqual(parsed["verdict"]["applies_to_target"], "no")

    def test_no_verdict_signal_is_false_green_safe(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "noise.json"
            p.write_text(json.dumps({"unit": "x", "note": "no verdict here"}))
            self.assertIsNone(m.parse_sidecar(p))

    def test_legacy_mimo_api_wrapper_still_parses(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "legacy.json"
            inner = {"applies_to_target": "no", "candidate_finding": ""}
            p.write_text(json.dumps(
                {"status": "ok", "result": "```json\n" + json.dumps(inner) + "\n```"}))
            parsed = m.parse_sidecar(p)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed["verdict"]["applies_to_target"], "no")


class WorkspaceMineScansHuntSidecars(unittest.TestCase):
    def test_workspace_mine_scans_all_flat_sidecars(self):
        n = 5
        with tempfile.TemporaryDirectory() as ws_root, \
                tempfile.TemporaryDirectory() as auditooor_root:
            ws = Path(ws_root)
            hf = ws / ".auditooor" / "hunt_findings_sidecars"
            hf.mkdir(parents=True)
            # one YES so the yield matrix carries a real signal cell
            for i in range(n - 1):
                (hf / f"unit_{i}.json").write_text(json.dumps(
                    _flat_sidecar(f"Mod.fn{i}", "NEGATIVE")))
            (hf / f"unit_{n - 1}.json").write_text(json.dumps(
                _flat_sidecar(f"Mod.fn{n - 1}", "POSITIVE")))

            # redirect the miner's output dirs into a temp root so the real repo
            # corpus is untouched.
            old_root, old_derived, old_reports = m.AUDITOOOR_ROOT, m.DERIVED, m.REPORTS
            try:
                m.AUDITOOOR_ROOT = Path(auditooor_root)
                m.DERIVED = Path(auditooor_root) / "audit" / "corpus_tags" / "derived"
                m.REPORTS = Path(auditooor_root) / "reports"
                m.DERIVED.mkdir(parents=True)
                rc = m.main(["--workspace", str(ws),
                             "--audits-root", str(Path(auditooor_root) / "noaudits"),
                             "--json"])
            finally:
                m.AUDITOOOR_ROOT, m.DERIVED, m.REPORTS = old_root, old_derived, old_reports

            self.assertEqual(rc, 0)
            yield_path = (Path(auditooor_root) / "audit" / "corpus_tags"
                          / "derived" / "mimo_observed_yield.json")
            self.assertTrue(yield_path.exists())
            data = json.loads(yield_path.read_text())
            # all N flat sidecars scanned + parsed
            self.assertEqual(data["sidecars_scanned"], n)
            # non-zero signal: at least one (ws x class) yield cell emitted
            cells = sum(len(v) for v in data["by_workspace"].values())
            self.assertGreater(cells, 0)


if __name__ == "__main__":
    unittest.main()
