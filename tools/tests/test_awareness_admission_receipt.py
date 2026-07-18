from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "awareness-admission-receipt.py"


def _load():
    spec = importlib.util.spec_from_file_location("awareness_admission_receipt", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = _load()
PIN = "a" * 40
PIN_HASH = "b" * 64
TYPES = sorted(mod.SOURCE_TYPES)


def receipt(classification="team_aware"):
    sources = [
        {
            "source_id": f"src-{idx}",
            "source_type": source_type,
            "status": "reviewed",
            "team_awareness": "team_aware",
            "repository": "https://example.invalid/repository",
            "source_commit": PIN,
            "stable_ref": f"ref-{idx}",
            "snapshot_sha256": str(idx + 1) * 64,
            "audit_pin_sha256": PIN_HASH,
            "review_receipt": {"receipt_id": f"review-{idx}", "reviewer": "reviewer-1"},
        }
        for idx, source_type in enumerate(TYPES)
    ]
    evidence = {"fix_verification": "verified_at_current_pin", "fix_source_id": "src-0"}
    if classification == "fixed_bypass":
        evidence = {
            "fix_verification": "bypass_at_current_pin",
            "exact_source_ref": "src-0:line-10",
            "exact_exploit_ref": "proof:case-1",
        }
    return {
        "schema": mod.SCHEMA,
        "receipt_id": "receipt-1",
        "audit_pin": {"commit": PIN, "pin_sha256": PIN_HASH},
        "source_inventory": {
            "status": "complete",
            "coverage_status": "complete",
            "expected_source_types": TYPES,
            "sources": sources,
        },
        "semantic_decisions": [{
            "decision_id": "decision-1",
            "source_ids": ["src-0"],
            "classification": classification,
            "rationale": "semantic review conclusion",
            "root_cause": "root cause normalized from the reviewed source",
            "affected_execution_path": "the affected production execution path",
            "required_remediation": "the required remediation primitive",
            "evidence": evidence,
        }],
    }


def discovery_for(payload):
    sources = [
        {
            "source_id": source["source_id"],
            "source_kind": "issue",
            "source_ref": source["stable_ref"],
            "pin_binding": PIN,
        }
        for source in payload["source_inventory"]["sources"]
    ]
    payload["source_inventory"]["discovery_sources_sha256"] = mod.canonical_sha256(sources)
    return {"schema": mod.DISCOVERY_SCHEMA, "audit_pin": PIN, "sources": sources}


class AwarenessReceiptTest(unittest.TestCase):
    def test_team_aware_is_valid_but_excluded(self):
        payload = receipt()
        result = mod.validate_receipt(payload, discovery_for(payload))
        self.assertTrue(result.valid)
        self.assertFalse(result.promotion_allowed)
        self.assertEqual(result.excluded_decision_ids, ["decision-1"])

    def test_verified_fixed_is_closed(self):
        payload = receipt("verified_fixed")
        result = mod.validate_receipt(payload, discovery_for(payload))
        self.assertTrue(result.valid)
        self.assertFalse(result.promotion_allowed)
        self.assertEqual(result.closed_decision_ids, ["decision-1"])

    def test_fixed_bypass_requires_exact_source_and_exploit_evidence(self):
        payload = receipt("fixed_bypass")
        discovery = discovery_for(payload)
        result = mod.validate_receipt(payload, discovery)
        self.assertTrue(result.valid)
        self.assertTrue(result.promotion_allowed)
        payload["semantic_decisions"][0]["evidence"].pop("exact_exploit_ref")
        result = mod.validate_receipt(payload, discovery)
        self.assertFalse(result.valid)
        self.assertFalse(result.promotion_allowed)

    def test_unknown_or_incomplete_blocks_promotion(self):
        for classification in ("unknown", "incomplete"):
            payload = receipt(classification)
            result = mod.validate_receipt(payload, discovery_for(payload))
            self.assertFalse(result.valid)
            self.assertFalse(result.promotion_allowed)
            self.assertIn("decision-1", result.blocked_decision_ids)

    def test_partial_history_and_audit_pin_binding_mismatch_fail_closed(self):
        payload = receipt()
        payload["source_inventory"]["sources"] = payload["source_inventory"]["sources"][:-1]
        payload["source_inventory"]["coverage_status"] = "partial"
        payload["source_inventory"]["sources"][0]["audit_pin_sha256"] = "c" * 64
        result = mod.validate_receipt(payload, discovery_for(payload))
        self.assertFalse(result.valid)
        self.assertTrue(any("incomplete canonical source coverage" in error for error in result.errors))
        self.assertTrue(any("differs from audit pin" in error for error in result.errors))

    def test_receipt_cannot_omit_a_discovered_source(self):
        payload = receipt("fixed_bypass")
        discovery = discovery_for(payload)
        discovery["sources"].append({
            "source_id": "commit:acme/vault:" + "c" * 40,
            "source_kind": "commit",
            "source_ref": "https://github.com/acme/vault/commit/" + "c" * 40,
            "pin_binding": PIN,
        })
        result = mod.validate_receipt(payload, discovery)
        self.assertFalse(result.valid)
        self.assertTrue(any("exactly cover canonical discovery" in error for error in result.errors))

    def test_historical_source_commit_is_allowed_when_review_is_bound_to_audit_pin(self):
        payload = receipt("verified_fixed")
        payload["source_inventory"]["sources"][0]["source_commit"] = "d" * 40
        result = mod.validate_receipt(payload, discovery_for(payload))
        self.assertTrue(result.valid)
        self.assertFalse(result.promotion_allowed)

    def test_malformed_known_and_fixed_classifications_fail_closed(self):
        for classification in ("known-ish", "fixed", "marked_fixed"):
            payload = receipt(classification)
            result = mod.validate_receipt(payload, discovery_for(payload))
            self.assertFalse(result.valid)
            self.assertFalse(result.promotion_allowed)

    def test_cli_json_pass_and_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            discovery_path = Path(tmp) / "discovery.json"
            payload = receipt("fixed_bypass")
            discovery = discovery_for(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
            passed = subprocess.run([sys.executable, str(TOOL), str(path), "--discovery", str(discovery_path), "--json"], text=True, capture_output=True)
            self.assertEqual(passed.returncode, 0)
            self.assertTrue(json.loads(passed.stdout)["promotion_allowed"])
            payload = receipt("unknown")
            discovery = discovery_for(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
            failed = subprocess.run([sys.executable, str(TOOL), str(path), "--discovery", str(discovery_path), "--json"], text=True, capture_output=True)
            self.assertEqual(failed.returncode, 1)
            self.assertFalse(json.loads(failed.stdout)["promotion_allowed"])

    def test_cli_accepts_valid_exclusion_but_promotion_mode_rejects_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            discovery_path = Path(tmp) / "discovery.json"
            payload = receipt("team_aware")
            discovery = discovery_for(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
            validated = subprocess.run([sys.executable, str(TOOL), str(path), "--discovery", str(discovery_path)], text=True, capture_output=True)
            self.assertEqual(validated.returncode, 0)
            self.assertIn("promotion withheld", validated.stdout)
            promotion = subprocess.run(
                [sys.executable, str(TOOL), str(path), "--discovery", str(discovery_path), "--require-promotion"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(promotion.returncode, 1)


if __name__ == "__main__":
    unittest.main()
