#!/usr/bin/env python3
# r36-rebuttal: lane finding-sidecars-etl registered 2 files via tools/agent-pathspec-register.py at lane start
"""Tests for tools/hackerman-etl-from-finding-sidecars.py.

Covers:
  1. CONFIRMED sidecar (CRITICAL severity) -> 1 INV + 1 detector record.
  2. CONFIRMED staging draft -> INV + detector record (draft path).
  3. DROPPED sidecar (verdict=VERIFIED-SOUND) -> KDE record with drop_class.
  4. fixed-at-pin vs oos vs defended-sound drop sub-classification.
  5. Every INV + detector record carries a non-empty verification_tier (R37).
  6. Idempotent: re-running --dry-run yields identical confirmed counts, and
     a second non-dry-run does not duplicate KDE records.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "hackerman-etl-from-finding-sidecars.py"
_spec = importlib.util.spec_from_file_location("finding_sidecars_etl", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _make_workspace(tmp: Path) -> Path:
    ws = tmp / "audits" / "testchain"
    sc = ws / ".auditooor" / "hunt_findings_sidecars"
    sc.mkdir(parents=True, exist_ok=True)

    # CONFIRMED sidecar (CRITICAL, no drop verdict)
    _write_json(sc / "confirmed-bsc.json", {
        "schema": "auditooor.hunt_finding_sidecar.v1",
        "slug": "bsc-epoch-ancestry-injection",
        "title": "BSC verifier accepts unanchored epoch ancestry (validator-set injection)",
        "proposed_severity": "CRITICAL",
        "audit_pin": "70c8429d9b",
        "affected_component": "modules/consensus/bsc/verifier/src/lib.rs:123",
        "summary": "Attacker installs an attacker-chosen validator set; drain bridged funds.",
        "rubric_row": "Bridge logic failure enabling unauthorized asset movement / theft",
        "pin_evidence": ["lib.rs:123-150 only hash-linkage checked"],
        "fix_evidence": ["commit 61bf3c38 anchors epoch_header_ancestry[0].number"],
        "attack_class": "consensus-validator-set-injection",
        "state_evidence": {
            "role": "producer-consumer",
            "source_refs": ["modules/consensus/bsc/verifier/src/lib.rs:123"],
            "produces_state": ["state:invalid-validator-set-accepted"],
            "requires_state": ["state:unanchored-epoch-header"],
        },
    })

    # DROPPED sidecar (verified-sound)
    _write_json(sc / "dropped-sound.json", {
        "schema": "auditooor.hunt_finding_sidecar.v1",
        "slug": "intentgw-some-sound-path",
        "title": "IntentGateway some path",
        "verdict": "VERIFIED-SOUND-NO-FINDING",
        "audit_pin": "70c8429d9b",
        "file_line": "contracts/IntentGateway.sol:200",
        "why_dropped": "The duplicate guard at line 244 blocks the second payout.",
        "attack_class": "fee-accounting",
    })

    # DROPPED sidecar (fixed-at-pin)
    _write_json(sc / "dropped-fixed.json", {
        "schema": "auditooor.hunt_finding_sidecar.v1",
        "slug": "grandpa-multi-set-change",
        "title": "GRANDPA multi set change",
        "verdict": "KILLED-NOT-LIVE-AT-PIN",
        "audit_pin": "70c8429d9b",
        "file_line": "modules/consensus/grandpa/src/lib.rs:88",
        "attack_class": "consensus-validator-set-injection",
    })

    # DROPPED sidecar (out-of-scope)
    _write_json(sc / "dropped-oos.json", {
        "schema": "auditooor.hunt_finding_sidecar.v1",
        "slug": "vat-sweep-screening",
        "title": "Vat sweep screening",
        "verdict": "out-of-scope",
        "file_line": "contracts/Vat.sol:10",
    })

    # CONFIRMED staging draft
    draft_dir = ws / "submissions" / "staging" / "hb-intentgw-partial-fill-HIGH"
    draft_dir.mkdir(parents=True, exist_ok=True)
    (draft_dir / "hb-intentgw-partial-fill-HIGH.md").write_text(
        "# IntentGateway partial fill skips calldata validation leading to theft\n\n"
        "- Severity: High\n"
        "- Impact(s): direct loss of funds via skipped calldata\n"
        "- Audit pin: `70c8429d9b`\n"
        "- Component: `modules/ismp/intent-gateway`\n"
        "attack_class: theft\n",
        encoding="utf-8")

    return ws


class TestFindingSidecarsEtl(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = _make_workspace(self.tmp)
        # redirect the canonical KDE path to a tmp file so tests don't touch
        # the real reports/known_dead_ends.jsonl
        self._orig_kde = mod.KDE_PATH
        mod.KDE_PATH = self.tmp / "reports" / "known_dead_ends.jsonl"
        self._orig_inv = mod.INV_BATCH_ROOT
        self._orig_det = mod.DET_BATCH_ROOT
        mod.INV_BATCH_ROOT = self.tmp / "derived" / "invariant_library_extended"
        mod.DET_BATCH_ROOT = self.tmp / "derived" / "detector_synthesis_v2"

    def tearDown(self):
        mod.KDE_PATH = self._orig_kde
        mod.INV_BATCH_ROOT = self._orig_inv
        mod.DET_BATCH_ROOT = self._orig_det
        self._tmp.cleanup()

    def _run(self, dry_run: bool):
        return mod.run(self.ws, "test-batch", dry_run=dry_run, limit=None)

    def test_confirmed_emits_invariant_and_detector(self):
        s = self._run(dry_run=True)
        # 1 confirmed sidecar + 1 staging draft = 2 confirmed findings
        self.assertEqual(s["confirmed_findings"], 2)
        self.assertEqual(s["invariant_records"], 2)
        self.assertEqual(s["detector_seed_records"], 2)

    def test_dropped_emits_kde(self):
        s = self._run(dry_run=True)
        # 3 dropped sidecars (sound, fixed-at-pin, oos)
        self.assertEqual(s["dropped_candidates"], 3)

    def test_aggregate_jsonl_rejected_rows_emit_kde(self):
        # The README-endorsed Agent-dispatch hunt path emits ONE aggregate *.jsonl
        # per batch with many verdict rows (verdict=REJECTED/OOS). The ETL globbed
        # only *.json -> these were dropped on the floor (0 dead-ends banked despite
        # thousands of ruled-out verdicts). Assert they are now read AND that
        # REJECTED is a recognized kill verdict.
        sc = self.ws / ".auditooor" / "hunt_findings_sidecars"
        rows = [
            {"unit_id": "U1", "file_line": "src/X.sol:10", "verdict": "REJECTED",
             "code_excerpt": "require(msg.sender==owner)", "in_scope": True,
             "why_dropped": "onlyOwner gate; unprivileged attacker cannot reach"},
            {"unit_id": "U2", "file_line": "src/Y.sol:20", "verdict": "OOS",
             "code_excerpt": "func helper()", "in_scope": False,
             "why_dropped": "unmodified upstream go-ethereum"},
        ]
        (sc / "batch_000_verdicts.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        before = self._run(dry_run=True)["dropped_candidates"]
        # 3 single-object drops + 2 aggregate-jsonl REJECTED/OOS rows = 5
        self.assertGreaterEqual(before, 5,
                                "aggregate *.jsonl REJECTED/OOS rows must be read + banked")
        # REJECTED must be a recognized kill verdict
        self.assertIn("REJECTED", mod.KILL_VERDICT_TOKENS)

    def test_drop_class_subclassification(self):
        self._run(dry_run=False)
        recs = [json.loads(l) for l in mod.KDE_PATH.read_text().splitlines() if l.strip()]
        by_slug = {r["candidate_id"]: r for r in recs}
        self.assertEqual(by_slug["intentgw-some-sound-path"]["drop_class"], "defended-sound")
        self.assertEqual(by_slug["grandpa-multi-set-change"]["drop_class"], "fixed-at-pin")
        self.assertEqual(by_slug["vat-sweep-screening"]["drop_class"], "oos")
        for r in recs:
            self.assertEqual(r["schema_version"], "auditooor.known_dead_end.v1")

    def test_every_inv_and_detector_has_tier(self):
        self._run(dry_run=False)
        inv_dir = mod.INV_BATCH_ROOT / "test-batch"
        det_dir = mod.DET_BATCH_ROOT / "test-batch"
        inv_files = list(inv_dir.glob("INV-*.yaml"))
        det_files = list(det_dir.glob("*.json"))
        self.assertEqual(len(inv_files), 2)
        self.assertEqual(len(det_files), 2)
        for f in inv_files:
            body = f.read_text().split("---\n", 1)[1]
            rec = json.loads(body)
            self.assertTrue(rec["verification_tier"])
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            self.assertTrue(rec.get("tier_decision"))
            self.assertTrue(rec["content"]["invariant_id"].startswith("INV-FINDING-"))
        for f in det_files:
            rec = json.loads(f.read_text())
            self.assertTrue(rec["verification_tier"])
            self.assertEqual(rec["status"], "ok")
            # detector payload round-trips
            payload = json.loads(rec["result"])
            self.assertIn("detector_sketch", payload)
            self.assertTrue(payload["attack_class"])

    def test_confirmed_invariant_gets_source_backed_chain_metadata(self):
        self._run(dry_run=False)
        inv_dir = mod.INV_BATCH_ROOT / "test-batch"
        records = []
        for f in inv_dir.glob("INV-*.yaml"):
            body = f.read_text().split("---\n", 1)[1]
            records.append(json.loads(body))
        by_slug = {r["source"]["slug"]: r for r in records}

        confirmed = by_slug["bsc-epoch-ancestry-injection"]
        expected_refs = ["modules/consensus/bsc/verifier/src/lib.rs:123"]
        self.assertEqual(confirmed["source_refs"], expected_refs)
        self.assertEqual(confirmed["content"]["source_refs"], expected_refs)
        self.assertEqual(
            confirmed["produces_state"],
            ["state:invalid-validator-set-accepted"],
        )
        self.assertEqual(
            confirmed["requires_state"],
            ["state:unanchored-epoch-header"],
        )
        self.assertEqual(confirmed["producer_source_refs"], expected_refs)
        self.assertEqual(confirmed["consumer_source_refs"], expected_refs)

        draft = by_slug["hb-intentgw-partial-fill-high"]
        self.assertNotIn("source_refs", draft)
        self.assertNotIn("produces_state", draft)

    def test_idempotent(self):
        s1 = self._run(dry_run=True)
        s2 = self._run(dry_run=True)
        self.assertEqual(s1["confirmed_findings"], s2["confirmed_findings"])
        self.assertEqual(s1["dropped_candidates"], s2["dropped_candidates"])
        # first real run appends KDE
        r1 = self._run(dry_run=False)
        self.assertEqual(r1["new_kde_records"], 3)
        recs1 = len([l for l in mod.KDE_PATH.read_text().splitlines() if l.strip()])
        # second real run dedupes by record_id -> no new KDE
        r2 = self._run(dry_run=False)
        self.assertEqual(r2["new_kde_records"], 0)
        recs2 = len([l for l in mod.KDE_PATH.read_text().splitlines() if l.strip()])
        self.assertEqual(recs1, recs2)
        # INV files are content-deterministic (same record_id filenames)
        inv_dir = mod.INV_BATCH_ROOT / "test-batch"
        self.assertEqual(len(list(inv_dir.glob("INV-*.yaml"))), 2)

    def test_draft_path_attack_class_parsed(self):
        findings, draft_slugs = mod._iter_artifacts(self.ws, "testchain")
        drafts = [f for f in findings if f.get("_is_draft")]
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0]["attack_class"], "theft")
        self.assertEqual(drafts[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
