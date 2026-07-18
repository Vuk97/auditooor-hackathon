"""Tests for tools/invariant-grounded-finding-check.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "invariant_grounded_finding_check",
    ROOT / "tools" / "invariant-grounded-finding-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


class InvariantGroundedFindingCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="r58_invariant_")
        self.root = Path(self.tmp.name)
        self.index = self.root / "invariant_library_index.json"
        self.pilot_audited = self.root / "invariants_pilot_audited.jsonl"
        self.pilot = self.root / "invariants_pilot.jsonl"
        self.extracted = self.root / "invariants_extracted.jsonl"
        self.draft = self.root / "draft.md"
        self.index.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.invariant_library_index.v1",
                    "reverse_lookup_finding_to_invariant": {
                        "bridge-attacks:wormhole-2022:signature-replay": ["INV-UNI-001"],
                        "prior-audit:amm:callback-reentrancy": ["INV-ATM-EX-0001"],
                    },
                }
            ),
            encoding="utf-8",
        )
        self.pilot.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.invariant_pilot.v1",
                    "invariant_id": "INV-UNI-001",
                    "category": "uniqueness",
                    "attack_signature": "signature-replay|bridge-message-replay",
                    "statement": "A signed cross-chain message MUST be consumable at most once.",
                    "source_finding_ids": ["bridge-attacks:wormhole-2022:signature-replay"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.extracted.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.invariant_extraction.v1",
                    "invariant_id": "INV-ATM-EX-0001",
                    "category": "atomicity",
                    "attack_signature": "callback-reentrancy|reentrancy",
                    "statement": "External calls MUST NOT happen before state writes commit.",
                    "source_finding_ids": ["prior-audit:amm:callback-reentrancy"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.pilot_audited.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, body: str) -> Path:
        self.draft.write_text(body, encoding="utf-8")
        return self.draft

    def _run(self, draft: Path | None = None, *, severity: str | None = None) -> tuple[int, dict]:
        return mod.run(
            draft or self.draft,
            severity_override=severity,
            index_path=self.index,
            pilot_audited_path=self.pilot_audited,
            pilot_path=self.pilot,
            extracted_path=self.extracted,
            strict=True,
        )

    def _run_discovery(
        self,
        draft: Path,
        *,
        workspace: Path,
        severity: str | None = None,
    ) -> tuple[int, dict]:
        return mod.run_with_discovery(
            draft,
            workspace=workspace,
            severity_override=severity,
            index_path=self.index,
            pilot_audited_path=self.pilot_audited,
            pilot_path=self.pilot,
            extracted_path=self.extracted,
            strict=True,
        )

    def test_passes_when_invariant_id_is_indexed(self) -> None:
        self._write(
            "Severity: Medium\n"
            "attack_class: signature-replay\n\n"
            "Invariant grounding: INV-UNI-001 covers the replay predicate.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["schema"], "auditooor.r58_invariant_grounded_finding.v1")
        self.assertEqual(payload["verdict"], "pass-invariant-cited-and-indexed")
        self.assertEqual(payload["cited_invariant_ids"], ["INV-UNI-001"])
        self.assertEqual(payload["cited_unaudited_invariant_ids"], ["INV-UNI-001"])

    def test_tracks_audited_citations_when_audited_subset_contains_id(self) -> None:
        self.pilot_audited.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.invariant_pilot.v1",
                    "invariant_id": "INV-UNI-001",
                    "category": "uniqueness",
                    "quality_audited": True,
                    "audit_verdict": "TRUE-POSITIVE",
                    "source_finding_ids": ["bridge-attacks:wormhole-2022:signature-replay"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self._write(
            "Severity: Medium\n"
            "attack_class: signature-replay\n\n"
            "Invariant grounding: INV-UNI-001 covers the replay predicate.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["cited_audited_invariant_ids"], ["INV-UNI-001"])
        self.assertEqual(payload["cited_unaudited_invariant_ids"], [])

    def test_fails_when_cited_invariant_is_not_indexed(self) -> None:
        self._write(
            "Severity: High\n"
            "attack_class: signature-replay\n\n"
            "Invariant grounding: INV-NOT-999 should exist but is not in the corpus.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-invariant-cited-but-not-indexed")
        self.assertEqual(payload["unknown_cited_invariant_ids"], ["INV-NOT-999"])

    def test_fails_closed_when_known_class_has_no_invariant_citation(self) -> None:
        self._write(
            "Severity: Medium\n"
            "attack_class: callback-reentrancy\n\n"
            "The external callback happens before the accounting write commits.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-invariant-cited-but-class-has-known-invariant")
        self.assertIn("INV-ATM-EX-0001", payload["evidence"]["class_matched_invariant_ids"])

    def test_index_only_reverse_lookup_can_trigger_known_class(self) -> None:
        self.pilot.write_text("", encoding="utf-8")
        self.extracted.write_text("", encoding="utf-8")
        self._write(
            "Severity: Medium\n"
            "attack_class: signature-replay\n\n"
            "The proof replays a signed message.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-invariant-cited-but-class-has-known-invariant")
        self.assertEqual(payload["evidence"]["class_matched_invariant_ids"], ["INV-UNI-001"])

    def test_accepts_html_rebuttal(self) -> None:
        self._write(
            "Severity: High\n"
            "attack_class: signature-replay\n"
            "<!-- r58-rebuttal: new target-specific invariant not yet in the library -->\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_low_severity_is_out_of_scope(self) -> None:
        self._write(
            "Severity: Low\n"
            "attack_class: signature-replay\n\n"
            "No invariant citation is present.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_unknown_class_requires_citation_or_no_binding_reason(self) -> None:
        self._write(
            "Severity: High\n"
            "attack_class: target-specific-edge\n\n"
            "The proof packet claims a high severity invariant-like violation.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-invariant-cited-or-binding-justification")

    def test_high_unknown_class_accepts_no_binding_reason(self) -> None:
        self._write(
            "Severity: High\n"
            "attack_class: target-specific-edge\n"
            "<!-- r58-no-invariant-binding: source-only parser bug with no reusable invariant family -->\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_placeholder_rebuttal_is_not_accepted(self) -> None:
        self._write(
            "Severity: High\n"
            "attack_class: target-specific-edge\n"
            "<!-- r58-rebuttal: <reason> -->\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-invariant-cited-or-binding-justification")

    def test_json_proof_packet_severity_and_attack_class_are_parsed(self) -> None:
        self._write(
            json.dumps(
                {
                    "packets": [
                        {
                            "candidate_id": "hb-arbitrum-orbit-unconfirmed-node-HIGH",
                            "severity_claim": "high",
                            "attack_class": "theft",
                            "title": "loss of bridged funds",
                        }
                    ]
                },
                indent=2,
            )
        )
        self.index.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.invariant_library_index.v1",
                    "reverse_lookup_finding_to_invariant": {
                        "immunefi-public:28934:d3eb62407b57": ["INV-AUTH-009"],
                    },
                }
            ),
            encoding="utf-8",
        )
        self.pilot.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.invariant_pilot.v1",
                    "invariant_id": "INV-AUTH-009",
                    "category": "authorization",
                    "attack_signature": "theft|unauthorized-loss",
                    "statement": "A token-burning path MUST be authorized by the caller who loses value.",
                    "source_finding_ids": ["immunefi-public:28934:d3eb62407b57"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.extracted.write_text("", encoding="utf-8")

        rc, payload = self._run(severity=None)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_observed"], "high")
        self.assertEqual(payload["severity_source"], "proof-packet-severity")
        self.assertEqual(payload["attack_class_observed"], "theft")
        self.assertEqual(payload["verdict"], "fail-no-invariant-cited-but-class-has-known-invariant")
        self.assertIn("INV-AUTH-009", payload["evidence"]["class_matched_invariant_ids"])

    def test_markdown_proof_packet_severity_claim_is_parsed(self) -> None:
        self._write(
            "# Candidate Judgment Packet\n\n"
            "- Severity claim: `high`\n"
            "- No invariant binding: source-only parser bug with no reusable invariant family.\n"
        )
        rc, payload = self._run(severity=None)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["severity_observed"], "high")
        self.assertEqual(payload["severity_source"], "proof-packet-severity")
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_discovery_fails_relevant_auditooor_proof_packet_sidecar(self) -> None:
        ws = self.root / "ws"
        draft = ws / "submissions" / "staging" / "callback-drain" / "source-draft.md"
        aud = ws / ".auditooor"
        aud.mkdir(parents=True)
        draft.parent.mkdir(parents=True)
        draft.write_text(
            "Severity: High\n"
            "attack_class: callback-reentrancy\n\n"
            "Invariant grounding: INV-ATM-EX-0001 covers the callback ordering invariant.\n",
            encoding="utf-8",
        )
        (aud / "callback-drain-proof-packet.json").write_text(
            json.dumps(
                {
                    "submission_path": "submissions/staging/callback-drain/source-draft.md",
                    "severity_claim": "high",
                    "attack_class": "callback-reentrancy",
                    "summary": "packet forgot invariant grounding",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        rc, payload = self._run_discovery(draft, workspace=ws, severity="High")
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-batch")
        self.assertEqual(payload["discovery"]["matched_count"], 1)
        sidecars = [r for r in payload["results"] if r["kind"] == "discovered-proof-packet-sidecar"]
        self.assertEqual(len(sidecars), 1)
        self.assertEqual(sidecars[0]["verdict"], "fail-no-invariant-cited-but-class-has-known-invariant")

    def test_discovery_ignores_unrelated_proof_packet_sidecar(self) -> None:
        ws = self.root / "ws"
        draft = ws / "submissions" / "staging" / "callback-drain" / "source-draft.md"
        aud = ws / ".auditooor"
        aud.mkdir(parents=True)
        draft.parent.mkdir(parents=True)
        draft.write_text(
            "Severity: High\n"
            "attack_class: callback-reentrancy\n\n"
            "Invariant grounding: INV-ATM-EX-0001 covers the callback ordering invariant.\n",
            encoding="utf-8",
        )
        (aud / "other-finding-proof-packet.json").write_text(
            json.dumps(
                {
                    "submission_path": "submissions/staging/other-finding/source-draft.md",
                    "severity_claim": "high",
                    "attack_class": "callback-reentrancy",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        rc, payload = self._run_discovery(draft, workspace=ws, severity="High")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["discovery"]["matched_count"], 0)
        self.assertEqual(payload["results"][0]["verdict"], "pass-invariant-cited-and-indexed")

    def test_discovery_is_immediate_auditooor_only_and_does_not_edit_draft(self) -> None:
        ws = self.root / "ws"
        draft = ws / "submissions" / "staging" / "callback-drain" / "source-draft.md"
        nested = ws / ".auditooor" / "nested"
        nested.mkdir(parents=True)
        draft.parent.mkdir(parents=True)
        body = (
            "Severity: High\n"
            "attack_class: callback-reentrancy\n\n"
            "Invariant grounding: INV-ATM-EX-0001 covers the callback ordering invariant.\n"
        )
        draft.write_text(body, encoding="utf-8")
        (nested / "callback-drain-proof-packet.json").write_text(
            json.dumps(
                {
                    "submission_path": "submissions/staging/callback-drain/source-draft.md",
                    "severity_claim": "high",
                    "attack_class": "callback-reentrancy",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        rc, payload = self._run_discovery(draft, workspace=ws, severity="High")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["discovery"]["matched_count"], 0)
        self.assertEqual(draft.read_text(encoding="utf-8"), body)


class PreSubmitR58WiringTests(unittest.TestCase):
    def test_pre_submit_wires_check_105_as_medium_plus_gate(self) -> None:
        pre_submit = (ROOT / "tools" / "pre-submit-check.sh").read_text(encoding="utf-8")
        self.assertIn("Check #105: R58-INVARIANT-GROUNDED-FINDING", pre_submit)
        self.assertIn("tools/invariant-grounded-finding-check.py", pre_submit)
        self.assertIn("--discover-sidecars", pre_submit)
        self.assertIn("MEDIUM|HIGH|CRITICAL", pre_submit)
        self.assertIn("fail-no-invariant-cited-but-class-has-known-invariant", pre_submit)
        self.assertIn("fail-no-invariant-cited-or-binding-justification", pre_submit)


if __name__ == "__main__":
    unittest.main()
