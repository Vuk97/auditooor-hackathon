# <!-- r36-rebuttal: PR8a-chain-synth-proof lane; file declared in .auditooor/agent_pathspec.json -->
"""tests/test_chain_synth_driver.py - PR8a proof-seeking unit tests.

Covers the proof-seeking decomposition added in PR8a:
  1. _is_real_evidence: file:line and proof-obligation ids pass; placeholders fail.
  2. build_invariant_evidence_index: harvests real evidence per INV-* from the
     exploit queue, attributing entry evidence to referenced invariants.
  3. _template_invariant_hops: ordered de-dup across member/matched fields.
  4. decorate_template_with_hop_evidence: a chain ADVANCES iff every hop has
     evidence plus source-backed composition linkage; a missing hop or missing
     linkage blocks the chain.
  5. empty-hop template never advances.
  6. build_chain_proof_obligation: one multi-hop obligation per composed chain.
  7. write_proof_obligations: idempotent merge by obligation_id.

No network; pure unit tests on the proof-seeking helpers.
"""
from __future__ import annotations

import importlib.util
import io
import json
from unittest import mock
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "chain-synth-driver.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("chain_synth_driver", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


csd = _load_module()


class TestIsRealEvidence(unittest.TestCase):
    def test_file_line_citation_passes(self):
        self.assertTrue(csd._is_real_evidence("src/Gateway.sol:142"))
        self.assertTrue(csd._is_real_evidence("pallet-ismp/src/lib.rs:256"))

    def test_proof_obligation_id_passes(self):
        self.assertTrue(csd._is_real_evidence("PO-cross-chain-replay-7"))
        self.assertTrue(csd._is_real_evidence("OBL-42"))
        self.assertTrue(csd._is_real_evidence("PA-merkle-forge"))

    def test_placeholders_fail(self):
        for bad in ("", "unknown", "manual-source", "N/A", "none", "tbd",
                    "<workspace>/.auditooor/hacker_brief.md"):
            self.assertFalse(csd._is_real_evidence(bad), bad)

    def test_non_string_fails(self):
        self.assertFalse(csd._is_real_evidence(None))
        self.assertFalse(csd._is_real_evidence(123))


class TestEvidenceIndex(unittest.TestCase):
    def _ws_with_queue(self, tmp: str, queue: dict) -> Path:
        ws = Path(tmp) / "ws"
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps(queue))
        return ws

    def test_single_row_multi_invariant_evidence_is_not_broadcast(self):
        queue = {
            "queue": [
                {
                    "lead_id": "EQ-1",
                    "broken_invariant_ids": ["INV-A", "INV-B"],
                    "source_refs": ["src/Vault.sol:88"],
                    "proof_path": "manual-source",  # placeholder, ignored
                },
                {
                    "lead_id": "EQ-2",
                    "broken_invariant_ids": ["INV-C"],
                    "proof_artifact_precedent_refs": ["PO-conservation-12"],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
        self.assertNotIn("INV-A", idx)
        self.assertNotIn("INV-B", idx)
        self.assertEqual(idx["INV-C"], ["PO-conservation-12"])

    def test_structured_per_invariant_evidence_is_harvested(self):
        queue = {"queue": [{
            "lead_id": "EQ-1",
            "broken_invariant_ids": ["INV-A", "INV-B"],
            "invariant_evidence": {
                "INV-A": ["src/A.sol:10"],
                "INV-B": ["src/B.sol:20"],
            },
            "source_refs": ["src/Shared.sol:88"],
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
        self.assertEqual(idx["INV-A"], ["src/A.sol:10"])
        self.assertEqual(idx["INV-B"], ["src/B.sol:20"])

    def test_entry_with_only_placeholder_evidence_is_dropped(self):
        queue = {"queue": [{
            "broken_invariant_ids": ["INV-X"],
            "proof_path": "manual-source",
            "impact_path": "unknown",
            "source_refs": ["<workspace>/.auditooor/hacker_brief.md"],
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
        self.assertNotIn("INV-X", idx)

    def test_rows_without_real_queue_lead_ids_do_not_feed_chain_synth(self):
        queue = {"queue": [{
            "broken_invariant_ids": ["INV-X"],
            "source_refs": ["src/X.sol:44"],
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
            inv_ids = csd.collect_broken_invariant_ids(ws)
            lead_ids = csd.collect_current_queue_lead_ids(ws)
        self.assertEqual(idx, {})
        self.assertEqual(inv_ids, [])
        self.assertEqual(lead_ids, set())

    def test_blocked_advisory_and_dry_run_queue_rows_are_dropped(self):
        queue = {"queue": [
            {
                "lead_id": "EQ-BLOCKED",
                "status": "blocked_missing_impact_contract",
                "broken_invariant_ids": ["INV-BLOCKED"],
                "source_refs": ["src/Blocked.sol:10"],
            },
            {
                "lead_id": "EQ-ADVISORY",
                "advisory_only": True,
                "broken_invariant_ids": ["INV-ADVISORY"],
                "source_refs": ["src/Advisory.sol:20"],
            },
            {
                "lead_id": "EQ-DRY",
                "dry_run": True,
                "broken_invariant_ids": ["INV-DRY"],
                "source_refs": ["src/Dry.sol:30"],
            },
            {
                "lead_id": "EQ-LIVE",
                "status": "ready",
                "broken_invariant_ids": ["INV-LIVE"],
                "source_refs": ["src/Live.sol:40"],
            },
        ]}
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
            current_ids = csd.collect_current_queue_lead_ids(ws)
            lead_inv_ids = csd.collect_current_queue_lead_invariant_ids(ws)
            inv_ids = csd.collect_broken_invariant_ids(ws)
        self.assertEqual(idx, {"INV-LIVE": ["src/Live.sol:40"]})
        self.assertEqual(current_ids, {"EQ-LIVE"})
        self.assertEqual(lead_inv_ids, {"EQ-LIVE": {"INV-LIVE"}})
        self.assertEqual(inv_ids, ["INV-LIVE"])

    def test_inv_mentioned_in_text_gets_attributed(self):
        # No broken_invariant_ids field, but INV-Z appears in root_cause_hypothesis text.
        queue = {"queue": [{
            "lead_id": "EQ-Z",
            "root_cause_hypothesis": "breaking INV-Z at src/Bridge.sol:55 enables forge",
            "source_refs": ["src/Bridge.sol:55"],
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
        self.assertIn("INV-Z", idx)
        self.assertIn("src/Bridge.sol:55", idx["INV-Z"])

    def test_declared_single_invariant_ignores_extra_prose_invariant_for_evidence(self):
        queue = {"queue": [{
            "lead_id": "EQ-A",
            "broken_invariant_ids": ["INV-A"],
            "root_cause_hypothesis": "INV-A fails at src/A.sol:55; compare INV-B later",
            "source_refs": ["src/A.sol:55"],
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
        self.assertEqual(idx["INV-A"], ["src/A.sol:55"])
        self.assertNotIn("INV-B", idx)

    def test_full_sentence_evidence_is_normalized_to_tokens(self):
        queue = {"queue": [{
            "lead_id": "EQ-A",
            "broken_invariant_ids": ["INV-A"],
            "root_cause_hypothesis": (
                "impact at src/Bridge.sol:55 is discharged by PO-bridge-7"
            ),
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_queue(tmp, queue)
            idx = csd.build_invariant_evidence_index(ws)
        self.assertEqual(idx["INV-A"], ["src/Bridge.sol:55", "PO-bridge-7"])

    def test_ccia_dict_container_is_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / csd.CCIA_ANGLES_FILE).write_text(json.dumps({
                "attack_angles": [{
                    "angle_id": "CCIA-1",
                    "broken_invariant_ids": ["INV-CCIA"],
                    "source_refs": ["src/Ccia.sol:12"],
                }]
            }))
            idx = csd.build_invariant_evidence_index(ws)
            ids = csd.collect_broken_invariant_ids(ws)
        self.assertEqual(idx["INV-CCIA"], ["src/Ccia.sol:12"])
        self.assertEqual(ids, ["INV-CCIA"])

    def test_extra_source_link_entries_are_attributed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            entry = {
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-A",
                "to_queue_lead_id": "EQ-B",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "current_queue_verified": True,
            }
            idx = csd.build_invariant_evidence_index(ws, extra_entries=[entry])
        self.assertEqual(idx["INV-A"], ["src/A.sol:10", "src/B.sol:20"])
        self.assertEqual(idx["INV-B"], ["src/A.sol:10", "src/B.sol:20"])

    def test_unverified_extra_source_link_entries_are_not_attributed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            entry = {
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-A",
                "to_queue_lead_id": "EQ-B",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
            }
            idx = csd.build_invariant_evidence_index(ws, extra_entries=[entry])
        self.assertEqual(idx, {})


class TestTemplateHops(unittest.TestCase):
    def test_ordered_dedup_across_fields(self):
        t = {
            "member_invariant_ids": ["INV-A", "INV-B"],
            "matched_invariant_ids": ["INV-B", "INV-C"],
        }
        self.assertEqual(csd._template_invariant_hops(t), ["INV-A", "INV-B", "INV-C"])

    def test_empty_template(self):
        self.assertEqual(csd._template_invariant_hops({}), [])

    def test_matcher_chain_template_id_is_stable_id(self):
        t = {"chain_template_id": "GCT-123", "member_invariant_ids": ["INV-A"]}
        d = csd.decorate_template_with_hop_evidence(t, {"INV-A": ["src/A.sol:1"]})
        self.assertEqual(d["template_id"], "GCT-123")


class TestDecorateAndGate(unittest.TestCase):
    def test_advances_when_every_hop_has_evidence(self):
        t = {
            "template_id": "T1",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "source_backed_edges": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-A",
                "to_queue_lead_id": "EQ-B",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:1", "src/B.sol:2"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "current_queue_verified": True,
            }],
        }
        idx = {"INV-A": ["src/A.sol:1"], "INV-B": ["PO-9"]}
        d = csd.decorate_template_with_hop_evidence(t, idx)
        self.assertTrue(d["advances"])
        self.assertEqual(d["missing_evidence_hops"], [])
        self.assertEqual(d["hop_count"], 2)
        self.assertTrue(d["composition_supported"])

    def test_blocked_without_source_backed_composition_link(self):
        t = {
            "template_id": "T1",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "composition_breakdown": {
                "shared_commit_point_keywords": [],
                "co_occurrence_incident_count": 50,
            },
        }
        idx = {"INV-A": ["src/A.sol:1"], "INV-B": ["PO-9"]}
        d = csd.decorate_template_with_hop_evidence(t, idx)
        self.assertFalse(d["advances"])
        self.assertEqual(d["missing_evidence_hops"], [])
        self.assertFalse(d["composition_supported"])
        self.assertEqual(
            d["composition_support"],
            ["missing-source-backed-composition-link"],
        )

    def test_blocked_when_one_hop_lacks_evidence(self):
        t = {"template_id": "T2", "member_invariant_ids": ["INV-A", "INV-B"]}
        idx = {"INV-A": ["src/A.sol:1"]}  # INV-B has no evidence
        d = csd.decorate_template_with_hop_evidence(t, idx)
        self.assertFalse(d["advances"])
        self.assertEqual(d["missing_evidence_hops"], ["INV-B"])

    def test_empty_hop_template_never_advances(self):
        d = csd.decorate_template_with_hop_evidence({"template_id": "T3"}, {})
        self.assertFalse(d["advances"])
        self.assertEqual(d["hop_count"], 0)

    def test_single_hop_template_is_single_detector_restatement(self):
        d = csd.decorate_template_with_hop_evidence(
            {"template_id": "T-single", "member_invariant_ids": ["INV-A"]},
            {"INV-A": ["src/A.sol:1"]},
        )
        self.assertFalse(d["advances"])
        self.assertEqual(d["composition_support"], ["single-detector-restatement"])

    def test_single_row_multi_invariant_chain_does_not_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps({
                "queue": [{
                    "broken_invariant_ids": ["INV-A", "INV-B"],
                    "source_refs": ["src/Only.sol:7"],
                }],
            }))
            idx = csd.build_invariant_evidence_index(ws)
        t = {
            "template_id": "T-overcredit",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "composition_breakdown": {
                "shared_commit_point_keywords": ["root"],
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "source_refs": ["src/Join.sol:9"],
            },
        }
        d = csd.decorate_template_with_hop_evidence(t, idx)
        self.assertFalse(d["advances"])
        self.assertEqual(d["missing_evidence_hops"], ["INV-A", "INV-B"])

    def test_placeholder_composition_edge_does_not_advance(self):
        t = {
            "template_id": "T-placeholder",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "composition_edges": [{"note": "manual-source"}],
        }
        idx = {"INV-A": ["src/A.sol:1"], "INV-B": ["src/B.sol:2"]}
        d = csd.decorate_template_with_hop_evidence(t, idx)
        self.assertFalse(d["advances"])
        self.assertFalse(d["composition_supported"])


class TestSourceLinkArtifacts(unittest.TestCase):
    def _valid_entry(self, **overrides):
        entry = {
            "link_id": "SL-1",
            "status": "source_backed",
            "broken_invariant_ids": ["INV-A", "INV-B"],
            "from_invariant_id": "INV-A",
            "to_invariant_id": "INV-B",
            "source_refs": ["src/A.sol:10", "src/B.sol:20"],
            "manual_seeding_absent": True,
            "source_artifacts_complete": True,
            "target_template_ids": ["GCT-1"],
        }
        entry.update(overrides)
        return entry

    def test_loads_links_from_default_and_explicit_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            default = ws / ".auditooor" / "chain_synth_source_links.json"
            explicit = ws / "manual_links.json"
            default.parent.mkdir(parents=True)
            default.write_text(json.dumps({"links": [self._valid_entry()]}))
            explicit.write_text(json.dumps({"entries": [
                self._valid_entry(link_id="SL-2", target_template_ids=["GCT-2"])
            ]}))
            rows = csd.load_source_link_entries(ws, [Path("manual_links.json")])
        self.assertEqual([r["link_id"] for r in rows], ["SL-2", "SL-1"])
        self.assertTrue(all("artifact_path" in r for r in rows))

    def test_coerces_all_source_link_container_shapes(self):
        row = self._valid_entry()
        self.assertEqual(csd.coerce_source_link_rows([row]), [row])
        for key in ("links", "entries", "source_links", "source_backed_edges"):
            with self.subTest(key=key):
                self.assertEqual(csd.coerce_source_link_rows({key: [row]}), [row])

    def test_source_link_rejects_placeholder_or_single_boundary_ref(self):
        one_ref = self._valid_entry(source_refs=["src/A.sol:10"])
        proof_only = self._valid_entry(source_refs=["PO-1", "OBL-2"])
        placeholder = self._valid_entry(source_refs=["manual-source", "unknown"])
        self.assertIsNone(csd.normalize_source_link_entry(one_ref))
        self.assertIsNone(csd.normalize_source_link_entry(proof_only))
        self.assertIsNone(csd.normalize_source_link_entry(placeholder))

    def test_source_link_rejects_killed_or_refuted_rows(self):
        for status in ("killed", "refuted", "advisory_only",
                       "candidate_not_submit_ready"):
            self.assertIsNone(csd.normalize_source_link_entry(
                self._valid_entry(status=status),
            ))

    def test_source_link_edges_match_by_template_or_invariants_without_mutation(self):
        template = {
            "chain_template_id": "GCT-1",
            "member_invariant_ids": ["INV-A", "INV-B"],
        }
        edge = csd.normalize_source_link_entry(self._valid_entry())
        edge["current_queue_verified"] = True
        attached = csd.attach_source_link_edges_to_templates([template], [edge])
        self.assertNotIn("source_backed_edges", template)
        self.assertEqual(attached[0]["source_backed_edges"][0]["link_id"], "SL-1")

    def test_source_link_edges_fallback_to_two_invariant_membership_without_target_ids(self):
        template = {
            "chain_template_id": "GCT-X",
            "member_invariant_ids": ["INV-A", "INV-B"],
        }
        edge = csd.normalize_source_link_entry(
            self._valid_entry(target_template_ids=[]),
        )
        edge["current_queue_verified"] = True
        attached = csd.attach_source_link_edges_to_templates([template], [edge])
        self.assertEqual(attached[0]["source_backed_edges"][0]["link_id"], "SL-1")

    def test_source_link_target_template_ids_do_not_replace_invariant_match(self):
        template = {
            "chain_template_id": "GCT-SL",
            "member_invariant_ids": ["INV-A", "INV-B"],
        }
        edge = csd.normalize_source_link_entry(
            self._valid_entry(
                target_template_ids=["GCT-SL"],
                broken_invariant_ids=["INV-X", "INV-Y"],
                from_invariant_id="INV-X",
                to_invariant_id="INV-Y",
            ),
        )
        self.assertIsNotNone(edge)
        attached = csd.attach_source_link_edges_to_templates([template], [edge])
        self.assertEqual(attached[0]["source_backed_edges"], [])

    def test_source_link_entries_without_queue_leads_are_rejected(self):
        entry = csd.normalize_source_link_entry(
            self._valid_entry(target_template_ids=["GCT-SL"]),
        )
        self.assertEqual(
            csd.filter_source_link_entries_for_current_queue([entry], {"EQ-OTHER"}),
            [],
        )

    def test_source_link_entries_with_stale_same_lead_invariants_are_rejected(self):
        entry = csd.normalize_source_link_entry(
            self._valid_entry(
                from_queue_lead_id="EQ-LIVE",
                to_queue_lead_id="EQ-LIVE",
                from_invariant_id="INV-X",
                to_invariant_id="INV-Y",
                broken_invariant_ids=["INV-X", "INV-Y"],
            ),
        )
        self.assertIsNotNone(entry)
        self.assertEqual(
            csd.filter_source_link_entries_for_current_queue(
                [entry],
                {"EQ-LIVE"},
                {"EQ-LIVE": {"INV-A"}},
            ),
            [],
        )

    def test_source_link_entries_with_stale_endpoint_invariants_are_rejected(self):
        entry = csd.normalize_source_link_entry(
            self._valid_entry(
                from_queue_lead_id="EQ-PRODUCER",
                to_queue_lead_id="EQ-CONSUMER",
                from_invariant_id="INV-X",
                to_invariant_id="INV-Y",
                broken_invariant_ids=["INV-X", "INV-Y"],
            ),
        )
        self.assertIsNotNone(entry)
        self.assertEqual(
            csd.filter_source_link_entries_for_current_queue(
                [entry],
                {"EQ-PRODUCER", "EQ-CONSUMER"},
                {
                    "EQ-PRODUCER": {"INV-A"},
                    "EQ-CONSUMER": {"INV-B"},
                },
            ),
            [],
        )

    def test_existing_template_source_backed_edges_are_not_trusted(self):
        template = {
            "chain_template_id": "GCT-RAW",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "source_backed_edges": [self._valid_entry()],
        }
        idx = {"INV-A": ["src/A.sol:10"], "INV-B": ["src/B.sol:20"]}
        decorated = csd.decorate_template_with_hop_evidence(template, idx)
        self.assertFalse(decorated["advances"])
        self.assertFalse(decorated["composition_supported"])

    def test_raw_template_source_backed_edges_are_not_serialized_when_other_signal_exists(self):
        template = {
            "chain_template_id": "GCT-RAW",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "composition_edges": [{
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "source_refs": ["src/Join.sol:9"],
            }],
            "source_backed_edges": [self._valid_entry()],
        }
        idx = {"INV-A": ["src/A.sol:10"], "INV-B": ["src/B.sol:20"]}
        decorated = csd.decorate_template_with_hop_evidence(template, idx)
        self.assertFalse(decorated["advances"])
        self.assertEqual(decorated["source_backed_edges"], [])
        with tempfile.TemporaryDirectory() as tmp:
            ob = csd.build_chain_proof_obligation(decorated, Path(tmp))
        self.assertEqual(ob["source_backed_edges"], [])


class TestProofObligation(unittest.TestCase):
    def test_build_obligation_is_multi_hop(self):
        t = {
            "template_id": "T1",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "composition_breakdown": {
                "shared_commit_point_keywords": ["root"],
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "source_refs": ["src/Join.sol:9"],
            },
        }
        idx = {"INV-A": ["src/A.sol:1"], "INV-B": ["PO-9"]}
        d = csd.decorate_template_with_hop_evidence(t, idx)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ob = csd.build_chain_proof_obligation(d, ws)
        self.assertEqual(ob["schema"], csd.PROOF_OBLIGATION_SCHEMA_ID)
        self.assertEqual(ob["obligation_id"], "CPO-T1")
        self.assertEqual(ob["hop_count"], 2)
        self.assertEqual([h["step"] for h in ob["hops"]], [1, 2])
        self.assertEqual(ob["hops"][0]["broken_invariant_id"], "INV-A")
        self.assertEqual(ob["proof_status"], "pending")

    def test_write_obligations_idempotent_merge(self):
        t = {"template_id": "T1", "member_invariant_ids": ["INV-A"]}
        idx = {"INV-A": ["src/A.sol:1"]}
        d = csd.decorate_template_with_hop_evidence(t, idx)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            ob = csd.build_chain_proof_obligation(d, ws)
            csd.write_proof_obligations(ws, [ob])
            # second write of same obligation_id must not duplicate
            path = csd.write_proof_obligations(ws, [ob])
            doc = json.loads(path.read_text())
        self.assertEqual(len(doc["obligations"]), 1)
        self.assertEqual(doc["obligations"][0]["obligation_id"], "CPO-T1")


class TestBatchGeneration(unittest.TestCase):
    def test_build_batch_uses_reported_output_path_not_stale_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "batch"
            out.mkdir()
            stale = out / "tok_chain_exploit_synth-batch-stale.jsonl"
            stale.write_text(json.dumps({"task_id": "stale"}) + "\n")
            fresh = out / "tok_chain_exploit_synth-batch-fresh.jsonl"

            def fake_run(*args, **kwargs):
                fresh.write_text(json.dumps({"task_id": "fresh"}) + "\n")
                return mock.Mock(returncode=0, stdout=json.dumps({"output_path": str(fresh)}), stderr="")

            with mock.patch.object(csd.subprocess, "run", side_effect=fake_run):
                got = csd.build_batch_jsonl(Path(tmp), "dydx", [{"chain_template_id": "GCT-1"}], out)

        self.assertEqual(got, fresh)


class TestMainReports(unittest.TestCase):
    def assert_terminal_observability(self, report: dict, expected_status: str) -> None:
        for key in (
            "audit_run_id",
            "stage",
            "input_fingerprints",
            "input_counts",
            "template_match",
            "advancement",
            "dispatch",
        ):
            self.assertIn(key, report)
        self.assertEqual(report["status"], expected_status)
        self.assertIn("exploit_queue", report["input_fingerprints"])
        self.assertIn("ccia_angles", report["input_fingerprints"])
        self.assertIn("source_link_artifacts", report["input_fingerprints"])
        self.assertIn("broken_invariant_ids", report["input_counts"])
        self.assertIn("matched_templates", report["template_match"])
        self.assertIn("advancing_chains", report["advancement"])
        self.assertIn("chains_synthesized", report["dispatch"])

    def _setup_real_multi_hop_queue(self, ws: Path) -> list[dict]:
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "A.sol").write_text(
            "\n".join(f"// A line {i}" for i in range(1, 21)) + "\n"
        )
        (ws / "src" / "B.sol").write_text(
            "\n".join(f"// B line {i}" for i in range(1, 31)) + "\n"
        )
        plan = ws / "swarm" / "chained_attack_plans.json"
        plan.parent.mkdir(parents=True, exist_ok=True)
        plan.write_text(json.dumps({"plans": []}))
        (ws / ".auditooor" / "chain_synth_source_links.json").write_text(json.dumps({
            "links": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-PRODUCER",
                "to_queue_lead_id": "EQ-CONSUMER",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "target_template_ids": ["GCT-SL"],
                "source_plan_artifact": "swarm/chained_attack_plans.json",
            }]
        }))
        (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps({
            "queue": [
                {"lead_id": "EQ-PRODUCER", "broken_invariant_ids": ["INV-A"]},
                {"lead_id": "EQ-CONSUMER", "broken_invariant_ids": ["INV-B"]},
            ],
        }))
        return [{
            "chain_template_id": "GCT-SL",
            "member_invariant_ids": ["INV-A", "INV-B"],
            "composition_breakdown": {"shared_commit_point_keywords": []},
        }]

    def test_blocked_report_is_written_when_no_chains_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-A",
                        "broken_invariant_ids": ["INV-A"],
                    },
                    {
                        "lead_id": "EQ-B",
                        "broken_invariant_ids": ["INV-B"],
                    },
                ],
            }))
            stale = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            stale.write_text(json.dumps({"status": "stale", "advancing_chains": 99}))

            templates = [
                {
                    "chain_template_id": "GCT-BLOCKED",
                    "member_invariant_ids": ["INV-A", "INV-B"],
                    "composition_breakdown": {"shared_commit_point_keywords": []},
                }
            ]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            report = json.loads(stale.read_text())
            self.assertEqual(report["status"], "blocked-missing-hop-evidence")
            self.assertEqual(report["advancing_chains"], 0)
            self.assertEqual(report["proof_obligations"], 1)
            self.assertTrue(report["proof_obligations_path"])
            self.assertFalse(report["blocked_chains"][0]["composition_supported"])
            self.assert_terminal_observability(report, "blocked-missing-hop-evidence")
            obligations = json.loads((ws / csd.PROOF_OBLIGATIONS_FILE).read_text())
            obligation = obligations["obligations"][0]
            self.assertEqual(obligation["template_id"], "GCT-BLOCKED")
            self.assertEqual(
                obligation["advancement_status"],
                "blocked-missing-hop-evidence",
            )
            self.assertEqual(
                obligation["missing_evidence_hops"],
                ["INV-A", "INV-B"],
            )
            self.assertEqual(
                obligation["composition_support"],
                ["missing-source-backed-composition-link"],
            )

    def test_blocked_without_source_links_is_non_applicable_when_hops_are_evidenced(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "A.sol").write_text("// source A\n")
            (ws / "src" / "B.sol").write_text("// source B\n")
            (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-A",
                        "broken_invariant_ids": ["INV-A"],
                        "source_refs": ["src/A.sol:1"],
                    },
                    {
                        "lead_id": "EQ-B",
                        "broken_invariant_ids": ["INV-B"],
                        "source_refs": ["src/B.sol:1"],
                    },
                ],
            }))
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"

            templates = [
                {
                    "chain_template_id": "GCT-NO-LINK",
                    "member_invariant_ids": ["INV-A", "INV-B"],
                    "composition_breakdown": {"shared_commit_point_keywords": []},
                }
            ]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "blocked-missing-hop-evidence")
            self.assertEqual(report["proof_obligations"], 0)
            self.assertEqual(report["applicability_verdict"], "pass-not-applicable")
            self.assertFalse((ws / csd.PROOF_OBLIGATIONS_FILE).exists())

    def test_single_detector_restatement_is_blocked_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps({
                "queue": [{
                    "lead_id": "EQ-A",
                    "broken_invariant_ids": ["INV-A"],
                    "source_refs": ["src/A.sol:1"],
                }],
            }))
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": [{
                                       "chain_template_id": "GCT-SINGLE",
                                       "member_invariant_ids": ["INV-A"],
                                   }]}), \
                    mock.patch.object(csd, "build_batch_jsonl") as build_batch, \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            build_batch.assert_not_called()
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "blocked-missing-hop-evidence")
            self.assertEqual(report["proof_obligations"], 0)
            self.assertEqual(
                report["blocked_chains"][0]["composition_support"],
                ["single-detector-restatement"],
            )

    def test_failed_dispatches_do_not_count_as_synthesized_chains(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            templates = self._setup_real_multi_hop_queue(ws)
            batch = ws / ".auditooor" / "batch.jsonl"
            batch.write_text(json.dumps({"task_id": "t1", "prompt": "prove"}) + "\n")
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd, "build_batch_jsonl", return_value=batch), \
                    mock.patch.object(csd, "dispatch_batch",
                                      return_value=[{"task_id": "t1", "error": "boom"}]), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 1)
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "dispatch-failed")
            self.assertEqual(report["chains_synthesized"], 0)
            self.assertEqual(report["dispatch_errors"], 1)
            self.assertEqual(report["dispatch_results"][0]["error"], "boom")
            self.assert_terminal_observability(report, "dispatch-failed")

    def test_terminal_report_observability_uses_audit_run_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps({
                "queue": [{
                    "lead_id": "EQ-A",
                    "broken_invariant_ids": ["INV-A"],
                    "source_refs": ["src/A.sol:1"],
                }],
            }))

            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--json"]
            stdout = io.StringIO()
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": []}), \
                    mock.patch.object(csd.sys, "stdout", stdout), \
                    mock.patch.object(csd.sys, "argv", argv), \
                    mock.patch.dict(csd.os.environ, {
                        "AUDITOOOR_AUDIT_RUN_FULL_ID": "auditrun-test-123",
                        "AUDITOOOR_AUDIT_RUN_FULL_STAGE": "post-coverage-chain-synth",
                    }):
                rc = csd.main()

            self.assertEqual(rc, 0)
            report = json.loads(stdout.getvalue())
            self.assert_terminal_observability(report, "no-template-matches")
            self.assertEqual(report["audit_run_id"], "auditrun-test-123")
            self.assertEqual(report["stage"], "post-coverage-chain-synth")
            self.assertTrue(report["input_fingerprints"]["exploit_queue"]["exists"])
            self.assertEqual(report["input_counts"]["broken_invariant_ids"], 1)
            self.assertEqual(report["template_match"]["status"], "no-template-matches")
            self.assertEqual(report["dispatch"]["chains_synthesized"], 0)

    def test_batch_generation_failure_writes_terminal_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            templates = self._setup_real_multi_hop_queue(ws)
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--json"]
            stdout = io.StringIO()
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd, "build_batch_jsonl", return_value=None), \
                    mock.patch.object(csd.sys, "stdout", stdout), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 1)
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(json.loads(stdout.getvalue()), report)
            self.assert_terminal_observability(report, "batch-generation-failed")
            self.assertEqual(report["advancement"]["advancing_chains"], 1)
            self.assertEqual(report["dispatch"]["batch_jsonl"], None)
            self.assertFalse(report["dispatch"]["attempted"])

    def test_source_link_artifact_without_current_queue_does_not_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            source_links = ws / ".auditooor" / "chain_synth_source_links.json"
            source_links.write_text(json.dumps({"links": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-PRODUCER",
                "to_queue_lead_id": "EQ-CONSUMER",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "target_template_ids": ["GCT-SL"],
            }]}))
            stale = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            batch = ws / ".auditooor" / "batch.jsonl"
            batch.write_text(json.dumps({"task_id": "t1"}) + "\n")
            templates = [{
                "chain_template_id": "GCT-SL",
                "member_invariant_ids": ["INV-A", "INV-B"],
                "composition_breakdown": {"shared_commit_point_keywords": []},
            }]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            stdout = io.StringIO()
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}) as vault, \
                    mock.patch.object(csd, "build_batch_jsonl", return_value=batch), \
                    mock.patch.object(csd, "dispatch_batch", return_value=[{"task_id": "t1"}]), \
                    mock.patch.object(csd.sys, "stdout", stdout), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            vault.assert_not_called()
            self.assertFalse((ws / csd.EXPLOIT_QUEUE_FILE).exists())
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["status"], "no-invariant-ids")
            self.assertEqual(report["source_link_entries"], 0)
            self.assertEqual(report["source_link_entries_total"], 1)
            self.assertEqual(report["source_link_entries_rejected_stale_queue"], 1)
            self.assertTrue(stale.exists())
            self.assertEqual(json.loads(stale.read_text()), report)
            self.assert_terminal_observability(report, "no-invariant-ids")
            self.assertFalse((ws / csd.PROOF_OBLIGATIONS_FILE).exists())

    def test_no_invariant_ids_non_dry_run_writes_fresh_empty_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            stale = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            stale.write_text(json.dumps({
                "schema": csd.SCHEMA_ID,
                "status": "complete",
                "narratives": [{"task_id": "stale"}],
            }), encoding="utf-8")

            argv = ["chain-synth-driver.py", "--workspace", str(ws)]
            with mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            report = json.loads(stale.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "no-invariant-ids")
            self.assertEqual(report["narratives"], [])
            self.assertEqual(report["chains_synthesized"], 0)
            self.assert_terminal_observability(report, "no-invariant-ids")

    def test_source_link_artifact_advances_with_current_queue_leads_without_queue_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "A.sol").write_text(
                "\n".join(f"// A line {i}" for i in range(1, 21)) + "\n"
            )
            (ws / "src" / "B.sol").write_text(
                "\n".join(f"// B line {i}" for i in range(1, 31)) + "\n"
            )
            plan = ws / "swarm" / "chained_attack_plans.json"
            plan.parent.mkdir(parents=True)
            plan.write_text(json.dumps({"plans": []}))
            source_links = ws / ".auditooor" / "chain_synth_source_links.json"
            source_links.write_text(json.dumps({"links": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-PRODUCER",
                "to_queue_lead_id": "EQ-CONSUMER",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "target_template_ids": ["GCT-SL"],
                "source_plan_artifact": "swarm/chained_attack_plans.json",
            }]}))
            queue_path = ws / csd.EXPLOIT_QUEUE_FILE
            queue_doc = {
                "schema": "auditooor.exploit_queue.v1",
                "queue": [
                    {"lead_id": "EQ-PRODUCER", "broken_invariant_ids": ["INV-A"]},
                    {"lead_id": "EQ-CONSUMER", "broken_invariant_ids": ["INV-B"]},
                ],
            }
            queue_path.write_text(json.dumps(queue_doc))
            before_queue_bytes = queue_path.read_bytes()
            stale = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            batch = ws / ".auditooor" / "batch.jsonl"
            batch.write_text(json.dumps({"task_id": "t1"}) + "\n")
            templates = [{
                "chain_template_id": "GCT-SL",
                "member_invariant_ids": ["INV-A", "INV-B"],
                "composition_breakdown": {"shared_commit_point_keywords": []},
            }]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}) as vault, \
                    mock.patch.object(csd, "build_batch_jsonl", return_value=batch), \
                    mock.patch.object(csd, "dispatch_batch", return_value=[{"task_id": "t1"}]), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            vault.assert_called_once()
            self.assertEqual(queue_path.read_bytes(), before_queue_bytes)
            called_ids = vault.call_args.args[2]
            self.assertEqual(called_ids, ["INV-A", "INV-B"])
            report = json.loads(stale.read_text())
            self.assertEqual(report["status"], "dry-run")
            self.assertEqual(report["source_link_entries"], 1)
            self.assertEqual(report["source_link_entries_total"], 1)
            self.assertEqual(report["source_link_entries_rejected_stale_queue"], 0)
            self.assertEqual(report["advancing_chains"], 1)
            self.assertEqual(report["proof_obligations"], 1)
            self.assert_terminal_observability(report, "dry-run")
            obligations_path = ws / csd.PROOF_OBLIGATIONS_FILE
            obligations = json.loads(obligations_path.read_text())
            edge = obligations["obligations"][0]["source_backed_edges"][0]
            self.assertEqual(edge["link_id"], "SL-1")
            self.assertEqual(edge["from_queue_lead_id"], "EQ-PRODUCER")
            self.assertEqual(edge["to_queue_lead_id"], "EQ-CONSUMER")
            self.assertEqual(edge["source_refs"], ["src/A.sol:10", "src/B.sol:20"])
            self.assertTrue(edge["current_queue_verified"])
            self.assertEqual(edge["source_plan_artifact"], "swarm/chained_attack_plans.json")

    def test_source_link_artifact_with_current_queue_but_missing_plan_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            source_links = ws / ".auditooor" / "chain_synth_source_links.json"
            source_links.write_text(json.dumps({"links": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-PRODUCER",
                "to_queue_lead_id": "EQ-CONSUMER",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "target_template_ids": ["GCT-SL"],
                "source_plan_artifact": "swarm/missing_chained_attack_plans.json",
            }]}))
            queue_path = ws / csd.EXPLOIT_QUEUE_FILE
            queue_path.write_text(json.dumps({
                "queue": [
                    {"lead_id": "EQ-PRODUCER", "broken_invariant_ids": ["INV-A"]},
                    {"lead_id": "EQ-CONSUMER", "broken_invariant_ids": ["INV-B"]},
                ],
            }))
            batch = ws / ".auditooor" / "batch.jsonl"
            batch.write_text(json.dumps({"task_id": "t1"}) + "\n")
            templates = [{
                "chain_template_id": "GCT-SL",
                "member_invariant_ids": ["INV-A", "INV-B"],
                "composition_breakdown": {"shared_commit_point_keywords": []},
            }]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            stdout = io.StringIO()
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}) as vault, \
                    mock.patch.object(csd, "build_batch_jsonl", return_value=batch), \
                    mock.patch.object(csd, "dispatch_batch", return_value=[{"task_id": "t1"}]), \
                    mock.patch.object(csd.sys, "stdout", stdout), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            vault.assert_called_once()
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "blocked-missing-hop-evidence")

    def test_source_link_artifact_with_missing_source_refs_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            plan = ws / "swarm" / "chained_attack_plans.json"
            plan.parent.mkdir(parents=True)
            plan.write_text(json.dumps({"plans": []}))
            source_links = ws / ".auditooor" / "chain_synth_source_links.json"
            source_links.write_text(json.dumps({"links": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-PRODUCER",
                "to_queue_lead_id": "EQ-CONSUMER",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/MissingA.sol:10", "src/MissingB.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "target_template_ids": ["GCT-SL"],
                "source_plan_artifact": "swarm/chained_attack_plans.json",
            }]}))
            queue_path = ws / csd.EXPLOIT_QUEUE_FILE
            queue_path.write_text(json.dumps({
                "queue": [
                    {"lead_id": "EQ-PRODUCER", "broken_invariant_ids": ["INV-A"]},
                    {"lead_id": "EQ-CONSUMER", "broken_invariant_ids": ["INV-B"]},
                ],
            }))
            batch = ws / ".auditooor" / "batch.jsonl"
            batch.write_text(json.dumps({"task_id": "t1"}) + "\n")
            templates = [{
                "chain_template_id": "GCT-SL",
                "member_invariant_ids": ["INV-A", "INV-B"],
            }]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd, "build_batch_jsonl", return_value=batch), \
                    mock.patch.object(csd, "dispatch_batch", return_value=[{"task_id": "t1"}]), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(report["source_link_entries"], 0)
            self.assertEqual(report["source_link_entries_rejected_stale_queue"], 1)
            self.assertEqual(report["status"], "blocked-missing-hop-evidence")
            self.assertEqual(report["source_link_entries"], 0)
            self.assertEqual(report["source_link_entries_total"], 1)
            self.assertEqual(report["source_link_entries_rejected_stale_queue"], 1)
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            self.assertEqual(json.loads(report_path.read_text()), report)
            self.assert_terminal_observability(report, "blocked-missing-hop-evidence")
            self.assertEqual(report["proof_obligations"], 1)
            self.assertTrue((ws / csd.PROOF_OBLIGATIONS_FILE).exists())

    def test_source_link_artifact_with_out_of_range_source_refs_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "A.sol").write_text("contract A {}\n")
            (ws / "src" / "B.sol").write_text("contract B {}\n")
            plan = ws / "swarm" / "chained_attack_plans.json"
            plan.parent.mkdir(parents=True)
            plan.write_text(json.dumps({"plans": []}))
            source_links = ws / ".auditooor" / "chain_synth_source_links.json"
            source_links.write_text(json.dumps({"links": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-PRODUCER",
                "to_queue_lead_id": "EQ-CONSUMER",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "target_template_ids": ["GCT-SL"],
                "source_plan_artifact": "swarm/chained_attack_plans.json",
            }]}))
            queue_path = ws / csd.EXPLOIT_QUEUE_FILE
            queue_path.write_text(json.dumps({
                "queue": [
                    {"lead_id": "EQ-PRODUCER", "broken_invariant_ids": ["INV-A"]},
                    {"lead_id": "EQ-CONSUMER", "broken_invariant_ids": ["INV-B"]},
                ],
            }))
            templates = [{
                "chain_template_id": "GCT-SL",
                "member_invariant_ids": ["INV-A", "INV-B"],
            }]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(report["source_link_entries"], 0)
            self.assertEqual(report["source_link_entries_total"], 1)
            self.assertEqual(report["source_link_entries_rejected_stale_queue"], 1)
            self.assertEqual(report["status"], "blocked-missing-hop-evidence")
            self.assertEqual(report["proof_obligations"], 1)
            self.assertTrue((ws / csd.PROOF_OBLIGATIONS_FILE).exists())

    def test_source_link_artifact_with_blocked_current_queue_rows_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "A.sol").write_text(
                "\n".join(f"// A line {i}" for i in range(1, 21)) + "\n"
            )
            (ws / "src" / "B.sol").write_text(
                "\n".join(f"// B line {i}" for i in range(1, 31)) + "\n"
            )
            plan = ws / "swarm" / "chained_attack_plans.json"
            plan.parent.mkdir(parents=True)
            plan.write_text(json.dumps({"plans": []}))
            source_links = ws / ".auditooor" / "chain_synth_source_links.json"
            source_links.write_text(json.dumps({"links": [{
                "link_id": "SL-1",
                "status": "source_backed",
                "broken_invariant_ids": ["INV-A", "INV-B"],
                "from_queue_lead_id": "EQ-PRODUCER",
                "to_queue_lead_id": "EQ-CONSUMER",
                "from_invariant_id": "INV-A",
                "to_invariant_id": "INV-B",
                "source_refs": ["src/A.sol:10", "src/B.sol:20"],
                "manual_seeding_absent": True,
                "source_artifacts_complete": True,
                "target_template_ids": ["GCT-SL"],
                "source_plan_artifact": "swarm/chained_attack_plans.json",
            }]}))
            queue_path = ws / csd.EXPLOIT_QUEUE_FILE
            queue_path.write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-PRODUCER",
                        "status": "blocked_missing_impact_contract",
                        "broken_invariant_ids": ["INV-A"],
                    },
                    {
                        "lead_id": "EQ-CONSUMER",
                        "advisory_only": True,
                        "broken_invariant_ids": ["INV-B"],
                    },
                ],
            }))
            templates = [{
                "chain_template_id": "GCT-SL",
                "member_invariant_ids": ["INV-A", "INV-B"],
            }]
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--dry-run", "--json"]
            stdout = io.StringIO()
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}) as vault, \
                    mock.patch.object(csd.sys, "stdout", stdout), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            vault.assert_not_called()
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["status"], "no-invariant-ids")
            self.assertEqual(report["source_link_entries"], 0)
            self.assertEqual(report["source_link_entries_total"], 1)
            self.assertEqual(report["source_link_entries_rejected_stale_queue"], 1)
            self.assertFalse((ws / csd.PROOF_OBLIGATIONS_FILE).exists())

    def test_no_require_hop_evidence_flag_cannot_dispatch_blocked_multi_hop_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / csd.EXPLOIT_QUEUE_FILE).write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-A",
                        "broken_invariant_ids": ["INV-A"],
                        "source_refs": ["src/A.sol:1"],
                    },
                    {
                        "lead_id": "EQ-B",
                        "broken_invariant_ids": ["INV-B"],
                        "source_refs": ["src/B.sol:1"],
                    },
                ],
            }))
            templates = [{
                "chain_template_id": "GCT-BLOCKED",
                "member_invariant_ids": ["INV-A", "INV-B"],
            }]
            argv = [
                "chain-synth-driver.py",
                "--workspace",
                str(ws),
                "--no-require-hop-evidence",
                "--dry-run",
                "--json",
            ]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd, "build_batch_jsonl") as build_batch, \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 0)
            build_batch.assert_not_called()
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "blocked-missing-hop-evidence")
            self.assertEqual(report["applicability_verdict"], "pass-not-applicable")
            self.assertEqual(report["chains_synthesized"], 0)

    def test_candidate_not_submit_ready_dispatch_output_does_not_count_as_narrative(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            templates = self._setup_real_multi_hop_queue(ws)
            batch = ws / ".auditooor" / "batch.jsonl"
            batch.write_text(json.dumps({"task_id": "t1", "prompt": "prove"}) + "\n")
            argv = ["chain-synth-driver.py", "--workspace", str(ws), "--json"]
            with mock.patch.object(csd, "call_vault_global_chain_template_match",
                                   return_value={"matched_templates": templates}), \
                    mock.patch.object(csd, "build_batch_jsonl", return_value=batch), \
                    mock.patch.object(csd, "dispatch_batch",
                                      return_value=[{
                                          "task_id": "t1",
                                          "narrative": {
                                              "status": "candidate_not_submit_ready",
                                              "candidate_not_submit_ready": True,
                                          },
                                      }]), \
                    mock.patch.object(csd.sys, "argv", argv):
                rc = csd.main()

            self.assertEqual(rc, 1)
            report_path = ws / ".auditooor" / f"chain_synthesis_{csd.datetime.now(csd.timezone.utc).strftime('%Y-%m-%d')}.json"
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "dispatch-no-successful-narratives")
            self.assertEqual(report["chains_synthesized"], 0)
            self.assertEqual(report["narratives"], [])
            self.assert_terminal_observability(report, "dispatch-no-successful-narratives")


if __name__ == "__main__":
    unittest.main()
