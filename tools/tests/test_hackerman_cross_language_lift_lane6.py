"""Tests for tools/hackerman-cross-language-lift-lane6.py (HACKERMAN_V2 Lane 6)."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hackerman-cross-language-lift-lane6.py"
ANALOGUE_RECORD = ROOT / "reports" / "lane6_cross_language_analogue_share_inflation.json"
DSL_PATTERN = ROOT / "reference" / "patterns.dsl.r73_crosslang" / "first-deposit-share-inflation-cross-language.yaml"
VULN_FIXTURE = ROOT / "reference" / "patterns.dsl.r73_crosslang" / "fixtures" / "first-deposit-share-inflation" / "vuln_ERC4626_no_virtual_offset.sol"
CLEAN_FIXTURE = ROOT / "reference" / "patterns.dsl.r73_crosslang" / "fixtures" / "first-deposit-share-inflation" / "clean_ERC4626_with_virtual_offset.sol"
GO_VULN_FIXTURE = ROOT / "reference" / "patterns.dsl.r73_crosslang" / "fixtures" / "first-deposit-share-inflation" / "vuln_go_osmosis_gamm_shares.go"


def _load_tool():
    spec = importlib.util.spec_from_file_location("hackerman_cl_lift_lane6", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestLane6InvariantFieldInference(unittest.TestCase):
    """Verify _infer_invariant_fields returns correct fields per attack class."""

    def setUp(self) -> None:
        self.mod = _load_tool()

    def test_accounting_drift_gets_share_fields(self) -> None:
        fields = self.mod._infer_invariant_fields("accounting-drift", "solidity->go: ratio-based share calc")
        self.assertIn("asset_custody", fields)
        self.assertIn("share_mint_burn_conservation", fields)
        self.assertIn("price_nav_conversion", fields)

    def test_replay_domain_gets_nonce_fields(self) -> None:
        fields = self.mod._infer_invariant_fields("signature-replay", "EIP-712 nonce/domain binding -> sign-bytes")
        self.assertIn("nonce_domain_binding", fields)
        self.assertIn("replay_uniqueness", fields)
        self.assertIn("source_domain_proof", fields)

    def test_bridge_gets_source_domain_and_settlement(self) -> None:
        fields = self.mod._infer_invariant_fields("bridge", "bridge proof-domain across languages")
        self.assertIn("source_domain_proof", fields)
        self.assertIn("destination_settlement", fields)

    def test_access_control_gets_authority_check(self) -> None:
        fields = self.mod._infer_invariant_fields("access-control", "modifier/role gate -> keeper authority check")
        self.assertIn("authority_check", fields)

    def test_share_terms_always_add_asset_custody(self) -> None:
        fields = self.mod._infer_invariant_fields("oracle", "share vault deposit pool")
        self.assertIn("asset_custody", fields)

    def test_empty_class_returns_list(self) -> None:
        fields = self.mod._infer_invariant_fields("", "")
        self.assertIsInstance(fields, list)


class TestLane6QueryPackets(unittest.TestCase):
    """Verify query packet definitions are well-formed."""

    def setUp(self) -> None:
        self.mod = _load_tool()

    def test_all_five_packets_defined(self) -> None:
        packets = self.mod._QUERY_PACKETS
        self.assertEqual(len(packets), 5)

    def test_packet_ids_unique(self) -> None:
        packets = self.mod._QUERY_PACKETS
        ids = [p["packet_id"] for p in packets]
        self.assertEqual(len(ids), len(set(ids)))

    def test_sol_to_go_packet_exists(self) -> None:
        mod = self.mod
        pkt_id = mod._infer_query_packet("solidity", "go")
        self.assertEqual(pkt_id, "sol-to-go")

    def test_go_to_sol_packet_exists(self) -> None:
        pkt_id = self.mod._infer_query_packet("go", "solidity")
        self.assertEqual(pkt_id, "go-to-sol")

    def test_unknown_pair_returns_slug(self) -> None:
        pkt_id = self.mod._infer_query_packet("move", "cairo")
        self.assertIn("move", pkt_id)
        self.assertIn("cairo", pkt_id)

    def test_each_packet_has_required_fields(self) -> None:
        required = {"packet_id", "source_language", "target_language", "description", "translation_frame", "attack_classes"}
        for pkt in self.mod._QUERY_PACKETS:
            self.assertTrue(required.issubset(set(pkt.keys())), f"Packet {pkt.get('packet_id')} missing fields")


class TestLane6EnrichSidecarRow(unittest.TestCase):
    """Verify sidecar row enrichment adds Lane 6 invariant fields."""

    def setUp(self) -> None:
        self.mod = _load_tool()

    def _make_row(self, attack_class: str = "accounting-drift", confidence: float = 0.98,
                  src_lang: str = "solidity", tgt_lang: str = "go") -> dict:
        return {
            "source_record_id": "test/src",
            "analogue_record_id": "test/analogue",
            "attack_class": attack_class,
            "confidence": confidence,
            "source_language": src_lang,
            "target_language": tgt_lang,
            "pattern_translation": f"{src_lang}->{tgt_lang}: share calc",
            "reason": "shared attack_class=accounting-drift",
        }

    def test_enrichment_adds_invariant_fields(self) -> None:
        row = self._make_row()
        enriched = self.mod.enrich_sidecar_row(row)
        self.assertIn("invariant_fields", enriched)
        self.assertIsInstance(enriched["invariant_fields"], list)
        self.assertTrue(len(enriched["invariant_fields"]) > 0)

    def test_enrichment_adds_schema(self) -> None:
        row = self._make_row()
        enriched = self.mod.enrich_sidecar_row(row)
        self.assertIn("schema", enriched)
        self.assertIn("lane6", enriched["schema"])

    def test_enrichment_adds_query_packet(self) -> None:
        row = self._make_row(src_lang="solidity", tgt_lang="go")
        enriched = self.mod.enrich_sidecar_row(row)
        self.assertEqual(enriched["query_packet"], "sol-to-go")

    def test_enrichment_adds_verification_tier(self) -> None:
        row = self._make_row(confidence=0.98)
        enriched = self.mod.enrich_sidecar_row(row)
        self.assertIn("verification_tier", enriched)
        self.assertIn("tier-", enriched["verification_tier"])

    def test_high_confidence_marks_exploit_queue_ingestable(self) -> None:
        row = self._make_row(confidence=0.98)
        enriched = self.mod.enrich_sidecar_row(row)
        self.assertTrue(enriched["exploit_queue_ingestable"])

    def test_low_confidence_not_exploit_queue_ingestable(self) -> None:
        row = self._make_row(confidence=0.50)
        enriched = self.mod.enrich_sidecar_row(row)
        self.assertFalse(enriched["exploit_queue_ingestable"])

    def test_original_fields_preserved(self) -> None:
        row = self._make_row()
        enriched = self.mod.enrich_sidecar_row(row)
        for k in row:
            self.assertIn(k, enriched)


class TestLane6ExploitQueueRow(unittest.TestCase):
    """Verify exploit-queue-ingestable row structure matches REQUIRED_ROW_FIELDS."""

    REQUIRED_FIELDS = [
        "lead_id", "title", "source_refs", "source_artifacts_complete",
        "source_artifact_gaps", "quality_gate_status", "attack_class",
        "likely_severity", "severity_confidence", "attacker_control",
        "impact_path", "proof_path", "proof_artifact_precedent_refs",
        "metric_integrity_refs", "learning_route", "next_command",
        "blockers", "dupe_risk", "priority_score",
    ]

    def setUp(self) -> None:
        self.mod = _load_tool()

    def _enriched_row(self, confidence: float = 0.98) -> dict:
        raw = {
            "source_record_id": "test/src",
            "analogue_record_id": "test/analogue",
            "attack_class": "accounting-drift",
            "confidence": confidence,
            "source_language": "solidity",
            "target_language": "go",
            "pattern_translation": "solidity->go: share calc without virtual offset",
            "reason": "shared attack_class",
        }
        return self.mod.enrich_sidecar_row(raw)

    def test_eligible_row_has_all_required_fields(self) -> None:
        enriched = self._enriched_row(confidence=0.98)
        eq_row = self.mod.build_exploit_queue_row(enriched)
        self.assertIsNotNone(eq_row)
        for field in self.REQUIRED_FIELDS:
            self.assertIn(field, eq_row, f"Missing required field: {field}")

    def test_ineligible_row_returns_none(self) -> None:
        enriched = self._enriched_row(confidence=0.50)
        eq_row = self.mod.build_exploit_queue_row(enriched)
        self.assertIsNone(eq_row)

    def test_lead_id_is_slug_safe(self) -> None:
        enriched = self._enriched_row()
        eq_row = self.mod.build_exploit_queue_row(enriched)
        self.assertRegex(eq_row["lead_id"], r"^[a-z0-9-]+$")

    def test_metric_integrity_refs_are_invariant_fields(self) -> None:
        enriched = self._enriched_row()
        eq_row = self.mod.build_exploit_queue_row(enriched)
        self.assertIsInstance(eq_row["metric_integrity_refs"], list)
        # Invariant fields should be present
        self.assertTrue(len(eq_row["metric_integrity_refs"]) > 0)

    def test_learning_route_is_lane6(self) -> None:
        enriched = self._enriched_row()
        eq_row = self.mod.build_exploit_queue_row(enriched)
        self.assertIn("lane6", eq_row["learning_route"])


class TestLane6AnalogueDonecondition(unittest.TestCase):
    """Verify Lane 6 done condition: detector + fixture + exploit-queue row + proof path."""

    def test_dsl_pattern_file_exists(self) -> None:
        self.assertTrue(DSL_PATTERN.is_file(), f"DSL pattern missing: {DSL_PATTERN}")

    def test_vuln_fixture_exists(self) -> None:
        self.assertTrue(VULN_FIXTURE.is_file(), f"Vuln fixture missing: {VULN_FIXTURE}")

    def test_clean_fixture_exists(self) -> None:
        self.assertTrue(CLEAN_FIXTURE.is_file(), f"Clean fixture missing: {CLEAN_FIXTURE}")

    def test_go_vuln_fixture_exists(self) -> None:
        self.assertTrue(GO_VULN_FIXTURE.is_file(), f"Go vuln fixture missing: {GO_VULN_FIXTURE}")

    def test_analogue_record_exists(self) -> None:
        self.assertTrue(ANALOGUE_RECORD.is_file(), f"Analogue record missing: {ANALOGUE_RECORD}")

    def test_analogue_record_has_exploit_queue_row(self) -> None:
        record = json.loads(ANALOGUE_RECORD.read_text(encoding="utf-8"))
        self.assertIn("exploit_queue_row", record)
        eq = record["exploit_queue_row"]
        self.assertIn("lead_id", eq)
        self.assertIn("proof_path", eq)

    def test_analogue_record_done_condition_satisfied(self) -> None:
        record = json.loads(ANALOGUE_RECORD.read_text(encoding="utf-8"))
        self.assertTrue(record.get("lane6_done_condition_satisfied"))
        evidence = record.get("done_condition_evidence") or {}
        self.assertTrue(evidence.get("detector_produced"))
        self.assertTrue(evidence.get("fixture_vuln_fires"))
        self.assertTrue(evidence.get("fixture_clean_silent"))
        self.assertTrue(evidence.get("exploit_queue_row_present"))

    def test_detector_fires_on_vuln_not_on_clean(self) -> None:
        """Verify the detector regex pattern fires on vuln and not on clean fixture."""
        import re
        vuln_src = VULN_FIXTURE.read_text(encoding="utf-8")
        clean_src = CLEAN_FIXTURE.read_text(encoding="utf-8")
        go_src = GO_VULN_FIXTURE.read_text(encoding="utf-8")

        name_pat = re.compile(r"(?i)(deposit|joinPool|mint|addLiquidity|joinSwap|CalcJoinPool|_convertToShares|mintFresh|computeShares)")
        total_pat = re.compile(r"(?i)(totalSupply\(\)|GetTotalShares\(\)|total_supply\(\)|totalShares\b)")
        arith_pat = re.compile(r"(?i)(mulDiv|Mul.*Div|\.mul\(|\.Mul\(|MulInt|mulInt|\*\s*\w+|\*\s*[a-z_][a-z0-9_]*\s*\)|\*\s*supply\b)")
        prot_pat = re.compile(r"(?i)(VIRTUAL_SHARES\s*=|VIRTUAL_ASSETS\s*=|_decimalsOffset|virtual_offset\s*=|MINIMUM_LIQUIDITY\s*=\s*[1-9][0-9]{3}|uint.*minShares\s*=|sdk\.Int.*minimum|minSharesOut\s*=|virtual_reserve)")

        def fires(src: str) -> bool:
            return (
                bool(name_pat.search(src))
                and bool(total_pat.search(src))
                and bool(arith_pat.search(src))
                and not bool(prot_pat.search(src))
            )

        self.assertTrue(fires(vuln_src), "Detector should fire on vuln Solidity fixture")
        self.assertFalse(fires(clean_src), "Detector should NOT fire on clean Solidity fixture")
        self.assertTrue(fires(go_src), "Detector should fire on vuln Go fixture")

    def test_analogue_record_verification_tier(self) -> None:
        record = json.loads(ANALOGUE_RECORD.read_text(encoding="utf-8"))
        tier = record.get("verification_tier") or ""
        self.assertIn("tier-", tier)
        self.assertNotIn("tier-5", tier)  # not quarantined


class TestLane6CLIQueryPackets(unittest.TestCase):
    """Verify the CLI --query-packets flag emits all 5 packet definitions."""

    def setUp(self) -> None:
        self.mod = _load_tool()

    def test_query_packets_output(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            out_path = f.name
        rc = self.mod.main(["--query-packets", "--out", out_path])
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in Path(out_path).read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 5)
        ids = {r["packet_id"] for r in rows}
        self.assertIn("sol-to-go", ids)
        self.assertIn("bridge-proof-domain", ids)


class TestLane6CLIAnaloguRecordEnrichment(unittest.TestCase):
    """Verify the CLI --analogue-record flag enriches and emits the record."""

    def setUp(self) -> None:
        self.mod = _load_tool()

    def test_enrich_share_inflation_record(self) -> None:
        if not ANALOGUE_RECORD.is_file():
            self.skipTest("analogue record not present")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            out_path = f.name
        rc = self.mod.main(["--analogue-record", str(ANALOGUE_RECORD), "--out", out_path])
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in Path(out_path).read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIn("invariant_fields", row)
        self.assertIn("query_packets", row)
        self.assertIn("asset_custody", row["invariant_fields"])

    def test_missing_analogue_record_returns_error(self) -> None:
        rc = self.mod.main(["--analogue-record", "/nonexistent/path.json", "--out", "-"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
