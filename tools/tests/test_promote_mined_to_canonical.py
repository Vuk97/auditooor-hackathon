"""Tests for tools/promote-mined-to-canonical.py (CAP-GAP-97a + CAP-GAP-97b).

Covers:
  - 97b: 3 wrapper shapes (header+frontmatter, flat YAML, flat JSON)
  - 97a: per-router happy-path, dedup-collision, malformed record handling
  - end-to-end: dry-run promotion against in-memory fixtures
  - truncated-JSON recovery
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMOTER = REPO_ROOT / "tools" / "promote-mined-to-canonical.py"


def _load_promoter_module():
    spec = importlib.util.spec_from_file_location("p", str(PROMOTER))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class CapGap97bWrapperShapes(unittest.TestCase):
    """CAP-GAP-97b: _extract_record_content_from_ingested_yaml handles 3 shapes."""

    def setUp(self):
        self.m = _load_promoter_module()
        self.tmp = Path(tempfile.mkdtemp(prefix="r97b_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_shape_a_header_frontmatter_json_body(self):
        body = {
            "content": {"invariant_id": "INV-TEST-001", "statement": "X must Y."},
            "schema_version": "auditooor.invariant.v1",
        }
        text = ("# auditooor-deepseek-ingest record\n"
                "# schema: auditooor.invariant.v1\n"
                "---\n" + json.dumps(body))
        f = self.tmp / "a.yaml"
        f.write_text(text)
        rec = self.m._extract_record_content_from_ingested_yaml(f)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.get("content", {}).get("invariant_id"), "INV-TEST-001")

    def test_shape_b_flat_yaml(self):
        text = ("schema_version: auditooor.invariant_pilot.v1\n"
                "invariant_id: INV-FLAT-001\n"
                "category: \"storage-collision\"\n"
                "statement: |\n"
                "  Storage slots must not collide across upgrade paths.\n"
                "target_lang: solidity\n"
                "verification_tier: tier-2-verified-public-archive\n")
        f = self.tmp / "b.yaml"
        f.write_text(text)
        rec = self.m._extract_record_content_from_ingested_yaml(f)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.get("invariant_id"), "INV-FLAT-001")
        self.assertIn("Storage slots", rec.get("statement", ""))

    def test_shape_c_flat_json(self):
        body = {"task_id": "lift-001", "status": "ok",
                "result": json.dumps({"invariant_id": "INV-JSON-001"}),
                "verification_tier": "tier-3-synthetic-taxonomy-anchored"}
        f = self.tmp / "c.json"
        f.write_text(json.dumps(body))
        rec = self.m._extract_record_content_from_ingested_yaml(f)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.get("task_id"), "lift-001")
        self.assertEqual(rec.get("status"), "ok")

    def test_invalid_yaml_returns_none_or_dict(self):
        f = self.tmp / "garbage.yaml"
        f.write_text("@@not yaml@@\n!!!\n###")
        rec = self.m._extract_record_content_from_ingested_yaml(f)
        if rec is not None:
            self.assertIsInstance(rec, dict)

    def test_truncated_json_array_recovery(self):
        s = '[{"hypothesis_id": "h1", "attack_class": "theft"}, {"hypothesis_id":'
        out = self.m._recover_truncated_json(s)
        self.assertIsNotNone(out)
        self.assertIsInstance(out, list)
        self.assertEqual(out[0]["hypothesis_id"], "h1")

    def test_truncated_json_object_recovery(self):
        s = '{"invariant_id": "I1", "statement": "X must Y", "applicability_caveats": ["a"], "extra": "trunc'
        out = self.m._recover_truncated_json(s)
        self.assertIsNotNone(out)
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("invariant_id"), "I1")
        self.assertEqual(out.get("statement"), "X must Y")


class CapGap97aSourceRouters(unittest.TestCase):
    """CAP-GAP-97a: SOURCE_ROUTERS registry + promote_from_router()."""

    def setUp(self):
        self.m = _load_promoter_module()

    def test_source_routers_registry_size(self):
        self.assertGreaterEqual(len(self.m.SOURCE_ROUTERS), 15,
                                "SOURCE_ROUTERS should expand to ~20 routers")

    def test_router_schema_fields(self):
        for r in self.m.SOURCE_ROUTERS:
            for field in ("name", "kind", "source_dir", "glob",
                          "dst_path", "key_field", "extractor"):
                self.assertIn(field, r, f"router {r.get('name')} missing {field}")
            self.assertTrue(callable(r["extractor"]),
                            f"router {r['name']} extractor not callable")

    def test_invariant_library_extended_router_present(self):
        names = {r["name"] for r in self.m.SOURCE_ROUTERS}
        self.assertIn("invariant_library_extended", names)

    def test_dispatch_ledger_routers_present(self):
        names = {r["name"] for r in self.m.SOURCE_ROUTERS}
        for required in ("hacker_q_full_expansions", "detector_synthesis_v2",
                          "tok_b_full_library_lifted", "multi_hop_chains",
                          "per_contract_hypotheses", "tok_a_enrichment",
                          "tok_c_hypotheses"):
            self.assertIn(required, names, f"router {required} missing")


class GenericExtractorBehavior(unittest.TestCase):
    def setUp(self):
        self.m = _load_promoter_module()

    def test_extract_dispatch_ledger_single_object(self):
        rec = {
            "task_id": "t1", "status": "ok",
            "result": json.dumps({"invariant_id": "INV-X-1",
                                   "lifted_statement_any": "X must hold.",
                                   "attack_class": "theft"}),
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
        }
        out = self.m._extract_dispatch_ledger_generic(
            rec, Path("/tmp/t1.json"), "batch-1", kind="invariant")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["category"], "theft")
        self.assertIn("X must hold.", out[0]["statement"])

    def test_extract_dispatch_ledger_array_of_hypotheses(self):
        rec = {
            "task_id": "t2", "status": "ok",
            "result": json.dumps([
                {"hypothesis_id": "h1", "root_cause_one_sentence": "A.",
                 "attack_class": "dos"},
                {"hypothesis_id": "h2", "root_cause_one_sentence": "B.",
                 "attack_class": "theft"},
            ]),
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
        }
        out = self.m._extract_dispatch_ledger_generic(
            rec, Path("/tmp/t2.json"), "batch-1", kind="hypothesis")
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["statement"], "A.")
        self.assertEqual(out[1]["statement"], "B.")

    def test_extract_dispatch_ledger_failed_record_skipped(self):
        rec = {"task_id": "t3", "status": "failed", "result": None,
               "error": "dispatch-failed",
               "verification_tier": "tier-3-synthetic-taxonomy-anchored"}
        out = self.m._extract_dispatch_ledger_generic(
            rec, Path("/tmp/t3.json"), "batch-1", kind="x")
        self.assertEqual(out, [])

    def test_extract_dispatch_ledger_halted_skipped(self):
        rec = {"task_id": "t4", "status": "halted", "result": None}
        out = self.m._extract_dispatch_ledger_generic(
            rec, Path("/tmp/t4.json"), "batch-1", kind="x")
        self.assertEqual(out, [])

    def test_extract_invariant_library_extended_happy_path(self):
        rec = {
            "content": {"invariant_id": "INV-IE-1", "statement": "Y holds.",
                         "category": "proof-verification"},
            "invariant_id": "INV-IE-1",
            "statement": "Y holds.",
            "verification_tier": "tier-2-verified-public-archive",
        }
        out = self.m._extract_invariant_library_extended(
            rec, Path("/tmp/x.yaml"), "batch-1")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["invariant_id"], "INV-IE-1")
        self.assertEqual(out[0]["category"], "proof-verification")

    def test_extract_invariant_library_extended_missing_id_skipped(self):
        out = self.m._extract_invariant_library_extended(
            {"statement": "X"}, Path("/tmp/x.yaml"), "batch-1")
        self.assertEqual(out, [])


class PromoteFromRouterIntegration(unittest.TestCase):
    def setUp(self):
        self.m = _load_promoter_module()
        self.tmp = Path(tempfile.mkdtemp(prefix="r97a_e2e_"))
        src = self.tmp / "src"
        src.mkdir()
        for i in (1, 2, 3):
            (src / f"good_{i}.json").write_text(json.dumps({
                "task_id": f"good-{i}", "status": "ok",
                "result": json.dumps({
                    "invariant_id": f"INV-E2E-{i}",
                    "lifted_statement_any": f"Statement {i}.",
                    "attack_class": "theft",
                }),
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            }))
        (src / "fail_1.json").write_text(json.dumps({
            "task_id": "fail-1", "status": "failed", "result": None,
        }))
        (src / "malformed.json").write_text("not json {{{")
        self.src_dir = src
        self.dst = self.tmp / "dst.jsonl"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _router(self):
        return {
            "name": "e2e-test",
            "kind": "invariant",
            "source_dir": self.src_dir,
            "glob": "*.json",
            "dst_path": self.dst,
            "key_field": "record_id",
            "extractor": lambda r, s, b: self.m._extract_dispatch_ledger_generic(
                r, s, b, kind="invariant"),
        }

    def test_promote_dry_run_no_writes(self):
        promoted, skipped = self.m.promote_from_router(
            self._router(), min_conf="low", only_batch=None, dry_run=True)
        self.assertEqual(promoted, 3)
        self.assertGreaterEqual(skipped, 2)
        self.assertFalse(self.dst.exists())

    def test_promote_writes_jsonl(self):
        promoted, skipped = self.m.promote_from_router(
            self._router(), min_conf="low", only_batch=None, dry_run=False)
        self.assertEqual(promoted, 3)
        self.assertTrue(self.dst.exists())
        lines = [json.loads(l) for l in self.dst.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)
        ids = {r["record_id"] for r in lines}
        self.assertEqual(len(ids), 3)

    def test_promote_dedup_idempotent(self):
        self.m.promote_from_router(
            self._router(), min_conf="low", only_batch=None, dry_run=False)
        promoted, _ = self.m.promote_from_router(
            self._router(), min_conf="low", only_batch=None, dry_run=False)
        self.assertEqual(promoted, 0)
        lines = [l for l in self.dst.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)

    def test_only_batch_filter(self):
        promoted, _ = self.m.promote_from_router(
            self._router(), min_conf="low", only_batch="e2e-test",
            dry_run=True)
        self.assertEqual(promoted, 3)

    def test_only_batch_no_match(self):
        promoted, _ = self.m.promote_from_router(
            self._router(), min_conf="low", only_batch="no-such-batch",
            dry_run=True)
        self.assertEqual(promoted, 0)


class ConfidenceGating(unittest.TestCase):
    def setUp(self):
        self.m = _load_promoter_module()

    def test_tier_2_record_is_medium(self):
        rec = {"verification_tier": "tier-2-verified-public-archive"}
        self.assertEqual(self.m._record_confidence(rec), "medium")

    def test_tier_3_record_is_low(self):
        rec = {"verification_tier": "tier-3-synthetic-taxonomy-anchored"}
        self.assertEqual(self.m._record_confidence(rec), "low")

    def test_explicit_confidence_field_takes_precedence(self):
        rec = {"verification_tier": "tier-3-synthetic-taxonomy-anchored",
               "confidence": "high"}
        self.assertEqual(self.m._record_confidence(rec), "high")

    def test_min_confidence_gate(self):
        rec_low = {"verification_tier": "tier-3-synthetic-taxonomy-anchored"}
        rec_med = {"verification_tier": "tier-2-verified-public-archive"}
        self.assertTrue(self.m._meets_min_confidence(rec_low, "low"))
        self.assertFalse(self.m._meets_min_confidence(rec_low, "medium"))
        self.assertTrue(self.m._meets_min_confidence(rec_med, "medium"))


class RecursiveGlobBatchSubdir(unittest.TestCase):
    """Regression for the detector_synthesis_v2 ``**/*.json`` glob fix.

    Batch-subdir miners (e.g. the zkbugs-dataset detector miner) write seeds
    into ``<source_dir>/<batch>/*.json``. Before the fix the router used a
    flat ``*.json`` glob, so the detector half was a silent no-op: zero files
    in nested batch dirs were ever promoted. The 278 zkbugs detectors only
    landed once the glob became recursive. These tests pin that behavior and
    confirm the batch-derivation logic still tags the immediate parent dir.
    """

    def setUp(self):
        self.m = _load_promoter_module()
        self.tmp = Path(tempfile.mkdtemp(prefix="r_recursive_glob_"))
        src = self.tmp / "detector_synthesis_v2"
        src.mkdir()
        # One legacy flat file at the source root.
        (src / "detector_synth_v2_flat.json").write_text(json.dumps({
            "task_id": "flat-1", "status": "ok",
            "result": json.dumps({
                "invariant_id": "DET-FLAT-1",
                "lifted_statement_any": "Flat-root detector seed.",
                "attack_class": "theft",
            }),
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
        }))
        # Two batch-subdir files (the shape the fix unblocks).
        batch = src / "zkbugs_batch_001"
        batch.mkdir()
        for i in (1, 2):
            (batch / f"seed_{i}.json").write_text(json.dumps({
                "task_id": f"nested-{i}", "status": "ok",
                "result": json.dumps({
                    "invariant_id": f"DET-NESTED-{i}",
                    "lifted_statement_any": f"Nested detector seed {i}.",
                    "attack_class": "theft",
                }),
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            }))
        self.src_dir = src
        self.dst = self.tmp / "dst.jsonl"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _router(self, glob):
        return {
            "name": "detector_synthesis_v2",
            "kind": "detector_seed",
            "source_dir": self.src_dir,
            "glob": glob,
            "dst_path": self.dst,
            "key_field": "record_id",
            "extractor": lambda r, s, b: self.m._extract_dispatch_ledger_generic(
                r, s, b, kind="detector_seed"),
        }

    def test_recursive_glob_promotes_nested_batch_files(self):
        promoted, _ = self.m.promote_from_router(
            self._router("**/*.json"), min_conf="low", only_batch=None,
            dry_run=False)
        # 1 flat + 2 nested = 3 promoted.
        self.assertEqual(promoted, 3)
        ids = {json.loads(l)["record_id"]
               for l in self.dst.read_text().splitlines() if l.strip()}
        # Both nested seeds and the flat seed are present.
        self.assertTrue(any("DET-NESTED-1" in i for i in ids), ids)
        self.assertTrue(any("DET-NESTED-2" in i for i in ids), ids)
        self.assertTrue(any("DET-FLAT-1" in i for i in ids), ids)

    def test_flat_glob_misses_nested_batch_files(self):
        # Proves the pre-fix bug: a flat ``*.json`` glob only sees the
        # root-level file and silently drops the nested batch seeds.
        promoted, _ = self.m.promote_from_router(
            self._router("*.json"), min_conf="low", only_batch=None,
            dry_run=True)
        self.assertEqual(promoted, 1)

    def test_recursive_glob_batch_derivation_tags_parent_dir(self):
        # only_batch filtering must work on the immediate parent dir name of
        # nested files; the recursive-glob router relies on this.
        promoted, _ = self.m.promote_from_router(
            self._router("**/*.json"), min_conf="low",
            only_batch="zkbugs_batch_001", dry_run=True)
        self.assertEqual(promoted, 2)

    def test_live_detector_synthesis_v2_router_uses_recursive_glob(self):
        routers = [r for r in self.m.SOURCE_ROUTERS
                   if r["name"] == "detector_synthesis_v2"]
        self.assertEqual(len(routers), 1)
        self.assertEqual(routers[0]["glob"], "**/*.json")


class RegressionLegacy(unittest.TestCase):
    def setUp(self):
        self.m = _load_promoter_module()

    def test_legacy_constants_preserved(self):
        self.assertTrue(hasattr(self.m, "INV_SRC_ROOT"))
        self.assertTrue(hasattr(self.m, "INV_DST"))
        self.assertTrue(hasattr(self.m, "ANTI_PATTERN_SRC_ROOT"))
        self.assertTrue(hasattr(self.m, "ANTI_PATTERN_DST_DIR"))

    def test_promote_invariants_alias_still_callable(self):
        result = self.m.promote_invariants(
            min_conf="medium", only_batch=None, dry_run=True)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_promote_anti_patterns_still_works(self):
        result = self.m.promote_anti_patterns(
            min_conf="low", only_batch=None, dry_run=True)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


class CapGap97cFaithfulJsonlRouters(unittest.TestCase):
    """CAP-GAP-97c: faithful JSONL-source routers copy full content verbatim
    (no lossy YAML round-trip) and preserve verification_tier."""

    def setUp(self):
        self.m = _load_promoter_module()
        self.tmp = Path(tempfile.mkdtemp(prefix="r97c_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _zebra_inv_record(self):
        return {
            "content": {
                "invariant_id": "INV-ZEBRA-test-aaaa-bbbb",
                "invariant_text": ("A network codec MUST NOT reserve buffer capacity "
                                   "sized by an attacker-claimed length field from an "
                                   "unauthenticated/pre-handshake peer; large reservations "
                                   "MUST be bounded and/or deferred until after handshake."),
                "attack_class": "untrusted-length-driven-allocation-pre-auth",
                "bug_class": "pre-handshake-buffer-reserve",
                "preconditions": ["Commit point: codec decode", "Defense: bound reservation"],
                "violation_consequence": "Unauthenticated peer drives address-space reservation.",
                "target_language": "rust",
                "source_findings": ["https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h72h-ppcx-998p"],
            },
            "verification_tier": "tier-1-officially-disclosed",
            "source": {"task_type": "ghsa-advisory-etl", "task_id": "zebra:GHSA-h72h"},
        }

    def _zebra_det_record(self):
        inner = '{"ast_query_hint": "Flag reserve() sized by peer length", "regex_pattern": "reserve\\(", "language": "rust"}'
        return {
            "record_id": "zebra-det:ghsa-h72h-ppcx-998p:deadbeef",
            "statement": inner,
            "attack_class": "untrusted-length-driven-allocation-pre-auth",
            "category": "allocation",
            "kind": "detector_seed",
            "raw_keys": ["ast_query_hint", "regex_pattern", "language"],
            "router": "zebra_advisories_etl",
            "target_lang": "rust",
            "verification_tier": "tier-1-officially-disclosed",
            "source_audit_ref": "https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h72h-ppcx-998p",
            "source_task_id": "zebra-advisories-etl:GHSA-h72h-ppcx-998p",
            "audit_status": "tier-1-officially-disclosed:zebra-advisories-etl",
        }

    def test_invariant_extractor_preserves_full_content_and_tier(self):
        out = self.m._extract_zebra_invariant_jsonl(self._zebra_inv_record())
        self.assertEqual(len(out), 1)
        rec = out[0]
        self.assertEqual(rec["invariant_id"], "INV-ZEBRA-test-aaaa-bbbb")
        self.assertEqual(rec["verification_tier"], "tier-1-officially-disclosed")
        # Full statement preserved (NOT truncated to a single line)
        self.assertGreater(len(rec["statement"]), 150)
        self.assertIn("attacker-claimed length", rec["statement"])
        # source_finding_ids preserved (the lossy YAML path lost these)
        self.assertEqual(len(rec["source_finding_ids"]), 1)
        self.assertIn("GHSA-h72h", rec["source_finding_ids"][0])
        # advisory fields copied verbatim
        self.assertEqual(rec["bug_class"], "pre-handshake-buffer-reserve")
        self.assertEqual(len(rec["preconditions"]), 2)
        self.assertIn("address-space", rec["violation_consequence"])
        self.assertEqual(rec["target_lang"], "rust")

    def test_detector_extractor_preserves_inner_json_and_tier(self):
        out = self.m._extract_zebra_detector_jsonl(self._zebra_det_record())
        self.assertEqual(len(out), 1)
        rec = out[0]
        # bare record_id (no -0 suffix), matching the source
        self.assertEqual(rec["record_id"], "zebra-det:ghsa-h72h-ppcx-998p:deadbeef")
        self.assertEqual(rec["verification_tier"], "tier-1-officially-disclosed")
        self.assertIn("ast_query_hint", rec["statement"])
        self.assertIn("regex_pattern", rec["statement"])
        self.assertEqual(rec["attack_class"], "untrusted-length-driven-allocation-pre-auth")
        self.assertEqual(rec["target_lang"], "rust")

    def test_extractors_reject_incomplete_records(self):
        self.assertEqual(self.m._extract_zebra_invariant_jsonl({"content": {}}), [])
        self.assertEqual(self.m._extract_zebra_invariant_jsonl({}), [])
        self.assertEqual(self.m._extract_zebra_detector_jsonl({"record_id": "x"}), [])
        self.assertEqual(self.m._extract_zebra_detector_jsonl({}), [])

    def test_jsonl_router_promote_dedup_idempotent(self):
        src = self.tmp / "inv.jsonl"
        import json as _json
        src.write_text(_json.dumps(self._zebra_inv_record()) + "\n", encoding="utf-8")
        dst = self.tmp / "canon_inv.jsonl"
        router = {
            "name": "test_inv_jsonl",
            "source_file": src,
            "dst_path": dst,
            "key_field": "invariant_id",
            "extractor": self.m._extract_zebra_invariant_jsonl,
        }
        # First run promotes 1
        promoted, skipped = self.m.promote_from_jsonl_router(router, "low", dry_run=False)
        self.assertEqual((promoted, skipped), (1, 0))
        self.assertTrue(dst.exists())
        first = dst.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(first), 1)
        # Second run is idempotent: dedups by invariant_id, promotes 0
        promoted2, skipped2 = self.m.promote_from_jsonl_router(router, "low", dry_run=False)
        self.assertEqual((promoted2, skipped2), (0, 1))
        self.assertEqual(len(dst.read_text(encoding="utf-8").strip().splitlines()), 1)

    def test_jsonl_routers_registered_and_point_at_canonical(self):
        names = {r["name"] for r in self.m.JSONL_SOURCE_ROUTERS}
        self.assertIn("invariants_zebra_advisories_jsonl", names)
        self.assertIn("detector_seeds_zebra_advisories_jsonl", names)
        by_name = {r["name"]: r for r in self.m.JSONL_SOURCE_ROUTERS}
        self.assertEqual(
            by_name["invariants_zebra_advisories_jsonl"]["dst_path"], self.m.INV_DST)
        self.assertTrue(str(by_name["detector_seeds_zebra_advisories_jsonl"]["dst_path"])
                        .endswith("detector_seed_library_promoted.jsonl"))

    def test_advisory_jsonl_routers_glob_discovered_per_target(self):
        """2026-05-29 hyperbridge anchor: the JSONL router set is glob-discovered,
        so any invariants_<target>_advisories.jsonl / detector_seeds_<target>_advisories.jsonl
        in derived/ gets a faithful-copy router automatically (not just zebra)."""
        import json as _json
        derived = self.tmp / "derived"
        derived.mkdir()
        (derived / "invariants_hyperbridge_advisories.jsonl").write_text(
            _json.dumps(self._zebra_inv_record()) + "\n", encoding="utf-8")
        (derived / "detector_seeds_hyperbridge_advisories.jsonl").write_text(
            _json.dumps(self._zebra_det_record()) + "\n", encoding="utf-8")
        (derived / "invariants_zebra_advisories.jsonl").write_text("", encoding="utf-8")
        orig = self.m.DERIVED_ROOT
        try:
            self.m.DERIVED_ROOT = derived
            routers = self.m._discover_advisory_jsonl_routers()
        finally:
            self.m.DERIVED_ROOT = orig
        names = {r["name"] for r in routers}
        self.assertIn("invariants_hyperbridge_advisories_jsonl", names)
        self.assertIn("detector_seeds_hyperbridge_advisories_jsonl", names)
        self.assertIn("invariants_zebra_advisories_jsonl", names)
        by_name = {r["name"]: r for r in routers}
        # invariant routers point at the canonical invariant ledger
        self.assertEqual(
            by_name["invariants_hyperbridge_advisories_jsonl"]["dst_path"], self.m.INV_DST)
        # detector routers point at the canonical detector seed library
        self.assertTrue(str(by_name["detector_seeds_hyperbridge_advisories_jsonl"]["dst_path"])
                        .endswith("detector_seed_library_promoted.jsonl"))
        # extractor is the source-agnostic alias (identity with zebra extractor)
        self.assertIs(by_name["invariants_hyperbridge_advisories_jsonl"]["extractor"],
                      self.m._extract_zebra_invariant_jsonl)

    def test_source_agnostic_extractor_aliases_exist(self):
        self.assertIs(self.m._extract_advisory_invariant_jsonl,
                      self.m._extract_zebra_invariant_jsonl)
        self.assertIs(self.m._extract_advisory_detector_jsonl,
                      self.m._extract_zebra_detector_jsonl)


if __name__ == "__main__":
    unittest.main()
