"""Tests for ``tools/hackerman-attack-class-inventory.py``.

The tests build a small synthetic corpus on disk under a tmp dir and
exercise the walker / aggregator / orphan-and-well-covered classifiers
plus the markdown renderer.

Coverage (>=8 cases):

1. ``_yaml_load`` fallback parser handles minimal schema (key/value plus
   ``function_shape.shape_tags`` list).
2. ``_extract_verification_tier`` returns tier int from shape_tags.
3. ``_extract_verification_tier`` returns None when no tier tag.
4. ``_subtree_of`` returns the top-level subtree name for a record path.
5. ``build_inventory`` walks the tree, sums per-class records, captures
   subtree set, and sorts by total_records desc.
6. ``build_inventory`` handles records with missing ``attack_class``
   (bucketed under ``<missing-attack-class>``).
7. Orphan classifier returns classes with zero tier-1+2 records.
8. Well-covered classifier requires >=50 records, >=3 subtrees,
   >=80% tier-1+2.
9. Markdown renderer emits all four required sections.
10. JSON-only fallback when record.yaml is missing but record.json is present.
11. YAML preferred when both yaml + json exist in same dir.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-attack-class-inventory.py"


def _load_tool() -> Any:
    name = "_hackerman_attack_class_inventory_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _record_yaml(
    record_id: str,
    attack_class: str,
    shape_tags: list[str],
) -> str:
    tag_lines = "\n".join(f"    - {t}" for t in shape_tags)
    body = (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        f"target_repo: owner/{record_id}\n"
        "function_shape:\n"
        "  raw_signature: synthetic\n"
        "  shape_tags:\n"
        f"{tag_lines}\n"
    )
    if attack_class:
        body += f"attack_class: {attack_class}\n"
    return body


def _write_record(
    tags_dir: Path,
    subtree: str,
    record_id: str,
    attack_class: str,
    shape_tags: list[str],
    *,
    fmt: str = "yaml",
) -> Path:
    sub = tags_dir / subtree / record_id
    sub.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        p = sub / "record.yaml"
        p.write_text(
            _record_yaml(record_id, attack_class, shape_tags),
            encoding="utf-8",
        )
    else:
        p = sub / "record.json"
        body: dict[str, Any] = {
            "schema_version": "auditooor.hackerman_record.v1",
            "record_id": record_id,
            "target_repo": f"owner/{record_id}",
            "function_shape": {
                "raw_signature": "synthetic",
                "shape_tags": shape_tags,
            },
        }
        if attack_class:
            body["attack_class"] = attack_class
        p.write_text(json.dumps(body), encoding="utf-8")
    return p


class HelperUnitTests(unittest.TestCase):
    def test_yaml_load_fallback_basic_fields(self):
        text = (
            "schema_version: foo\n"
            "attack_class: bar-class\n"
            "function_shape:\n"
            "  shape_tags:\n"
            "    - one\n"
            "    - verification_tier:tier-1-real\n"
        )
        data = tool._yaml_load(text)
        self.assertEqual(data["attack_class"], "bar-class")
        self.assertIn("function_shape", data)
        self.assertIn("verification_tier:tier-1-real", data["function_shape"]["shape_tags"])

    def test_extract_verification_tier_present(self):
        rec = {
            "function_shape": {
                "shape_tags": ["alpha", "verification_tier:tier-3-synthetic-taxonomy-anchored"],
            }
        }
        self.assertEqual(tool._extract_verification_tier(rec), 3)

    def test_extract_verification_tier_absent(self):
        rec = {"function_shape": {"shape_tags": ["alpha", "beta"]}}
        self.assertIsNone(tool._extract_verification_tier(rec))

    def test_extract_verification_tier_malformed(self):
        for bad in [None, {}, {"function_shape": None}, {"function_shape": {"shape_tags": None}}]:
            self.assertIsNone(tool._extract_verification_tier(bad))

    def test_subtree_of_returns_top_level(self):
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            (tags / "lending_protocols" / "abc").mkdir(parents=True)
            p = tags / "lending_protocols" / "abc" / "record.yaml"
            p.write_text("schema_version: x\n", encoding="utf-8")
            self.assertEqual(tool._subtree_of(p, tags), "lending_protocols")


class CorpusBackedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hac-inv-test-")
        self.root = Path(self.tmp.name)
        self.tags_dir = self.root / "tags"
        self.tags_dir.mkdir()

        # Class A: 60 records across 3 subtrees, mostly tier-1/2 (well-covered).
        for i in range(20):
            _write_record(
                self.tags_dir,
                "lending_protocols",
                f"a-lend-{i}",
                "reentrancy",
                ["verification_tier:tier-1-verified-realtime-api"],
            )
        for i in range(20):
            _write_record(
                self.tags_dir,
                "dex_fix_history",
                f"a-dex-{i}",
                "reentrancy",
                ["verification_tier:tier-2-verified-public-archive"],
            )
        # Drop tier-1+2 share just below 100% with a few tier-3s and
        # a couple in a 3rd subtree so it crosses the >=3-subtree threshold.
        for i in range(18):
            _write_record(
                self.tags_dir,
                "audit_firm_public_reports",
                f"a-pub-{i}",
                "reentrancy",
                ["verification_tier:tier-1-verified-realtime-api"],
            )
        for i in range(2):
            _write_record(
                self.tags_dir,
                "audit_firm_public_reports",
                f"a-pub3-{i}",
                "reentrancy",
                ["verification_tier:tier-3-synthetic-taxonomy-anchored"],
            )

        # Class B: 10 records in one subtree, only tier-3/4/5 (orphan).
        for i in range(5):
            _write_record(
                self.tags_dir,
                "zk_circuit_bugs",
                f"b-{i}",
                "unconstrained-variable",
                ["verification_tier:tier-3-synthetic-taxonomy-anchored"],
            )
        for i in range(3):
            _write_record(
                self.tags_dir,
                "zk_circuit_bugs",
                f"b-q-{i}",
                "unconstrained-variable",
                ["verification_tier:tier-5-quarantine"],
            )
        for i in range(2):
            _write_record(
                self.tags_dir,
                "zk_circuit_bugs",
                f"b-n-{i}",
                "unconstrained-variable",
                ["foo", "bar"],
            )

        # Class C: 1 record only, no attack_class (bucketed under missing).
        _write_record(
            self.tags_dir,
            "mev_exploits",
            "c-missing",
            "",
            ["verification_tier:tier-1-verified-realtime-api"],
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_build_inventory_totals_and_sort(self):
        inv = tool.build_inventory(self.tags_dir)
        self.assertEqual(inv["schema"], tool.SCHEMA)
        # 20+20+18+2 + 5+3+2 + 1 = 71.
        self.assertEqual(inv["total_records"], 71)
        # 3 named classes plus the synthetic missing one == 3 (missing bucket
        # uses placeholder name).
        names = [r["attack_class"] for r in inv["classes"]]
        self.assertIn("reentrancy", names)
        self.assertIn("unconstrained-variable", names)
        self.assertIn("<missing-attack-class>", names)
        # Sort: reentrancy (60) > unconstrained (10) > missing (1).
        self.assertEqual(inv["classes"][0]["attack_class"], "reentrancy")
        self.assertEqual(inv["classes"][0]["total_records"], 60)

    def test_build_inventory_subtrees_per_class(self):
        inv = tool.build_inventory(self.tags_dir)
        reentrancy = next(r for r in inv["classes"] if r["attack_class"] == "reentrancy")
        self.assertEqual(
            sorted(reentrancy["subtrees"]),
            ["audit_firm_public_reports", "dex_fix_history", "lending_protocols"],
        )
        # tier-1+2 = 20 lend + 20 dex + 18 pub = 58 out of 60 = 96.67%.
        self.assertEqual(reentrancy["tier12_count"], 58)
        self.assertAlmostEqual(reentrancy["tier12_pct"], 96.67, places=2)

    def test_missing_attack_class_bucketed(self):
        inv = tool.build_inventory(self.tags_dir)
        missing = next(r for r in inv["classes"] if r["attack_class"] == "<missing-attack-class>")
        self.assertEqual(missing["total_records"], 1)
        self.assertEqual(missing["subtrees"], ["mev_exploits"])

    def test_orphan_classifier(self):
        inv = tool.build_inventory(self.tags_dir)
        orphans = tool._orphan_classes(inv)
        names = [r["attack_class"] for r in orphans]
        # unconstrained-variable is orphan (no tier-1/2).
        self.assertIn("unconstrained-variable", names)
        # reentrancy has tier-1/2 records, not an orphan.
        self.assertNotIn("reentrancy", names)
        # <missing-attack-class> is excluded by the classifier filter.
        self.assertNotIn("<missing-attack-class>", names)

    def test_well_covered_classifier(self):
        inv = tool.build_inventory(self.tags_dir)
        well = tool._well_covered_classes(inv)
        names = [r["attack_class"] for r in well]
        self.assertIn("reentrancy", names)
        # unconstrained-variable fails: <50 records AND <3 subtrees.
        self.assertNotIn("unconstrained-variable", names)

    def test_markdown_renderer_has_all_sections(self):
        inv = tool.build_inventory(self.tags_dir)
        md = tool._render_markdown(inv, top_n=10)
        self.assertIn("# Hackerman attack-class taxonomy inventory", md)
        self.assertIn("## Top-10 attack classes by record count", md)
        self.assertIn("## Orphan classes", md)
        self.assertIn("## Well-covered classes", md)
        self.assertIn("## Per-subtree coverage", md)
        self.assertIn("## Aggregate verification-tier histogram", md)
        self.assertIn("## Methodology", md)
        # The MCP integration footer references the v1 schema.
        self.assertIn("auditooor.vault_attack_class_taxonomy.v1", md)
        # Reentrancy shows up in the top-N table.
        self.assertIn("`reentrancy`", md)

    def test_json_only_fallback(self):
        # Add a class D with only record.json present in its dir.
        _write_record(
            self.tags_dir,
            "solana_svm",
            "d-json-only",
            "solana-class",
            ["verification_tier:tier-2-verified-public-archive"],
            fmt="json",
        )
        inv = tool.build_inventory(self.tags_dir)
        names = [r["attack_class"] for r in inv["classes"]]
        self.assertIn("solana-class", names)

    def test_yaml_preferred_when_both_present(self):
        # Class E directory ships BOTH yaml + json with conflicting attack_class.
        sub = self.tags_dir / "cosmos_sdk_ibc" / "e-conflict"
        sub.mkdir(parents=True)
        (sub / "record.yaml").write_text(
            _record_yaml("e-conflict", "yaml-wins", ["verification_tier:tier-1-verified-realtime-api"]),
            encoding="utf-8",
        )
        (sub / "record.json").write_text(
            json.dumps({"attack_class": "json-loses", "record_id": "e-conflict",
                        "function_shape": {"shape_tags": ["verification_tier:tier-1-verified-realtime-api"]}}),
            encoding="utf-8",
        )
        inv = tool.build_inventory(self.tags_dir)
        names = [r["attack_class"] for r in inv["classes"]]
        self.assertIn("yaml-wins", names)
        self.assertNotIn("json-loses", names)

    def test_main_writes_json_and_markdown(self):
        out_json = self.root / "out.json"
        out_md = self.root / "out.md"
        rc = tool.main(
            [
                "--tags-dir",
                str(self.tags_dir),
                "--out-json",
                str(out_json),
                "--out-md",
                str(out_md),
                "--top-n",
                "5",
                "--quiet",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(out_json.exists())
        self.assertTrue(out_md.exists())
        loaded = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(loaded["schema"], tool.SCHEMA)
        self.assertEqual(loaded["total_records"], 71)
        md_text = out_md.read_text(encoding="utf-8")
        self.assertIn("## Top-5 attack classes by record count", md_text)


def _write_confirmed_finding_record(
    tags_dir: Path,
    subtree: str,
    record_id: str,
    attack_class: str,
    shape_tags: list[str],
    *,
    confirmed: bool = True,
    id_prefix_own: bool = False,
) -> Path:
    """Write an own-confirmed-finding style record.yaml (P45 SELF signal).

    Mirrors the real corpus shape: ``record_extensions.confirmed_finding``
    + optional ``own-finding:`` id prefix.
    """
    rid = f"own-finding:{record_id}" if id_prefix_own else record_id
    tag_lines = "\n".join(f"    - {t}" for t in shape_tags)
    body = (
        "schema_version: auditooor.hackerman_record.v1.1\n"
        f'record_id: "{rid}"\n'
        f"target_repo: owner/{record_id}\n"
        "function_shape:\n"
        "  raw_signature: synthetic\n"
        "  shape_tags:\n"
        f"{tag_lines}\n"
        f"attack_class: {attack_class}\n"
        "record_extensions:\n"
        "  origin_workspace: testws\n"
        f"  confirmed_finding: {'true' if confirmed else 'false'}\n"
    )
    sub = tags_dir / subtree / record_id
    sub.mkdir(parents=True, exist_ok=True)
    p = sub / "record.yaml"
    p.write_text(body, encoding="utf-8")
    return p


class OriginSkewP45Tests(unittest.TestCase):
    """P45: SELF-vs-INDEPENDENT origin dimension + JSD/slope skew metric."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hac-inv-p45-")
        self.root = Path(self.tmp.name)
        self.tags_dir = self.root / "tags"
        self.tags_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # --- origin bucketing (the exact bug the naive provenance.kind map gets wrong).
    def test_record_origin_self_via_confirmed_finding(self):
        rec = {
            "record_id": "some-plain-id",
            "record_extensions": {"confirmed_finding": True},
        }
        self.assertEqual(tool._record_origin(rec), tool.ORIGIN_SELF)

    def test_record_origin_self_via_confirmed_finding_string_true(self):
        # YAML fallback parser yields the scalar as a string.
        rec = {"record_extensions": {"confirmed_finding": "true"}}
        self.assertEqual(tool._record_origin(rec), tool.ORIGIN_SELF)

    def test_record_origin_self_via_own_finding_id_prefix(self):
        rec = {"record_id": "own-finding:dydx:foo"}
        self.assertEqual(tool._record_origin(rec), tool.ORIGIN_SELF)

    def test_record_origin_self_via_source_audit_ref_prefix(self):
        rec = {"source_audit_ref": "own-finding:mezo:bar"}
        self.assertEqual(tool._record_origin(rec), tool.ORIGIN_SELF)

    def test_record_origin_independent_default(self):
        # No SELF signal -> INDEPENDENT (strict complement; no third bucket).
        for rec in (
            {"record_id": "solodit-1234"},
            {"record_extensions": {"confirmed_finding": False}},
            {"record_extensions": {"confirmed_finding": "false"}},
            {},
            None,
            {"provenance": {"kind": "own-confirmed-finding"}},  # nonexistent path -> NOT self
        ):
            self.assertEqual(tool._record_origin(rec), tool.ORIGIN_INDEPENDENT)

    def test_confirmed_finding_records_bucket_to_self_in_inventory(self):
        # 40 confirmed SELF findings + 10 independent, same class.
        for i in range(40):
            _write_confirmed_finding_record(
                self.tags_dir, "auditooor_own_findings", f"own-{i}",
                "reentrancy", ["verification_tier:tier-1-officially-disclosed"],
                confirmed=True, id_prefix_own=True,
            )
        for i in range(10):
            _write_record(
                self.tags_dir, "solodit_findings", f"ind-{i}",
                "reentrancy", ["verification_tier:tier-2-verified-public-archive"],
            )
        inv = tool.build_inventory(self.tags_dir)
        reentrancy = next(r for r in inv["classes"] if r["attack_class"] == "reentrancy")
        self.assertIn("origin", reentrancy)
        self.assertEqual(reentrancy["origin"][tool.ORIGIN_SELF], 40)
        self.assertEqual(reentrancy["origin"][tool.ORIGIN_INDEPENDENT], 10)
        # total_records unchanged / consistent with origin split.
        self.assertEqual(reentrancy["total_records"], 50)

    def test_jsd_hand_calc_matches(self):
        # Two disjoint distributions -> JSD == 1.0 (base-2).
        self.assertAlmostEqual(
            tool._jensen_shannon_divergence({"a": 10}, {"b": 10}), 1.0, places=9
        )
        # Identical distributions -> JSD == 0.0.
        self.assertAlmostEqual(
            tool._jensen_shannon_divergence({"a": 5, "b": 5}, {"a": 5, "b": 5}),
            0.0, places=9,
        )
        # Known hand-calc: p={a:1}, q={a:0.5,b:0.5}.
        # M={a:0.75,b:0.25}. KL(p||M)=1*log2(1/0.75)=0.415037...
        # KL(q||M)=0.5*log2(0.5/0.75)+0.5*log2(0.5/0.25)=0.5*(-0.584963)+0.5*(1.0)
        #        =0.207518...  JSD=0.5*(0.415037+0.207518)=0.311278...
        jsd = tool._jensen_shannon_divergence({"a": 1.0}, {"a": 0.5, "b": 0.5})
        self.assertAlmostEqual(jsd, 0.311278, places=5)

    def test_origin_skew_sufficient_sample_computes_jsd(self):
        # SELF concentrated in class A, INDEPENDENT in class B (disjoint) ->
        # JSD == 1.0, sample above the floor.
        for i in range(tool.ORIGIN_SKEW_MIN_SELF_RECORDS + 5):
            _write_confirmed_finding_record(
                self.tags_dir, "own", f"s-{i}", "class-a",
                ["verification_tier:tier-1-officially-disclosed"],
                confirmed=True,
            )
        for i in range(20):
            _write_record(
                self.tags_dir, "solodit", f"i-{i}", "class-b",
                ["verification_tier:tier-2-verified-public-archive"],
            )
        inv = tool.build_inventory(self.tags_dir)
        skew = inv["origin_skew"]
        self.assertTrue(skew["sufficient_self_sample"])
        self.assertIsNone(skew["sentinel"])
        self.assertAlmostEqual(skew["jensen_shannon_divergence"], 1.0, places=6)
        self.assertEqual(skew["self_records"], tool.ORIGIN_SKEW_MIN_SELF_RECORDS + 5)
        self.assertEqual(skew["independent_records"], 20)

    def test_origin_skew_insufficient_sample_sentinel(self):
        # Tiny SELF sample (below floor) -> sentinel, JSD/slope suppressed.
        for i in range(3):
            _write_confirmed_finding_record(
                self.tags_dir, "own", f"s-{i}", "class-a",
                ["verification_tier:tier-1-officially-disclosed"],
                confirmed=True,
            )
        for i in range(50):
            _write_record(
                self.tags_dir, "solodit", f"i-{i}", "class-b",
                ["verification_tier:tier-2-verified-public-archive"],
            )
        inv = tool.build_inventory(self.tags_dir)
        skew = inv["origin_skew"]
        self.assertFalse(skew["sufficient_self_sample"])
        self.assertEqual(skew["sentinel"], "insufficient-SELF-sample")
        self.assertIsNone(skew["jensen_shannon_divergence"])
        self.assertIsNone(skew["slope"])
        self.assertEqual(skew["self_records"], 3)

    def test_origin_skew_no_self_records_is_sentinel(self):
        # Pure INDEPENDENT corpus -> sentinel, never a misleading number.
        for i in range(20):
            _write_record(
                self.tags_dir, "solodit", f"i-{i}", "class-b",
                ["verification_tier:tier-2-verified-public-archive"],
            )
        inv = tool.build_inventory(self.tags_dir)
        skew = inv["origin_skew"]
        self.assertEqual(skew["self_records"], 0)
        self.assertEqual(skew["sentinel"], "insufficient-SELF-sample")

    def test_missing_attack_class_excluded_from_skew(self):
        # A missing-attack-class SELF record must not leak into the skew dists.
        _write_confirmed_finding_record(
            self.tags_dir, "own", "s-missing", "",  # empty attack_class
            ["verification_tier:tier-1-officially-disclosed"],
            confirmed=True,
        )
        inv = tool.build_inventory(self.tags_dir)
        skew = inv["origin_skew"]
        # The <missing-attack-class> bucket is excluded from the skew totals.
        self.assertEqual(skew["self_records"], 0)

    def test_markdown_has_origin_skew_section(self):
        for i in range(5):
            _write_confirmed_finding_record(
                self.tags_dir, "own", f"s-{i}", "class-a",
                ["verification_tier:tier-1-officially-disclosed"], confirmed=True,
            )
        for i in range(10):
            _write_record(
                self.tags_dir, "solodit", f"i-{i}", "class-b",
                ["verification_tier:tier-2-verified-public-archive"],
            )
        inv = tool.build_inventory(self.tags_dir)
        md = tool._render_markdown(inv, top_n=5)
        self.assertIn("## Corpus origin skew (SELF vs INDEPENDENT)", md)
        self.assertIn("Jensen-Shannon", md)


class P45AdditiveRegressionTests(unittest.TestCase):
    """Regression: flag-unset output preserves every pre-P45 key/value byte-stable.

    Compares the CURRENT tool output against the captured baseline (if present)
    to prove additive-only discipline on the real corpus.
    """

    BASELINE_JSON = Path("/tmp/qna-build-baselines/P45_taxonomy.json")

    def test_flag_unset_json_is_additive_only_vs_baseline(self):
        import os

        if not self.BASELINE_JSON.exists():
            self.skipTest("baseline taxonomy snapshot not present")
        # Ensure the strict flag is NOT set for this comparison.
        prior = os.environ.pop("AUDITOOOR_CORPUS_SKEW_STRICT", None)
        try:
            default_tags = tool.DEFAULT_TAGS_DIR
            if not default_tags.exists():
                self.skipTest("default corpus tags dir not present")
            new = tool.build_inventory(default_tags)
        finally:
            if prior is not None:
                os.environ["AUDITOOOR_CORPUS_SKEW_STRICT"] = prior
        base = json.loads(self.BASELINE_JSON.read_text(encoding="utf-8"))

        # 1. Every baseline top-level key survives with an identical value,
        #    except ``classes`` (each row gains only the additive ``origin`` key).
        for k in base:
            self.assertIn(k, new, f"baseline top-level key dropped: {k}")
        added_top = set(new) - set(base)
        self.assertEqual(added_top, {"origin_skew"}, f"unexpected top-level additions: {added_top}")
        for k in ("schema", "total_records", "subtrees", "per_subtree", "tags_dir"):
            self.assertEqual(base[k], new[k], f"baseline value changed for {k}")

        # 2. Classes: same count, same ordering, all 8 baseline per-class keys
        #    byte-stable across ALL rows; only ``origin`` added.
        bc, nc = base["classes"], new["classes"]
        self.assertEqual(len(bc), len(nc), "class count changed")
        base_class_keys = set(bc[0].keys())
        added_class_keys = set(nc[0].keys()) - base_class_keys
        self.assertEqual(added_class_keys, {"origin"}, f"unexpected per-class additions: {added_class_keys}")
        for b, n in zip(bc, nc):
            self.assertEqual(b["attack_class"], n["attack_class"], "class ordering perturbed")
            for k in base_class_keys:
                self.assertEqual(b[k], n[k], f"per-class value changed for {k} in {b['attack_class']}")


if __name__ == "__main__":
    unittest.main()
