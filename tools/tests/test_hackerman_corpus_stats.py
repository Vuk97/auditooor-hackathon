"""Tests for ``tools/hackerman-corpus-stats.py``.

The tool emits a deterministic stats report over the hackerman corpus tree.
These tests build a small synthetic ``audit/corpus_tags/tags/`` structure
on disk and assert the walker / aggregator / renderer behave correctly
across the three record shapes (``record.yaml`` / ``record.json`` /
flat ``<name>.yaml``) plus quarantine bookkeeping plus the (mocked) gate
delegation hooks.

Coverage (>=8 cases):

1. ``_yaml_load`` fallback parser handles a minimal schema.
2. ``_extract_verification_tier`` returns tier int from shape_tags.
3. ``_extract_verification_tier`` returns None when no tier tag present.
4. ``_subtree_of`` returns the top-level subtree, with flat root sentinel.
5. ``build_stats`` walks record.yaml + record.json (json-only when no yaml
   sibling exists) + flat .yaml, with stable shape_counts and per-subtree
   sorting.
6. ``build_stats`` aggregates quarantine records under
   ``_QUARANTINE_<reason>/<reason_dir>/...`` and per-reason buckets.
7. ``build_stats`` records ``<missing-attack-class>`` / ``<missing-target-domain>``
   sentinel buckets when fields are absent.
8. ``render_report`` emits all five mandatory sections (shape histogram,
   per-subtree, quarantine, verification-tier gate, acceptance gate).
9. JSON mode (``--json``) produces parseable JSON whose ``stats`` block
   matches ``build_stats`` for the same tree.
10. ``--skip-gates`` short-circuits the subprocess delegation and reports
    ``skipped`` verdicts.
11. Output size for a synthetic tree stays well under 1MB.
12. Determinism: two consecutive runs over the same tree produce
    byte-identical reports when ``--generated-at`` is pinned.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-corpus-stats.py"


def _load_tool() -> Any:
    name = "_hackerman_corpus_stats_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _yaml_record(
    *,
    record_id: str,
    attack_class: str = "test-attack-class",
    target_domain: str = "vault",
    tier_tag: str | None = "verification_tier:tier-1-verified-realtime-api",
    schema_version: str = "auditooor.hackerman_record.v1",
) -> str:
    shape_tags = []
    if tier_tag:
        shape_tags.append(tier_tag)
    shape_tags.append("synthetic-test")
    tag_lines = "\n".join(f"    - {t}" for t in shape_tags)
    parts = [
        f"schema_version: {schema_version}",
        f"record_id: {record_id}",
        f"target_domain: {target_domain}",
        "function_shape:",
        "  raw_signature: synthetic",
        "  shape_tags:",
        tag_lines,
    ]
    if attack_class:
        parts.append(f"attack_class: {attack_class}")
    return "\n".join(parts) + "\n"


def _write_record_yaml(
    tags_dir: Path,
    subtree: str,
    record_id: str,
    *,
    attack_class: str = "test-attack-class",
    target_domain: str = "vault",
    tier_tag: str | None = "verification_tier:tier-1-verified-realtime-api",
) -> Path:
    sub = tags_dir / subtree / record_id
    sub.mkdir(parents=True, exist_ok=True)
    p = sub / "record.yaml"
    p.write_text(
        _yaml_record(
            record_id=record_id,
            attack_class=attack_class,
            target_domain=target_domain,
            tier_tag=tier_tag,
        ),
        encoding="utf-8",
    )
    return p


def _write_record_json(
    tags_dir: Path,
    subtree: str,
    record_id: str,
    *,
    attack_class: str = "test-attack-class",
    target_domain: str = "vault",
    tier_tag: str | None = "verification_tier:tier-2-verified-public-archive",
) -> Path:
    sub = tags_dir / subtree / record_id
    sub.mkdir(parents=True, exist_ok=True)
    p = sub / "record.json"
    payload: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "target_domain": target_domain,
        "function_shape": {
            "raw_signature": "synthetic",
            "shape_tags": [tier_tag] if tier_tag else [],
        },
    }
    if attack_class:
        payload["attack_class"] = attack_class
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _write_flat_yaml(
    tags_dir: Path,
    *,
    record_id: str,
    attack_class: str = "flat-attack-class",
    target_domain: str = "dex",
    tier_tag: str | None = "verification_tier:tier-2-verified-public-archive",
    subdir: str | None = None,
) -> Path:
    parent = tags_dir if subdir is None else tags_dir / subdir
    parent.mkdir(parents=True, exist_ok=True)
    p = parent / f"{record_id}.yaml"
    p.write_text(
        _yaml_record(
            record_id=record_id,
            attack_class=attack_class,
            target_domain=target_domain,
            tier_tag=tier_tag,
        ),
        encoding="utf-8",
    )
    return p


class HelperUnitTests(unittest.TestCase):
    def test_yaml_load_fallback_basic(self):
        text = (
            "schema_version: foo\n"
            "attack_class: alpha-class\n"
            "function_shape:\n"
            "  shape_tags:\n"
            "    - one\n"
            "    - verification_tier:tier-1-real-source\n"
        )
        data = tool._yaml_load(text)
        self.assertEqual(data.get("attack_class"), "alpha-class")
        self.assertIn("function_shape", data)
        self.assertIn(
            "verification_tier:tier-1-real-source",
            data["function_shape"]["shape_tags"],
        )

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
        # Malformed shapes too.
        for bad in [None, {}, {"function_shape": None}, {"function_shape": {"shape_tags": None}}]:
            self.assertIsNone(tool._extract_verification_tier(bad))

    def test_is_hackerman_v1_accepts_v1_and_v1_1(self):
        """Wave-2 Phase-3 schema migration: v1.1 records must be recognised
        (NOT skipped). Regression-guard for the exact-match → prefix-match
        migration on the _is_hackerman_v1 helper. Both v1 and v1.1 records
        must pass; verdict_tag.v2 siblings and unrelated schemas must fail."""
        self.assertTrue(
            tool._is_hackerman_v1({"schema_version": "auditooor.hackerman_record.v1"})
        )
        self.assertTrue(
            tool._is_hackerman_v1({"schema_version": "auditooor.hackerman_record.v1.1"})
        )
        # Whitespace tolerance preserved.
        self.assertTrue(
            tool._is_hackerman_v1({"schema_version": "  auditooor.hackerman_record.v1.1  "})
        )
        # Non-hackerman schemas still rejected.
        self.assertFalse(
            tool._is_hackerman_v1({"schema_version": "auditooor.verdict_tag.v2"})
        )
        self.assertFalse(tool._is_hackerman_v1({"schema_version": ""}))
        self.assertFalse(tool._is_hackerman_v1({}))

    def test_subtree_of_returns_top_level_and_flat_root(self):
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            (tags / "lending_protocols" / "abc").mkdir(parents=True)
            p = tags / "lending_protocols" / "abc" / "record.yaml"
            p.write_text("schema_version: x\n", encoding="utf-8")
            self.assertEqual(tool._subtree_of(p, tags), "lending_protocols")
            # Flat at tags-dir root reports <flat-root>.
            flat = tags / "flat-name.yaml"
            flat.write_text("schema_version: x\n", encoding="utf-8")
            self.assertEqual(tool._subtree_of(flat, tags), "<flat-root>")


class StatsBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hac-corpus-stats-")
        self.tags_dir = Path(self.tmp.name) / "tags"
        self.tags_dir.mkdir()

        # subtree 1: 3 record.yaml records (lending_protocols).
        for i in range(3):
            _write_record_yaml(
                self.tags_dir,
                "lending_protocols",
                f"lp-{i}",
                attack_class="reentrancy",
                target_domain="lending",
            )
        # subtree 2: 2 record.json-only records (solana_svm), tier-2.
        for i in range(2):
            _write_record_json(
                self.tags_dir,
                "solana_svm",
                f"sol-{i}",
                attack_class="signer-authorization-bypass",
                target_domain="solana-svm",
            )
        # subtree 3 (record.yaml + record.json sibling - yaml wins, json
        # ignored because of the seen_dirs filter).
        sub = self.tags_dir / "dex_fix_history" / "both"
        sub.mkdir(parents=True)
        (sub / "record.yaml").write_text(
            _yaml_record(record_id="both", attack_class="yaml-wins", target_domain="dex"),
            encoding="utf-8",
        )
        (sub / "record.json").write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.hackerman_record.v1",
                    "record_id": "both",
                    "attack_class": "json-loses",
                    "target_domain": "dex",
                    "function_shape": {
                        "shape_tags": ["verification_tier:tier-1-verified-realtime-api"],
                    },
                }
            ),
            encoding="utf-8",
        )

        # Flat root: 4 loose .yaml at tags-dir root.
        for i in range(4):
            _write_flat_yaml(
                self.tags_dir,
                record_id=f"flat-{i}",
                attack_class="protocol-invariant-bypass",
                target_domain="vault",
            )
        # Flat root: 1 with NO attack_class to exercise the sentinel bucket.
        _write_flat_yaml(
            self.tags_dir,
            record_id="flat-missing-ac",
            attack_class="",
            target_domain="oracle",
            tier_tag=None,
        )

        # Quarantine: 5 loose .yaml under
        # ``_QUARANTINE_FABRICATED_CVE/vyper_cve_fabricated/...`` plus 1 under
        # a different reason directory.
        q_root = self.tags_dir / "_QUARANTINE_FABRICATED_CVE"
        for i in range(5):
            _write_flat_yaml(
                self.tags_dir,
                record_id=f"q-vyper-{i}",
                attack_class="vyper-compiler-bug",
                target_domain="dex",
                tier_tag="verification_tier:tier-5-quarantine",
                subdir="_QUARANTINE_FABRICATED_CVE/vyper_cve_fabricated",
            )
        _write_flat_yaml(
            self.tags_dir,
            record_id="q-other",
            attack_class="other-quarantine-class",
            target_domain="bridge",
            tier_tag="verification_tier:tier-5-quarantine",
            subdir="_QUARANTINE_FABRICATED_CVE/other_reason",
        )
        assert q_root.is_dir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_shape_counts_split_yaml_json_flat(self):
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["schema"], tool.SCHEMA)
        # 4 record.yaml (3 lp + 1 dex-yaml-wins).
        self.assertEqual(stats["shape_counts"]["record.yaml"], 4)
        # 2 record.json (the sol-* dirs; the dex/both/record.json is
        # suppressed because its sibling record.yaml claimed the dir).
        self.assertEqual(stats["shape_counts"]["record.json"], 2)
        # 4 flat root + 1 missing-ac + 5 quarantine vyper + 1 quarantine other = 11.
        self.assertEqual(stats["shape_counts"]["flat.yaml"], 11)
        self.assertEqual(stats["total_records"], 4 + 2 + 11)
        # All synthetic records carry the hackerman_v1 schema.
        self.assertEqual(stats["hackerman_v1_total"], stats["total_records"])

    def test_per_subtree_sorted_alphabetically(self):
        stats = tool.build_stats(self.tags_dir)
        names = [r["subtree"] for r in stats["subtrees"]]
        self.assertEqual(names, sorted(names))
        # Specific names show up.
        self.assertIn("lending_protocols", names)
        self.assertIn("solana_svm", names)
        self.assertIn("<flat-root>", names)
        self.assertIn("_QUARANTINE_FABRICATED_CVE", names)

    def test_per_subtree_target_domain_and_attack_class_top5(self):
        stats = tool.build_stats(self.tags_dir)
        lp = next(r for r in stats["subtrees"] if r["subtree"] == "lending_protocols")
        # 3 records, all target_domain=lending, all attack_class=reentrancy.
        self.assertEqual(lp["records"], 3)
        self.assertEqual(lp["target_domain_top5"], [("lending", 3)])
        self.assertEqual(lp["attack_class_top5"], [("reentrancy", 3)])
        self.assertEqual(lp["verification_tier_histogram"], {"tier-1": 3})

    def test_missing_attack_class_bucketed_in_flat_root(self):
        stats = tool.build_stats(self.tags_dir)
        flat = next(r for r in stats["subtrees"] if r["subtree"] == "<flat-root>")
        ac_names = [name for name, _ in flat["attack_class_top5"]]
        self.assertIn("<missing-attack-class>", ac_names)
        # no-tier bucket present (the flat-missing-ac entry has no tier tag).
        self.assertIn("no-tier", flat["verification_tier_histogram"])

    def test_quarantine_aggregation(self):
        stats = tool.build_stats(self.tags_dir)
        q = stats["quarantine"]
        self.assertEqual(q["total"], 6)
        self.assertEqual(q["per_reason"]["vyper_cve_fabricated"], 5)
        self.assertEqual(q["per_reason"]["other_reason"], 1)

    def test_yaml_preferred_over_json_when_both_present(self):
        stats = tool.build_stats(self.tags_dir)
        dex = next(r for r in stats["subtrees"] if r["subtree"] == "dex_fix_history")
        ac_names = [name for name, _ in dex["attack_class_top5"]]
        # yaml-wins NOT json-loses.
        self.assertIn("yaml-wins", ac_names)
        self.assertNotIn("json-loses", ac_names)


class RenderAndCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hac-corpus-stats-cli-")
        self.tags_dir = Path(self.tmp.name) / "tags"
        self.tags_dir.mkdir()
        # Single record.yaml is enough for the renderer tests.
        _write_record_yaml(
            self.tags_dir,
            "lending_protocols",
            "lp-0",
            attack_class="reentrancy",
            target_domain="lending",
        )
        _write_flat_yaml(
            self.tags_dir,
            record_id="flat-0",
            attack_class="protocol-invariant-bypass",
            target_domain="vault",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_render_report_has_all_sections(self):
        stats = tool.build_stats(self.tags_dir)
        tier_gate = {"verdict": "pass", "summary": "ok", "rc": 0, "stderr_tail": ""}
        accept_gate = {"verdict": "pass", "summary": "ok", "rc": 0, "stderr_tail": ""}
        report = tool.render_report(
            stats, tier_gate, accept_gate, generated_at="2026-05-16T00:00:00Z"
        )
        self.assertIn("# hackerman corpus stats", report)
        self.assertIn("## Record-shape histogram", report)
        self.assertIn("## Per-corpus-subtree breakdown", report)
        self.assertIn("## Quarantine status", report)
        self.assertIn("## Verification-tier gate", report)
        self.assertIn("## Acceptance gate", report)
        # Tags-dir is anchored in the header.
        self.assertIn(str(self.tags_dir), report)
        # 1MB output budget is preserved for synthetic trees.
        self.assertLess(len(report.encode("utf-8")), 1_000_000)

    def test_cli_skip_gates_exits_zero_with_skipped_verdicts(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags_dir),
                "--skip-gates",
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("verdict: skipped", proc.stdout)
        self.assertIn("lending_protocols", proc.stdout)

    def test_cli_json_mode_produces_parseable_payload(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags_dir),
                "--skip-gates",
                "--generated-at",
                "2026-05-16T00:00:00Z",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertEqual(payload["generated_at"], "2026-05-16T00:00:00Z")
        self.assertEqual(payload["stats"]["schema"], tool.SCHEMA)
        # Same totals as build_stats() over the synthetic tree.
        expected = tool.build_stats(self.tags_dir)
        self.assertEqual(payload["stats"]["total_records"], expected["total_records"])
        # Gates reported as skipped.
        self.assertEqual(payload["verification_tier_gate"]["verdict"], "skipped")
        self.assertEqual(payload["acceptance_gate"]["verdict"], "skipped")

    def test_cli_deterministic_when_generated_at_pinned(self):
        cmd = [
            sys.executable,
            str(TOOL_PATH),
            "--tags-dir",
            str(self.tags_dir),
            "--skip-gates",
            "--generated-at",
            "2026-05-16T00:00:00Z",
        ]
        first = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        second = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(first.returncode, 0, msg=first.stderr)
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        # Byte-identical outputs - the determinism guarantee in the spec.
        self.assertEqual(first.stdout, second.stdout)


if __name__ == "__main__":
    unittest.main()
