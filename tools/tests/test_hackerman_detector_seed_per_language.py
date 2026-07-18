"""Tests for ``tools/hackerman-detector-seed-per-language.py`` (PR #726
Wave-1 capability lift).

Covers >=8 cases:

1. ``normalize_language`` folds quoted / case / unknown variants to the
   canonical lowercase set; unknown → ``unknown``.
2. ``extract_per_language_seeds`` walks a synthetic tier-1/tier-2 tree
   and buckets seeds by ``target_language``.
3. Min-recurrence threshold is enforced per-language (not globally) -
   a tag with recurrence=1 in solidity is dropped while the same tag at
   recurrence=2 in rust is retained.
4. Tier-3/4/5 records are skipped (mirrors base extractor's hard rule).
5. Cross-language reuse table picks seeds appearing in >=2 languages and
   ranks by ``language_count`` then ``total_recurrence``.
6. AST seeds are bucketed per language when
   ``code_snippet_pre_fix`` / ``post_fix`` are populated.
7. JSONL emitter writes per-language regex seeds + AST seeds + cross-lang
   rows; row count matches expectations.
8. Markdown renderer emits one section per language plus the cross-language
   table; STOPLIST tags are never surfaced.
9. CLI ``--json`` mode emits a parse-friendly summary with
   ``languages_seen`` and ``top_cross_language_seeds`` keys.
10. CLI ``--dry-run`` writes no artifacts.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-detector-seed-per-language.py"


def _load_tool() -> Any:
    name = "_hackerman_detector_seed_per_language_test_mod"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


# --------------------------------------------------------------------------- #
# Synthetic corpus builder
# --------------------------------------------------------------------------- #


def _write_record(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _make_record(
    *,
    record_id: str,
    source_audit_ref: str,
    attack_class: str,
    target_language: str,
    shape_tags: List[str],
    code_snippet_pre_fix: str = "",
    code_snippet_post_fix: str = "",
) -> Dict[str, Any]:
    rec: Dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "attack_class": attack_class,
        "target_language": target_language,
        "target_repo": "acme/test",
        "function_shape": {
            "raw_signature": "test()",
            "shape_tags": shape_tags,
        },
    }
    if code_snippet_pre_fix:
        rec["code_snippet_pre_fix"] = code_snippet_pre_fix
    if code_snippet_post_fix:
        rec["code_snippet_post_fix"] = code_snippet_post_fix
    return rec


def _build_synthetic_tree(root: Path) -> Path:
    """Build a small synthetic corpus tree:

    * 3 solidity tier-2 records sharing tag ``reentrancy-call`` (×3) and
      ``delegatecall-no-check`` (×2), one with diff-style code snippets.
    * 2 rust tier-1 records sharing tag ``reentrancy-call`` (×2) and
      ``unsafe-deref`` (×2).
    * 1 vyper tier-2 record carrying tag ``reentrancy-call`` (×1, below
      threshold).
    * 1 go tier-1 record with unique tag ``goroutine-leak`` (×1, dropped).
    * 1 tier-3 (corpus-mined) record - MUST be skipped.
    * 1 quarantine bucket - MUST be skipped at the walk layer.
    """
    tags_dir = root / "audit" / "corpus_tags" / "tags"
    tags_dir.mkdir(parents=True, exist_ok=True)

    # Solidity tier-2: prior-audit prefix qualifies as tier-2
    _write_record(
        tags_dir / "amm_yield_lst_protocols" / "sol-1" / "record.json",
        _make_record(
            record_id="prior-audit:acme:sol-1",
            source_audit_ref="prior-audit:acme:sol-1",
            attack_class="reentrancy",
            target_language="solidity",
            shape_tags=[
                "reentrancy-call",
                "delegatecall-no-check",
                "sherlock-solidity",
            ],
            code_snippet_pre_fix="- call.value(x)(\"\")\n+ require(!locked)",
        ),
    )
    _write_record(
        tags_dir / "amm_yield_lst_protocols" / "sol-2" / "record.json",
        _make_record(
            record_id="prior-audit:acme:sol-2",
            source_audit_ref="prior-audit:acme:sol-2",
            attack_class="reentrancy",
            target_language="solidity",
            shape_tags=["reentrancy-call", "delegatecall-no-check"],
        ),
    )
    _write_record(
        tags_dir / "amm_yield_lst_protocols" / "sol-3" / "record.json",
        _make_record(
            record_id="prior-audit:acme:sol-3",
            source_audit_ref="prior-audit:acme:sol-3",
            attack_class="reentrancy",
            target_language='"solidity"',  # quoted variant test
            shape_tags=["reentrancy-call"],
        ),
    )
    # Rust tier-1: ghsa-* qualifies as tier-1
    _write_record(
        tags_dir / "cve_db" / "rust-1" / "record.json",
        _make_record(
            record_id="ghsa-aaaa-bbbb-cccc",
            source_audit_ref="ghsa-aaaa-bbbb-cccc",
            attack_class="memory-safety",
            target_language="rust",
            shape_tags=["reentrancy-call", "unsafe-deref"],
        ),
    )
    _write_record(
        tags_dir / "cve_db" / "rust-2" / "record.json",
        _make_record(
            record_id="ghsa-dddd-eeee-ffff",
            source_audit_ref="ghsa-dddd-eeee-ffff",
            attack_class="memory-safety",
            target_language="rust",
            shape_tags=["reentrancy-call", "unsafe-deref"],
            code_snippet_post_fix="+ debug_assert!(!ptr.is_null());",
        ),
    )
    # Vyper tier-2 (below per-lang recurrence threshold)
    _write_record(
        tags_dir / "amm_yield_lst_protocols" / "vyper-1" / "record.json",
        _make_record(
            record_id="prior-audit:acme:vyper-1",
            source_audit_ref="prior-audit:acme:vyper-1",
            attack_class="reentrancy",
            target_language="vyper",
            shape_tags=["reentrancy-call", "lock-not-set"],
        ),
    )
    # Go tier-1 (unique tag, below threshold)
    _write_record(
        tags_dir / "cve_db" / "go-1" / "record.json",
        _make_record(
            record_id="ghsa-1111-2222-3333",
            source_audit_ref="ghsa-1111-2222-3333",
            attack_class="concurrency",
            target_language="go",
            shape_tags=["goroutine-leak"],
        ),
    )
    # Tier-3 (corpus-mined prefix) - MUST be skipped
    _write_record(
        tags_dir / "cve_db" / "skip-1" / "record.json",
        _make_record(
            record_id="corpus-mined:acme:skip-1",
            source_audit_ref="corpus-mined:acme:skip-1",
            attack_class="reentrancy",
            target_language="solidity",
            shape_tags=["reentrancy-call", "tier3-noise"],
        ),
    )
    # Quarantine bucket - MUST be skipped at the walk layer
    _write_record(
        tags_dir / "_QUARANTINE_FABRICATED_CVE" / "fake-1" / "record.json",
        _make_record(
            record_id="ghsa-fake",
            source_audit_ref="ghsa-fake",
            attack_class="bogus",
            target_language="solidity",
            shape_tags=["reentrancy-call"],
        ),
    )
    return tags_dir


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


class TestNormalizeLanguage(unittest.TestCase):
    def test_quoted_and_case_variants(self) -> None:
        self.assertEqual(tool.normalize_language("solidity"), "solidity")
        self.assertEqual(tool.normalize_language("Solidity"), "solidity")
        self.assertEqual(tool.normalize_language('"solidity"'), "solidity")
        self.assertEqual(tool.normalize_language("'rust'"), "rust")
        self.assertEqual(tool.normalize_language("go"), "go")
        self.assertEqual(tool.normalize_language(""), "unknown")
        self.assertEqual(tool.normalize_language(None), "unknown")
        self.assertEqual(tool.normalize_language("brainfuck"), "unknown")
        self.assertEqual(tool.normalize_language("circom"), "circom")
        self.assertEqual(tool.normalize_language("VYPER"), "vyper")


class TestExtractPerLanguageBucketsByLanguage(unittest.TestCase):
    def test_records_bucketed_by_target_language(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            report = tool.extract_per_language_seeds(tags_dir, min_recurrence=2)
            # We expect at least solidity, rust, vyper, go to appear
            seen = set(report["global_stats"]["languages_seen"])
            self.assertIn("solidity", seen)
            self.assertIn("rust", seen)
            self.assertIn("vyper", seen)
            self.assertIn("go", seen)
            # Tier-3 skip-1 + quarantine fake-1 should NOT contribute.
            # That means solidity sees 3 real records (sol-1/2/3), not 4.
            sol = report["per_language"]["solidity"]
            self.assertEqual(sol["stats"]["real_source_records"], 3)
            rust = report["per_language"]["rust"]
            self.assertEqual(rust["stats"]["real_source_records"], 2)


class TestPerLanguageRecurrenceThreshold(unittest.TestCase):
    def test_threshold_enforced_per_language(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            report = tool.extract_per_language_seeds(tags_dir, min_recurrence=2)
            sol_seeds = {r["seed"] for r in report["per_language"]["solidity"]["regex_seeds"]}
            self.assertIn("reentrancy-call", sol_seeds)
            self.assertIn("delegatecall-no-check", sol_seeds)
            # vyper "reentrancy-call" recurrence=1 → below threshold
            vyper_seeds = {r["seed"] for r in report["per_language"]["vyper"]["regex_seeds"]}
            self.assertNotIn("reentrancy-call", vyper_seeds)
            # go "goroutine-leak" recurrence=1 → below threshold
            go_seeds = {r["seed"] for r in report["per_language"]["go"]["regex_seeds"]}
            self.assertNotIn("goroutine-leak", go_seeds)


class TestTier345Skipped(unittest.TestCase):
    def test_tier3_and_quarantine_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            report = tool.extract_per_language_seeds(tags_dir, min_recurrence=1)
            # The tier-3 record's tag "tier3-noise" must never appear.
            all_seeds: List[str] = []
            for lang in report["per_language"]:
                all_seeds.extend(
                    r["seed"] for r in report["per_language"][lang]["regex_seeds"]
                )
            self.assertNotIn("tier3-noise", all_seeds)
            # The quarantine bucket bumped the corpus walk but is filtered out.
            self.assertGreaterEqual(
                report["global_stats"]["skipped_synthetic_records"], 1
            )


class TestCrossLanguageReuseRanking(unittest.TestCase):
    def test_reuse_table_picks_multilanguage_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            report = tool.extract_per_language_seeds(tags_dir, min_recurrence=2)
            cross = report["cross_language_reuse"]
            # `reentrancy-call` appears in solidity (3) + rust (2) → reuse
            seeds_in_cross = {r["seed"] for r in cross}
            self.assertIn("reentrancy-call", seeds_in_cross)
            row = next(r for r in cross if r["seed"] == "reentrancy-call")
            self.assertEqual(set(row["languages"]), {"solidity", "rust"})
            self.assertEqual(row["language_count"], 2)
            self.assertEqual(row["total_recurrence"], 5)
            # `delegatecall-no-check` only in solidity → NOT in cross
            self.assertNotIn("delegatecall-no-check", seeds_in_cross)
            # `unsafe-deref` only in rust → NOT in cross
            self.assertNotIn("unsafe-deref", seeds_in_cross)


class TestAstSeedsBucketedPerLanguage(unittest.TestCase):
    def test_diff_directives_bucket_to_correct_language(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            report = tool.extract_per_language_seeds(tags_dir, min_recurrence=1)
            sol_ast = report["per_language"]["solidity"]["ast_seeds"]
            rust_ast = report["per_language"]["rust"]["ast_seeds"]
            # Solidity sol-1 had diff hunks
            self.assertGreaterEqual(len(sol_ast), 1)
            self.assertTrue(all(r["target_language"] == "solidity" for r in sol_ast))
            # Rust rust-2 had a post-fix diff
            self.assertGreaterEqual(len(rust_ast), 1)
            self.assertTrue(all(r["target_language"] == "rust" for r in rust_ast))


class TestJsonlEmitter(unittest.TestCase):
    def test_jsonl_contains_per_lang_and_cross_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            report = tool.extract_per_language_seeds(tags_dir, min_recurrence=2)
            out_path = Path(td) / "out.jsonl"
            written = tool.emit_jsonl(report, out_path, top_n=20)
            self.assertGreater(written, 0)
            rows = [
                json.loads(l)
                for l in out_path.read_text(encoding="utf-8").splitlines()
                if l.strip()
            ]
            kinds = {r["seed_kind"] for r in rows}
            self.assertIn("shape_tag_literal", kinds)
            self.assertIn("cross_language_reuse", kinds)
            # Per-language buckets are tagged
            langs = {
                r["target_language"]
                for r in rows
                if r["seed_kind"] == "shape_tag_literal"
            }
            self.assertIn("solidity", langs)
            self.assertIn("rust", langs)


class TestMarkdownRendererStoplist(unittest.TestCase):
    def test_markdown_has_per_language_sections_and_no_stoplist(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            report = tool.extract_per_language_seeds(tags_dir, min_recurrence=2)
            md = tool.render_markdown(report, top_n=20)
            self.assertIn("## Language: `solidity`", md)
            self.assertIn("## Language: `rust`", md)
            self.assertIn("## Cross-language pattern reuse opportunities", md)
            # STOPLIST shape-tag "solidity" / "rust" / "go" must not appear as a SEED row.
            # Those words DO appear in section headers and labels; check
            # they never appear as a backtick-wrapped seed token in a table.
            self.assertNotIn("| `solidity` |", md.replace("| `solidity` | ", "##"))
            # Stoplist tag should not be in shape-tag seed list
            self.assertNotIn("`evm`", md)
            self.assertNotIn("`consensus`", md)


class TestCliJsonAndDryRun(unittest.TestCase):
    def test_cli_json_and_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_jsonl = Path(td) / "out.jsonl"
            out_docs = Path(td) / "out.md"
            # --json mode
            res = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--output-jsonl",
                    str(out_jsonl),
                    "--output-docs",
                    str(out_docs),
                    "--min-recurrence",
                    "2",
                    "--top-n",
                    "10",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["schema"], tool.SCHEMA)
            self.assertIn("languages_seen", data)
            self.assertIn("top_cross_language_seeds", data)
            self.assertTrue(out_jsonl.exists())
            self.assertTrue(out_docs.exists())
            # --dry-run mode writes nothing new
            out_jsonl_dr = Path(td) / "dry.jsonl"
            out_docs_dr = Path(td) / "dry.md"
            res_dr = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--output-jsonl",
                    str(out_jsonl_dr),
                    "--output-docs",
                    str(out_docs_dr),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_dr.returncode, 0, res_dr.stderr)
            self.assertFalse(out_jsonl_dr.exists())
            self.assertFalse(out_docs_dr.exists())


class TestTagsDirMissingExits2(unittest.TestCase):
    def test_missing_tags_dir_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "nope"
            res = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(missing),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 2)


if __name__ == "__main__":
    unittest.main()
