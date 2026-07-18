"""Tests for ``tools/hackerman-reentrancy-pattern-extractor.py``.

Covers:
  1. variant matching against attack_class
  2. variant matching against bug_class
  3. variant matching against function_shape.shape_tags
  4. specific-variant precedence over generic-reentrancy fallback
  5. non-reentrancy records skipped
  6. tier-3 / tier-4 / tier-5 records skipped (real-source only)
  7. pre-fix and post-fix shape signal scoring
  8. JSONL emission shape (summary envelope + per-record rows)
  9. markdown rendering contains expected sections
 10. CLI entrypoint produces files end-to-end on a synthetic corpus
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-reentrancy-pattern-extractor.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_reentrancy_pattern_extractor", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()


def _write_record(
    tags_dir: Path,
    bucket: str,
    slug: str,
    *,
    record_id: str = "ghsa-fake-0001",
    source_audit_ref: str = "https://github.com/example/repo/security/advisories/ghsa-fake-0001",
    attack_class: str = "external-call-reentrancy",
    bug_class: str = "reentrancy",
    shape_tags=None,
    raw_signature: str = "function withdraw() external",
    fix_pattern: str = "Added nonReentrant modifier to follow checks-effects-interactions.",
    fix_anti_pattern_avoided: str = "External call before state update with missing nonReentrant guard.",
    target_language: str = "solidity",
    target_repo: str = "example/repo",
    target_component: str = "contracts/Vault.sol",
    severity: str = "high",
    code_snippet_pre_fix: str = "",
    code_snippet_post_fix: str = "",
    extra: dict = None,
) -> Path:
    if shape_tags is None:
        shape_tags = ["external-call-reentrancy", "reentrancy", "verification_tier:tier-1-verified-realtime-api"]
    rec_dir = tags_dir / bucket / slug
    rec_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "attack_class": attack_class,
        "bug_class": bug_class,
        "function_shape": {
            "shape_tags": shape_tags,
            "raw_signature": raw_signature,
        },
        "fix_pattern": fix_pattern,
        "fix_anti_pattern_avoided": fix_anti_pattern_avoided,
        "target_language": target_language,
        "target_repo": target_repo,
        "target_component": target_component,
        "severity_at_finding": severity,
        "record_tier": "public-corpus",
    }
    if code_snippet_pre_fix:
        payload["code_snippet_pre_fix"] = code_snippet_pre_fix
    if code_snippet_post_fix:
        payload["code_snippet_post_fix"] = code_snippet_post_fix
    if extra:
        payload.update(extra)
    (rec_dir / "record.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return rec_dir


class VariantMatchingTests(unittest.TestCase):
    def test_matches_external_call_reentrancy_via_attack_class(self):
        rec = {
            "attack_class": "external-call-reentrancy",
            "bug_class": "reentrancy",
            "function_shape": {"shape_tags": []},
        }
        self.assertEqual(TOOL.match_variant(rec), "external-call-reentrancy")

    def test_matches_erc777_via_shape_tag(self):
        rec = {
            "attack_class": "callback-injected",
            "bug_class": "unsafe-callback",
            "function_shape": {"shape_tags": ["TokensReceived", "ERC777-reentrancy"]},
        }
        self.assertEqual(TOOL.match_variant(rec), "erc777-reentrancy")

    def test_matches_read_only_reentrancy_via_bug_class(self):
        rec = {
            "attack_class": "view-function-stale-state",
            "bug_class": "read-only-reentrancy",
            "function_shape": {"shape_tags": []},
        }
        self.assertEqual(TOOL.match_variant(rec), "read-only-reentrancy")

    def test_specific_variant_wins_over_generic_fallback(self):
        # bug_class mentions "reentrancy" generically; attack_class is the
        # specific "cross-function-reentrancy". Specific must win.
        rec = {
            "attack_class": "cross-function-reentrancy",
            "bug_class": "reentrancy",
            "function_shape": {"shape_tags": []},
        }
        self.assertEqual(TOOL.match_variant(rec), "cross-function-reentrancy")

    def test_non_reentrancy_record_returns_none(self):
        rec = {
            "attack_class": "missing-modifier-on-state-write",
            "bug_class": "access-control",
            "function_shape": {"shape_tags": []},
        }
        self.assertIsNone(TOOL.match_variant(rec))


class TierGateTests(unittest.TestCase):
    def test_real_source_tier_predicate(self):
        self.assertTrue(TOOL.is_real_source_tier("tier-1-verified-realtime-api"))
        self.assertTrue(TOOL.is_real_source_tier("tier-2-verified-public-archive"))
        self.assertFalse(TOOL.is_real_source_tier("tier-3-synthetic-taxonomy-anchored"))
        self.assertFalse(TOOL.is_real_source_tier("tier-4-bundled-fixture"))
        self.assertFalse(TOOL.is_real_source_tier("tier-5-quarantine"))

    def test_classify_record_honors_verification_tier_shape_tag(self):
        rec = {
            "record_id": "regex-derived-9999",  # would heuristic as tier-3
            "function_shape": {
                "shape_tags": ["external-call-reentrancy", "verification_tier:tier-1-verified-realtime-api"]
            },
        }
        tier, reason = TOOL.classify_record(rec)
        self.assertEqual(tier, "tier-1-verified-realtime-api")
        self.assertEqual(reason, "shape-tag")

    def test_classify_record_falls_back_to_heuristic(self):
        rec = {
            "record_id": "regex-derived-1234",
            "source_audit_ref": "regex-derived-1234",
            "function_shape": {"shape_tags": ["external-call-reentrancy"]},
        }
        tier, _ = TOOL.classify_record(rec)
        self.assertEqual(tier, "tier-3-synthetic-taxonomy-anchored")


class SignalScoringTests(unittest.TestCase):
    def test_score_signals_finds_substrings_case_insensitive(self):
        text = "The fix added nonReentrant modifier and enforced Checks-Effects-Interactions ordering."
        signals = TOOL.score_signals(text, TOOL.POST_FIX_SHAPE_SIGNALS)
        self.assertIn("nonreentrant", signals)
        self.assertIn("checks-effects-interactions", signals)

    def test_score_signals_returns_empty_when_no_match(self):
        text = "completely unrelated prose with no canonical signal terms"
        self.assertEqual(TOOL.score_signals(text, TOOL.PRE_FIX_SHAPE_SIGNALS), [])

    def test_extract_diff_tokens_captures_plus_minus_lines(self):
        snippet = (
            "  // unchanged context line\n"
            "- foo.transfer(amount);\n"
            "+ require(!_locked, \"reentrant\");\n"
            "+ _locked = true;\n"
            "  // another context\n"
        )
        tokens = TOOL.extract_diff_tokens(snippet)
        self.assertIn("foo.transfer(amount);", tokens)
        self.assertIn("require(!_locked, \"reentrant\");", tokens)
        self.assertIn("_locked = true;", tokens)


class ClusterExtractionTests(unittest.TestCase):
    def test_extract_clusters_filters_to_reentrancy_real_source(self):
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            # Hit 1: matches external-call-reentrancy (real source)
            _write_record(
                tags,
                "dex_fix_history",
                "balancer__deadbeef",
                record_id="cantina-001",
                source_audit_ref="cantina-001",
                attack_class="external-call-reentrancy",
                bug_class="reentrancy",
                shape_tags=["external-call-reentrancy", "verification_tier:tier-1-verified-realtime-api"],
                fix_pattern="Added nonReentrant modifier and reordered to checks-effects-interactions.",
                fix_anti_pattern_avoided="external call before state update; missing nonReentrant guard.",
            )
            # Hit 2: matches erc777-reentrancy via tag
            _write_record(
                tags,
                "dex_fix_history",
                "token__cafebabe",
                record_id="cantina-002",
                source_audit_ref="cantina-002",
                attack_class="callback-hook",
                bug_class="callback-hook-malicious-impl",
                shape_tags=["ERC777-reentrancy", "TokensReceived", "verification_tier:tier-2-verified-public-archive"],
                fix_pattern="Added reentrancyGuard around the affected entry point.",
                fix_anti_pattern_avoided="missing nonReentrant; external call into untrusted token hook.",
            )
            # Skip 1: non-reentrancy
            _write_record(
                tags,
                "lending_protocols",
                "liquity__noise",
                record_id="cantina-003",
                source_audit_ref="cantina-003",
                attack_class="missing-modifier-on-state-write",
                bug_class="access-control",
                shape_tags=["missing-modifier", "verification_tier:tier-1-verified-realtime-api"],
            )
            # Skip 2: reentrancy but tier-3 synthetic
            _write_record(
                tags,
                "dex_fix_history",
                "synth__regex001",
                record_id="regex-derived-9999",
                source_audit_ref="regex-derived-9999",
                attack_class="external-call-reentrancy",
                bug_class="reentrancy",
                shape_tags=["external-call-reentrancy", "verification_tier:tier-3-synthetic-taxonomy-anchored"],
            )
            # Skip 3: quarantine bucket entirely skipped at walk layer
            _write_record(
                tags,
                "_QUARANTINE_FABRICATED_CVE",
                "fake__doesnotexist",
                record_id="fake-cve-9001",
                attack_class="external-call-reentrancy",
                bug_class="reentrancy",
            )

            report = TOOL.extract_clusters(tags)
            s = report["summary"]
            self.assertEqual(s["matched_records"], 2)
            self.assertEqual(s["variant_counts"]["external-call-reentrancy"], 1)
            self.assertEqual(s["variant_counts"]["erc777-reentrancy"], 1)
            # Two real-source non-reentrancy records were skipped — at
            # least the missing-modifier hit. Synthetic + quarantine fall
            # under skipped_non_real_source / are walk-skipped.
            self.assertGreaterEqual(s["skipped_non_reentrancy"], 1)
            self.assertGreaterEqual(s["skipped_non_real_source"], 1)
            # Pre-fix and post-fix shape signals were populated.
            self.assertIn("missing nonreentrant", s["pre_fix_shape_signal_counts"])
            self.assertIn("nonreentrant", s["post_fix_shape_signal_counts"])

    def test_extract_clusters_handles_empty_tags_dir(self):
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            report = TOOL.extract_clusters(tags)
            self.assertEqual(report["summary"]["matched_records"], 0)
            self.assertEqual(report["rows"], [])


class EmissionTests(unittest.TestCase):
    def _build_minimal_report(self, tags: Path):
        _write_record(
            tags,
            "dex_fix_history",
            "uniswap_v4_3407bce4",
            record_id="cantina-uni-001",
            source_audit_ref="cantina-uni-001",
            attack_class="hook-reentrancy",
            bug_class="callback-hook-malicious-impl",
            shape_tags=[
                "hook-reentrancy",
                "callback-hook-malicious-impl",
                "verification_tier:tier-1-verified-realtime-api",
            ],
        )
        return TOOL.extract_clusters(tags)

    def test_jsonl_emission_envelope_plus_rows(self):
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            report = self._build_minimal_report(tags)
            out = Path(td) / "out.jsonl"
            n = TOOL.emit_jsonl(report, out)
            self.assertEqual(n, 1 + len(report["rows"]))
            self.assertTrue(out.exists())
            lines = out.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), n)
            envelope = json.loads(lines[0])
            self.assertEqual(envelope["_kind"], "summary")
            for raw in lines[1:]:
                row = json.loads(raw)
                self.assertEqual(row["_kind"], "record")
                self.assertIn("variant", row)
                self.assertIn("tier_key", row)

    def test_markdown_render_has_expected_sections(self):
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            report = self._build_minimal_report(tags)
            md = TOOL.render_markdown(report, top_n=5)
            self.assertIn("Hackerman Re-entrancy Patterns Preview", md)
            self.assertIn("## Variant counts", md)
            self.assertIn("## Common pre-fix shape signals", md)
            self.assertIn("## Common post-fix shape signals", md)
            self.assertIn("## Provenance / how to regenerate", md)
            # Variant we wrote is rendered.
            self.assertIn("callback-reentrancy", md)


class CliEntrypointTests(unittest.TestCase):
    def test_main_writes_jsonl_and_markdown_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            _write_record(
                tags,
                "dex_fix_history",
                "curve__bb1a707e",
                record_id="cantina-curve-001",
                source_audit_ref="cantina-curve-001",
                attack_class="external-call-reentrancy",
                bug_class="reentrancy",
                shape_tags=[
                    "external-call-reentrancy",
                    "reentrancy",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
            )
            out_jsonl = Path(td) / "preview.jsonl"
            out_md = Path(td) / "preview.md"
            rc = TOOL.main(
                [
                    "--tags-dir",
                    str(tags),
                    "--out",
                    str(out_jsonl),
                    "--markdown",
                    str(out_md),
                    "--quiet",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(out_jsonl.exists())
            self.assertTrue(out_md.exists())
            envelope = json.loads(out_jsonl.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(envelope["_kind"], "summary")
            self.assertEqual(envelope["matched_records"], 1)
            self.assertEqual(
                envelope["variant_counts"]["external-call-reentrancy"], 1
            )

    def test_main_returns_2_when_tags_dir_missing(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "does-not-exist"
            out_jsonl = Path(td) / "preview.jsonl"
            out_md = Path(td) / "preview.md"
            rc = TOOL.main(
                [
                    "--tags-dir",
                    str(missing),
                    "--out",
                    str(out_jsonl),
                    "--markdown",
                    str(out_md),
                    "--quiet",
                ]
            )
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
