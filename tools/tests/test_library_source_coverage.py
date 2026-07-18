#!/usr/bin/env python3
"""Tests for tools/library-source-coverage.py — V5 Gap-28 + Gap-41.

Stdlib-only, hermetic. The tool is loaded via ``importlib`` because the
script name contains a hyphen.

Coverage:
  1. Citation classifier: 1 fixture per class (workspace, cve, academic-
     corpus, external-feed, glider, synthetic) — exact taxonomy round-trip.
  2. Workspace canonicalization collapses spelling variants.
  3. ``build_report`` emits the JSON shape contract.
  4. Workspace cross-check: missing engage_report.md is recorded as
     ``engage_report_seen: false`` for high-claim workspaces (with a
     warning row).
  5. ``--no-cross-check`` and missing audits-root degrade to
     ``engage_report_seen: null`` (no FAIL).
  6. The ``feed-as-workspace`` re-classification: a tag like
     ``auditooor-R76-immunefi-aurora`` resolves to ``external-feed``,
     NOT to a phantom ``immunefi`` workspace claim.
  7. M14-style attack: a synthetic source value
     (``"my-internal-thing"``) lands in ``synthetic`` and surfaces in
     ``uncited_patterns``.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "library-source-coverage.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "library_source_coverage", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["library_source_coverage"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_pattern(dirpath: Path, name: str, source: str,
                   help_text: str = "x") -> None:
    """Write a minimal valid pattern YAML."""
    body = (
        f"pattern: {name}\n"
        f"source: {source}\n"
        f"severity: HIGH\n"
        f"help: \"{help_text}\"\n"
        f"wiki_title: \"{name} title\"\n"
    )
    (dirpath / f"{name}.yaml").write_text(body)


class TestClassifier(unittest.TestCase):
    """1 fixture per citation class — taxonomy round-trip."""

    def _classify(self, source: str, name: str = "p") -> tuple[str, str]:
        rec = MOD.PatternRecord(
            path=Path(f"{name}.yaml"),
            pattern_name=name,
            source_value=source,
            description="",
        )
        return MOD.classify_pattern(rec)

    def test_workspace_auditooor_round(self):
        cls, ws = self._classify(
            "auditooor-R107-thegraph-OZ-L-01"
        )
        self.assertEqual(cls, "workspace")
        self.assertEqual(ws, "thegraph")

    def test_workspace_round_then_workspace(self):
        cls, ws = self._classify(
            "snowbridge-r109-source-mine-oak-v2-major-finding-5"
        )
        self.assertEqual(cls, "workspace")
        self.assertEqual(ws, "snowbridge")

    def test_workspace_round_prefixed(self):
        cls, ws = self._classify(
            "r106-centrifuge-v3-BatchRequestManager.notifyDeposit"
        )
        self.assertEqual(cls, "workspace")
        self.assertEqual(ws, "centrifuge-v3")

    def test_cve_class(self):
        cls, ws = self._classify("CVE-2023-12345 reentrancy variant")
        self.assertEqual(cls, "cve")
        self.assertEqual(ws, "")

    def test_academic_corpus_lisa(self):
        cls, ws = self._classify(
            "lisa-mine-r99-case-00308-sherlock-perennial-v2-3-2024-02"
        )
        self.assertEqual(cls, "academic-corpus")

    def test_academic_corpus_swc(self):
        cls, _ = self._classify("SWC-107 reentrancy")
        self.assertEqual(cls, "academic-corpus")

    def test_external_feed_solodit(self):
        cls, _ = self._classify("solodit/C0240")
        self.assertEqual(cls, "external-feed")

    def test_external_feed_immunefi(self):
        # Immunefi WITHOUT auditooor round prefix = pure external feed
        cls, _ = self._classify("immunefi-aave-2023-disclosure")
        self.assertEqual(cls, "external-feed")

    def test_glider_class(self):
        cls, _ = self._classify(
            "glider-docs/dvbridge-flat-fee-validator-reward-no-msgvalue-check"
        )
        self.assertEqual(cls, "glider")

    def test_synthetic_class(self):
        cls, _ = self._classify("my-internal-thing")
        # Falls through, no workspace/cve/academic/glider/feed match.
        # NEW behavior is to fall through to synthetic.
        self.assertEqual(cls, "synthetic")

    def test_synthetic_explicit_token(self):
        cls, _ = self._classify("synthesized")
        self.assertEqual(cls, "synthetic")

    def test_feed_as_workspace_demoted(self):
        """Minimax attack: an auditooor round that CURATED a contest
        feed (e.g. ``auditooor-R76-immunefi-aurora``) must NOT be
        recorded as a workspace claim — that would falsely inflate
        ``immunefi`` as a workspace and hide the lack of any real
        ``immunefi/`` audit folder."""
        cls, ws = self._classify("auditooor-R76-immunefi-aurora-$6M")
        self.assertEqual(cls, "external-feed")
        self.assertEqual(ws, "")


class TestCanonicalization(unittest.TestCase):
    """Workspace name aliasing (Minimax attack #3)."""

    def test_centrifuge_variants_collapse(self):
        for variant in ("centrifuge_v3", "Centrifuge-V3", "centrifugev3",
                        "centrifuge-v3"):
            self.assertEqual(MOD.canonicalize_workspace(variant),
                             "centrifuge-v3",
                             f"variant {variant!r} did not collapse")

    def test_morpho_variants(self):
        self.assertEqual(MOD.canonicalize_workspace("morpho-blue"),
                         "morpho")
        self.assertEqual(MOD.canonicalize_workspace("morphoblue"),
                         "morpho")

    def test_unknown_workspace_passthrough(self):
        self.assertEqual(MOD.canonicalize_workspace("polymarket"),
                         "polymarket")

    def test_empty_returns_empty(self):
        self.assertEqual(MOD.canonicalize_workspace(""), "")


class TestBuildReport(unittest.TestCase):
    """End-to-end report shape with a 6-pattern fixture."""

    def test_one_per_class_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "patterns.dsl"
            d.mkdir()
            _write_pattern(d, "ws_pat", "auditooor-R107-thegraph-OZ-L-01")
            _write_pattern(d, "cve_pat", "CVE-2023-12345-flashloan")
            _write_pattern(d, "ac_pat",
                           "lisa-mine-r99-case-00337-sherlock-axis-finance")
            _write_pattern(d, "feed_pat", "solodit/C0240")
            _write_pattern(d, "glider_pat",
                           "glider-docs/dvbridge-validator-reward")
            _write_pattern(d, "synth_pat", "my-internal-thing")

            rep = MOD.build_report(d, audits_root=None)
            self.assertEqual(rep.patterns_total, 6)
            self.assertEqual(rep.by_class["workspace"]["count"], 1)
            self.assertEqual(rep.by_class["cve"]["count"], 1)
            self.assertEqual(rep.by_class["academic-corpus"]["count"], 1)
            self.assertEqual(rep.by_class["external-feed"]["count"], 1)
            self.assertEqual(rep.by_class["glider"]["count"], 1)
            self.assertEqual(rep.by_class["synthetic"]["count"], 1)
            self.assertEqual(len(rep.uncited_patterns), 1)
            self.assertEqual(rep.by_workspace, {"thegraph": 1})

    def test_unmined_workspace_flagged(self):
        """Library/source coverage fixture flags an unmined source dir.

        The tool is fed an audits-root that DOES NOT contain an
        engage_report.md for the claimed workspace. Cross-check rows
        record ``engage_report_seen: false`` for high-claim workspaces
        AND emit a warning."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "patterns.dsl"
            d.mkdir()
            audits = Path(tmp) / "audits"
            audits.mkdir()
            # Write 5 patterns for a workspace that has no engage_report
            for i in range(5):
                _write_pattern(
                    d, f"unmined_{i}",
                    f"auditooor-R109-bogusws-finding-{i}",
                )
            # Write 1 pattern for a workspace that DOES exist
            seen_ws = audits / "polymarket"
            seen_ws.mkdir()
            (seen_ws / "engage_report.md").write_text("# poly\n")
            _write_pattern(d, "real_pat",
                           "auditooor-R37d-polymarket-CTFExchange-foo")

            rep = MOD.build_report(d, audits_root=audits)
            self.assertEqual(rep.by_workspace.get("bogusws"), 5)
            self.assertEqual(rep.by_workspace.get("polymarket"), 1)
            cc = rep.workspace_cross_check
            self.assertFalse(cc["bogusws"]["engage_report_seen"])
            self.assertTrue(cc["polymarket"]["engage_report_seen"])
            self.assertTrue(
                any("bogusws" in w for w in rep.warnings),
                f"expected bogusws warning, got {rep.warnings}",
            )

    def test_no_audits_root_skips_cross_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "patterns.dsl"
            d.mkdir()
            _write_pattern(d, "p1", "auditooor-R37d-polymarket-CTFExchange-foo")
            rep = MOD.build_report(d, audits_root=None)
            seen = rep.workspace_cross_check["polymarket"]["engage_report_seen"]
            self.assertIsNone(seen)


class TestCLI(unittest.TestCase):
    """End-to-end CLI invocation (stdout + JSON file)."""

    def test_cli_writes_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "patterns.dsl"
            d.mkdir()
            _write_pattern(d, "p1",
                           "auditooor-R37d-polymarket-CTFExchange-foo")
            out = Path(tmp) / "cov.json"
            argv = [
                "--library-dir", str(d),
                "--no-cross-check",
                "--out", str(out),
                "--json",
            ]
            from contextlib import redirect_stdout
            import io
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(argv)
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists(), "JSON manifest not written")
            payload = json.loads(out.read_text())
            self.assertEqual(payload["patterns_total"], 1)
            self.assertEqual(payload["tool_version"], "1")
            self.assertIn("polymarket", payload["by_workspace"])


if __name__ == "__main__":
    unittest.main()
