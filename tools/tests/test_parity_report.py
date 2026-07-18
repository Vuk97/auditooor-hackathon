#!/usr/bin/env python3
"""Item-#6 burn-down — parity-report `deliberate` exclusion regression tests.

The 49 platform-only BUG_CLASSES rows reported by `tools/detector-lint.py`
Check 5 are NOT all real gaps. The vast majority are intentionally
single-platform (Soroban TTL/archival, Solana PDA seeds, EVM selfdestruct,
Cosmos IBC, etc.). Per PR `codex/burndown-item-6-parity-gap-reduce`:

  1. `tools/parity-report.py` `BUG_CLASSES` entries that are platform-only
     by design carry `deliberate: True` + a `rationale:` string.
  2. `tools/parity-report.py` defaults `deliberate = True` for every row
     with `applies_to in {rust_only, solidity_only}` — explicit override
     to `deliberate: False` would mean "this is a suspect mistake".
  3. `tools/detector-lint.py` Check 5 honours the discriminator:
     - True gaps (status `GAP_RUST` / `GAP_SOLIDITY`) are surfaced.
     - Suspect platform-only rows (`deliberate: False`) are surfaced.
     - Deliberate platform-only rows are EXCLUDED.

These tests pin those guarantees so the gap count cannot silently
re-inflate to 49.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PARITY_PATH = REPO_ROOT / "tools" / "parity-report.py"
LINT_PATH = REPO_ROOT / "tools" / "detector-lint.py"


def _load_module(name: str, path: Path):
    """Import a hyphenated tool module."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"could not load {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ParityReportSchemaTest(unittest.TestCase):
    """Parity-report JSON output exposes the deliberate discriminator."""

    @classmethod
    def setUpClass(cls):
        proc = subprocess.run(
            [sys.executable, str(PARITY_PATH), "--json"],
            check=True, capture_output=True, text=True, timeout=120,
        )
        cls.report = json.loads(proc.stdout)

    def test_summary_fields_present(self):
        for key in (
            "real_gap_count",
            "platform_only_total",
            "platform_only_deliberate",
            "platform_only_suspect",
        ):
            self.assertIn(key, self.report, f"summary key `{key}` missing")

    def test_every_row_has_deliberate_field(self):
        rows = self.report.get("rows", [])
        self.assertGreater(len(rows), 0)
        for r in rows:
            self.assertIn("deliberate", r, f"row `{r.get('bug_class')}` missing deliberate")
            self.assertIn("rationale", r, f"row `{r.get('bug_class')}` missing rationale")

    def test_applies_to_both_rows_are_not_deliberate(self):
        # `deliberate` is meaningless for two-sided classes; ensure it's False.
        for r in self.report["rows"]:
            if r["applies_to"] == "both":
                self.assertFalse(
                    r["deliberate"],
                    f"`{r['bug_class']}` is applies_to=both but flagged deliberate",
                )

    def test_platform_only_default_is_deliberate(self):
        # Rule (2): default `deliberate=True` for platform-only rows.
        # No platform-only row should be silently un-rationalized in the
        # current main-line library — the burn-down expects 0 suspects.
        self.assertEqual(
            self.report["platform_only_suspect"],
            0,
            "platform-only rows missing deliberate:true / rationale: "
            f"{[r['bug_class'] for r in self.report['rows'] if r['status'].startswith('PLATFORM_ONLY') and not r['deliberate']]}",
        )


class CheckParityGapsExclusionTest(unittest.TestCase):
    """`detector-lint.py` Check 5 excludes deliberate rows."""

    def setUp(self):
        self.lint = _load_module("detector_lint", LINT_PATH)

    def test_canonical_check5_count_is_below_legacy_49(self):
        """The whole point of item-#6 burn-down: real-world gap count drops."""
        gaps = self.lint.check_parity_gaps()
        self.assertLess(
            len(gaps),
            49,
            f"Check 5 must report < 49 with the deliberate filter; got {len(gaps)}",
        )

    def test_check5_includes_real_gap_rust(self):
        """Synthetic parity script with one true GAP_RUST row → surfaced."""
        with tempfile.TemporaryDirectory() as td:
            stub = Path(td) / "fake-parity.py"
            stub.write_text(_FAKE_PARITY_REPORT)
            stub.chmod(0o755)
            rows = self.lint._parity_gap_rows(parity_script=stub)
        # `apple-pie-class` is applies_to=both with sol=1 rust=0 → GAP_RUST.
        self.assertIn("apple-pie-class [GAP_RUST]", rows["real_gaps"])

    def test_check5_excludes_deliberate_platform_only(self):
        """`solana-only-class` is platform-only + deliberate → excluded."""
        with tempfile.TemporaryDirectory() as td:
            stub = Path(td) / "fake-parity.py"
            stub.write_text(_FAKE_PARITY_REPORT)
            stub.chmod(0o755)
            rows = self.lint._parity_gap_rows(parity_script=stub)
        joined = " ".join(rows["display"])
        self.assertNotIn("solana-only-class", joined)

    def test_check5_flags_suspect_platform_only(self):
        """Platform-only with deliberate:false → surfaced as suspect."""
        with tempfile.TemporaryDirectory() as td:
            stub = Path(td) / "fake-parity.py"
            stub.write_text(_FAKE_PARITY_REPORT)
            stub.chmod(0o755)
            rows = self.lint._parity_gap_rows(parity_script=stub)
        suspect = " ".join(rows["suspect_platform_only"])
        self.assertIn("suspect-untagged-class", suspect)


# Synthetic parity report stub used by the exclusion tests above. Emits
# JSON with three rows: one real gap, one deliberate platform-only,
# one suspect platform-only.
_FAKE_PARITY_REPORT = '''#!/usr/bin/env python3
import json, sys
report = {
    "solidity_total": 1,
    "rust_total": 1,
    "bug_classes_registered": 3,
    "bug_classes_applicable_to_both": 1,
    "bug_classes_covered_both": 0,
    "parity_pct_bidirectional": 0.0,
    "platform_only_total": 2,
    "platform_only_deliberate": 1,
    "platform_only_suspect": 1,
    "real_gap_count": 1,
    "rows": [
        {
            "bug_class": "apple-pie-class",
            "applies_to": "both",
            "solidity_count": 1,
            "rust_count": 0,
            "deliberate": False,
            "rationale": "",
            "description": "synthetic real gap",
            "status": "GAP_RUST",
        },
        {
            "bug_class": "solana-only-class",
            "applies_to": "rust_only",
            "solidity_count": 0,
            "rust_count": 1,
            "deliberate": True,
            "rationale": "Solana-specific by design",
            "description": "synthetic deliberate platform-only",
            "status": "PLATFORM_ONLY_RUST",
        },
        {
            "bug_class": "suspect-untagged-class",
            "applies_to": "rust_only",
            "solidity_count": 0,
            "rust_count": 1,
            "deliberate": False,
            "rationale": "",
            "description": "synthetic suspect platform-only",
            "status": "PLATFORM_ONLY_RUST",
        },
    ],
}
if "--json" in sys.argv:
    print(json.dumps(report))
'''


class TtlArchivalKeywordTighteningTest(unittest.TestCase):
    """Item-#6 sub-fix: ttl-archival keywords no longer false-positive on
    Solidity expiration / settlement patterns."""

    @classmethod
    def setUpClass(cls):
        cls.parity = _load_module("parity_report", PARITY_PATH)

    def test_solidity_count_is_zero(self):
        """Pre-fix: 20 Solidity files matched via `expire`/`archiv`. Post-fix: 0."""
        sol = self.parity.load_solidity_patterns()
        hits = [slug for slug, _ in sol if "ttl-archival" in self.parity.classify(slug)]
        self.assertEqual(
            hits, [],
            f"ttl-archival should not match any Solidity pattern; hit: {hits}",
        )

    def test_rust_persistent_storage_detectors_still_match(self):
        """Soroban-side keyword tightening must not break the real Rust matches."""
        rust = self.parity.load_rust_detectors()
        hits = [slug for slug, _ in rust if "ttl-archival" in self.parity.classify(slug)]
        # The library currently has at least these three Soroban detectors.
        # If anyone removes one we want the test to flag — keyword tightening
        # was a one-shot adjustment, not an ongoing freeze.
        for expected in (
            "missing_ttl_bump_on_persistent_read",
            "instance_vs_persistent_storage_confusion",
            "unwrap_or_zero_on_persistent_storage",
        ):
            self.assertIn(
                expected, hits,
                f"ttl-archival lost coverage of `{expected}`: {hits}",
            )


if __name__ == "__main__":
    unittest.main()
