"""Hermetic tests for ``tools/hackerman-etl-from-swc-registry.py`` (Wave-5 L2).

The SWC registry miner (``SmartContractSecurity/SWC-registry``) is exercised
against synthetic SWC-shaped markdown fixtures injected as ``prefetched``
URL->bytes maps. Zero live network.

Each fixture is marked ``synthetic_fixture`` in its prose so it cannot be
mistaken for a real SWC registry entry.

Coverage:
* honest-zero gate (BLOCKED-NO-REAL-SOURCE) when neither --fetch nor a
  cache / injected bytes are supplied;
* every emitted record carries a first-class non-empty ``verification_tier``
  equal to ``tier-3-synthetic-taxonomy-anchored`` (Rule 37);
* every emitted record carries a canonical ``record_source_url`` pointing
  at the SWC registry GitHub blob;
* the markdown section parser extracts title / CWE / description /
  remediation;
* attack_class classification from the title keyword table;
* CWE id extraction from the Relationships section;
* the miner rejects a non-SWC id.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-swc-registry.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


MINER = _load(TOOL, "_hackerman_etl_from_swc_registry_under_test")


# ---------------------------------------------------------------------------
# Synthetic SWC-shaped markdown fixtures (synthetic_fixture).
# Contrived SWC-registry-shaped markdown with enough structure to exercise
# the section parser. None are real registry entries.
# ---------------------------------------------------------------------------

_MD_REENTRANCY = """# Title

Reentrancy

## Relationships

[CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

## Description

synthetic_fixture: a malicious contract calls back into the calling
contract before the first invocation finishes.

## Remediation

synthetic_fixture: use the checks-effects-interactions pattern and a
reentrancy lock.

## Samples

### sample.sol

```solidity
pragma solidity ^0.5.0;
```
"""

_MD_OVERFLOW = """# Title

Integer Overflow and Underflow

## Relationships

[CWE-682: Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)

## Description

synthetic_fixture: an arithmetic operation wraps around the type bound.

## Remediation

synthetic_fixture: use a safe-math library or Solidity 0.8 checked math.
"""

_MD_NO_TITLE = """## Description

synthetic_fixture: an entry with no title section at all.

## Remediation

synthetic_fixture remediation prose.
"""


def _prefetched():
    base = MINER.SWC_RAW_BASE
    return {
        f"{base}/SWC-107.md": _MD_REENTRANCY.encode("utf-8"),
        f"{base}/SWC-101.md": _MD_OVERFLOW.encode("utf-8"),
    }


class SwcRegistryMinerTest(unittest.TestCase):
    def test_01_blocked_when_no_real_source(self) -> None:
        """Honest-zero gate: no --fetch, no cache, no injected bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                summary = MINER.convert(
                    Path(tmp) / "out",
                    dry_run=True,
                    fetch_live=False,
                    cache_file=None,
                    prefetched=None,
                )
            self.assertTrue(summary["blocked"])
            self.assertEqual(summary["records_emitted"], 0)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_02_records_emitted_from_injected_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = MINER.convert(
                Path(tmp) / "out",
                dry_run=False,
                fetch_live=False,
                prefetched=_prefetched(),
            )
            self.assertFalse(summary["blocked"])
            self.assertEqual(summary["records_emitted"], 2)
            self.assertEqual(summary["records_pre_filter"], 2)

    def test_03_every_record_has_first_class_verification_tier(self) -> None:
        """Rule 37: verification_tier is a first-class non-empty field."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            MINER.convert(out, dry_run=False, fetch_live=False, prefetched=_prefetched())
            jsons = sorted(out.glob("*/record.json"))
            self.assertEqual(len(jsons), 2)
            for jp in jsons:
                rec = json.loads(jp.read_text(encoding="utf-8"))
                self.assertIn("verification_tier", rec)
                self.assertEqual(
                    rec["verification_tier"],
                    "tier-3-synthetic-taxonomy-anchored",
                )
                self.assertNotIn(
                    "verification_tier",
                    rec["function_shape"].get("shape_tags", []),
                    "Rule 37: tier must not be smuggled into shape_tags",
                )

    def test_04_record_source_url_points_at_swc_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            MINER.convert(out, dry_run=False, fetch_live=False, prefetched=_prefetched())
            for jp in sorted(out.glob("*/record.json")):
                rec = json.loads(jp.read_text(encoding="utf-8"))
                self.assertTrue(
                    rec["record_source_url"].startswith(
                        "https://github.com/SmartContractSecurity/SWC-registry/blob/"
                    )
                )
                self.assertTrue(rec["record_source_url"].endswith(".md"))

    def test_05_markdown_section_parser(self) -> None:
        parsed = MINER.parse_swc_markdown(_MD_REENTRANCY)
        self.assertEqual(parsed["title"], "Reentrancy")
        self.assertEqual(parsed["cwe_id"], "CWE-841")
        self.assertIn("malicious contract", parsed["description"])
        self.assertIn("checks-effects-interactions", parsed["remediation"])

    def test_06_attack_class_classification(self) -> None:
        reent = MINER.entry_to_record(
            swc_id="SWC-107",
            parsed=MINER.parse_swc_markdown(_MD_REENTRANCY),
        )
        overflow = MINER.entry_to_record(
            swc_id="SWC-101",
            parsed=MINER.parse_swc_markdown(_MD_OVERFLOW),
        )
        self.assertEqual(reent["attack_class"], "swc-reentrancy")
        self.assertEqual(reent["impact_class"], "theft")
        self.assertEqual(reent["severity_at_finding"], "high")
        self.assertEqual(overflow["attack_class"], "swc-integer-overflow")
        self.assertEqual(overflow["impact_class"], "precision-loss")

    def test_07_cwe_id_extraction(self) -> None:
        rec = MINER.entry_to_record(
            swc_id="SWC-107",
            parsed=MINER.parse_swc_markdown(_MD_REENTRANCY),
        )
        self.assertEqual(rec["cwe_id"], "CWE-841")

    def test_08_record_rejects_non_swc_id(self) -> None:
        self.assertIsNone(
            MINER.entry_to_record(
                swc_id="CVE-2099-99999",
                parsed=MINER.parse_swc_markdown(_MD_REENTRANCY),
            )
        )

    def test_09_no_title_entry_still_emits(self) -> None:
        """An entry missing the Title section still produces a record."""
        rec = MINER.entry_to_record(
            swc_id="SWC-136",
            parsed=MINER.parse_swc_markdown(_MD_NO_TITLE),
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["record_id"][:13], "swc-registry:")
        self.assertTrue(rec["target_component"].startswith("SWC-136"))

    def test_10_cache_file_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            payload = {
                "_meta": {"files_listed": 1, "entries_fetched": 1},
                "entries": {"SWC-107": _MD_REENTRANCY},
            }
            cache.write_text(json.dumps(payload), encoding="utf-8")
            summary = MINER.convert(
                Path(tmp) / "out",
                dry_run=True,
                fetch_live=False,
                cache_file=cache,
            )
            self.assertFalse(summary["blocked"])
            self.assertEqual(summary["records_emitted"], 1)

    def test_11_cli_blocked_exit_zero(self) -> None:
        """BLOCKED is an honest verdict, not an error exit."""
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = MINER.main(["--out-dir", str(Path(tmp) / "out"), "--dry-run"])
            self.assertEqual(rc, 0)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_12_record_core_fields(self) -> None:
        rec = MINER.entry_to_record(
            swc_id="SWC-107",
            parsed=MINER.parse_swc_markdown(_MD_REENTRANCY),
        )
        self.assertEqual(rec["schema_version"], MINER.SCHEMA_VERSION)
        self.assertEqual(rec["target_language"], "solidity")
        self.assertEqual(rec["target_repo"], "SmartContractSecurity/SWC-registry")
        self.assertEqual(rec["target_domain"], "smart-contract")
        self.assertEqual(rec["bug_class"], "swc-weakness-taxonomy")
        self.assertEqual(rec["year"], 2020)

    def test_13_taxonomy_tier_disclosed_in_preconditions(self) -> None:
        """Rule 37: tier-3 records must disclose the taxonomy-anchor limit."""
        rec = MINER.entry_to_record(
            swc_id="SWC-107",
            parsed=MINER.parse_swc_markdown(_MD_REENTRANCY),
        )
        joined = " ".join(rec["required_preconditions"])
        self.assertIn("tier-3-synthetic-taxonomy-anchored", joined)
        self.assertIn("not sole evidence for HIGH+", joined)


if __name__ == "__main__":
    unittest.main()
