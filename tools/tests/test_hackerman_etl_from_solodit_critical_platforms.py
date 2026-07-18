from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-solodit-critical-platforms.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"
# The Wave 6b-v2 sibling that ships the parser/inference helpers reused by
# this tool. Ships on `exec-wave7-make-audit-deep-wiring` (commit 08cbbc8358);
# not present on `wave-1-hackerman-capability-lift`. When absent, the
# functional tests below skip gracefully via SISTER_MODULE_AVAILABLE.
SISTER_TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-sherlock-c4-historic.py"
SISTER_MODULE_AVAILABLE = SISTER_TOOL.is_file()
SISTER_SKIP_REASON = (
    "depends-on-sister-branch: tools/hackerman-etl-from-sherlock-c4-historic.py "
    "ships on `exec-wave7-make-audit-deep-wiring` (commit 08cbbc8358); not "
    "present on this branch."
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _mcp_payload(text: str) -> str:
    return json.dumps([{"type": "text", "text": text}])


SHERLOCK_FIXTURE = """**47 findings found** (page 1/16, 3/page)

---

### #3351 [HIGH] H-3: CTokenOracle.sol#getCErc20Price contains critical math error
https://solodit.cyfrin.io/issues/h-3-ctokenoraclesolgetcerc20price-contains-critical-math-error-sherlock-sentiment-sentiment-git
**Firm:** Sherlock | **Protocol:** Sentiment | **Quality:** 5/5 | **Rarity:** 2/5
**Finders:** 0x52 (1 total)
**Date:** [object Object]

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/021-H

## Found by
0x52

### Summary
CTokenOracle.sol#getCErc20Price contains a math error that immensely overvalues CTokens leading to direct theft of funds.

### Vulnerability Detail
The price calculation drains the pool.

### Recommendation
Use the corrected formula.

---

### #55034 [HIGH] H-3: Integer overflow in observation index calculation leads to denial of service
https://solodit.cyfrin.io/issues/h-3-integer-overflow-in-observation-index-calculation-leads-to-denial-of-service-sherlock-yieldoor-git
**Firm:** Sherlock | **Protocol:** Yieldoor | **Quality:** 0/5 | **Rarity:** 0/5
**Finders:** iamnmt (1 total)
**Date:** [object Object]

Source: https://github.com/sherlock-audit/2025-02-yieldoor-judging/issues/103

### Summary
Integer overflow in checkPoolActivity leads to denial of service for critical protocol functions.

"""

CODE4RENA_FIXTURE = """**1669 findings found** (page 1/17, 100/page)

---

### #64869 [HIGH] [H-01] Order double-linked list is broken because order.prevOrderId is not persisted
https://solodit.cyfrin.io/issues/h-01-order-double-linked-list-is-broken-code4rena-gte-gte-git
**Firm:** Code4rena | **Protocol:** GTE | **Quality:** 5/5 | **Rarity:** 3/5
**Finders:** volodya, 0x1998 (2 total)
**Date:** [object Object]

Source: https://github.com/code-423n4/2025-07-gte-clob/blob/main/contracts/clob/types/Book.sol

### Summary
Critical orderbook double-linked list is broken because prevOrderId is not persisted, breaking matching.

### Recommendation
Persist prevOrderId during insertion.

"""

CANTINA_FIXTURE = """**321 findings found** (page 1/107, 3/page)

---

### #53434 [HIGH] Poseidon2 verify_batch: start_top_level is not constrained to happen only once during top level
https://solodit.cyfrin.io/issues/poseidon2-verify_batch-start_top_levelis-not-constrained-to-happen-only-once-during-top-level-cantina-none-openvm-pdf
**Firm:** Cantina | **Protocol:** OpenVM | **Quality:** 0/5 | **Rarity:** 0/5
**Finders:** cergyk (1 total)
**Date:** [object Object]

## Context

**File:** `air.rs#L476-L480`

## Description

The variable `start_top_level` is supposed to be true only once during top-level processing. Setting it in the middle of the top-level process can influence the row_hash result.

---

### #53433 [HIGH] Incorrect opcode offset used for Branch Less instruction
https://solodit.cyfrin.io/issues/incorrect-opcode-offset-used-for-branch-less-instruction-cantina-none-openvm-pdf
**Firm:** Cantina | **Protocol:** OpenVM | **Quality:** 5/5 | **Rarity:** 5/5
**Finders:** Rhaydden (1 total)
**Date:** [object Object]

## Description
The Rv32BranchLessThan256Chip uses the wrong opcode offset, leading to incorrect 256-bit branch-less-than operations.

"""


class HackermanEtlFromSoloditCriticalPlatformsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_solodit_critical_platforms")
        self.validator = _load(
            VALIDATOR, "_hackerman_record_validate_for_critical_platforms"
        )

    def test_blocked_when_no_inputs(self) -> None:
        rc = self.tool.main(["--out-dir", "/tmp/exec_w8sc_test_noinputs"])
        self.assertEqual(rc, 2)

    @unittest.skipUnless(SISTER_MODULE_AVAILABLE, SISTER_SKIP_REASON)
    def test_parses_sherlock_block_into_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="critical-platforms-sherlock-") as tmp:
            root = Path(tmp)
            inp = root / "sherlock_p1.txt"
            inp.write_text(_mcp_payload(SHERLOCK_FIXTURE), encoding="utf-8")
            out_dir = root / "out"
            summary = self.tool.convert([inp], out_dir)
            self.assertEqual(summary["validation_errors"], [])
            self.assertEqual(summary["parse_errors"], [])
            self.assertEqual(summary["build_errors"], [])
            self.assertEqual(summary["scanned_findings"], 2)
            self.assertEqual(summary["records_emitted"], 2)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertEqual(len(files), 2)
            records = [self.validator.load_yaml(p) for p in files]
            sentiment = next(
                r for r in records if "sentiment" in r["source_audit_ref"].lower()
            )
            self.assertEqual(sentiment["severity_at_finding"], "high")
            self.assertEqual(
                sentiment["target_repo"], "sherlock-audit/2022-08-sentiment-judging"
            )
            self.assertEqual(sentiment["year"], 2022)
            self.assertIn("critical-class", sentiment["function_shape"]["shape_tags"])
            self.assertIn("firm-sherlock", sentiment["function_shape"]["shape_tags"])
            self.assertEqual(
                sentiment["source_audit_ref"],
                "https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/021-H",
            )
            # record_id is namespaced under critical: (not historic:).
            self.assertTrue(sentiment["record_id"].startswith("critical:sherlock:"))

    @unittest.skipUnless(SISTER_MODULE_AVAILABLE, SISTER_SKIP_REASON)
    def test_parses_code4rena_block_into_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="critical-platforms-c4-") as tmp:
            root = Path(tmp)
            inp = root / "c4_p1.txt"
            inp.write_text(_mcp_payload(CODE4RENA_FIXTURE), encoding="utf-8")
            out_dir = root / "out"
            summary = self.tool.convert([inp], out_dir)
            self.assertEqual(summary["validation_errors"], [])
            self.assertEqual(summary["records_emitted"], 1)
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertEqual(record["severity_at_finding"], "high")
            self.assertEqual(record["target_repo"], "code-423n4/2025-07-gte-clob")
            self.assertEqual(record["year"], 2025)
            self.assertIn("firm-code4rena", record["function_shape"]["shape_tags"])
            self.assertIn("critical-class", record["function_shape"]["shape_tags"])
            self.assertTrue(record["record_id"].startswith("critical:code4rena:"))

    @unittest.skipUnless(SISTER_MODULE_AVAILABLE, SISTER_SKIP_REASON)
    def test_parses_cantina_pdf_block_with_fallback_repo(self) -> None:
        # Cantina PDF rows ship NO GitHub Source: URL. Verify the synthetic
        # cantina-audit/<protocol-slug> fallback fires AND that the verbatim
        # solodit_url is still carried into source_audit_ref.
        with tempfile.TemporaryDirectory(prefix="critical-platforms-cantina-") as tmp:
            root = Path(tmp)
            inp = root / "cantina_p1.txt"
            inp.write_text(_mcp_payload(CANTINA_FIXTURE), encoding="utf-8")
            out_dir = root / "out"
            summary = self.tool.convert([inp], out_dir)
            self.assertEqual(summary["validation_errors"], [])
            self.assertEqual(summary["records_emitted"], 2)
            records = [self.validator.load_yaml(p) for p in out_dir.glob("*.yaml")]
            for record in records:
                self.assertEqual(record["severity_at_finding"], "high")
                self.assertIn("firm-cantina", record["function_shape"]["shape_tags"])
                self.assertIn("critical-class", record["function_shape"]["shape_tags"])
                # Cantina PDF rows lack GitHub Source URL → synthetic fallback.
                self.assertEqual(record["target_repo"], "cantina-audit/openvm")
                # source_audit_ref must still cite the verbatim Solodit URL.
                self.assertTrue(
                    record["source_audit_ref"].startswith(
                        "https://solodit.cyfrin.io/issues/"
                    ),
                    record["source_audit_ref"],
                )
                self.assertTrue(record["record_id"].startswith("critical:cantina:"))

    @unittest.skipUnless(SISTER_MODULE_AVAILABLE, SISTER_SKIP_REASON)
    def test_record_id_is_deterministic_across_reruns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="critical-platforms-det-") as tmp:
            root = Path(tmp)
            inp = root / "p1.txt"
            inp.write_text(_mcp_payload(SHERLOCK_FIXTURE), encoding="utf-8")
            out1 = root / "out1"
            out2 = root / "out2"
            self.tool.convert([inp], out1)
            self.tool.convert([inp], out2)
            ids1 = sorted(p.name for p in out1.glob("*.yaml"))
            ids2 = sorted(p.name for p in out2.glob("*.yaml"))
            self.assertEqual(ids1, ids2)

    @unittest.skipUnless(SISTER_MODULE_AVAILABLE, SISTER_SKIP_REASON)
    def test_does_not_invent_mitigation_state(self) -> None:
        # Discipline test (mirrored from Wave 6b-v2): the tool must never
        # assert fix-shipped / mitigation-applied. fix_pattern carries the
        # explicit disclaimer.
        with tempfile.TemporaryDirectory(prefix="critical-platforms-fix-") as tmp:
            root = Path(tmp)
            for fixture, name in (
                (SHERLOCK_FIXTURE, "sherlock.txt"),
                (CODE4RENA_FIXTURE, "c4.txt"),
                (CANTINA_FIXTURE, "cantina.txt"),
            ):
                inp = root / name
                inp.write_text(_mcp_payload(fixture), encoding="utf-8")
            out_dir = root / "out"
            self.tool.convert(
                [root / "sherlock.txt", root / "c4.txt", root / "cantina.txt"],
                out_dir,
            )
            yaml_files = list(out_dir.glob("*.yaml"))
            self.assertGreater(len(yaml_files), 0)
            for path in yaml_files:
                record = self.validator.load_yaml(path)
                low = record["fix_pattern"].lower()
                self.assertIn("do not assume", low)
                self.assertIn("post-audit fix commit", low)
                self.assertNotIn("fix shipped", low)
                self.assertNotIn("fix has been applied", low)
                self.assertNotIn("mitigation applied", low)

    @unittest.skipUnless(SISTER_MODULE_AVAILABLE, SISTER_SKIP_REASON)
    def test_dedupes_by_solodit_id_across_platforms(self) -> None:
        with tempfile.TemporaryDirectory(prefix="critical-platforms-dedup-") as tmp:
            root = Path(tmp)
            inp1 = root / "p1.txt"
            inp2 = root / "p2.txt"
            inp1.write_text(_mcp_payload(CANTINA_FIXTURE), encoding="utf-8")
            inp2.write_text(_mcp_payload(CANTINA_FIXTURE), encoding="utf-8")
            out_dir = root / "out"
            summary = self.tool.convert([inp1, inp2], out_dir)
            self.assertEqual(summary["scanned_findings"], 4)
            self.assertEqual(summary["unique_findings"], 2)
            self.assertEqual(summary["records_emitted"], 2)

    @unittest.skipUnless(SISTER_MODULE_AVAILABLE, SISTER_SKIP_REASON)
    def test_record_id_namespace_distinct_from_wave6b_v2(self) -> None:
        # Critical-class records use a distinct identity_seed namespace
        # ("critical-class\n..."), so even if the Wave 6b-v2 lift covered
        # the same Solodit ID, the Wave-8 record_id digest will differ.
        with tempfile.TemporaryDirectory(prefix="critical-platforms-namespace-") as tmp:
            root = Path(tmp)
            inp = root / "p1.txt"
            inp.write_text(_mcp_payload(SHERLOCK_FIXTURE), encoding="utf-8")
            out_dir = root / "out"
            self.tool.convert([inp], out_dir)
            files = list(out_dir.glob("*.yaml"))
            self.assertGreater(len(files), 0)
            for path in files:
                record = self.validator.load_yaml(path)
                self.assertTrue(record["record_id"].startswith("critical:"))
                self.assertFalse(record["record_id"].startswith("historic:"))


if __name__ == "__main__":
    unittest.main()
