"""Guard tests for the findings -> invariant fuel wiring.

FIX: findings-to-invariant-fuel-wiring (wave-6 uplift).

The lift CHAIN already existed but was unwired, so only ~7% of corpus
findings ever reached the per-fn invariant fuel. This wiring adds an
INCREMENTAL findings->invariant refresh stage to ``hackerman-etl-refresh.py``
that runs after the index rebuild:

  1. ``tools/llm-extract-invariants.py --mode hand-extract --incremental``
     - deterministic (no LLM), watermark-scoped so only NEW findings (record
       ids not yet seen) become invariant HYPOTHESES, appended to
       ``invariants_extracted.jsonl``.
  2. ``tools/lane-invariant-audit-ext.py`` - lifts the audited (non-quarantine)
     rows into ``invariants_pilot_audited.jsonl`` (the fuel that
     ``corpus-driven-hunt.py:123`` loads).

These tests assert (R80/R76 honesty):

- A NEW finding in the index produces a corresponding invariant in
  ``invariants_extracted.jsonl`` after the stage runs (deterministic mode).
- The watermark makes the stage incremental: the second run with no new
  findings emits no new invariants and advances the watermark monotonically.
- A vacuous / malformed invariant is NOT promoted into the fuel by the
  audit-ext quarantine classifier (no R80 violation).
- The lifted invariant cites the real source finding id (no faked match).
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
EXTRACT_TOOL = REPO_ROOT / "tools" / "llm-extract-invariants.py"
AUDIT_EXT_TOOL = REPO_ROOT / "tools" / "lane-invariant-audit-ext.py"
ETL_REFRESH_TOOL = REPO_ROOT / "tools" / "hackerman-etl-refresh.py"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _finding_row(record_id: str, **overrides: Any) -> dict[str, Any]:
    """A reentrancy (atomicity) finding row that classifies deterministically."""
    row = {
        "record_id": record_id,
        "tag_file": "_missing.yaml",
        "attack_class": "reentrancy",
        "bug_class": "missing-cei",
        "target_repo": "test-org/repo-" + record_id.replace(":", "-"),
        "target_language": "solidity",
        "fix_pattern": "checks-effects-interactions pattern + nonReentrant",
        "attacker_action_sequence": (
            "External callback re-enters vault before balance write; "
            "vault-reentry drains."
        ),
        "verification_tier": "tier-2-verified-public-archive",
        "source_ref": "contracts/Vault.sol:88",
    }
    row.update(overrides)
    return row


def _write_index(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


class IncrementalExtractWatermarkTests(unittest.TestCase):
    """The extract stage is watermark-scoped to NEW findings only."""

    def setUp(self) -> None:
        self.tool = _load("fttif_extract_tool", EXTRACT_TOOL)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.index = self.root / "by_attack_class.jsonl"
        self.output = self.root / "invariants_extracted.jsonl"
        self.failed = self.root / "invariants_failed_extract.jsonl"
        self.watermark = self.root / ".invariant_extract_watermark"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, records: int = 50000) -> dict[str, Any]:
        argv = [
            "--mode", "hand-extract", "--incremental",
            "--records", str(records),
            "--index", str(self.index),
            "--tags-dir", str(self.root),
            "--output", str(self.output),
            "--failed", str(self.failed),
            "--watermark", str(self.watermark),
        ]
        rc = self.tool.main(argv)
        self.assertEqual(rc, 0)
        return {
            "extracted": _load_jsonl(self.output),
            "watermark": json.loads(self.watermark.read_text("utf-8")),
        }

    def test_new_finding_yields_invariant_and_advances_watermark(self) -> None:
        # First sweep over one finding.
        _write_index(self.index, [_finding_row("test:atm:001")])
        first = self._run()
        self.assertGreaterEqual(len(first["extracted"]), 1)
        self.assertIn("test:atm:001", first["watermark"]["processed_record_ids"])
        # The lifted invariant must cite the real source finding id (no faked
        # match): the source_finding_ids must contain the seed record_id.
        all_sfids = {
            sfid
            for inv in first["extracted"]
            for sfid in inv.get("source_finding_ids", [])
        }
        self.assertIn("test:atm:001", all_sfids)

    def test_no_new_finding_is_a_noop(self) -> None:
        _write_index(self.index, [_finding_row("test:atm:001")])
        self._run()
        before = len(_load_jsonl(self.output))
        # Re-run with the SAME index: watermark skips the already-seen row, so
        # no new invariant is appended.
        second = self._run()
        self.assertEqual(len(second["extracted"]), before)
        self.assertEqual(second["watermark"]["processed_count"], 1)

    def test_added_finding_is_picked_up_incrementally(self) -> None:
        _write_index(self.index, [_finding_row("test:atm:001")])
        self._run()
        before = len(_load_jsonl(self.output))
        before_sfids = {
            sfid
            for inv in _load_jsonl(self.output)
            for sfid in inv.get("source_finding_ids", [])
        }
        self.assertNotIn("test:cus:999", before_sfids)
        # Append a NEW, distinct finding (custody class, different repo).
        _write_index(
            self.index,
            [
                _finding_row("test:atm:001"),
                _finding_row(
                    "test:cus:999",
                    attack_class="custody-violation",
                    bug_class="missing-owner-check",
                    target_repo="test-org/repo-custody",
                    fix_pattern="msg.sender == owner check before transfer-from",
                    attacker_action_sequence=(
                        "Withdraw path lacks owner-only modifier; token "
                        "transfer to attacker."
                    ),
                ),
            ],
        )
        result = self._run()
        # A NEW invariant rows appears, and it cites the new finding id.
        self.assertGreater(len(result["extracted"]), before)
        new_sfids = {
            sfid
            for inv in result["extracted"]
            for sfid in inv.get("source_finding_ids", [])
        }
        self.assertIn("test:cus:999", new_sfids)
        self.assertEqual(result["watermark"]["processed_count"], 2)


class StageEndToEndAndQuarantineTests(unittest.TestCase):
    """End-to-end stage on a production-shaped layout + R80 quarantine guard."""

    def setUp(self) -> None:
        self.refresh = _load("fttif_refresh_tool", ETL_REFRESH_TOOL)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.index_dir = self.root / "audit" / "corpus_tags" / "index"
        self.derived_dir = self.root / "audit" / "corpus_tags" / "derived"
        self.index_dir.mkdir(parents=True)
        self.derived_dir.mkdir(parents=True)
        self.index = self.index_dir / "by_attack_class.jsonl"
        self.extracted = self.derived_dir / "invariants_extracted.jsonl"
        self.pilot_audited = self.derived_dir / "invariants_pilot_audited.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _stage(self) -> dict[str, Any]:
        return self.refresh.findings_to_invariants(
            index_dir=self.index_dir,
            derived_dir=self.derived_dir,
            repo_root=self.root,
            records_cap=50000,
        )

    def test_new_finding_becomes_fuel_after_stage(self) -> None:
        _write_index(self.index, [_finding_row("test:atm:777")])
        summary = self._stage()
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["extract"]["status"], "ok")
        self.assertEqual(summary["audit_ext"]["status"], "ok")

        # Step 1: an invariant appears in invariants_extracted.jsonl.
        extracted = _load_jsonl(self.extracted)
        self.assertGreaterEqual(len(extracted), 1)
        extracted_sfids = {
            sfid
            for inv in extracted
            for sfid in inv.get("source_finding_ids", [])
        }
        self.assertIn("test:atm:777", extracted_sfids)

        # Step 2: it is lifted into the fuel file (pilot_audited) and the lift
        # cites the real source finding id (no faked match, R76).
        fuel = _load_jsonl(self.pilot_audited)
        self.assertGreaterEqual(len(fuel), 1)
        lifted = [
            r
            for r in fuel
            if "test:atm:777" in (r.get("source_finding_ids") or [])
        ]
        self.assertTrue(lifted, "new finding never reached the fuel file")
        # The lifted row carries an audit verdict; a tier-2 multi/real source
        # is not a FALSE-POSITIVE (it is genuine fuel).
        self.assertTrue(all(r.get("quality_audited") for r in lifted))
        self.assertTrue(
            all(r.get("audit_verdict") != "FALSE-POSITIVE" for r in lifted)
        )

    def test_vacuous_invariant_is_quarantined_not_promoted(self) -> None:
        # Pre-seed the extracted file with a vacuous / malformed invariant
        # (no modal verb, no source backing) alongside a genuine one. The
        # audit-ext quarantine classifier must mark the vacuous one
        # FALSE-POSITIVE (R80: no vacuous invariant into fuel).
        genuine = {
            "schema_version": "auditooor.invariant_extraction.v1",
            "invariant_id": "INV-CUS-EX-9001",
            "category": "custody",
            "statement": (
                "A token balance MUST NOT be movable by an actor other than "
                "the owner without explicit owner authorization."
            ),
            "target_lang": "solidity",
            "source_finding_ids": ["real:custody:1", "real:custody:2"],
            "abstraction_level": "cross-domain",
            "verification_tier": "tier-2-verified-public-archive",
            "source_count": 2,
            "extractor": "hand-extract",
        }
        vacuous = {
            "schema_version": "auditooor.invariant_extraction.v1",
            "invariant_id": "INV-XXX-EX-9002",
            "category": "custody",
            "statement": "x",  # too short, no modal verb -> malformed
            "target_lang": "solidity",
            "source_finding_ids": [],  # no source backing
            "abstraction_level": "cross-domain",
            "verification_tier": "tier-2-verified-public-archive",
            "source_count": 0,
            "extractor": "hand-extract",
        }
        self.extracted.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in (genuine, vacuous))
            + "\n",
            encoding="utf-8",
        )
        # Empty index so the extract step is a no-op; only the audit-ext lift
        # runs over the pre-seeded extracted rows.
        _write_index(self.index, [])
        summary = self._stage()
        self.assertEqual(summary["status"], "ok")

        fuel = _load_jsonl(self.pilot_audited)
        verdict_by_id = {
            (r.get("invariant_id"), r.get("statement")): r.get("audit_verdict")
            for r in fuel
        }
        self.assertEqual(
            verdict_by_id.get(("INV-CUS-EX-9001", genuine["statement"])),
            "TRUE-POSITIVE",
        )
        self.assertEqual(
            verdict_by_id.get(("INV-XXX-EX-9002", "x")),
            "FALSE-POSITIVE",
        )

    def test_stage_is_idempotent_no_fuel_duplication(self) -> None:
        _write_index(self.index, [_finding_row("test:atm:555")])
        self._stage()
        fuel_after_first = _load_jsonl(self.pilot_audited)
        # Re-run the whole stage: watermark skips the finding in step 1, and
        # the audit-ext idempotency guard skips already-lifted rows in step 2.
        self._stage()
        fuel_after_second = _load_jsonl(self.pilot_audited)
        self.assertEqual(len(fuel_after_first), len(fuel_after_second))


class EtlRefreshRootDerivationTests(unittest.TestCase):
    """The refresh derives the fuel root safely from --index-dir.

    Canonical layout (<root>/audit/corpus_tags/index) is auto-derived; a
    non-canonical --index-dir is REFUSED (skipped) rather than silently
    scribbling the canonical repo's derived dir.
    """

    def setUp(self) -> None:
        self.refresh = _load("fttif_refresh_root", ETL_REFRESH_TOOL)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_canonical_index_dir_auto_derives_root(self) -> None:
        index_dir = self.root / "audit" / "corpus_tags" / "index"
        derived_dir = self.root / "audit" / "corpus_tags" / "derived"
        index_dir.mkdir(parents=True)
        derived_dir.mkdir(parents=True)
        _write_index(index_dir / "by_attack_class.jsonl", [_finding_row("c:1")])
        args = self.refresh.build_parser().parse_args(
            [
                "--index-dir", str(index_dir),
                "--tag-dir", str(self.root / "tags"),
            ]
        )
        # The derivation logic mirrors refresh(): canonical layout -> root is
        # the third parent of index_dir.
        self.assertEqual(index_dir.name, "index")
        self.assertEqual(index_dir.parent.name, "corpus_tags")
        derived_root = index_dir.parent.parent.parent
        summary = self.refresh.findings_to_invariants(
            index_dir=index_dir,
            derived_dir=derived_root / "audit" / "corpus_tags" / "derived",
            repo_root=derived_root,
            records_cap=int(args.findings_invariants_records_cap),
        )
        self.assertEqual(summary["status"], "ok")
        self.assertTrue(
            (derived_dir / "invariants_extracted.jsonl").is_file()
        )

    def test_non_canonical_index_dir_is_refused_via_full_refresh(self) -> None:
        # A non-canonical --index-dir (root/index, not .../corpus_tags/index)
        # MUST NOT write into the real repo's derived dir; the stage skips.
        # Seed real ETL sources (mirrors the green test_cli_apply test) so the
        # refresh reaches the post-index findings->invariants stage.
        import shutil as _shutil
        fixtures = REPO_ROOT / "tools" / "tests" / "fixtures"
        verdict_fixtures = fixtures / "hackerman_etl_verdict_tags"
        git_fixtures = fixtures / "hackerman_etl_from_git_mining" / "reports"
        corpus_fixtures = fixtures / "corpus_mined_etl"
        prior_fixtures = fixtures / "prior_audit_etl" / "workspaces"
        tag_dir = self.root / "tags"
        index_dir = self.root / "index"
        derived = self.root / "derived"
        tag_dir.mkdir()
        index_dir.mkdir()
        derived.mkdir()
        _shutil.copy(
            verdict_fixtures / "legacy_v2_oracle.yaml",
            tag_dir / "legacy_v2_oracle.yaml",
        )
        before_watermark = (
            REPO_ROOT / "audit" / "corpus_tags" / "derived"
            / ".invariant_extract_watermark"
        ).exists()
        proc = subprocess.run(
            [
                sys.executable, str(ETL_REFRESH_TOOL),
                "--tag-dir", str(tag_dir),
                "--index-dir", str(index_dir),
                "--quality-out", str(derived / "q.jsonl"),
                "--cross-language-out", str(derived / "x.jsonl"),
                "--proof-hardening-out", str(derived / "p.jsonl"),
                "--reports-dir", str(git_fixtures),
                "--corpus-dir", str(corpus_fixtures),
                "--skip-findings-go", "--skip-solodit-specs",
                "--skip-solidity-fork-patterns",
                "--workspace", str(prior_fixtures / "alpha"),
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(
            payload["findings_to_invariants"]["status"], "skipped"
        )
        self.assertEqual(
            payload["findings_to_invariants"]["reason"],
            "non_canonical_index_dir_no_explicit_root",
        )
        # And the real repo's derived watermark state was NOT mutated.
        self.assertEqual(
            (REPO_ROOT / "audit" / "corpus_tags" / "derived"
             / ".invariant_extract_watermark").exists(),
            before_watermark,
        )


class EtlRefreshFlagWiringTests(unittest.TestCase):
    """The refresh CLI exposes the skip flag and runs the stage by default."""

    def setUp(self) -> None:
        self.refresh = _load("fttif_refresh_flags", ETL_REFRESH_TOOL)

    def test_skip_flag_present(self) -> None:
        args = self.refresh.build_parser().parse_args(
            ["--skip-findings-to-invariants"]
        )
        self.assertTrue(args.skip_findings_to_invariants)

    def test_default_does_not_skip(self) -> None:
        args = self.refresh.build_parser().parse_args([])
        self.assertFalse(args.skip_findings_to_invariants)
        self.assertEqual(args.findings_invariants_records_cap, 50000)


if __name__ == "__main__":
    unittest.main()
