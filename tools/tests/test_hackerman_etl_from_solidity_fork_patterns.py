from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-solidity-fork-patterns.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromSolidityForkPatternsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_solidity_fork_patterns")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_solidity_fork_patterns")

    def test_converts_fork_markdown_to_valid_hackerman_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fork-pattern-etl-") as tmp:
            root = Path(tmp)
            patterns_dir = root / "patterns"
            out_dir = root / "out"
            family_dir = patterns_dir / "compound-comptroller"
            family_dir.mkdir(parents=True)
            (family_dir / "reward-index-boundary.md").write_text(
                """
# reward-index-boundary

- family: compound-comptroller
- target: compound-finance/compound-protocol
- trigger-shape: Reward accounting uses strict > when seeding a new user's index, causing over-accrual after the next reward update.
- fix-shape: Use >= for the initial index boundary and add an invariant test for brand-new markets.
- detector-regex: `supplierIndex.*supplyIndex.*compInitialIndex`
- applicability heuristic: Applicable to forks retaining Compound reward distributor accounting.
- origin commit SHA: fcf067f6fa
- source report reference: reports/git_commits_mining_compound.json
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_patterns([patterns_dir], out_dir)

            self.assertEqual(summary["records_emitted"], 1)
            path = next(out_dir.glob("*.yaml"))
            status, errors = self.validator.validate_file(path, self.validator.load_schema())
            self.assertEqual(status, "valid", errors)
            record = self.validator.load_yaml(path)
            self.assertEqual(record["target_language"], "solidity")
            self.assertEqual(record["target_repo"], "compound-finance/compound-protocol")
            self.assertEqual(record["target_domain"], "lending")
            self.assertEqual(record["attack_class"], "state-accounting-drift")
            self.assertIn("Compound reward distributor", record["required_preconditions"][0])

    def test_quotes_trailing_colon_scalars_and_validates_dry_run_rendered_yaml(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fork-pattern-scalar-etl-") as tmp:
            root = Path(tmp)
            patterns_dir = root / "patterns" / "fixtures"
            out_dir = root / "out"
            patterns_dir.mkdir(parents=True)
            (patterns_dir / "colon-scalar.md").write_text(
                """
# if-you-want-gas-reports

- family: solidity-fork
- target: example/protocol
- trigger-shape: optional gas report command leaves a downstream invariant unchecked.
- fix-shape: add the missing invariant regression before shipping.
- detector-regex: if-you-want-gas-reports:
- applicability heuristic: Applicable to forks retaining the same invariant surface.
- origin commit SHA: abcdef
- source report reference: local-test
""".lstrip(),
                encoding="utf-8",
            )

            dry_summary = self.tool.convert_patterns([patterns_dir], out_dir, dry_run=True)
            self.assertEqual(dry_summary["errors"], [])
            self.assertEqual(dry_summary["file_count"], 1)
            self.assertFalse(out_dir.exists())

            summary = self.tool.convert_patterns([patterns_dir], out_dir)
            self.assertEqual(summary["errors"], [])
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertIn("if-you-want-gas-reports:", record["required_preconditions"])

    def test_optionally_converts_schema_supported_dsl_and_skips_unsupported_language(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fork-pattern-dsl-etl-") as tmp:
            root = Path(tmp)
            patterns_dir = root / "patterns"
            dsl_dir = root / "dsl"
            out_dir = root / "out"
            patterns_dir.mkdir()
            dsl_dir.mkdir()
            (dsl_dir / "oracle-spot-price.yaml").write_text(
                """
pattern: oracle-spot-price
source: auditooor/local
severity: HIGH
confidence: MEDIUM
match:
  - function.kind: external
help: "Vault uses an oracle spot price for collateral accounting."
wiki_title: "Vault collateral uses spot oracle price"
wiki_exploit_scenario: "Attacker manipulates the oracle spot price before borrowing against collateral."
wiki_recommendation: "Use a TWAP and bound stale price deviation."
""".lstrip(),
                encoding="utf-8",
            )
            (dsl_dir / "rust-row.yaml").write_text(
                """
pattern: rust-row
backend: rust
severity: HIGH
wiki_title: "Rust governance checkpoint stale read"
wiki_exploit_scenario: "Attacker votes against a stale checkpoint and changes governance outcome."
wiki_recommendation: "Use proposal-start snapshots."
""".lstrip(),
                encoding="utf-8",
            )
            (dsl_dir / "func-row.yaml").write_text(
                """
pattern: func-row
language: func
severity: HIGH
help: "Unsupported FunC row should be skipped until the v1 schema supports it."
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_patterns([patterns_dir], out_dir, dsl_dirs=[dsl_dir], include_dsl=True)

            self.assertEqual(summary["dsl_scanned"], 3)
            self.assertEqual(summary["dsl_skipped"], 1)
            self.assertEqual(summary["records_emitted"], 2)
            records = []
            for path in out_dir.glob("*.yaml"):
                status, errors = self.validator.validate_file(path, self.validator.load_schema())
                self.assertEqual(status, "valid", errors)
                records.append(self.validator.load_yaml(path))
            by_lang = {record["target_language"]: record for record in records}
            self.assertEqual(by_lang["solidity"]["target_domain"], "oracle")
            self.assertEqual(by_lang["solidity"]["bug_class"], "oracle-manipulation")
            self.assertEqual(by_lang["solidity"]["severity_at_finding"], "high")
            self.assertEqual(by_lang["rust"]["target_domain"], "governance")
            self.assertTrue(by_lang["rust"]["function_shape"]["raw_signature"].startswith("fn "))
            self.assertIn("Canonical rust DSL", by_lang["rust"]["required_preconditions"][0])

    def test_cli_limit_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fork-pattern-cli-") as tmp:
            root = Path(tmp)
            patterns_dir = root / "patterns" / "cdp"
            out_dir = root / "out"
            patterns_dir.mkdir(parents=True)
            for idx in range(2):
                (patterns_dir / f"pattern-{idx}.md").write_text(
                    f"""
# pattern-{idx}

- family: cdp
- target: MakerDAO/dss
- trigger-shape: Security-shaped Solidity upstream commit touches src/vat.sol; subject: fix accounting {idx}.
- fix-shape: Replay the upstream semantic fix.
- detector-regex: `fix`
- applicability heuristic: Applicable to cdp forks.
- origin commit SHA: abc{idx}
- source report reference: reports/sample-{idx}.json
""".lstrip(),
                    encoding="utf-8",
                )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--patterns-dir",
                        str(root / "patterns"),
                        "--out-dir",
                        str(out_dir),
                        "--limit",
                        "1",
                        "--json-summary",
                    ]
                )

            self.assertEqual(rc, 0)
            self.assertIn('"records_emitted": 1', stdout.getvalue())
            self.assertEqual(len(list(out_dir.glob("*.yaml"))), 1)


if __name__ == "__main__":
    unittest.main()
