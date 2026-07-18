from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
LINT = REPO / "tools" / "predicate-yaml-lint.py"


def _load_lint():
    spec = importlib.util.spec_from_file_location("predicate_yaml_lint", LINT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class PredicateYamlLintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lint = _load_lint()

    def test_accepts_supported_contract_and_function_predicates(self) -> None:
        doc = {
            "preconditions": [{"contract.name_matches": "Vault"}],
            "match": [
                {"contract.inherits_regex": "ERC4626"},
                {"function.name_matches": "withdraw"},
                {"function.body_contains_regex": "transfer"},
            ],
        }

        findings = self.lint.lint_doc(Path("ok.yaml"), doc)

        self.assertEqual(findings, [])

    def test_accepts_cross_context_contract_and_legacy_param_keys_in_match(self) -> None:
        doc = {
            "preconditions": [{"contract.source_matches_regex": "Ownable"}],
            "match": [
                {"function.contract.not_source_matches_regex": "Ownable2Step"},
                {"function.parameters_include": "(bytes|calldata).*data"},
            ],
        }

        findings = self.lint.lint_doc(Path("ok.yaml"), doc)

        self.assertEqual(findings, [])

    def test_accepts_safe_alias_predicates(self) -> None:
        doc = {
            "preconditions": [
                {"contract.has_func_matching": "withdraw"},
                {"contract.has_func_body_matching": "transfer"},
                {"contract.has_func_body_matching_invert": "_disableInitializers"},
                {"contract.has_field_matching": "owner"},
                {"contract.inherits": "Ownable"},
                {"contract.source_contains_regex": "owner"},
                {"contract.source_contains": "address owner"},
            ],
            "match": [
                {"function.body_matches_regex": "return"},
                {"function.not_body_matches_regex": "transfer"},
                {"function.contract_has_source_matching": "owner"},
                {"function.not_calls_function_matching": "refresh"},
                {"function.not_in_slither_synthetic": True},
                {"function.has_modifier_regex": "onlyOwner"},
                {"function.has_modifier_not": "onlyAdmin"},
                {"function.modifiers_not_matching": "onlyAdmin"},
                {"function.parameter_named": "recipient"},
                {"function.parameter_matches_regex": "address\\s+recipient"},
                {"function.parameter_not_matches_regex": "bytes\\s+data"},
                {"function.param_list_contains_regex": "uint256\\s+amount"},
                {"function.signature_matches_regex": "uint256\\s+amount"},
                {"function.writes_state_var_matches": "balance"},
                {"function.body_contains_regex_ordered": ["call", "lastTradeTimestamp"]},
                {"function.body_not_matches_regex": "timelock"},
            ],
        }

        findings = self.lint.lint_doc(Path("ok.yaml"), doc)

        self.assertEqual(findings, [])

    def test_reports_stringified_predicate_entry(self) -> None:
        doc = {
            "match": [
                "function.name_matches: withdraw",
                {"function.not_in_skip_list": True},
            ]
        }

        findings = self.lint.lint_doc(Path("bad.yaml"), doc)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].warning_class, "stringified_predicate_entry")
        self.assertEqual(findings[0].predicate, "match[0]")
        self.assertEqual(findings[0].key, "__stringified__")

    def test_reports_unsupported_contract_function_and_chain_keys(self) -> None:
        doc = {
            "preconditions": [
                {"contract.typo_predicate": True},
                {"function.has_param_matching": "onlyMatchIsWrongHere"},
                {"chain.unknown_domain": True},
            ],
            "match": [
                {"function.has_param_matching": "amount"},
                {"contract.typo_predicate": True},
                {"chain.is_zk_circuit": True},
            ],
        }

        findings = self.lint.lint_doc(Path("bad.yaml"), doc)
        classes = [finding.warning_class for finding in findings]

        self.assertEqual(
            classes,
            [
                "unsupported_contract_key",
                "unsupported_function_key",
                "unsupported_chain_key",
                "unsupported_function_key",
                "unsupported_contract_key",
                "unsupported_chain_key",
            ],
        )
        self.assertEqual(findings[0].predicate, "preconditions[0]")
        self.assertEqual(findings[3].predicate, "match[0]")

    def test_accepts_function_predicates_in_preconditions_runtime_compatibility(self) -> None:
        doc = {
            "preconditions": [
                {"function.name_matches": "withdraw"},
                {"function.source_matches_regex": "transfer"},
                {"function.not_source_matches_regex": "mock"},
                {"function.has_modifier": "onlyOwner"},
            ],
            "match": [{"function.name_matches": "withdraw"}],
        }

        findings = self.lint.lint_doc(Path("ok.yaml"), doc)

        self.assertEqual(findings, [])

    def test_reports_unsupported_context_namespace(self) -> None:
        doc = {
            "preconditions": [{"context.contract_name": "Vault"}],
            "match": [{"context.function_name": "withdraw"}],
        }

        findings = self.lint.lint_doc(Path("bad.yaml"), doc)

        self.assertEqual([f.warning_class for f in findings], ["unsupported_context_use", "unsupported_context_use"])
        self.assertEqual([f.key for f in findings], ["context.contract_name", "context.function_name"])

    def test_cli_exits_zero_by_default_and_nonzero_in_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "bad.yaml"
            report_path = Path(tmp) / "report.md"
            yaml_path.write_text(
                textwrap.dedent(
                    """
                    pattern: bad
                    match:
                      - "function.name_matches: withdraw"
                    """
                ),
                encoding="utf-8",
            )

            warn = subprocess.run(
                [sys.executable, str(LINT), str(yaml_path), "--report", str(report_path)],
                cwd=REPO,
                text=True,
                capture_output=True,
                check=False,
            )
            strict = subprocess.run(
                [sys.executable, str(LINT), str(yaml_path), "--report", str(report_path), "--strict"],
                cwd=REPO,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(warn.returncode, 0, warn.stderr + warn.stdout)
        self.assertEqual(strict.returncode, 1, strict.stderr + strict.stdout)
        self.assertIn("stringified_predicate_entry", warn.stdout)

    def test_make_target_is_advisory_unless_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "bad.yaml"
            report_path = Path(tmp) / "make-report.md"
            yaml_path.write_text(
                textwrap.dedent(
                    """
                    pattern: bad
                    match:
                      - "function.name_matches: withdraw"
                    """
                ),
                encoding="utf-8",
            )

            warn = subprocess.run(
                ["make", "predicate-yaml-lint", f"PATHS={yaml_path}", f"REPORT={report_path}"],
                cwd=REPO,
                text=True,
                capture_output=True,
                check=False,
            )
            strict = subprocess.run(
                [
                    "make",
                    "predicate-yaml-lint",
                    f"PATHS={yaml_path}",
                    f"REPORT={report_path}",
                    "STRICT=1",
                ],
                cwd=REPO,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(warn.returncode, 0, warn.stderr + warn.stdout)
            self.assertEqual(strict.returncode, 2, strict.stderr + strict.stdout)
            self.assertIn("stringified_predicate_entry", warn.stdout)
            self.assertTrue(report_path.is_file())

    def test_collect_paths_expands_positional_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nested"
            nested.mkdir()
            keep = nested / "keep.yaml"
            skip = nested / "skip.txt"
            keep.write_text("match: []\n", encoding="utf-8")
            skip.write_text("match: []\n", encoding="utf-8")

            paths = self.lint.collect_paths([str(root)], [])

        self.assertEqual([p.name for p in paths], ["keep.yaml"])

    def test_glider_erc20_permit_name_mismatch_yaml_is_lint_clean(self) -> None:
        yaml_path = REPO / "reference" / "patterns.dsl" / "glider-erc-20-permit-and-erc-20-name-mismatch-causes-eip.yaml"

        findings = self.lint.lint_path(yaml_path)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
