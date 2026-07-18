"""
Regression test: tools/deepseek-batch-gen-tok-b.py --target-lang argparse choices
must match the full target_language enum from auditooor.hackerman_record.v1.1.schema.json.
R36-registered lane: work1-dispatcher-argparse-choices-2026-05-26
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.1.schema.json"
SCRIPT_PATH = REPO_ROOT / "tools" / "deepseek-batch-gen-tok-b.py"

EXPECTED_ENUM = [
    "solidity", "go", "rust", "vyper", "move", "cairo",
    "huff", "assembly", "typescript-onchain", "python-onchain",
    "circom", "sway", "noir", "leo", "cairo-zk",
]


def _get_schema_enum() -> list:
    with open(SCHEMA_PATH) as f:
        schema = json.load(f)
    return schema["properties"]["target_language"]["enum"]


def _get_cli_choices() -> list:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        capture_output=True, text=True
    )
    for line in (result.stdout + result.stderr).splitlines():
        if "--target-lang" in line and "{" in line:
            start = line.index("{") + 1
            end = line.index("}")
            return line[start:end].split(",")
    raise AssertionError("Could not find --target-lang choices in --help output")


class TestTargetLangChoices(unittest.TestCase):

    def test_schema_enum_matches_expected(self):
        schema_enum = _get_schema_enum()
        for lang in EXPECTED_ENUM:
            self.assertIn(lang, schema_enum, f"Schema missing language: {lang}")

    def test_cli_choices_cover_full_schema_enum(self):
        schema_enum = _get_schema_enum()
        cli_choices = _get_cli_choices()
        for lang in schema_enum:
            self.assertIn(lang, cli_choices, f"CLI choices missing schema lang: {lang}")

    def test_cli_includes_any(self):
        cli_choices = _get_cli_choices()
        self.assertIn("any", cli_choices)

    def test_cli_rejects_invalid_lang(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--target-lang", "cobol"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr.lower())

    def test_noir_accepted(self):
        self.assertIn("noir", _get_cli_choices())

    def test_sway_accepted(self):
        self.assertIn("sway", _get_cli_choices())

    def test_typescript_onchain_accepted(self):
        self.assertIn("typescript-onchain", _get_cli_choices())

    def test_vyper_accepted(self):
        self.assertIn("vyper", _get_cli_choices())


if __name__ == "__main__":
    unittest.main()
