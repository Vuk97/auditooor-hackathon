from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "predicate-key-compatibility-burndown.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("predicate_key_compatibility_burndown", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class PredicateKeyCompatibilityBurndownTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_summarize_groups_by_key_and_marks_safe_aliases(self) -> None:
        class Finding:
            def __init__(self, yaml_path: str, predicate: str, key: str, warning_class: str) -> None:
                self.yaml_path = yaml_path
                self.predicate = predicate
                self.key = key
                self.warning_class = warning_class

        summary = self.tool.summarize(
            [
                Finding("a.yaml", "match[0]", "function.body_matches_regex", "unsupported_function_key"),
                Finding("b.yaml", "match[1]", "function.body_matches_regex", "unsupported_function_key"),
                Finding("b.yaml", "match[2]", "function.body_matches_regex", "unsupported_function_key"),
                Finding("c.yaml", "match[0]", "crate.is_execution_client", "unsupported_predicate_key"),
            ],
            checked=3,
            top=10,
        )

        self.assertEqual(summary["checked_yaml_count"], 3)
        self.assertEqual(summary["affected_pattern_count"], 3)
        self.assertEqual(summary["unknown_key_count"], 2)
        top = summary["top_unknown_keys"][0]
        self.assertEqual(top["key"], "function.body_matches_regex")
        self.assertEqual(top["affected_patterns"], 2)
        self.assertEqual(top["occurrences"], 3)
        self.assertEqual(top["alias_status"], "safe_alias")
        self.assertEqual(top["alias_target"], "function.body_contains_regex")
        self.assertEqual(summary["top_unknown_keys"][1]["alias_status"], "not_safe_alias")

    def test_cli_is_read_only_json_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yaml_path = root / "bad.yaml"
            yaml_path.write_text(
                textwrap.dedent(
                    """
                    id: bad
                    match:
                      - function.source_contains: raw literal
                      - crate.is_execution_client: true
                    """
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys.executable, str(TOOL), str(yaml_path), "--top", "5"],
                cwd=REPO,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        payload = json.loads(result.stdout)
        rows = {row["key"]: row for row in payload["top_unknown_keys"]}
        self.assertEqual(rows["function.source_contains"]["alias_status"], "value_transform")
        self.assertEqual(rows["crate.is_execution_client"]["alias_status"], "not_safe_alias")


if __name__ == "__main__":
    unittest.main()
