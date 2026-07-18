"""DETECTOR-CODIFY-1 — unit tests for the 5 codified patterns.

Covers:
  Pattern 2: erc4626-balanceOf-share-calc-narrowed   (RG-N4 narrowing)
  Pattern 3: lockup-bypass-duration-vs-timestamp     (RG-N3 narrowing)
  Pattern 4: poke-accrue-source-vs-sink              (RG-N5 narrowing)
  Pattern 5: vault_exploit_context semantic-match    (SP-A1..SP-A5 saturation)
  Pattern 6: commitment-nonce-map-no-delete-after-consume  (SP-A1 FROST hygiene)

For each YAML pattern we assert:
  - The DSL spec exists, parses, lists vuln + clean fixtures.
  - Both fixture files exist on disk.
  - `pattern-compile.py` compiles the YAML into a Slither detector module.
  - The compiled detector's preconditions / match keys are non-empty.
  - The vuln fixture body contains the regex tokens the matcher requires;
    the clean fixture body either lacks those tokens or contains the
    inverse-regex (negation) match the YAML uses.

Pattern 5 is exercised directly against `_semantic_match_factor` because it
lives inside `tools/exploit-memory-brief.py` rather than the DSL pipeline.

Stdlib-only.
"""

from __future__ import annotations

import importlib.util
import io
import re
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DSL_DIR = REPO / "reference" / "patterns.dsl"
FIX_DIR = REPO / "patterns" / "fixtures"
COMPILE = REPO / "tools" / "pattern-compile.py"
BRIEF = REPO / "tools" / "exploit-memory-brief.py"


def _load_module(path: Path, mod_name: str):
    # exploit-memory-brief.py uses sibling-folder imports (e.g.,
    # `from outcome_semantics import ...`) that only resolve when `tools/`
    # is on sys.path. Add it transparently so module loading works in CI.
    import sys
    tools_dir = str(path.parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _import_yaml():
    try:
        import yaml  # type: ignore
        return yaml
    except ImportError:
        return None


PATTERNS = [
    {
        "name": "erc4626-balanceOf-share-calc-narrowed",
        "vuln_must_contain": [
            r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
            r"_mint|totalSupply|deposit",
        ],
        "clean_must_lack_or_have_guard": [r"storedAssets|tracked|checkpoint|principalTracked"],
    },
    {
        "name": "lockup-bypass-duration-vs-timestamp",
        "vuln_must_contain": [r"block\.timestamp\s*\+\s*\w+|unlockTime"],
        "clean_must_lack_or_have_guard": [r"require\s*\(.*MIN|require\s*\(.*MIN_DELAY"],
    },
    {
        "name": "poke-accrue-source-vs-sink",
        "vuln_must_contain": [r"_mint\s*\(|deposit|redeem", r"balances|totalSupply"],
        "clean_must_lack_or_have_guard": [r"_accrueRewards\s*\("],
    },
    {
        "name": "commitment-nonce-map-no-delete-after-consume",
        "vuln_must_contain": [r"ecrecover|verify|consume", r"used\["],
        "clean_must_lack_or_have_guard": [r"delete\s+commitment\[|delete\s+nonce\["],
    },
]


class DslPatternSchemaTest(unittest.TestCase):
    """Each codified DSL pattern must be a parseable, non-empty spec."""

    def setUp(self):
        self.yaml = _import_yaml()
        if self.yaml is None:
            self.skipTest("PyYAML not available")

    def _spec(self, name: str) -> dict:
        path = DSL_DIR / f"{name}.yaml"
        self.assertTrue(path.exists(), f"missing DSL spec: {path}")
        return self.yaml.safe_load(path.read_text(encoding="utf-8"))

    def test_each_pattern_yaml_loads_with_required_fields(self):
        for entry in PATTERNS:
            with self.subTest(pattern=entry["name"]):
                spec = self._spec(entry["name"])
                self.assertEqual(spec.get("pattern"), entry["name"])
                self.assertIn("preconditions", spec)
                self.assertIn("match", spec)
                self.assertIn("fixtures", spec)
                self.assertIn("severity", spec)
                self.assertIsInstance(spec["preconditions"], list)
                self.assertGreater(len(spec["preconditions"]), 0)
                self.assertIsInstance(spec["match"], list)
                self.assertGreater(len(spec["match"]), 0)

    def test_each_pattern_lists_vuln_and_clean_fixtures(self):
        for entry in PATTERNS:
            with self.subTest(pattern=entry["name"]):
                spec = self._spec(entry["name"])
                vuln_rel = spec["fixtures"]["vuln"]
                clean_rel = spec["fixtures"]["clean"]
                self.assertTrue((REPO / vuln_rel).exists(), f"missing vuln fixture: {vuln_rel}")
                self.assertTrue((REPO / clean_rel).exists(), f"missing clean fixture: {clean_rel}")


class DslPatternFixtureTokenTest(unittest.TestCase):
    """The vuln fixture must contain the matcher tokens; the clean fixture
    must either lack them or carry the inverse-regex (negation) shape."""

    def test_each_vuln_fixture_carries_matcher_tokens(self):
        for entry in PATTERNS:
            with self.subTest(pattern=entry["name"]):
                vuln = (FIX_DIR / f"{entry['name']}_vuln.sol").read_text(encoding="utf-8")
                for tok in entry["vuln_must_contain"]:
                    self.assertRegex(vuln, tok, f"{entry['name']} vuln missing token: {tok}")

    def test_each_clean_fixture_carries_guard_or_negation_shape(self):
        for entry in PATTERNS:
            with self.subTest(pattern=entry["name"]):
                clean = (FIX_DIR / f"{entry['name']}_clean.sol").read_text(encoding="utf-8")
                # At least one of the listed guard/negation regexes must match.
                hits = [tok for tok in entry["clean_must_lack_or_have_guard"] if re.search(tok, clean)]
                self.assertGreater(
                    len(hits),
                    0,
                    f"{entry['name']} clean fixture lacks all guard/negation patterns: "
                    f"{entry['clean_must_lack_or_have_guard']}",
                )


class DslPatternCompileTest(unittest.TestCase):
    """Each codified DSL pattern must compile cleanly into a detector module."""

    def test_each_pattern_compiles_without_errors(self):
        tool = _load_module(COMPILE, "pattern_compile_codify1")
        for entry in PATTERNS:
            with self.subTest(pattern=entry["name"]):
                yaml_path = DSL_DIR / f"{entry['name']}.yaml"
                # Ensure compile() succeeds and returns the expected output path.
                compile_fn = getattr(tool, "compile_one", None) or getattr(tool, "main", None)
                self.assertIsNotNone(compile_fn, "pattern-compile.py exposes neither compile_one nor main")
                # Use the CLI shape to keep the test resilient to internal refactors.
                import subprocess
                rc = subprocess.run(
                    ["python3", str(COMPILE), str(yaml_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                ).returncode
                self.assertEqual(rc, 0, f"compile failed for {entry['name']}")

    def test_each_emitted_detector_module_exists(self):
        for entry in PATTERNS:
            with self.subTest(pattern=entry["name"]):
                # Compiler emits to detectors/wave17/<snake_case>.py
                snake = entry["name"].replace("-", "_")
                path = REPO / "detectors" / "wave17" / f"{snake}.py"
                self.assertTrue(path.exists(), f"compiled detector not found: {path}")
                # The body must reference the predicate engine (not be a stub).
                body = path.read_text(encoding="utf-8")
                self.assertIn("eval_function_match", body)
                self.assertIn("_PRECONDITIONS", body)
                self.assertIn("_MATCH", body)


class SemanticMatchFactorTest(unittest.TestCase):
    """Pattern 5: vault_exploit_context source-signal narrowing.

    The `_semantic_match_factor()` helper inside `tools/exploit-memory-brief.py`
    must downscore matches that occur on import / comment / type-declaration
    lines (the 5/5 NEGATIVE-control SP-A1..SP-A5 shape) while leaving
    real call-site matches at 1.0.
    """

    def setUp(self):
        self.brief = _load_module(BRIEF, "exploit_memory_brief_codify1")
        self.factor = self.brief._semantic_match_factor

    def test_call_site_match_keeps_full_factor(self):
        text = (
            "contract A {\n"
            "    function f() external {\n"
            "        uint256 c = balanceOf(address(this));\n"  # real call
            "    }\n"
            "}\n"
        )
        idx = text.index("balanceOf")
        self.assertEqual(self.factor(text, idx), 1.0)

    def test_import_line_match_is_suppressed(self):
        text = (
            'import {IERC20} from "openzeppelin/IERC20.sol";\n'
            "contract A {}\n"
        )
        idx = text.index("IERC20")
        self.assertLess(self.factor(text, idx), 0.1)

    def test_comment_line_match_is_suppressed(self):
        text = (
            "// uses balanceOf as a token-mention\n"
            "contract A {}\n"
        )
        idx = text.index("balanceOf")
        self.assertLess(self.factor(text, idx), 0.1)

    def test_interface_declaration_match_is_downscored(self):
        text = (
            "interface IBalanceOf { function balanceOf(address) external view returns (uint256); }\n"
        )
        idx = text.index("IBalanceOf")
        self.assertLessEqual(self.factor(text, idx), 0.35)

    def test_using_for_directive_is_downscored(self):
        text = "using SafeERC20 for IERC20;\n"
        idx = text.index("SafeERC20")
        self.assertLessEqual(self.factor(text, idx), 0.35)


if __name__ == "__main__":
    unittest.main()
