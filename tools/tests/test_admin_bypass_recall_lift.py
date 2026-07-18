#!/usr/bin/env python3
"""Focused regression for the admin-bypass umbrella recall lift."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "admin-bypass-umbrella"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "admin_bypass_umbrella"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
RUNNER = ROOT / "detectors" / "run_custom.py"


FUNCTION_RE = re.compile(
    r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*\{",
    re.MULTILINE,
)


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def _function_sources(path: Path) -> dict[str, str]:
    source = _strip_comments(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for match in FUNCTION_RE.finditer(source):
        start = match.start()
        cursor = match.end() - 1
        depth = 0
        end = cursor
        while end < len(source):
            char = source[end]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
            end += 1
        out[match.group(1)] = source[start:end]
    return out


def _body(function_source: str) -> str:
    open_brace = function_source.find("{")
    close_brace = function_source.rfind("}")
    return function_source[open_brace + 1 : close_brace]


def _pattern_list(spec: dict, key: str) -> list[str]:
    values: list[str] = []
    for row in spec["match"]:
        if key in row:
            values.append(str(row[key]))
    return values


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.14/bin/python3.14",
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class AdminBypassRecallLiftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

    def _matches(self, function_name: str, function_source: str) -> bool:
        body = _body(function_source)

        for pattern in _pattern_list(self.spec, "function.name_matches"):
            if not re.search(pattern, function_name):
                return False
        for pattern in _pattern_list(self.spec, "function.body_contains_regex"):
            if not re.search(pattern, body):
                return False
        for pattern in _pattern_list(self.spec, "function.body_not_contains_regex"):
            if re.search(pattern, body):
                return False
        for pattern in _pattern_list(self.spec, "function.not_source_matches_regex"):
            if re.search(pattern, function_source):
                return False
        return True

    def _hits(self, path: Path) -> set[str]:
        return {
            name
            for name, source in _function_sources(path).items()
            if self._matches(name, source)
        }

    def _runner_hits(self, path: Path) -> int:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [python, str(RUNNER), str(path), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("[ok] loaded 1 custom detector(s) (tier filter: S,E,A default)", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_metadata_tracks_current_recall_gap_and_sources(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")

        self.assertEqual(self.spec["pattern"], PATTERN)
        self.assertIn("admin-bypass", self.spec["tags"])
        self.assertEqual(self.spec["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(self.spec["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(self.spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(self.spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))

        self.assertIn("same-class recall = 59.38%", text)
        self.assertIn("role self-grant", text)
        self.assertIn("initializer ownership", text)
        self.assertIn("admin wrapper execution", text)
        self.assertIn("collision-prone signature auth", text)
        self.assertIn("blacklist-skipped-in-liquidation-path", text)
        self.assertNotIn("\u2014", text)
        self.assertNotIn("\u2013", text)

    def test_positive_fixture_covers_generalized_admin_bypass_shapes(self) -> None:
        hits = self._hits(POSITIVE)

        self.assertIn("setFeeRecipient", hits)
        self.assertIn("setCollateralEnabled", hits)
        self.assertIn("setOracle", hits)
        self.assertIn("updateSettings", hits)
        self.assertIn("initialize", hits)
        self.assertIn("grantRole", hits)
        self.assertIn("setController", hits)
        self.assertIn("setSelector", hits)
        self.assertIn("executeAdmin", hits)
        self.assertIn("authorizeControllerBySig", hits)
        self.assertIn("coverAccount", hits)

    def test_clean_fixture_keeps_guarded_and_self_service_paths_quiet(self) -> None:
        hits = self._hits(CLEAN)

        self.assertEqual(hits, set())
        clean_text = CLEAN.read_text(encoding="utf-8")
        self.assertIn("function setUserProfile(string calldata uri) external", clean_text)
        self.assertIn("function initialize(address newOwner) external initializer", clean_text)
        self.assertIn("function executeAdmin(address target, bytes calldata data) external onlyOwner", clean_text)
        self.assertIn("keccak256(abi.encode(scope, extraData, newController))", clean_text)
        self.assertIn('require(!blacklist[borrower], "blocked");', clean_text)

    def test_generated_detector_default_tier_hits_positive_and_skips_clean(self) -> None:
        self.assertEqual(self._runner_hits(POSITIVE), 11)
        self.assertEqual(self._runner_hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
