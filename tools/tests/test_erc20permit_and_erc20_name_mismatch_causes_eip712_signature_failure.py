from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "erc20permit-and-erc20-name-mismatch-causes-eip712-signature-failure"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave17"
    / "erc20permit_and_erc20_name_mismatch_causes_eip712_signature_failure.py"
)
SPEC_DRAFT = (
    ROOT
    / "detectors"
    / "_specs"
    / "drafts_glider"
    / f"{PATTERN}.yaml"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "erc20permit_and_erc20_name_mismatch_causes_eip712_signature_failure"
)
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
REQUIRED_SOLC_VERSION = "0.8.20"


def _parse_solc_version(output: str) -> tuple[int, int, int] | None:
    match = re.search(r"Version:\s*(\d+)\.(\d+)\.(\d+)", output)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _satisfies_fixture_pragma(version: tuple[int, int, int] | None) -> bool:
    if version is None:
        return False
    required = tuple(int(part) for part in REQUIRED_SOLC_VERSION.split("."))
    return version[0] == 0 and version[1] == 8 and version >= required


def _probe_solc(solc_version: str | None) -> tuple[bool, str]:
    env = os.environ.copy()
    if solc_version is None:
        env.pop("SOLC_VERSION", None)
    else:
        env["SOLC_VERSION"] = solc_version
    try:
        proc = subprocess.run(
            ["solc", "--version"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    output = proc.stdout.strip()
    return proc.returncode == 0 and _satisfies_fixture_pragma(_parse_solc_version(output)), output


def _fixture_solc_version() -> tuple[bool, str | None, str]:
    candidates: list[str | None] = [REQUIRED_SOLC_VERSION]
    inherited = os.environ.get("SOLC_VERSION")
    if inherited and inherited not in candidates:
        candidates.append(inherited)
    candidates.append(None)

    diagnostics = []
    for candidate in candidates:
        ok, output = _probe_solc(candidate)
        label = f"SOLC_VERSION={candidate}" if candidate else "active solc"
        diagnostics.append(f"{label}: {output}")
        if ok:
            return True, candidate, output
    return False, None, " ; ".join(diagnostics)


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class Erc20PermitAndErc20NameMismatchCausesEip712SignatureFailureTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        solc_ok, selected_solc, solc_diagnostic = _fixture_solc_version()
        if not solc_ok:
            self.skipTest(
                f"fixture requires solc ^{REQUIRED_SOLC_VERSION}; {solc_diagnostic}"
            )
        if selected_solc is None:
            env.pop("SOLC_VERSION", None)
        else:
            env["SOLC_VERSION"] = selected_solc
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_spec_and_reference_align_on_literal_name_mismatch_shape(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        spec_text = SPEC_DRAFT.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("ERC20Permit", detector_text)
        self.assertIn("string literals", detector_text)
        self.assertIn("manual_constructor_literal_mismatch", spec_text)
        self.assertIn("fixture-smoke approximation", spec_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)

    def test_fixture_pair_models_mismatched_and_aligned_names(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn('ERC20("Mismatch Token", "MMT")', positive)
        self.assertIn('ERC20Permit("Permit Token")', positive)
        self.assertIn('ERC20("Aligned Token", "ALT")', clean)
        self.assertIn('ERC20Permit("Aligned Token")', clean)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["detector_path"], str(DETECTOR.relative_to(ROOT)))
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["required_solc_version"], REQUIRED_SOLC_VERSION)
        self.assertIn(f"SOLC_VERSION={REQUIRED_SOLC_VERSION}", payload["commands"]["positive"])
        self.assertIn(f"SOLC_VERSION={REQUIRED_SOLC_VERSION}", payload["commands"]["clean"])
        self.assertNotIn("--include-graveyard", payload["commands"]["positive"])
        self.assertNotIn("--include-graveyard", payload["commands"]["clean"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
