"""Cross-workspace CI smoke fixture for the Wave-2 toolchain (PR #729 PR-B).

Regression guard ensuring the Wave-2 toolchain stays workspace-agnostic.
The graph workspace v1.1 schema validation work (doc
``V1_1_SCHEMA_VALIDATION_2026-05-16.md``) verified the Wave-2 toolchain
works on non-canonical workspaces after four capability gap fixes were
landed:

  * ``aa7a71912b`` PR-A: add ``--tags-dir`` override to the W2.1 validator
  * ``9c57fa7127`` PR-A cap-gap #2: harmonize runner/validator exit codes
  * ``4c55b265a0`` PR-A cap-gap #3: ship ``auditooor-yaml-schema-detect``
  * ``93de4c3721`` PR-A: schema-namespace registry doc (cap-gap #4)

This test file is the CI guard that keeps those four fixes landed. If a
future commit re-hardcodes ``/Users/wolf/auditooor-702-full`` into one of
the wave2 validators, the regression-guard test (which scans for the
literal canonical path) will fail loudly. If a future commit regresses
the ``--tags-dir`` override, the harmonized exit codes, or the schema
detect probe, the matching subprocess test will fail.

Design notes:

  * The synthetic workspace is built under
    ``tempfile.TemporaryDirectory()`` and never touches the canonical
    corpus. The fixture record is marked ``synthetic_fixture: true``.
  * Subprocess invocations target real CLIs (no mocking the tools).
  * Tool-presence tests use ``unittest.skipUnless`` so the suite degrades
    gracefully on a branch where the PR-A capability tools haven't
    landed yet; the hardcoded-path regression guard runs unconditionally.
  * The synthetic record uses
    ``verification_tier=tier-1-officially-disclosed``, the enum value
    added in PR-A commit ``58fdbe8e30``.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = REPO_ROOT / "tools"

W21_VALIDATOR = TOOLS_DIR / "wave2-w21-post-migration-validator.py"
V11_RUNNER = TOOLS_DIR / "hackerman-schema-v1-to-v1.1-runner.py"
YAML_SCHEMA_DETECT = TOOLS_DIR / "auditooor-yaml-schema-detect.py"

CANONICAL_HARDCODED_PATH = "/Users/wolf/auditooor-702-full"

# Minimal v1.1 hackerman record YAML. Every field is synthetic - no real
# CVE/GHSA/repo references. ``synthetic_fixture: true`` is the operator-
# emphasised marker keeping the fixture out of any real corpus index.
SYNTHETIC_V11_YAML = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1.1
    record_id: synthetic-pilot-001
    synthetic_fixture: true
    record_tier: tier-1-officially-disclosed
    verification_tier: tier-1-officially-disclosed
    attack_class: synthetic_cross_workspace_smoke
    cve_id: null
    ghsa_id: null
    incident_date: null
    firm: synthetic_pilot
    bug_class: synthetic
    function_shape:
      shape_tags:
        - verification_tier:tier-1-officially-disclosed
    """
)


def _run(
    cmd: list,
    *,
    cwd: Optional[Path] = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    """Run a subprocess capturing stdout/stderr; never raises on exit code."""
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _materialise_synthetic_workspace(tmp_root: Path) -> Path:
    """Build the synthetic workspace; returns the absolute tags-dir path."""
    tags_dir = tmp_root / "audit" / "corpus_tags" / "tags"
    sub = tags_dir / "synthetic_pilot"
    sub.mkdir(parents=True, exist_ok=True)
    sample = sub / "sample.yaml"
    sample.write_text(SYNTHETIC_V11_YAML, encoding="utf-8")
    return tags_dir


class CrossWorkspaceSmokeTests(unittest.TestCase):
    """Cross-workspace smoke fixture - PR #729 PR-B regression guard."""

    # ------------------------------------------------------------------
    # Tool-dependent tests
    # ------------------------------------------------------------------

    @unittest.skipUnless(
        W21_VALIDATOR.exists(),
        f"wave2-w21-post-migration-validator absent ({W21_VALIDATOR})",
    )
    def test_wave2_w21_validator_against_arbitrary_tagsdir(self) -> None:
        """Validator accepts an arbitrary --tags-dir without crashing.

        Asserts exit 0 (PASS or soft-FAIL without --strict) and that the
        JSON payload reports overall_status in {PASS, FAIL}. ERROR or a
        non-zero exit indicates a regression of cap-gap #1
        (aa7a71912b: --tags-dir override) or cap-gap #2 (9c57fa7127:
        exit-code harmonization).
        """
        with tempfile.TemporaryDirectory() as tmp:
            tags_dir = _materialise_synthetic_workspace(Path(tmp))
            proc = _run(
                [
                    sys.executable,
                    str(W21_VALIDATOR),
                    "--tags-dir",
                    str(tags_dir),
                    "--json",
                ]
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=(
                    "validator returned non-zero on a synthetic workspace "
                    f"(stdout={proc.stdout[:400]!r} stderr={proc.stderr[:400]!r})"
                ),
            )
            # JSON payload must parse and surface a clean diagnostic.
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError as exc:  # pragma: no cover
                self.fail(
                    f"validator stdout was not JSON: {exc}; "
                    f"stdout={proc.stdout[:400]!r}"
                )
            self.assertIn("overall_status", payload)
            self.assertIn(payload["overall_status"], {"PASS", "FAIL"})

    @unittest.skipUnless(
        V11_RUNNER.exists(),
        f"hackerman-schema-v1-to-v1.1-runner absent ({V11_RUNNER})",
    )
    def test_runner_against_arbitrary_tagsdir_dry_run(self) -> None:
        """Runner accepts an arbitrary --tags-dir in dry-run mode.

        --dry-run is the default; the test passes the flag explicitly for
        documentation. Asserts exit 0 (clean dry-run, nothing to write).
        """
        with tempfile.TemporaryDirectory() as tmp:
            tags_dir = _materialise_synthetic_workspace(Path(tmp))
            # The runner emits JSON to stdout by default in dry-run mode;
            # it does NOT accept a --json flag (passing one would yield
            # argparse exit 2).
            proc = _run(
                [
                    sys.executable,
                    str(V11_RUNNER),
                    "--tags-dir",
                    str(tags_dir),
                    "--dry-run",
                ]
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=(
                    "runner returned non-zero on a synthetic workspace "
                    f"(stdout={proc.stdout[:400]!r} stderr={proc.stderr[:400]!r})"
                ),
            )

    @unittest.skipUnless(
        YAML_SCHEMA_DETECT.exists(),
        f"auditooor-yaml-schema-detect absent ({YAML_SCHEMA_DETECT})",
    )
    def test_yaml_schema_detect_against_arbitrary_dir(self) -> None:
        """Schema-detect probe finds the synthetic v1.1 record.

        Validates the cap-gap #3 fix (4c55b265a0): operators must be able
        to point the probe at any directory. The synthetic record carries
        an explicit ``schema_version: auditooor.hackerman_record.v1.1``
        so the detector should report at least one v1.1 hit.
        """
        with tempfile.TemporaryDirectory() as tmp:
            _materialise_synthetic_workspace(Path(tmp))
            proc = _run(
                [
                    sys.executable,
                    str(YAML_SCHEMA_DETECT),
                    "--dir",
                    tmp,
                    "--json",
                ]
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=(
                    "schema-detect returned non-zero on a synthetic dir "
                    f"(stdout={proc.stdout[:400]!r} stderr={proc.stderr[:400]!r})"
                ),
            )
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError as exc:  # pragma: no cover
                self.fail(
                    f"schema-detect stdout was not JSON: {exc}; "
                    f"stdout={proc.stdout[:400]!r}"
                )
            # The probe should report at least one v1.1 record. The exact
            # key is the schema string the detector emits; check it
            # appears anywhere in the payload JSON.
            blob = json.dumps(payload)
            self.assertIn(
                "auditooor.hackerman_record.v1.1",
                blob,
                msg=(
                    "schema-detect did not surface the synthetic v1.1 "
                    f"record; payload={blob[:600]!r}"
                ),
            )

    @unittest.skipUnless(
        V11_RUNNER.exists(),
        f"hackerman-schema-v1-to-v1.1-runner absent ({V11_RUNNER})",
    )
    def test_runner_exit_2_on_missing_tagsdir(self) -> None:
        """Runner returns harmonized exit code 2 on missing tags-dir.

        Regression guard for cap-gap #2 (9c57fa7127): both runner and
        validator must agree that a missing tags-dir is exit code 2
        (structural ERROR), not 0 or 1.
        """
        proc = _run(
            [
                sys.executable,
                str(V11_RUNNER),
                "--tags-dir",
                "/nonexistent/path/" + "synthetic_does_not_exist",
                "--dry-run",
            ]
        )
        self.assertEqual(
            proc.returncode,
            2,
            msg=(
                "runner did not return exit code 2 on a missing tags-dir "
                f"(actual={proc.returncode} "
                f"stdout={proc.stdout[:300]!r} stderr={proc.stderr[:300]!r})"
            ),
        )

    @unittest.skipUnless(
        W21_VALIDATOR.exists(),
        f"wave2-w21-post-migration-validator absent ({W21_VALIDATOR})",
    )
    def test_validator_exit_2_on_missing_tagsdir(self) -> None:
        """Validator returns harmonized exit code 2 on missing tags-dir.

        Companion to test_runner_exit_2_on_missing_tagsdir; both tools
        must agree.
        """
        proc = _run(
            [
                sys.executable,
                str(W21_VALIDATOR),
                "--tags-dir",
                "/nonexistent/path/" + "synthetic_does_not_exist",
                "--json",
            ]
        )
        self.assertEqual(
            proc.returncode,
            2,
            msg=(
                "validator did not return exit code 2 on a missing tags-dir "
                f"(actual={proc.returncode} "
                f"stdout={proc.stdout[:300]!r} stderr={proc.stderr[:300]!r})"
            ),
        )

    # ------------------------------------------------------------------
    # Always-on regression guard
    # ------------------------------------------------------------------

    def test_hardcoded_canonical_path_absent(self) -> None:
        """No wave2-* tool may hard-code the canonical workspace path.

        Scans every ``tools/wave2-*.py`` file for the literal string
        ``/Users/wolf/auditooor-702-full``. The guard tolerates only
        documented benign uses; any other occurrence is a regression of
        the workspace-agnostic capability.

        Tolerated:
          * docstrings (triple-quoted blocks)
          * ``argparse`` help text (``help=...`` keyword)
          * comments / ``# ...``
          * example lines (``example`` substring)
          * ``DEFAULT_WORKSPACE`` / ``DEFAULT_TAGS_DIR`` constant
            assignments - these are CLI defaults that must be overridable
            via ``--workspace`` / ``--tags-dir``. If a future commit adds
            a non-default hardcoded reference (operational logic, not a
            CLI default), the test will fail.

        Empirical offender allowlist (existing, intentional CLI defaults):
          * ``wave2-b-close-readiness.py``: ``DEFAULT_WORKSPACE = Path("...")``
        """
        # Allowlist of (filename, line_substring) tuples for benign
        # existing CLI-default constants. New entries should be reviewed
        # carefully - the regression-guard rationale is to catch NEW
        # hardcoding, not to permit copy-paste of the existing default.
        ALLOWLIST = {
            (
                "wave2-b-close-readiness.py",
                'DEFAULT_WORKSPACE = Path("/Users/wolf/auditooor-702-full")',
            ),
        }
        wave2_files = sorted(TOOLS_DIR.glob("wave2-*.py"))
        self.assertGreater(
            len(wave2_files),
            0,
            msg=(
                "no wave2-*.py tools found under tools/ - test cannot "
                "meaningfully run on this checkout"
            ),
        )
        offenders: list = []
        for fp in wave2_files:
            text = fp.read_text(encoding="utf-8", errors="replace")
            if CANONICAL_HARDCODED_PATH not in text:
                continue
            # Walk lines and skip docstring/help/comment uses.
            in_docstring = False
            doc_marker = None
            for lineno, raw in enumerate(text.splitlines(), 1):
                stripped = raw.strip()
                # Track triple-quoted docstring blocks (handle both """ and ''').
                if not in_docstring:
                    for marker in ('"""', "'''"):
                        if marker in stripped:
                            # Same-line open + close on one line is a single-line docstring.
                            if stripped.count(marker) >= 2:
                                break
                            in_docstring = True
                            doc_marker = marker
                            break
                else:
                    if doc_marker and doc_marker in stripped:
                        in_docstring = False
                        doc_marker = None
                if CANONICAL_HARDCODED_PATH not in raw:
                    continue
                if in_docstring:
                    continue
                if stripped.startswith("#"):
                    continue
                if "help=" in raw:
                    continue
                if "example" in raw.lower() or "Example" in raw:
                    continue
                # Allowlisted benign CLI-default constants.
                if (fp.name, stripped) in ALLOWLIST:
                    continue
                offenders.append(f"{fp.name}:{lineno}: {stripped[:200]}")
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Hardcoded canonical workspace path detected in wave2-* "
                "tools - this regresses the workspace-agnostic capability "
                "validated by the graph-workspace v1.1 work. Offenders:\n"
                + "\n".join(offenders)
            ),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
