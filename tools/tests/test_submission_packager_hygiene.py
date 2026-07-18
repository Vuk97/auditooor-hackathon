#!/usr/bin/env python3
"""iter9-T5 regression tests — packager hygiene formats discovered by iter8 T1.

Locks two auxiliary packager behaviors that iter8 T1 (`16cf4d67`) surfaced
while remediating snowbridge drafts:

  1. Severity detection (`_extract_severity_from_draft`):
     - ACCEPTED: ``**Severity: High**`` (asterisks wrap the full phrase,
       line-anchored), returns ``HIGH``.
     - ACCEPTED: ``Severity: High`` (plain line), returns ``HIGH``.
     - ACCEPTED: ``- Severity: High`` (list-item-prefixed), returns ``HIGH``.
     - ACCEPTED: ``**Severity:** High`` (bold-header-only), returns ``HIGH``.
       PR560 policy keeps explicit user/draft severity visible. Platform-ready
       output is guarded later by locked/proved exact listed-impact contracts
       and severity-tier matching, not by hiding explicit severity syntax.

  2. PoC file discovery (`find_poc_for_draft`):
     - ACCEPTED: ``.t.sol`` file at ``<ws>/poc-tests/<name>.t.sol``
       referenced by bare basename in the draft — found via the
       basename-strip path.
     - ACCEPTED: ``.t.sol`` file referenced by full relative path
       (e.g. ``poc-tests/sub/foo.t.sol``) at ``<ws>/<full-rel-path>``
       — found via the full-path fallback.
     - REJECTED (returns ``None``): file inside a subdirectory of
       ``poc-tests/`` referenced only by bare basename, OR file at any
       location other than ``<ws>/poc-tests/<basename>`` or
       ``<ws>/<full-rel-path>``.

Offline. No network. No subprocess. Calls the packager functions
directly via importlib (the module has a dash in its name so it cannot
be imported by name).

Purpose: lock-in regression for iter8 T1's discovered formats. If a
future packager refactor changes either accepted format, these tests
fail loud — the refactor becomes an intentional format change, not an
accidental drift. Tests do NOT assert the current formats are optimal;
they assert consistency with iter8 T1's documented behavior.

No modifications to ``tools/submission-packager.py`` are made by this
test file. Pure regression lock.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGER_SRC = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    """Import ``tools/submission-packager.py`` under module name ``packager``.

    The dash in the filename blocks a normal ``import``, so we use
    ``importlib.util.spec_from_file_location`` to load it as a
    module-under-test.
    """
    spec = importlib.util.spec_from_file_location("_packager_under_test", PACKAGER_SRC)
    assert spec is not None and spec.loader is not None, (
        f"failed to build import spec for {PACKAGER_SRC}"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PKG = _load_packager_module()


class SeverityHeaderFormatTest(unittest.TestCase):
    """Lock explicit severity detection without making output paste-ready."""

    def _write(self, tmp: Path, name: str, content: str) -> Path:
        path = tmp / name
        path.write_text(content)
        return path

    def test_packager_accepts_bold_severity_header(self) -> None:
        """Draft with ``**Severity: High**`` format parses to ``HIGH``.

        This is the format iter8 T1 adopted for the two snowbridge drafts
        (``~/audits/snowbridge/submissions/staging/R67-F001.md`` line 13,
        verified against HEAD on 2026-04-23).
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            draft = self._write(
                tmpdir,
                "bold_wrap.md",
                "# Finding\n\n**Severity: High**\n\n## Summary\n\nbody\n",
            )
            severity = PKG._extract_severity_from_draft(draft)
            self.assertEqual(
                severity,
                "HIGH",
                msg=(
                    f"bold-wrap severity header must parse to HIGH, "
                    f"got {severity!r}. Iter8 T1 relies on this format for "
                    f"snowbridge R67-F001 / R67-F002."
                ),
            )

    def test_packager_accepts_plain_severity_line(self) -> None:
        """Draft with plain ``Severity: High`` line parses to ``HIGH``.

        Secondary accepted format (no asterisks) — also matches the
        regex and is the simplest severity line style.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            draft = self._write(
                tmpdir,
                "plain.md",
                "# Finding\n\nSeverity: High\n\n## Summary\n\nbody\n",
            )
            severity = PKG._extract_severity_from_draft(draft)
            self.assertEqual(severity, "HIGH")

    def test_packager_detects_bullet_list_severity_format(self) -> None:
        """Draft with ``- Severity: High`` is still an explicit claim.

        PR560 policy: detecting the claim is correct. Later platform-ready
        surfaces must still require a matching locked/proved listed-impact
        contract before output.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            draft = self._write(
                tmpdir,
                "bullet.md",
                "# Finding\n\n- Severity: High\n\n## Summary\n\nbody\n",
            )
            severity = PKG._extract_severity_from_draft(draft)
            self.assertEqual(
                severity,
                "HIGH",
                msg=(
                    f"bullet-list severity format is an explicit user/draft "
                    f"severity claim and must stay visible. Got {severity!r}."
                ),
            )

    def test_packager_detects_bold_colon_middle_format(self) -> None:
        """Draft with ``**Severity:** High`` (colon before closing ``**``)
        returns ``HIGH``.

        PR560 policy treats common explicit markdown severity syntax as a real
        claim so High+ gates cannot be bypassed through formatting.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            draft = self._write(
                tmpdir,
                "bold_colon_middle.md",
                "# Finding\n\n**Severity:** High\n\n## Summary\n\nbody\n",
            )
            severity = PKG._extract_severity_from_draft(draft)
            self.assertEqual(severity, "HIGH")


class PocDiscoveryLocationTest(unittest.TestCase):
    """Lock ``find_poc_for_draft`` path discovery (iter8 T1 fix #2)."""

    def _write(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_packager_finds_poc_in_workspace_poc_tests_dir(self) -> None:
        """A ``.t.sol`` file at ``<ws>/poc-tests/<name>.t.sol`` is
        discovered by ``find_poc_for_draft`` when the draft references
        the PoC by bare filename.

        This is the primary ACCEPTED location. Iter8 T1 had to copy the
        snowbridge PoC files into ``~/audits/snowbridge/poc-tests/``
        (see ITER8_PACKAGING_REPORT.md §R67-F001 "Copied ...
        into ``~/audits/snowbridge/poc-tests/`` so ``find_poc_for_draft``
        locates it"). Any refactor that changes this path will silently
        break every existing staged draft.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            poc = self._write(
                ws / "poc-tests" / "R67_L1AdaptorPreFundTheft.t.sol",
                "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract T {}\n",
            )
            draft = self._write(
                ws / "staging" / "finding.md",
                "# Finding\n\n"
                "**Severity: High**\n\n"
                "## PoC\n\n"
                "See `R67_L1AdaptorPreFundTheft.t.sol` for reproduction.\n",
            )
            found = PKG.find_poc_for_draft(draft, ws)
            self.assertIsNotNone(
                found,
                msg=(
                    f"find_poc_for_draft must resolve a bare `.t.sol` "
                    f"basename to <ws>/poc-tests/<basename>. "
                    f"Got None."
                ),
            )
            self.assertEqual(
                Path(found).resolve(),
                poc.resolve(),
                msg=(
                    f"find_poc_for_draft resolved to {found}, expected {poc}"
                ),
            )

    def test_packager_finds_poc_via_full_relative_path(self) -> None:
        """A ``.t.sol`` file referenced by full relative path
        (e.g. ``poc-tests/sub/foo.t.sol``) resolves to ``<ws>/<ref>``.

        Secondary accepted discovery path: the fallback after the
        basename-strip lookup fails.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            poc = self._write(
                ws / "poc-tests" / "sub" / "nested.t.sol",
                "// nested PoC\n",
            )
            draft = self._write(
                ws / "staging" / "finding.md",
                "# Finding\n\n**Severity: Medium**\n\n"
                "PoC: `poc-tests/sub/nested.t.sol`.\n",
            )
            found = PKG.find_poc_for_draft(draft, ws)
            self.assertIsNotNone(found)
            self.assertEqual(Path(found).resolve(), poc.resolve())

    def test_packager_does_not_find_poc_outside_accepted_paths(self) -> None:
        """A ``.t.sol`` file at a location OTHER than
        ``<ws>/poc-tests/<basename>`` or ``<ws>/<ref-rel-path>`` is
        NOT discovered (returns None).

        Hard-negative lock: iter8 T1 discovered that a PoC at
        ``<ws>/tests/foo.t.sol`` referenced by bare basename
        ``foo.t.sol`` is NOT found — the basename-strip lookup checks
        only ``<ws>/poc-tests/<basename>``, not ``<ws>/tests/<basename>``.
        Locks the current behavior so a future refactor that adds or
        removes search directories fails loud.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            # PoC lives at <ws>/tests/, NOT <ws>/poc-tests/.
            self._write(
                ws / "tests" / "orphan.t.sol",
                "// orphan PoC not in poc-tests/\n",
            )
            draft = self._write(
                ws / "staging" / "finding.md",
                "# Finding\n\n**Severity: Low**\n\n"
                "PoC: `orphan.t.sol` (bare ref — look in poc-tests/).\n",
            )
            found = PKG.find_poc_for_draft(draft, ws)
            self.assertIsNone(
                found,
                msg=(
                    f"find_poc_for_draft must NOT discover a PoC at "
                    f"<ws>/tests/ when referenced by bare basename — "
                    f"only <ws>/poc-tests/<basename> is searched via "
                    f"the basename-strip path. Got {found!r}."
                ),
            )


if __name__ == "__main__":
    unittest.main()
