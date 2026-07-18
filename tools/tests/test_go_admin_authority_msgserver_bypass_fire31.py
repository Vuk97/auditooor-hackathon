from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lang-detect.py"
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-admin-authority-msgserver-bypass-fire31.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-admin-authority-msgserver-bypass-fire31"
POSITIVE = FIXTURE_DIR / f"{PATTERN}_positive.go"
NEGATIVE = FIXTURE_DIR / f"{PATTERN}_negative.go"
SOURCE_POSITIVE = FIXTURE_DIR / "cosmos_msgserver_missing_authority_check_positive.go"


def _python_with_go_parser() -> str | None:
    candidates = [
        os.environ.get("AUDITOOOR_PYTHON_AST"),
        sys.executable,
        "python3",
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "from tree_sitter_language_pack import get_parser; get_parser('go')",
                ],
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


class GoAdminAuthorityMsgServerBypassFire31Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_admin_authority_", suffix=".log") as tmp:
            proc = subprocess.run(
                [
                    python_ast,
                    str(TOOL),
                    "--lang",
                    "go",
                    str(FIXTURE_DIR),
                    "--only",
                    PATTERN,
                    "--file",
                    str(fixture),
                    "--log",
                    tmp.name,
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            match = re.search(r"total hits:\s*(\d+)", proc.stdout)
            self.assertIsNotNone(match, proc.stdout)
            log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
            return int(match.group(1)), log_text

    def test_detector_compiles_and_keeps_ascii_dash_discipline(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = self._hits(POSITIVE)
        negative_hits, negative_log = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 4, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("UpdateParams", positive_log)
        self.assertIn("SetMarketConfig", positive_log)
        self.assertIn("RegisterModule", positive_log)
        self.assertIn("SetOracleOwner", positive_log)
        self.assertIn("admin-bypass", positive_log)

    def test_source_ref_fixture_is_covered_not_conceptual(self) -> None:
        source_hits, source_log = self._hits(SOURCE_POSITIVE)
        self.assertGreaterEqual(source_hits, 3, source_log)
        self.assertIn("UpdateParams", source_log)
        self.assertIn("SetMarketConfig", source_log)
        self.assertIn("RegisterModule", source_log)

    def test_negative_fixture_locks_false_positive_boundaries(self) -> None:
        clean = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("msg.Authority != m.Keeper.GetAuthority()", clean)
        self.assertIn("m.Keeper.AssertAuthority(ctx, msg.Admin)", clean)
        self.assertIn("authtypes.NewModuleAddress(govtypes.ModuleName)", clean)
        self.assertIn("UpdateProfile", clean)


if __name__ == "__main__":
    unittest.main()
