#!/usr/bin/env python3
"""Regression tests for CCIA attack-angle wiring in Makefile audit-deep."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
MAKEFILE = REPO / "Makefile"
STERILE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class TestCciaAttackAnglesWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("make"):
            raise unittest.SkipTest("make not on PATH")
        if not shutil.which("python3"):
            raise unittest.SkipTest("python3 not on PATH")
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")

    def setUp(self) -> None:
        self.sandbox = Path(tempfile.mkdtemp(prefix="ccia_attack_angles_wire_"))
        self.ws = self.sandbox / "audits" / "solidity-ws"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / "src" / "Token.sol").write_text(
            "\n".join(
                [
                    "pragma solidity ^0.8.20;",
                    "contract Token {",
                    "    uint256 public total;",
                    "    function setTotal(uint256 next) external {",
                    "        total = next;",
                    "    }",
                    "}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (self.ws / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.sandbox, ignore_errors=True)

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(self.sandbox)
        env["PATH"] = STERILE_PATH
        empty_bin = self.sandbox / "empty-deep-bin"
        empty_bin.mkdir(exist_ok=True)
        env["AUDITOOOR_DEEP_BIN_DIR"] = str(empty_bin)
        env["AUDITOOOR_AUDIT_DEEP_SOLIDITY_SMOKE"] = "1"
        env["AUDITOOOR_AUDIT_DEEP_ROUTE_ONLY"] = "1"
        env["AUDIT_COMMIT_MINING_SKIP"] = "1"
        return env

    def _run_make(self, target: str, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["make", target, f"WS={self.ws}", *extra],
            cwd=REPO,
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _run_make_dry(self, target: str, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["make", "-n", target, f"WS={self.ws}", *extra],
            cwd=REPO,
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _angles_path(self) -> Path:
        return self.ws / ".auditooor" / "ccia_attack_angles.json"

    def _load_angles(self) -> list[dict]:
        path = self._angles_path()
        self.assertTrue(path.is_file(), f"missing CCIA attack-angle output at {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(data, list)
        return data

    def test_helper_target_writes_attack_angle_json(self) -> None:
        proc = self._run_make("audit-deep-ccia-attack-angles")
        self.assertEqual(
            proc.returncode,
            0,
            f"make audit-deep-ccia-attack-angles failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )

        angles = self._load_angles()
        self.assertTrue(angles, "expected at least one attack angle for unauthenticated state write fixture")
        self.assertTrue(any(isinstance(row, dict) and row.get("id") for row in angles))

    def test_audit_deep_solidity_route_invokes_ccia_helper(self) -> None:
        proc = self._run_make_dry(
            "audit-deep",
            "AUDIT_DEEP_SKIP_AUDIT_PREREQ=1",
            "AUDIT_DEEP_ALLOW_STALE_AUDIT_PREREQ=1",
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"make -n audit-deep failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        self.assertIn("Solidity workspace detected; routing to audit-deep-solidity", proc.stdout)
        self.assertIn("audit-deep-solidity WS=", proc.stdout)
        self.assertIn("audit-deep-ccia-attack-angles WS=", proc.stdout)


if __name__ == "__main__":
    unittest.main()
