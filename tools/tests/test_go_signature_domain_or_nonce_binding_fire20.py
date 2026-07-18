from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lang-detect.py"
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-cosmos-signature-replay-scope-missing.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-cosmos-signature-replay-scope-missing"
DETECTOR_TO_AC_MAP = ROOT / "reference" / "detector_to_attack_classes_map.yaml"
POSITIVE = FIXTURE_DIR / "go-signature-domain-or-nonce-binding-fire20_positive.go"
NEGATIVE = FIXTURE_DIR / "go-signature-domain-or-nonce-binding-fire20_negative.go"


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
                [candidate, "-c", "from tree_sitter_language_pack import get_parser; get_parser('go')"],
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


class GoSignatureDomainOrNonceBindingFire20Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_signature_fire20_", suffix=".log") as tmp:
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
            log_text = Path(tmp.name).read_text(encoding="utf-8")
            return int(match.group(1)), proc.stdout + "\n" + log_text

    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_detector_ids_route_to_signature_replay_cross_domain(self) -> None:
        detector_map = yaml.safe_load(DETECTOR_TO_AC_MAP.read_text(encoding="utf-8"))["mappings"]
        self.assertEqual(detector_map[PATTERN][0], "signature-replay-cross-domain")

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_stdout = self._hits(POSITIVE)
        negative_hits, negative_stdout = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 1, positive_stdout)
        self.assertIn("class: signature-replay-cross-domain", positive_stdout)
        self.assertEqual(negative_hits, 0, negative_stdout)

    def test_fixtures_lock_confirmed_go_source_shape(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("solodit-58650-zetachain-solana-withdraw-nonce-not-incremented", positive)
        self.assertIn("MarkWithdrawalFailed(ctx, msg.Sender, msg.Nonce)", positive)
        self.assertIn("fmt.Sprintf(\"%s:%s:%d\"", positive)
        self.assertIn("ctx.ChainID()", negative)
        self.assertIn("domain", negative)
        self.assertIn("action", negative)
        self.assertIn("msg.Signer", negative)
        self.assertIn("ConsumeNonce(ctx, msg.Signer, msg.Nonce)", negative)


if __name__ == "__main__":
    unittest.main()
