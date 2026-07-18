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
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-bridge-daemon-event-domain-binding-fire17.py"
FIXTURE_ROOT = ROOT / "tools" / "tests" / "fixtures" / "go-detector-runner"
PATTERN = "go-bridge-daemon-event-domain-binding-fire17"
POSITIVE = FIXTURE_ROOT / "positive" / "go_bridge_daemon_event_domain_binding_missing_fire17.go"
CLEAN = FIXTURE_ROOT / "negative" / "go_bridge_daemon_event_domain_binding_missing_fire17.go"


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


class GoBridgeDaemonEventDomainBindingFire17Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_bridge_domain_fire17_", suffix=".log") as tmp:
            proc = subprocess.run(
                [
                    python_ast,
                    str(TOOL),
                    "--lang",
                    "go",
                    str(FIXTURE_ROOT),
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

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_stdout = self._hits(POSITIVE)
        clean_hits, clean_stdout = self._hits(CLEAN)
        self.assertEqual(positive_hits, 1, positive_stdout)
        self.assertIn("class: bridge-proof-domain-bypass", positive_stdout)
        self.assertEqual(clean_hits, 0, clean_stdout)

    def test_fixtures_lock_domain_binding_semantics(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = CLEAN.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")

        self.assertIn("sha256.Sum256(event.EventID[:])", positive)
        self.assertIn("d.store.Mark(leaf)", positive)
        self.assertIn("return d.ForwardValue(ctx, event.Recipient, event.Amount)", positive)
        self.assertIn("ValidateEventDomainBinding", negative)
        self.assertIn("BuildBridgeEventDomainKey", negative)
        self.assertIn("event.SourceChain", negative)
        self.assertIn("event.EventNamespace", negative)
        self.assertIn("bridge-proof-domain-bypass", detector)


if __name__ == "__main__":
    unittest.main()
