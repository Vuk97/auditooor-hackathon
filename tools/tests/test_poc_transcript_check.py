"""poc-transcript-check: a submission claiming a runnable PoC PASS must embed the
execution transcript (command + output) + a what-it-proves summary (2026-07-05).
"""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "poc-transcript-check.py"
_spec = importlib.util.spec_from_file_location("ptc", str(_TOOL))
ptc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ptc)


def _run(md_text: str, extra_files: dict | None = None) -> int:
    d = Path(tempfile.mkdtemp())
    md = d / "finding.md"
    md.write_text(md_text)
    for name, content in (extra_files or {}).items():
        (d / name).write_text(content)
    return subprocess.run(
        [sys.executable, str(_TOOL), str(md)], capture_output=True, text=True
    ).returncode


class PocTranscriptCheckTest(unittest.TestCase):
    def test_no_run_claim_passes(self):
        self.assertEqual(_run(
            "# F\nReasoning-only narrowed finding, no PoC claimed.\n"), 0)

    def test_claim_without_transcript_fails(self):
        self.assertEqual(_run(
            "# F\nThe PoC PASSES and proves the bug.\nNo code block.\n"), 1)

    def test_claim_with_embedded_transcript_passes(self):
        self.assertEqual(_run(
            "# F\nThe test demonstrates the bug.\n\n"
            "```\n$ go test ./evmrpc/ -run TestX\n--- PASS: TestX (0.3s)\nok  pkg 2.9s\n```\n"), 0)

    def test_claim_with_sibling_transcript_passes(self):
        self.assertEqual(_run(
            "# F\nThe PoC passes; it proves unbounded growth.\n",
            {"finding.poc-transcript.txt": "$ go test ./x\n--- PASS: TestGrow (0.3s)\nok x 1s\n"}), 0)

    def test_transcript_present_but_no_proves_summary_fails(self):
        # has a run transcript but no what-it-proves sentence -> fail
        self.assertEqual(_run(
            "# F\nforge test output below.\n\n"
            "```\n$ forge test\n[PASS] testBug()\n```\n"), 1)

    def test_forge_pass_transcript_with_summary_passes(self):
        self.assertEqual(_run(
            "# F\nThe forge test proves the reentrancy.\n\n"
            "```\n$ forge test --match-test testBug\n[PASS] testBug() (gas: 123)\n```\n"), 0)


if __name__ == "__main__":
    unittest.main()
