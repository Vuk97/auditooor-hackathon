"""Tests for tools/v3-artifact-hygiene-check.py."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "v3-artifact-hygiene-check.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("v3_artifact_hygiene_check", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["v3_artifact_hygiene_check"] = module
    spec.loader.exec_module(module)
    return module


TOOL = _load_tool()


def _sha(path: Path) -> str:
    return TOOL._sha256(path)


class V3ArtifactHygieneCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="v3-artifact-hygiene-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_clean_paste(self, rel: str = "submissions/final_cantina_paste/FN1.md") -> Path:
        paste = self.write(
            rel,
            "# High finding\n\n"
            "## Proof of Concept\n\n"
            "Run `forge test --match-test testExploit`.\n\n"
            "Result: Suite result: ok. 2 passed; 0 failed; 0 skipped\n",
        )
        paste.with_suffix(paste.suffix + ".hash").write_text(_sha(paste) + "\n", encoding="utf-8")
        return paste

    def test_clean_folder_passes(self) -> None:
        self.write_clean_paste()
        report = TOOL.build_report(self.root)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["blockers"], [])

    def test_missing_hash_sidecar_blocks_platform_paste(self) -> None:
        self.write(
            "submissions/final_cantina_paste/FN1.md",
            "# Finding\n\n## Proof of Concept\n\nSuite result: ok. 1 passed; 0 failed\n",
        )

        report = TOOL.build_report(self.root)

        self.assertEqual(report["verdict"], "fail")
        self.assertTrue(
            any(blocker["code"] == "paste_hash_sidecar_missing" for blocker in report["blockers"])
        )

    def test_stale_hash_sidecar_blocks_platform_paste(self) -> None:
        paste = self.write_clean_paste()
        paste.write_text(paste.read_text(encoding="utf-8") + "\nEdited after hash.\n", encoding="utf-8")

        report = TOOL.build_report(self.root)

        self.assertEqual(report["verdict"], "fail")
        self.assertTrue(
            any(blocker["code"] == "paste_hash_sidecar_stale" for blocker in report["blockers"])
        )

    def test_json_paste_hash_sidecar_is_accepted(self) -> None:
        paste = self.write(
            "submissions/cantina_paste/FN2.md",
            "# Medium finding\n\n## Proof of Concept\n\nPASS [0.01s] test_fixture\n",
        )
        paste.with_suffix(paste.suffix + ".paste_hash").write_text(
            json.dumps({"paste_content_hash": _sha(paste)}),
            encoding="utf-8",
        )

        report = TOOL.build_report(self.root)

        self.assertEqual(report["verdict"], "pass")

    def test_plain_export_blocks_when_draft_hash_metadata_is_stale(self) -> None:
        draft = self.write("submissions/staging/FN3.md", "# Draft v1\n")
        recorded = _sha(draft)
        export = self.write("submissions/staging/FN3.hackenproof-plain.txt", "1. Title\n\nDraft v1\n")
        export.with_suffix(export.suffix + ".json").write_text(
            json.dumps({"draft_path": "FN3.md", "draft_sha256": recorded}),
            encoding="utf-8",
        )
        draft.write_text("# Draft v2\n", encoding="utf-8")

        report = TOOL.build_report(self.root)

        self.assertTrue(
            any(blocker["code"] == "plain_export_draft_hash_stale" for blocker in report["blockers"])
        )

    def test_plain_export_warns_when_older_than_draft_without_hash_metadata(self) -> None:
        draft = self.write("submissions/staging/FN4.md", "# Draft\n")
        export = self.write("submissions/staging/FN4.hackenproof-plain.txt", "1. Title\n\nDraft\n")
        old = time.time() - 120
        new = time.time()
        os.utime(export, (old, old))
        os.utime(draft, (new, new))

        report = TOOL.build_report(self.root)

        self.assertFalse(report["blockers"])
        self.assertTrue(
            any(warning["code"] == "plain_export_older_than_draft" for warning in report["warnings"])
        )

    def test_transcript_claimed_test_count_mismatch_blocks(self) -> None:
        paste = self.write(
            "submissions/final_cantina_paste/FN5.md",
            "# Finding\n\nClaimed test count: 3\n\n## Proof of Concept\n\nSee attached transcript.\n",
        )
        paste.with_suffix(paste.suffix + ".hash").write_text(_sha(paste) + "\n", encoding="utf-8")
        self.write("submissions/test-output/FN5_transcript.log", "Suite result: ok. 2 passed; 0 failed; 0 skipped\n")

        report = TOOL.build_report(self.root)

        self.assertTrue(
            any(
                blocker["code"] == "transcript_claimed_test_count_mismatch"
                for blocker in report["blockers"]
            )
        )

    def test_transcript_claimed_test_count_match_passes(self) -> None:
        paste = self.write(
            "submissions/final_cantina_paste/FN6.md",
            "# Finding\n\nClaimed test count: 2\n\n## Proof of Concept\n\nSee attached transcript.\n",
        )
        paste.with_suffix(paste.suffix + ".hash").write_text(_sha(paste) + "\n", encoding="utf-8")
        self.write("submissions/transcript/FN6.log", "test result: ok. 2 passed; 0 failed; 0 ignored\n")

        report = TOOL.build_report(self.root)

        self.assertFalse(
            any(
                blocker["code"] == "transcript_claimed_test_count_mismatch"
                for blocker in report["blockers"]
            )
        )
        self.assertEqual(report["verdict"], "pass")

    def test_internal_gate_label_leak_blocks_platform_paste(self) -> None:
        paste = self.write(
            "submissions/platform_paste/FN7.md",
            "# Finding\n\nWorker Q confirmed Gate R40 under STRICT=1.\n",
        )
        paste.with_suffix(paste.suffix + ".hash").write_text(_sha(paste) + "\n", encoding="utf-8")

        report = TOOL.build_report(self.root)

        blockers = [b for b in report["blockers"] if b["code"] == "platform_paste_internal_label_leak"]
        self.assertEqual(len(blockers), 1)
        labels = {hit["label"] for hit in blockers[0]["hits"]}
        self.assertIn("worker_label", labels)
        self.assertIn("gate_label", labels)
        self.assertIn("strict_env_label", labels)

    def test_cli_outputs_json_and_uses_strict_exit_code(self) -> None:
        self.write("submissions/final_cantina_paste/FN8.md", "# Finding\n\nNo sidecar.\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = TOOL.main([str(self.root)])

        payload = json.loads(buf.getvalue())
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail")
        self.assertTrue(payload["blockers"])

    def test_cli_missing_folder_returns_2_with_error_json(self) -> None:
        missing = self.root / "missing"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = TOOL.main([str(missing)])

        payload = json.loads(buf.getvalue())
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    def test_cli_missing_explicit_path_returns_2_with_error_json(self) -> None:
        self.root.mkdir(exist_ok=True)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = TOOL.main([str(self.root), "--json", "--paste", str(self.root / "missing.md")])

        payload = json.loads(buf.getvalue())
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")
        self.assertIn("missing", payload)


if __name__ == "__main__":
    unittest.main()
