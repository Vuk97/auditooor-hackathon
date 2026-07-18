"""Tests for tools/hackerman-wave1-shipment-receipt.py.

Wave-1 hackerman capability lift (PR #726). Covers the immutable shipment
receipt envelope builder: schema, collectors (git / baseline / targets /
callables / docs), readiness verdict, and the CLI main entry point.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


THIS_FILE = pathlib.Path(__file__).resolve()
REPO = THIS_FILE.parent.parent.parent
TOOL_PATH = REPO / "tools" / "hackerman-wave1-shipment-receipt.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "hackerman_wave1_shipment_receipt", TOOL_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


HM = _load_module()


def _make_baseline(path: pathlib.Path, *, corpus_sha: str = "deadbeef" * 8,
                   total: int = 36492) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "baseline_label": "test-baseline",
        "corpus_sha256": corpus_sha,
        "generated_at": "2026-05-16T00:00:00Z",
        "input_count": total,
        "schema": "auditooor.hackerman_baseline_freeze.v1",
        "stats": {
            "tier_distribution": {
                "tier-1": 100, "tier-2": 200, "tier-3": 50,
                "tier-4": 25, "tier-5": 5, "no-tier": 10,
            },
            "subtree_record_counts": {"<root>": 200, "alpha": 50},
            "total_records": total,
        },
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


class _CompletedProc:
    def __init__(self, rc: int, out: str = "", err: str = ""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class HackermanWave1ShipmentReceiptTests(unittest.TestCase):
    # 1. Tool file exists, schema constant present.
    def test_tool_file_exists_and_schema_constant(self):
        self.assertTrue(TOOL_PATH.exists(), f"missing: {TOOL_PATH}")
        self.assertEqual(
            HM.SCHEMA,
            "auditooor.hackerman_wave1_shipment_receipt.v1",
        )
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("def main", text)
        self.assertIn("def build_envelope", text)

    # 2. collect_baseline: happy path reads tier_distribution + corpus SHA.
    def test_collect_baseline_happy_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            bp = _make_baseline(
                root / "audit/wave1_snapshots/baseline_freeze/2026-05-16.json",
                corpus_sha="abc123" + "0" * 58,
                total=12345,
            )
            out = HM.collect_baseline(root, bp)
            self.assertEqual(out["corpus_sha256"], "abc123" + "0" * 58)
            self.assertEqual(out["total_records"], 12345)
            self.assertEqual(out["tier_distribution"]["tier-2"], 200)
            self.assertEqual(out["baseline_label"], "test-baseline")
            self.assertFalse(out["errors"])

    # 3. collect_baseline: auto-pick last-lexicographic file when path=None.
    def test_collect_baseline_auto_pick_last(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            _make_baseline(
                root / "audit/wave1_snapshots/baseline_freeze/2026-04-01.json",
                corpus_sha="a" * 64, total=1,
            )
            _make_baseline(
                root / "audit/wave1_snapshots/baseline_freeze/2026-05-16.json",
                corpus_sha="b" * 64, total=2,
            )
            out = HM.collect_baseline(root, None)
            # last lexicographic should be 2026-05-16.json -> corpus b...
            self.assertEqual(out["corpus_sha256"], "b" * 64)
            self.assertEqual(out["total_records"], 2)

    # 4. collect_baseline: missing file surfaces an error, not a crash.
    def test_collect_baseline_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            out = HM.collect_baseline(root, None)
            self.assertIsNone(out["corpus_sha256"])
            self.assertTrue(out["errors"])

    # 5. collect_hackerman_docs: enumerates HACKERMAN docs.
    def test_collect_hackerman_docs(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "docs").mkdir()
            (root / "docs/HACKERMAN_A.md").write_text("# a", encoding="utf-8")
            (root / "docs/HACKERMAN_B.md").write_text("# b", encoding="utf-8")
            (root / "docs/UNRELATED.md").write_text("# n", encoding="utf-8")
            out = HM.collect_hackerman_docs(root, "docs/HACKERMAN*.md")
            self.assertEqual(out["doc_count"], 2)
            self.assertIn("docs/HACKERMAN_A.md", out["docs"])
            self.assertNotIn("docs/UNRELATED.md", out["docs"])

    # 6. collect_vault_callables: regex extracts unique vault_* names.
    def test_collect_vault_callables_regex(self):
        fake_help = (
            "usage: vault-mcp-server.py [--call {vault_search,vault_get,"
            "vault_next_loop,vault_search,vault_remember}]"
        )
        with mock.patch.object(HM, "_run", return_value=(0, fake_help, "")):
            with tempfile.TemporaryDirectory() as td:
                root = pathlib.Path(td)
                (root / "tools").mkdir()
                (root / "tools/vault-mcp-server.py").write_text("#!stub", encoding="utf-8")
                out = HM.collect_vault_callables(root)
                self.assertEqual(out["callable_count"], 4)
                self.assertIn("vault_search", out["callables"])
                self.assertIn("vault_remember", out["callables"])

    # 7. collect_hackerman_targets: parses help-json envelope.
    def test_collect_hackerman_targets_parses_help_json(self):
        fake_json = json.dumps({
            "schema": "auditooor.hackerman_help.v1",
            "target_count": 3,
            "targets": [
                {"target": "hackerman-all", "purpose": "p"},
                {"target": "hackerman-help", "purpose": "p"},
                {"target": "hackerman-corpus-stats", "purpose": "p"},
            ],
        })
        with mock.patch.object(HM, "_run", return_value=(0, fake_json, "")):
            out = HM.collect_hackerman_targets(pathlib.Path("/tmp"))
            self.assertEqual(out["target_count"], 3)
            self.assertIn("hackerman-all", out["targets"])
            self.assertEqual(out["schema"], "auditooor.hackerman_help.v1")
            self.assertEqual(out["target_count_reported"], 3)

    # 8. derive_wave2_readiness: ready when all required fields present.
    def test_readiness_ready(self):
        verdict = HM.derive_wave2_readiness(
            git_state={"head_sha": "deadbeef", "errors": []},
            baseline={"corpus_sha256": "abc", "total_records": 100, "errors": []},
            targets={"target_count": 5, "errors": []},
            callables={"callable_count": 10, "errors": []},
            docs={"doc_count": 1},
        )
        self.assertEqual(verdict["verdict"], "ready")
        self.assertEqual(verdict["reasons"], [])

    # 9. derive_wave2_readiness: not-ready surfaces specific reasons.
    def test_readiness_not_ready_lists_reasons(self):
        verdict = HM.derive_wave2_readiness(
            git_state={"head_sha": None, "errors": []},
            baseline={"corpus_sha256": None, "total_records": 0, "errors": ["x"]},
            targets={"target_count": 0, "errors": []},
            callables={"callable_count": 0, "errors": []},
            docs={"doc_count": 0},
        )
        self.assertEqual(verdict["verdict"], "not-ready")
        joined = " | ".join(verdict["reasons"])
        self.assertIn("HEAD SHA", joined)
        self.assertIn("corpus_sha256", joined)
        self.assertIn("hackerman-* targets", joined)
        self.assertIn("vault_* callables", joined)
        self.assertIn("HACKERMAN docs", joined)
        self.assertIn("baseline errors", joined)

    # 10. build_envelope: produces canonical schema + nested keys.
    def test_build_envelope_canonical_shape(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "tools").mkdir()
            (root / "tools/vault-mcp-server.py").write_text("stub", encoding="utf-8")
            _make_baseline(
                root / "audit/wave1_snapshots/baseline_freeze/2026-05-16.json",
            )
            (root / "docs").mkdir()
            (root / "docs/HACKERMAN_X.md").write_text("# x", encoding="utf-8")

            def fake_run(cmd, cwd):
                if "git" in cmd[0]:
                    if cmd[1] == "rev-parse" and cmd[2] == "HEAD":
                        return (0, "abc123\n", "")
                    if cmd[1] == "rev-parse" and cmd[2] == "--abbrev-ref":
                        return (0, "wave-1-hackerman-capability-lift\n", "")
                    if cmd[1] == "rev-list":
                        return (0, "190\n", "")
                if "make" in cmd[0]:
                    return (0, json.dumps({
                        "schema": "auditooor.hackerman_help.v1",
                        "target_count": 1,
                        "targets": [{"target": "hackerman-all"}],
                    }), "")
                if "vault-mcp-server.py" in " ".join(cmd):
                    return (0, "vault_search vault_get", "")
                return (0, "", "")

            with mock.patch.object(HM, "_run", side_effect=fake_run):
                env = HM.build_envelope(
                    repo=root, base_branch="origin/main",
                    baseline_path=None, doc_glob="docs/HACKERMAN*.md",
                    generated_at="2026-05-16T00:00:00Z",
                )
        self.assertEqual(env["schema"], HM.SCHEMA)
        self.assertEqual(env["pr"]["number"], 726)
        self.assertEqual(env["pr"]["head_sha"], "abc123")
        self.assertEqual(env["pr"]["commit_count_vs_base"], 190)
        self.assertEqual(env["pr"]["branch"], "wave-1-hackerman-capability-lift")
        self.assertEqual(env["corpus_baseline"]["total_records"], 36492)
        self.assertEqual(env["hackerman_targets"]["count"], 1)
        self.assertEqual(env["vault_callables"]["count"], 2)
        self.assertEqual(env["hackerman_docs"]["count"], 1)
        self.assertEqual(env["wave2_readiness"]["verdict"], "ready")

    # 11. main(): writes the envelope file with canonical schema.
    def test_main_writes_envelope(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "tools").mkdir()
            (root / "tools/vault-mcp-server.py").write_text("stub", encoding="utf-8")
            _make_baseline(
                root / "audit/wave1_snapshots/baseline_freeze/2026-05-16.json",
            )
            (root / "docs").mkdir()
            (root / "docs/HACKERMAN_X.md").write_text("# x", encoding="utf-8")

            def fake_run(cmd, cwd):
                if "git" in cmd[0]:
                    if cmd[1] == "rev-parse" and cmd[2] == "HEAD":
                        return (0, "feedface\n", "")
                    if cmd[1] == "rev-parse" and cmd[2] == "--abbrev-ref":
                        return (0, "branch\n", "")
                    if cmd[1] == "rev-list":
                        return (0, "42\n", "")
                if "make" in cmd[0]:
                    return (0, json.dumps({
                        "schema": "auditooor.hackerman_help.v1",
                        "target_count": 1,
                        "targets": [{"target": "hackerman-all"}],
                    }), "")
                if "vault-mcp-server.py" in " ".join(cmd):
                    return (0, "vault_search", "")
                return (0, "", "")

            out_path = root / "audit/wave1_snapshots/shipment_receipt/2026-05-16.json"
            with mock.patch.object(HM, "_run", side_effect=fake_run):
                rc = HM.main([
                    "--root", str(root),
                    "--out", str(out_path),
                    "--generated-at", "2026-05-16T12:00:00Z",
                ])
            self.assertEqual(rc, 0)
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], HM.SCHEMA)
            self.assertEqual(data["pr"]["head_sha"], "feedface")
            self.assertEqual(data["generated_at"], "2026-05-16T12:00:00Z")

    # 12. main() --strict: returns 1 when not ready (no baseline file).
    def test_main_strict_returns_nonzero_when_not_ready(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            # Deliberately omit baseline + vault-mcp-server + docs to force not-ready.
            def fake_run(cmd, cwd):
                if "git" in cmd[0]:
                    if cmd[1] == "rev-parse" and cmd[2] == "HEAD":
                        return (1, "", "no git")
                    return (1, "", "")
                if "make" in cmd[0]:
                    return (1, "", "no make")
                return (1, "", "")
            with mock.patch.object(HM, "_run", side_effect=fake_run):
                rc = HM.main([
                    "--root", str(root),
                    "--no-write",
                    "--strict",
                ])
            self.assertEqual(rc, 1)

    # 13. Makefile target wired.
    def test_makefile_target_wired(self):
        mk = (REPO / "Makefile").read_text(encoding="utf-8")
        self.assertIn("hackerman-wave1-shipment-receipt", mk)
        self.assertIn(
            "tools/hackerman-wave1-shipment-receipt.py",
            mk,
        )

    # 14. CLI smoke: actually run the tool against the real repo (best effort).
    def test_cli_smoke_against_real_repo(self):
        with tempfile.TemporaryDirectory() as td:
            out_path = pathlib.Path(td) / "receipt.json"
            proc = subprocess.run(
                ["python3", str(TOOL_PATH),
                 "--root", str(REPO),
                 "--out", str(out_path),
                 "--generated-at", "2026-05-16T00:00:00Z"],
                capture_output=True, text=True, timeout=180,
            )
            # The tool must not crash even if some collectors fail.
            self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], HM.SCHEMA)
            self.assertEqual(data["pr"]["number"], 726)


if __name__ == "__main__":
    unittest.main()
