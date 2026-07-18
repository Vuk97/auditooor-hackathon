from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-corpus-ingest.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_corpus_ingest", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_corpus_ingest"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class RustCorpusIngestTests(unittest.TestCase):
    def test_missing_corpus_root_emits_exact_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            payload = MOD.build_payload(ws, [])
            self.assertFalse(payload["summary"]["corpus_present"])
            self.assertEqual(payload["summary"]["item_count"], 0)
            self.assertEqual(payload["summary"]["expected_swival_rust_stdlib_total"], 151)
            self.assertEqual(payload["blockers"][0]["blocker_id"], "rust-corpus-local-checkout-missing")
            self.assertIn("Swival/security-audits", payload["blockers"][0]["required_input"])
            self.assertIn("make rust-corpus-ingest", " ".join(payload["blockers"][0]["next_commands"]))

    def test_indexes_json_markdown_and_rust_reproducer_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rustbugs"
            root.mkdir()
            (root / "bugs.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "id": "RB-001",
                                "title": "unsafe from_raw_parts length primitive",
                                "description": "unsafe parser accepts attacker length",
                                "source_path": "src/lib.rs",
                                "fixtures": ["tests/repro.rs"],
                            },
                            {
                                "id": "RB-002",
                                "title": "cfg feature trait dispatch divergence",
                                "description": "cross-crate trait impl differs under cfg(feature)",
                                "source_path": "crates/runtime/src/lib.rs",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            repro = root / "tests" / "repro.rs"
            repro.parent.mkdir()
            repro.write_text(
                "fn poc() { /* bug repro: consensus decode unsafe overflow */ }\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "# Reth consensus liveness bug\n\nRun `cargo test consensus_replay`.\n",
                encoding="utf-8",
            )
            records = MOD.load_records(root)
            by_id = {rec.item_id: rec for rec in records}
            self.assertEqual(by_id["RB-001"].route, "detector")
            self.assertTrue(by_id["RB-001"].fixture_backed)
            self.assertEqual(by_id["RB-001"].corpus_severity, "unknown")
            self.assertEqual(by_id["RB-002"].route, "invariant")
            self.assertIn("requires_cross_crate_trait_macro_cfg_resolution", by_id["RB-002"].blockers)
            self.assertTrue(any(rec.route == "replay" for rec in records))

    def test_swival_security_audits_rust_stdlib_shape_pairs_markdown_patch_and_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "security-audits"
            root = checkout / "rust-stdlib"
            finding_dir = root / "findings" / "high"
            finding_dir.mkdir(parents=True)
            md = finding_dir / "H-001-unsafe-decode.md"
            md.write_text(
                "# H-001 Unsafe decode length overflow\n\n"
                "Severity: High\n\n"
                "Component: io\n\n"
                "A `from_raw_parts` parser accepts an attacker length and can panic.\n",
                encoding="utf-8",
            )
            (finding_dir / "H-001-unsafe-decode.patch").write_text("diff --git a/src/lib.rs b/src/lib.rs\n", encoding="utf-8")
            (finding_dir / "H-001-unsafe-decode-poc.rs").write_text("fn main() { /* poc */ }\n", encoding="utf-8")
            records = MOD.load_records(checkout)
            self.assertEqual(len(records), 2)  # markdown finding plus PoC source row
            finding = next(rec for rec in records if rec.rel_path.endswith(".md"))
            self.assertEqual(finding.corpus_severity, "High")
            self.assertEqual(finding.component, "io")
            self.assertEqual(finding.route, "detector")
            self.assertTrue(finding.patch_pointers)
            self.assertTrue(finding.poc_pointers)
            self.assertTrue(finding.fixture_backed)

    def test_large_swival_rust_stdlib_shape_counts_numbered_markdown_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "security-audits" / "rust-stdlib"
            pocs = root / "pocs"
            pocs.mkdir(parents=True)
            for idx in range(1, 102):
                stem = f"{idx:03d}-unsafe-length"
                (root / f"{stem}.md").write_text(
                    "# Unsafe length\n\n## Classification\n\nMedium severity.\n\n## Proof\n\nRun the repro.\n",
                    encoding="utf-8",
                )
                (root / f"{stem}.patch").write_text("diff --git a/src/lib.rs b/src/lib.rs\n", encoding="utf-8")
                (pocs / f"{stem}.rs").write_text("fn main() { /* poc */ }\n", encoding="utf-8")
            (root / "README.md").write_text("# Swival rust stdlib\n", encoding="utf-8")

            records = MOD.load_records(root)

            self.assertEqual(len(records), 101)
            self.assertTrue(all(rec.source_kind == "md" for rec in records))
            self.assertTrue(all(rec.patch_pointers for rec in records))
            self.assertTrue(all(rec.poc_pointers for rec in records))

    def test_cli_writes_workspace_artifacts_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            root = Path(tmp) / "rustbugs"
            ws.mkdir()
            root.mkdir()
            (root / "advisories.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "RB-DECODE",
                            "title": "snappy decode bomb",
                            "source_path": "src/decoder.rs",
                            "reproducer": "cargo test decode_bomb",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--corpus-root",
                    str(root),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["item_count"], 1)
            self.assertTrue((ws / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_index.json").is_file())
            self.assertTrue((ws / ".auditooor" / "rust_corpus_mining_coverage.json").is_file())


if __name__ == "__main__":
    unittest.main()
