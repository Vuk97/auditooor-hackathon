#!/usr/bin/env python3
"""Regression tests for vault_hacker_brief_for_lane."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_vault_mcp():
    path = REPO_ROOT / "tools" / "vault-mcp-server.py"
    spec = importlib.util.spec_from_file_location("vault_mcp_server_hacker_brief", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_mcp_server_hacker_brief"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class VaultHackerBriefForLaneTest(unittest.TestCase):
    def test_returns_generated_markdown_not_stdout_path(self) -> None:
        vault_mcp = _load_vault_mcp()
        with tempfile.TemporaryDirectory(prefix="vault-hacker-brief-") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            _write(ws / "SCOPE.md", "# Scope\n")
            _write(
                ws / "engage_report.md",
                "# Engagement Report\n\n"
                "- Total hits: **1**\n"
                "- Severity: HIGH=1  MEDIUM=0  LOW=0\n"
                "- Distinct detectors: **1**\n"
                "- Analogical clusters: **1**\n\n"
                "## Actionable Next Steps\n\n"
                "- Triage (HIGH severity, LOW dupe risk): **1** hits\n"
                "- Dupe-check (HIGH dupe risk): **0** hits\n"
                "- Mine for novelty (no anchor + no cross-ws match): **1** hits\n\n"
                "## Clusters\n\n"
                "### Cluster: `detector-alpha` (1 hits)\n\n"
                "- **[HIGH] `detector-alpha`** - `src/Target.sol:10`\n"
                "  - snippet: `issue in target`\n",
            )

            vault = vault_mcp.VaultQuery(REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT)
            result = vault.vault_hacker_brief_for_lane(
                workspace_path=str(ws),
                lane_id="H1-test",
                files=["src/Target.sol"],
            )

            self.assertFalse(result["degraded"], result.get("degraded_reason"))
            self.assertIn("# Hacker Mindset Injection", result["brief_markdown"])
            self.assertIn("vault_engage_report_context", result["brief_markdown"])
            self.assertIn("detector-alpha", result["brief_markdown"])
            expected_brief = ws / ".auditooor" / "hacker_brief.md"
            self.assertEqual(result["generated_brief_path"], "workspace:.auditooor/hacker_brief.md")
            self.assertEqual(result["workspace_path"], ws.name)
            self.assertEqual(result["files"], ["src/Target.sol"])
            self.assertTrue(expected_brief.is_file())
            self.assertTrue(Path(str(expected_brief) + ".json").is_file())
            payload = json.dumps(result, sort_keys=True)
            self.assertNotIn(str(ws), payload)
            self.assertNotIn("/private/var/", payload)
            self.assertNotIn("/var/folders/", payload)
            self.assertNotIn("/tmp/", payload)

    def test_omitted_files_reports_scope_default_without_absolute_paths(self) -> None:
        vault_mcp = _load_vault_mcp()
        with tempfile.TemporaryDirectory(prefix="vault-hacker-brief-default-files-") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            _write(ws / "SCOPE.md", "# Scope\n")
            _write(
                ws / "engage_report.md",
                "# Engagement Report\n\n"
                "- Total hits: **0**\n"
                "- Severity: HIGH=0  MEDIUM=0  LOW=0\n"
                "- Distinct detectors: **0**\n"
                "- Analogical clusters: **0**\n",
            )

            vault = vault_mcp.VaultQuery(REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT)
            result = vault.vault_hacker_brief_for_lane(
                workspace_path=str(ws),
                lane_id="H1-default",
            )

            self.assertFalse(result["degraded"], result.get("degraded_reason"))
            self.assertEqual(result["files"], ["SCOPE.md"])
            self.assertEqual(result["generated_brief_path"], "workspace:.auditooor/hacker_brief.md")
            payload = json.dumps(result, sort_keys=True)
            self.assertNotIn(str(ws), payload)
            self.assertNotIn("/private/var/", payload)
            self.assertNotIn("/var/folders/", payload)
            self.assertNotIn("/tmp/", payload)

    def test_mcp_brief_wrapper_passes_quality_and_cross_language_sidecars(self) -> None:
        vault_mcp = _load_vault_mcp()
        with tempfile.TemporaryDirectory(prefix="vault-hacker-brief-sidecars-") as tmp:
            root = Path(tmp)
            ws = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            derived_dir = tags_dir.parent / "derived"
            ws.mkdir()
            (ws / ".auditooor").mkdir()
            _write(ws / "protocol" / "x" / "clob" / "keeper" / "msg_server.go", "package keeper\n")
            _write(ws / "SCOPE.md", "# Scope\n")
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/go-clob-msg-server",
                "source_audit_ref": "prior:dydx:clob",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "protocol/x/clob/keeper/msg_server.go",
                "bug_class": "keeper-order-bypass",
                "attack_class": "keeper-order-bypass",
                "attacker_action_sequence": "submit a Cosmos SDK MsgPlaceOrder through the dYdX CLOB keeper",
            }
            _write(index_dir / "by_language.jsonl", json.dumps({"key": "go", "record": record}) + "\n")
            _write(
                derived_dir / "record_quality.jsonl",
                json.dumps(
                    {
                        "record_id": "dydx/go-clob-msg-server",
                        "record_tier": "dydx-filed",
                        "record_quality_score": 5.0,
                    }
                )
                + "\n",
            )
            _write(
                derived_dir / "cross_language_analogues.jsonl",
                json.dumps(
                    {
                        "source_record_id": "dydx/go-clob-msg-server",
                        "source_language": "go",
                        "target_language": "solidity",
                        "analogue_record_id": "solidity/order-bypass",
                        "attack_class": "keeper-order-bypass",
                        "confidence": 0.9,
                        "pattern_translation": "go->solidity: keeper authority check -> modifier/role gate",
                    }
                )
                + "\n",
            )

            vault = vault_mcp.VaultQuery(REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT)
            result = vault.vault_hacker_brief_for_lane(
                workspace_path=str(ws),
                lane_id="H4-dydx-cosmos-sdk-clob",
                files=["protocol/x/clob/keeper/msg_server.go"],
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
                limit=1,
            )

            self.assertFalse(result["hackerman_query"]["degraded"])
            self.assertEqual(result["hackerman_query"]["records"][0]["record_tier"], "dydx-filed")
            self.assertEqual(result["hackerman_query"]["records"][0]["record_quality_score"], 5.0)
            self.assertEqual(
                result["hackerman_query"]["records"][0]["cross_language_analogues"][0]["target_language"],
                "solidity",
            )
            self.assertIn("Quality: dydx-filed / 5.0", result["brief_markdown"])
            self.assertIn("keeper authority check", result["brief_markdown"])

    def test_mcp_brief_wrapper_reports_missing_sidecars_as_gaps(self) -> None:
        vault_mcp = _load_vault_mcp()
        with tempfile.TemporaryDirectory(prefix="vault-hacker-brief-missing-sidecars-") as tmp:
            root = Path(tmp)
            ws = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            ws.mkdir()
            (ws / ".auditooor").mkdir()
            _write(ws / "protocol" / "x" / "clob" / "keeper" / "msg_server.go", "package keeper\n")
            _write(ws / "SCOPE.md", "# Scope\n")
            _write(
                index_dir / "by_language.jsonl",
                json.dumps(
                    {
                        "key": "go",
                        "record": {
                            "record_id": "dydx/go-clob-msg-server",
                            "target_domain": "dex",
                            "target_language": "go",
                            "attack_class": "keeper-order-bypass",
                        },
                    }
                )
                + "\n",
            )

            vault = vault_mcp.VaultQuery(REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT)
            result = vault.vault_hacker_brief_for_lane(
                workspace_path=str(ws),
                lane_id="H4-dydx-cosmos-sdk-clob",
                files=["protocol/x/clob/keeper/msg_server.go"],
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
                limit=1,
            )

            self.assertFalse(result["hackerman_query"]["degraded"])
            self.assertFalse(any("record_quality.jsonl" in ref for ref in result["source_refs"]))
            self.assertFalse(any("cross_language_analogues.jsonl" in ref for ref in result["source_refs"]))
            self.assertEqual(
                {gap["label"] for gap in result["sidecar_gaps"]},
                {"record_quality", "cross_language_analogues", "proof_hardening"},
            )

    def test_brief_includes_consensus_predicate_advisory_questions(self) -> None:
        vault_mcp = _load_vault_mcp()
        with tempfile.TemporaryDirectory(prefix="vault-hacker-brief-cpd-") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            _write(ws / "SCOPE.md", "# Scope\nconsensus parser differential\n")
            _write(
                ws / "engage_report.md",
                "# Engagement Report\n\n"
                "- Total hits: **0**\n"
                "- Severity: HIGH=0  MEDIUM=0  LOW=0\n"
                "- Distinct detectors: **0**\n"
                "- Analogical clusters: **0**\n",
            )
            _write(
                ws / "crates/consensus/derive/src/attributes.rs",
                "pub fn is_deposits_only(payload: &[u8]) -> bool { payload.len() > 0 }\n",
            )
            _write(
                ws / "crates/consensus/engine/src/engine_request_processor.rs",
                "pub fn handle_payload() {}\n",
            )
            _write(
                ws / "crates/consensus/engine/src/seal/task.rs",
                "pub fn seal() {}\n",
            )
            _write(
                ws / "crates/consensus/stateful/mod.rs",
                "pub fn apply_state() {}\n",
            )

            vault = vault_mcp.VaultQuery(REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT)
            result = vault.vault_hacker_brief_for_lane(
                workspace_path=str(ws),
                lane_id="H2-cpd",
                files=[
                    "crates/consensus/derive/src/attributes.rs",
                    "crates/consensus/engine/src/engine_request_processor.rs",
                ],
            )

            self.assertFalse(result["degraded"], result.get("degraded_reason"))
            brief = result["brief_markdown"]
            self.assertIn("consensus_parser_differential", brief)
            self.assertIn(
                "Q-SEQ-consensus_parser_differential-cpd-step2-is_deposits_only_symbol_present",
                brief,
            )
            self.assertIn("attributes.rs", brief)

    def test_function_mindset_enabled_by_default_via_mcp_wrapper(self) -> None:
        """TIER A Lift 1 (Hackerman Capability Master Plan): vault_hacker_brief_for_lane
        must ship per-function attack-class mindset by default — the MCP wrapper
        invokes the augmenter without passing the flag and relies on the
        augmenter's default. Asserts the brief reports ENABLED, not the legacy
        'DISABLED (pass --inject-function-mindset to enable)' stub."""
        vault_mcp = _load_vault_mcp()
        with tempfile.TemporaryDirectory(prefix="vault-hacker-brief-fm-default-") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            _write(ws / "SCOPE.md", "# Scope\n")
            _write(
                ws / "engage_report.md",
                "# Engagement Report\n\n"
                "- Total hits: **0**\n"
                "- Severity: HIGH=0  MEDIUM=0  LOW=0\n"
                "- Distinct detectors: **0**\n"
                "- Analogical clusters: **0**\n",
            )

            vault = vault_mcp.VaultQuery(REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT)
            result = vault.vault_hacker_brief_for_lane(
                workspace_path=str(ws),
                lane_id="EXEC-A1-default-on",
                files=["SCOPE.md"],
            )

            self.assertFalse(result["degraded"], result.get("degraded_reason"))
            brief = result["brief_markdown"]
            # New default behavior: ENABLED, not the legacy disabled-stub line.
            self.assertIn("Function-mindset injection**: ENABLED", brief)
            self.assertNotIn(
                "DISABLED (pass --inject-function-mindset to enable)",
                brief,
                msg="Brief still emits legacy disabled stub — default flip regressed.",
            )
            # The section header is always present; the legacy stub text
            # ("disabled — pass `--inject-function-mindset` to enable") must be gone.
            self.assertIn("Function-Mindset Cheat Sheet", brief)
            self.assertNotIn(
                "(disabled — pass `--inject-function-mindset` to enable)",
                brief,
            )

    def test_context_pack_hash_ignores_generated_timestamps(self) -> None:
        vault_mcp = _load_vault_mcp()

        class FakeDateTime(datetime):
            values = [
                datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
                datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
            ]

            @classmethod
            def now(cls, tz=None):
                value = cls.values.pop(0)
                return value if tz is None else value.astimezone(tz)

        generated_lines = [
            "**Generated**: 2026-01-01T00:00:11+00:00",
            "**Generated**: 2026-01-01T00:00:22+00:00",
        ]

        def fake_run(cmd, *args, **kwargs):
            if cmd and cmd[0] == "git":
                return SimpleNamespace(returncode=0, stdout="abc123\n", stderr="")
            out_path = Path(cmd[cmd.index("--out") + 1])
            generated = generated_lines.pop(0)
            _write(
                out_path,
                "# Hacker Mindset Injection - lane H1-test\n\n"
                f"{generated}\n"
                "**Workspace**: <workspace>\n",
            )
            _write(Path(str(out_path) + ".json"), "{}\n")
            return SimpleNamespace(returncode=0, stdout=f"{out_path}\n", stderr="")

        with tempfile.TemporaryDirectory(prefix="vault-hacker-brief-hash-") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            _write(ws / "SCOPE.md", "# Scope\n")

            vault = vault_mcp.VaultQuery(REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT)
            with patch("datetime.datetime", FakeDateTime), patch("subprocess.run", fake_run):
                first = vault.vault_hacker_brief_for_lane(
                    workspace_path=str(ws),
                    lane_id="H1-test",
                    files=["SCOPE.md"],
                )
                second = vault.vault_hacker_brief_for_lane(
                    workspace_path=str(ws),
                    lane_id="H1-test",
                    files=["SCOPE.md"],
                )

            self.assertNotEqual(first["timestamp_utc"], second["timestamp_utc"])
            self.assertNotEqual(first["brief_markdown"], second["brief_markdown"])
            self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
            self.assertEqual(first["context_pack_id"], second["context_pack_id"])


if __name__ == "__main__":
    unittest.main()
