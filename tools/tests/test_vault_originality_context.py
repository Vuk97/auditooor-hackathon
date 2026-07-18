#!/usr/bin/env python3
"""Tests for the PR #658 P0-3 vault_originality_context callable.

Covers:
  - T1: empty workspace_path → degraded:true / reason=empty_workspace_path
  - T2: workspace with no external-audits-extracts/ → degraded:true / reason=section_missing
  - T3: keyword match returns hit with source_ref + frontmatter fields
  - T4: limit honored (cap at requested N, default 8, max 20)
  - T5: synonym expansion populates synonym_expansion.variants
  - T6: workspace tag filter — only returns notes whose workspace
        frontmatter / tag matches the requested workspace_path basename
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_for_test", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SERVER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_mcp_server_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


SERVER = _load_server_module()


def _seed_note(
    vault_root: Path,
    workspace: str,
    name: str,
    *,
    audit_id: str = "informal-systems-2024-q1",
    audit_year: str = "2024",
    finding_id: str = "M-01",
    finding_severity: str = "medium",
    body: str = "stub body",
    extra_tags: list[str] | None = None,
    modules: list[str] | None = None,
    status: str = "ACK",
) -> Path:
    section = vault_root / "external-audits-extracts" / workspace
    section.mkdir(parents=True, exist_ok=True)
    tags = [
        f"external-audit/informal-systems",
        f"workspace/{workspace}",
        f"severity/{finding_severity}",
    ]
    if extra_tags:
        tags.extend(extra_tags)
    modules = modules or []
    fm_lines = [
        "---",
        "source: external-audits-extract",
        f"workspace: {workspace}",
        f"audit_id: {audit_id}",
        f"audit_year: {audit_year}",
        f"finding_id: {finding_id}",
        f"finding_severity: {finding_severity}",
        f"modules_csv: {','.join(modules)}",
        "modules:",
        *[f"  - {m}" for m in modules],
        f"status: {status}",
        f"tags_csv: {','.join(tags)}",
        "tags:",
        *[f"  - {t}" for t in tags],
        "---",
        "",
        f"# {finding_id}: stub title",
        "",
        body,
        "",
    ]
    note_path = section / name
    note_path.write_text("\n".join(fm_lines), encoding="utf-8")
    return note_path


def _make_server(vault_dir: Path):
    """Build a VaultQuery instance bound to ``vault_dir``."""
    vault_dir.mkdir(parents=True, exist_ok=True)
    return SERVER.VaultQuery(vault_dir=vault_dir)


class VaultOriginalityContextTest(unittest.TestCase):
    """Six-test coverage of the P0-3 callable."""

    def test_t1_empty_workspace_path_is_degraded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-orig-t1-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            srv = _make_server(vault)
            res = srv.vault_originality_context(workspace_path="", keywords=["affiliate"])
            self.assertTrue(res.get("degraded"), res)
            self.assertEqual(res.get("reason"), "empty_workspace_path")
            # envelope present
            self.assertIn("context_pack_id", res)
            self.assertIn("context_pack_hash", res)
            self.assertEqual(res["schema"], SERVER.ORIGINALITY_CONTEXT_SCHEMA)

    def test_t2_workspace_with_no_extracts_returns_section_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-orig-t2-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            srv = _make_server(vault)
            res = srv.vault_originality_context(
                workspace_path="/Users/wolf/audits/some-unseeded-ws",
                keywords=["affiliate"],
            )
            self.assertTrue(res.get("degraded"), res)
            self.assertEqual(res.get("reason"), "section_missing")
            self.assertEqual(res.get("hits"), [])

    def test_t3_keyword_match_returns_hit_with_source_ref(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-orig-t3-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            _seed_note(
                vault, "dydx", "informal-2024-q1-m-01.md",
                body=(
                    "Description: when an affiliate address is blocked the "
                    "fee redirect path silently routes commission to zero, "
                    "leaving the affiliate uncollectable."
                ),
                modules=["affiliates"],
                status="ACK",
            )
            srv = _make_server(vault)
            res = srv.vault_originality_context(
                workspace_path="/Users/wolf/audits/dydx",
                keywords=["affiliate", "blocked"],
            )
            self.assertFalse(res.get("degraded"), res)
            self.assertEqual(res["workspace"], "dydx")
            hits = res["hits"]
            self.assertGreaterEqual(len(hits), 1)
            top = hits[0]
            self.assertEqual(top["audit_id"], "informal-systems-2024-q1")
            self.assertEqual(top["finding_id"], "M-01")
            self.assertEqual(top["finding_severity"], "medium")
            self.assertEqual(top["status"], "ACK")
            self.assertIn("affiliates", top["modules"])
            self.assertTrue(top["source_ref"].startswith("vault://"))
            self.assertGreater(top["score"], 0)
            # snippet contains a matched term
            self.assertTrue(
                any(t in top["snippet"].lower() for t in top["matched_terms"]),
                top,
            )

    def test_t4_limit_honored(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-orig-t4-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            for i in range(5):
                _seed_note(
                    vault, "dydx", f"informal-2024-q1-m-{i:02d}.md",
                    finding_id=f"M-{i:02d}",
                    body=f"affiliate redirect bug iteration {i}",
                )
            srv = _make_server(vault)
            res = srv.vault_originality_context(
                workspace_path="/Users/wolf/audits/dydx",
                keywords=["affiliate"],
                limit=2,
            )
            self.assertEqual(len(res["hits"]), 2, res)
            self.assertEqual(res["limit"], 2)
            # invalid limit (0) → clamped up to 1
            res_low = srv.vault_originality_context(
                workspace_path="/Users/wolf/audits/dydx",
                keywords=["affiliate"],
                limit=0,
            )
            self.assertEqual(res_low["limit"], 1)
            # huge limit → clamped to MAX
            res_high = srv.vault_originality_context(
                workspace_path="/Users/wolf/audits/dydx",
                keywords=["affiliate"],
                limit=999,
            )
            self.assertEqual(res_high["limit"], SERVER.MAX_ORIGINALITY_LIMIT)

    def test_t5_synonym_expansion_present_in_envelope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-orig-t5-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            _seed_note(
                vault, "dydx", "n.md",
                body="affiliate panic crash on blocked address",
            )
            srv = _make_server(vault)
            res = srv.vault_originality_context(
                workspace_path="/Users/wolf/audits/dydx",
                keywords=["panic"],
            )
            syn = res["synonym_expansion"]
            self.assertIn("variants", syn)
            self.assertIn("matched_canonicals", syn)
            # original keyword always present (lowercased)
            self.assertIn("panic", syn["variants"])
            self.assertIsInstance(syn["matched_canonicals"], list)

    def test_t6_workspace_tag_filter_excludes_other_workspaces(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-orig-t6-") as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            _seed_note(
                vault, "dydx", "in-scope.md",
                body="affiliate panic on dydx in-scope",
            )
            # Cross-pollution attempt: a note whose body matches but lives
            # under a DIFFERENT workspace section. The function only walks
            # external-audits-extracts/<ws>/ so it must be invisible.
            other_section = vault / "external-audits-extracts" / "spark"
            other_section.mkdir(parents=True, exist_ok=True)
            (other_section / "out-of-scope.md").write_text(
                "---\n"
                "workspace: spark\n"
                "audit_id: zcash-frost\n"
                "finding_id: M-02\n"
                "finding_severity: medium\n"
                "tags_csv: workspace/spark\n"
                "---\n\n"
                "# M-02: stub\n\n"
                "affiliate panic on spark — should NOT match dydx query\n",
                encoding="utf-8",
            )
            # Defence-in-depth attempt: a note inside dydx/ section but
            # whose frontmatter declares a different workspace. The
            # callable's tag filter must drop it.
            (vault / "external-audits-extracts" / "dydx" / "rogue.md").write_text(
                "---\n"
                "workspace: spark\n"
                "audit_id: zcash-frost\n"
                "finding_id: H-99\n"
                "finding_severity: high\n"
                "tags_csv: workspace/spark\n"
                "---\n\n"
                "# H-99: rogue\n\n"
                "affiliate panic — wrong workspace tag\n",
                encoding="utf-8",
            )
            srv = _make_server(vault)
            res = srv.vault_originality_context(
                workspace_path="/Users/wolf/audits/dydx",
                keywords=["affiliate"],
            )
            paths = [h["path"] for h in res["hits"]]
            self.assertTrue(any("in-scope.md" in p for p in paths), paths)
            # No spark-tagged note should appear.
            self.assertFalse(any("rogue.md" in p for p in paths), paths)
            self.assertFalse(any("/spark/" in p for p in paths), paths)


class ExternalAuditsExtractEmitterTest(unittest.TestCase):
    """Smoke tests for tools/external-audits-extract-emitter.py.

    Validates the end-to-end pipe: emitter → vault_originality_context.
    """

    def test_emitter_then_recall(self) -> None:
        emitter_path = REPO_ROOT / "tools" / "external-audits-extract-emitter.py"
        spec = importlib.util.spec_from_file_location(
            "external_audits_extract_emitter_for_test", emitter_path
        )
        if spec is None or spec.loader is None:
            self.skipTest("emitter not loadable")
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)

        with tempfile.TemporaryDirectory(prefix="vault-orig-emit-") as tmp:
            tmp_root = Path(tmp)
            ws_root = tmp_root / "audits"
            ws = ws_root / "demo-ws"
            (ws / "prior_audits").mkdir(parents=True)
            digest = ws / "prior_audits" / "DIGEST_demo_audit.md"
            digest.write_text(
                "# Demo audit digest\n\n"
                "Some preface text.\n\n"
                "### M-01 — Affiliate fee redirect bypass on blocked address\n\n"
                "**Severity:** Medium\n\n"
                "Description: affiliate flag check skipped, fee_redirect "
                "routes commissions silently. Status: Acknowledged.\n\n"
                "### L-01 — Trivial gas optimisation\n\n"
                "**Severity:** Low\n\n"
                "Body: drop unused storage var. Status: Fixed.\n",
                encoding="utf-8",
            )
            vault = tmp_root / "vault"
            dry = emitter.emit_for_workspace(ws, vault, force=True, dry_run=True)
            self.assertEqual(dry["sources_seen"], 1)
            self.assertGreaterEqual(dry["notes_written"], 2)
            self.assertGreaterEqual(len(dry["paths"]), 2)
            self.assertFalse(
                (vault / "external-audits-extracts" / "demo-ws").exists(),
                "dry-run must not create extract notes",
            )

            res = emitter.emit_for_workspace(ws, vault, force=True)
            self.assertEqual(res["sources_seen"], 1)
            self.assertGreaterEqual(res["notes_written"], 2)
            srv = _make_server(vault)
            recall = srv.vault_originality_context(
                workspace_path=str(ws),
                keywords=["affiliate"],
            )
            self.assertFalse(recall.get("degraded"), recall)
            self.assertGreaterEqual(len(recall["hits"]), 1)
            top = recall["hits"][0]
            self.assertEqual(top["finding_id"], "M-01")
            self.assertEqual(top["finding_severity"], "medium")

    def test_default_vault_resolution_prefers_active_shared_vault(self) -> None:
        emitter_path = REPO_ROOT / "tools" / "external-audits-extract-emitter.py"
        spec = importlib.util.spec_from_file_location(
            "external_audits_extract_emitter_vault_resolution_for_test", emitter_path
        )
        if spec is None or spec.loader is None:
            self.skipTest("emitter not loadable")
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)

        with tempfile.TemporaryDirectory(prefix="vault-orig-active-") as tmp:
            tmp_root = Path(tmp)
            local_vault = tmp_root / "repo-local-vault"
            local_vault.mkdir()
            active_vault = tmp_root / "active-vault"
            active_vault.mkdir()
            for name in ("INDEX.md", "INDEX_active.md", "NEXT_LOOP.md"):
                (active_vault / name).write_text("# active\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {"AUDITOOOR_VAULT_DIR": str(active_vault)}):
                resolved, note = emitter.resolve_vault_dir(local_vault, argv=[])

            self.assertEqual(resolved, active_vault.resolve())
            self.assertIsNotNone(note)

    def test_explicit_non_default_vault_resolution_is_preserved(self) -> None:
        emitter_path = REPO_ROOT / "tools" / "external-audits-extract-emitter.py"
        spec = importlib.util.spec_from_file_location(
            "external_audits_extract_emitter_explicit_vault_for_test", emitter_path
        )
        if spec is None or spec.loader is None:
            self.skipTest("emitter not loadable")
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)

        with tempfile.TemporaryDirectory(prefix="vault-orig-explicit-") as tmp:
            tmp_root = Path(tmp)
            explicit_vault = tmp_root / "explicit-vault"
            explicit_vault.mkdir()
            active_vault = tmp_root / "active-vault"
            active_vault.mkdir()
            for name in ("INDEX.md", "INDEX_active.md", "NEXT_LOOP.md"):
                (active_vault / name).write_text("# active\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {"AUDITOOOR_VAULT_DIR": str(active_vault)}):
                resolved, note = emitter.resolve_vault_dir(
                    explicit_vault,
                    argv=["--vault-dir", str(explicit_vault)],
                )

            self.assertEqual(resolved, explicit_vault.resolve())
            self.assertIsNone(note)


if __name__ == "__main__":
    unittest.main()
