"""Tests for W5-E1 relevance-ranked context packs.

synthetic_fixture: true

Verifies the relevance scorer inside `_context_pack` / `_rank_context_notes`:
  1. Helper functions exist and are deterministic.
  2. Recency decay: a fresh note outranks a stale same-relevance note.
  3. Keyword match: a workspace-relevant note outranks an unrelated note.
  4. Tier weighting: a live note outranks an `other`-tier note at equal
     keyword/recency.
  5. Degraded path: empty query + no dates preserves static input order
     (backward-compat floor).
  6. The resume pack carries an auditable `ranking` block.
  7. Determinism: same inputs -> same ordering and same composite scores.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()

# A fixed "now" so recency math is fully deterministic across runs.
# 2026-06-01T00:00:00Z as a POSIX timestamp.
_FIXED_NOW = 1780272000.0


def _note(path, title="", body="", status_class="live", frontmatter=None):
    # synthetic_fixture: true
    return {
        "path": path,
        "title": title,
        "category": path.split("/", 1)[0] if "/" in path else path,
        "status": "",
        "status_class": status_class,
        "frontmatter": frontmatter or {},
        "body": body,
    }


class TestRankingHelpers(unittest.TestCase):

    def test_helpers_exist(self):
        # synthetic_fixture: true
        for name in ("_rank_context_notes", "_derive_rank_query",
                     "_recency_multiplier", "_note_age_days"):
            self.assertTrue(hasattr(vault_mcp_server, name), name)

    def test_recency_multiplier_decays(self):
        # synthetic_fixture: true
        rm = vault_mcp_server._recency_multiplier
        self.assertEqual(rm(None), 1.0)
        self.assertEqual(rm(0.0), 1.0)
        # At one half-life the multiplier is ~0.5; older decays further.
        half = vault_mcp_server.RANK_RECENCY_HALF_LIFE_DAYS
        self.assertAlmostEqual(rm(half), 0.5, places=4)
        self.assertLess(rm(half * 2), rm(half))
        self.assertGreater(rm(1.0), rm(half))

    def test_recency_ordering_fresh_beats_stale(self):
        # synthetic_fixture: true
        # Two same-relevance notes; one fresh, one 90 days old.
        fresh = _note("notes/fresh.md", title="alpha",
                      frontmatter={"date": "2026-05-25"})
        stale = _note("notes/stale.md", title="alpha",
                      frontmatter={"date": "2026-03-01"})
        ranked, ranking = vault_mcp_server._rank_context_notes(
            [stale, fresh], "alpha", now_epoch=_FIXED_NOW)
        self.assertEqual(ranked[0]["path"], "notes/fresh.md")
        self.assertEqual(ranking[0]["rank"], 0)
        # Stale note carries a larger (older) age and smaller recency.
        ages = {r["path"]: r["age_days"] for r in ranking}
        self.assertGreater(ages["notes/stale.md"], ages["notes/fresh.md"])

    def test_keyword_match_beats_unrelated(self):
        # synthetic_fixture: true
        relevant = _note("patterns/bridge-reentrancy.md",
                         title="bridge reentrancy primer",
                         body="cross chain bridge atomicity")
        unrelated = _note("notes/misc.md", title="changelog",
                          body="formatting tweaks")
        ranked, _ = vault_mcp_server._rank_context_notes(
            [unrelated, relevant], "bridge reentrancy atomicity",
            now_epoch=_FIXED_NOW)
        self.assertEqual(ranked[0]["path"], "patterns/bridge-reentrancy.md")

    def test_tier_weight_breaks_ties(self):
        # synthetic_fixture: true
        # Equal keyword score (none) and no dates -> tier decides.
        live = _note("notes/live.md", title="x", status_class="live")
        other = _note("notes/other.md", title="x", status_class="other")
        ranked, _ = vault_mcp_server._rank_context_notes(
            [other, live], "", now_epoch=_FIXED_NOW)
        self.assertEqual(ranked[0]["path"], "notes/live.md")

    def test_degraded_path_preserves_input_order(self):
        # synthetic_fixture: true
        # No query terms, no dates, identical tier -> stable static order.
        a = _note("notes/a.md", title="a", status_class="live")
        b = _note("notes/b.md", title="b", status_class="live")
        c = _note("notes/c.md", title="c", status_class="live")
        ranked, _ = vault_mcp_server._rank_context_notes(
            [a, b, c], "", now_epoch=_FIXED_NOW)
        self.assertEqual([n["path"] for n in ranked],
                         ["notes/a.md", "notes/b.md", "notes/c.md"])

    def test_empty_notes_returns_empty(self):
        # synthetic_fixture: true
        ranked, ranking = vault_mcp_server._rank_context_notes(
            [], "anything", now_epoch=_FIXED_NOW)
        self.assertEqual(ranked, [])
        self.assertEqual(ranking, [])

    def test_determinism(self):
        # synthetic_fixture: true
        notes = [
            _note("notes/one.md", title="alpha bridge",
                  frontmatter={"date": "2026-04-01"}),
            _note("notes/two.md", title="alpha", status_class="other",
                  frontmatter={"date": "2026-05-20"}),
        ]
        r1, k1 = vault_mcp_server._rank_context_notes(
            list(notes), "alpha bridge", now_epoch=_FIXED_NOW)
        r2, k2 = vault_mcp_server._rank_context_notes(
            list(notes), "alpha bridge", now_epoch=_FIXED_NOW)
        self.assertEqual([n["path"] for n in r1], [n["path"] for n in r2])
        self.assertEqual(k1, k2)


class TestRankQueryDerivation(unittest.TestCase):

    def test_explicit_query_only(self):
        # synthetic_fixture: true
        q = vault_mcp_server._derive_rank_query(None, "reentrancy bridge")
        self.assertIn("reentrancy", q)
        self.assertIn("bridge", q)

    def test_workspace_class_and_intake(self):
        # synthetic_fixture: true
        with tempfile.TemporaryDirectory(prefix="w5e1-ws-") as tmp:
            ws = Path(tmp) / "morpho-audit"
            ws.mkdir()
            (ws / "INTAKE_BASELINE.md").write_text(
                "# Intake\n\nAttack class coverage: oracle manipulation, "
                "liquidation rounding.\n", encoding="utf-8")
            q = vault_mcp_server._derive_rank_query(ws, "")
            # _derive_workspace_class maps 'morpho' -> 'lending'.
            self.assertIn("lending", q)
            # INTAKE attack-class line tokens are pulled in.
            self.assertIn("oracle", q)

    def test_empty_when_nothing_derivable(self):
        # synthetic_fixture: true
        q = vault_mcp_server._derive_rank_query(None, "")
        self.assertEqual(q, "")


class TestRankingBlockInPack(unittest.TestCase):

    def setUp(self):
        # synthetic_fixture: true
        self.tmp = tempfile.TemporaryDirectory(prefix="w5e1-pack-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        self.vault.mkdir(parents=True)
        (self.vault / "INDEX_active.md").write_text(
            "---\ndate: 2026-05-28\n---\n# active\n- item\n", encoding="utf-8")
        (self.vault / "NEXT_LOOP.md").write_text(
            "---\ndate: 2026-01-01\n---\n# NEXT_LOOP\n## S\n- item\n",
            encoding="utf-8")
        goals = self.vault / "goals"
        goals.mkdir()
        (goals / "current.md").write_text(
            "---\nobjective: synth\ndate: 2026-05-30\n---\n# goal\n",
            encoding="utf-8")
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pack_has_ranking_block(self):
        # synthetic_fixture: true
        result = self.query.vault_resume_context()
        self.assertIn("ranking", result)
        ranking = result["ranking"]
        self.assertIn("model", ranking)
        self.assertIn("notes", ranking)
        self.assertEqual(len(ranking["notes"]), result["notes_read"])

    def test_pack_ranking_demotes_stale_note(self):
        # synthetic_fixture: true
        # NEXT_LOOP.md is dated 2026-01-01 (stale) vs INDEX_active 2026-05-28.
        # With no keyword query, recency must demote NEXT_LOOP below the
        # fresher notes.
        result = self.query.vault_resume_context()
        order = [n["path"] for n in result["notes"]]
        self.assertGreater(
            order.index("NEXT_LOOP.md"), order.index("INDEX_active.md"),
            f"stale NEXT_LOOP should rank below fresh INDEX_active: {order}")

    def test_pack_still_returns_notes_backward_compat(self):
        # synthetic_fixture: true
        result = self.query.vault_resume_context()
        self.assertGreaterEqual(len(result["notes"]), 1)
        self.assertEqual(result["kind"], "resume")


if __name__ == "__main__":
    unittest.main()
