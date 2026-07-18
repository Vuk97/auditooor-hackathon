"""Tests for W5-M2 freshness gate in the recall path.

synthetic_fixture: true

W5-E1 added a SMOOTH recency-decay multiplier to `_rank_context_notes`. W5-M2
adds, on top of that, a DISCRETE FRESH/AGING/STALE label per note plus a HARD
demote: a STALE note sorts below every non-STALE note regardless of its
composite (keyword * recency * tier) score. STALE notes are demoted + labelled,
never dropped.

Verifies:
  1. `_freshness_label` exists and mirrors the W4.14 soft/hard band model,
     including the conservative `None age -> STALE` posture.
  2. Each note dict emitted by `_rank_context_notes` carries a `freshness`
     field.
  3. Every `ranking` explain row carries `freshness` + `is_stale`.
  4. Hard demote: a STALE note with a HIGH composite score (strong keyword
     match) still ranks below a FRESH note with a LOW composite score.
  5. Non-stale ordering is unchanged - within the non-stale bucket the W5-E1
     composite order still holds.
  6. The resume pack carries a pack-level `ranking.freshness` summary with
     fresh/aging/stale counts and a `recall_degraded` flag.
  7. A stale fixture note in a real pack is demoted AND labelled STALE.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
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

# A fixed "now" so the age math is fully deterministic across runs.
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


class TestFreshnessLabel(unittest.TestCase):

    def test_helper_exists(self):
        # synthetic_fixture: true
        self.assertTrue(hasattr(vault_mcp_server, "_freshness_label"))
        for name in ("FRESH", "AGING", "STALE",
                     "FRESHNESS_SOFT_DAYS", "FRESHNESS_HARD_DAYS"):
            self.assertTrue(hasattr(vault_mcp_server, name), name)

    def test_bands(self):
        # synthetic_fixture: true
        fl = vault_mcp_server._freshness_label
        soft = vault_mcp_server.FRESHNESS_SOFT_DAYS
        hard = vault_mcp_server.FRESHNESS_HARD_DAYS
        self.assertEqual(fl(0.0), vault_mcp_server.FRESH)
        self.assertEqual(fl(soft), vault_mcp_server.FRESH)
        self.assertEqual(fl(soft + 0.01), vault_mcp_server.AGING)
        self.assertEqual(fl(hard), vault_mcp_server.AGING)
        self.assertEqual(fl(hard + 0.01), vault_mcp_server.STALE)
        self.assertEqual(fl(200.0), vault_mcp_server.STALE)

    def test_undateable_is_stale(self):
        # synthetic_fixture: true
        # A note with no resolvable age cannot be vouched for as current.
        self.assertEqual(
            vault_mcp_server._freshness_label(None), vault_mcp_server.STALE)


class TestFreshnessTagging(unittest.TestCase):

    def test_each_note_gets_freshness_field(self):
        # synthetic_fixture: true
        fresh = _note("notes/fresh.md", title="x",
                      frontmatter={"date": "2026-05-25"})
        stale = _note("notes/stale.md", title="x",
                      frontmatter={"date": "2026-01-01"})
        ranked, _ = vault_mcp_server._rank_context_notes(
            [fresh, stale], "x", now_epoch=_FIXED_NOW)
        for note in ranked:
            self.assertIn("freshness", note)
        by_path = {n["path"]: n["freshness"] for n in ranked}
        self.assertEqual(by_path["notes/fresh.md"], vault_mcp_server.FRESH)
        self.assertEqual(by_path["notes/stale.md"], vault_mcp_server.STALE)

    def test_ranking_rows_carry_freshness(self):
        # synthetic_fixture: true
        notes = [
            _note("notes/a.md", title="x", frontmatter={"date": "2026-05-28"}),
            _note("notes/b.md", title="x", frontmatter={"date": "2026-01-01"}),
        ]
        _, ranking = vault_mcp_server._rank_context_notes(
            notes, "x", now_epoch=_FIXED_NOW)
        for row in ranking:
            self.assertIn("freshness", row)
            self.assertIn("is_stale", row)
        stale_rows = [r for r in ranking if r["freshness"] == vault_mcp_server.STALE]
        self.assertTrue(all(r["is_stale"] for r in stale_rows))


class TestHardDemote(unittest.TestCase):

    def test_stale_high_score_ranks_below_fresh_low_score(self):
        # synthetic_fixture: true
        # The stale note keyword-matches strongly (high composite); the fresh
        # note does NOT match the query at all (low composite). Under W5-E1
        # alone the stale note would win on keyword score. W5-M2's hard demote
        # must still put the FRESH note first.
        stale_strong = _note(
            "patterns/bridge-reentrancy.md",
            title="bridge reentrancy atomicity primer",
            body="cross chain bridge reentrancy atomicity bridge reentrancy",
            frontmatter={"date": "2026-01-01"})  # ~150d old -> STALE
        fresh_weak = _note(
            "notes/changelog.md",
            title="changelog",
            body="formatting tweaks",
            frontmatter={"date": "2026-05-30"})  # 2d old -> FRESH
        ranked, ranking = vault_mcp_server._rank_context_notes(
            [stale_strong, fresh_weak], "bridge reentrancy atomicity",
            now_epoch=_FIXED_NOW)
        self.assertEqual(ranked[0]["path"], "notes/changelog.md",
                         "fresh note must hard-demote the stale keyword match")
        self.assertEqual(ranked[1]["path"], "patterns/bridge-reentrancy.md")
        # Sanity: the stale note really did score higher on composite.
        by_path = {r["path"]: r for r in ranking}
        self.assertGreater(
            by_path["patterns/bridge-reentrancy.md"]["composite_score"],
            by_path["notes/changelog.md"]["composite_score"],
            "test premise: stale note has the higher raw composite")
        self.assertTrue(by_path["patterns/bridge-reentrancy.md"]["is_stale"])
        self.assertFalse(by_path["notes/changelog.md"]["is_stale"])

    def test_non_stale_bucket_keeps_e1_order(self):
        # synthetic_fixture: true
        # Two non-stale notes: the keyword match must still win (W5-E1
        # behaviour is preserved inside the non-stale bucket).
        relevant = _note("patterns/oracle.md", title="oracle manipulation",
                          body="oracle price manipulation",
                          frontmatter={"date": "2026-05-28"})
        unrelated = _note("notes/misc.md", title="misc",
                          body="unrelated text",
                          frontmatter={"date": "2026-05-28"})
        ranked, _ = vault_mcp_server._rank_context_notes(
            [unrelated, relevant], "oracle manipulation price",
            now_epoch=_FIXED_NOW)
        self.assertEqual(ranked[0]["path"], "patterns/oracle.md")


class TestPackFreshnessSummary(unittest.TestCase):

    def setUp(self):
        # synthetic_fixture: true
        self.tmp = tempfile.TemporaryDirectory(prefix="w5m2-pack-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        self.vault.mkdir(parents=True)
        # `_safe_context_frontmatter` strips raw `date` keys, so freshness is
        # driven by the file mtime (W5-M2 signal-2 fallback). INDEX_active is
        # left with a just-now mtime -> FRESH.
        (self.vault / "INDEX_active.md").write_text(
            "# active\n- item\n", encoding="utf-8")
        # NEXT_LOOP gets an mtime 200 days in the past -> well past the 30d
        # hard threshold -> STALE.
        next_loop = self.vault / "NEXT_LOOP.md"
        next_loop.write_text(
            "# NEXT_LOOP\n## S\n- item\n", encoding="utf-8")
        old = time.time() - 200 * 86400
        os.utime(next_loop, (old, old))
        goals = self.vault / "goals"
        goals.mkdir()
        (goals / "current.md").write_text(
            "---\nobjective: synth\n---\n# goal\n", encoding="utf-8")
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pack_has_freshness_summary(self):
        # synthetic_fixture: true
        result = self.query.vault_resume_context()
        self.assertIn("ranking", result)
        fresh_block = result["ranking"].get("freshness")
        self.assertIsInstance(fresh_block, dict)
        for key in ("soft_days", "hard_days", "fresh_note_count",
                    "aging_note_count", "stale_note_count", "recall_degraded"):
            self.assertIn(key, fresh_block)
        counts = (fresh_block["fresh_note_count"]
                  + fresh_block["aging_note_count"]
                  + fresh_block["stale_note_count"])
        self.assertEqual(counts, result["notes_read"])

    def test_stale_fixture_note_demoted_and_labelled(self):
        # synthetic_fixture: true
        # NEXT_LOOP.md (2024-01-01) is STALE; INDEX_active.md is FRESH.
        result = self.query.vault_resume_context()
        order = [n["path"] for n in result["notes"]]
        # (1) labelled
        by_path = {n["path"]: n.get("freshness") for n in result["notes"]}
        self.assertEqual(by_path["NEXT_LOOP.md"], vault_mcp_server.STALE)
        self.assertEqual(by_path["INDEX_active.md"], vault_mcp_server.FRESH)
        # (2) demoted - the stale note ranks below the fresh one
        self.assertGreater(
            order.index("NEXT_LOOP.md"), order.index("INDEX_active.md"),
            f"stale NEXT_LOOP must be demoted below fresh INDEX_active: {order}")
        # (3) pack-level summary reflects the degradation
        fresh_block = result["ranking"]["freshness"]
        self.assertGreaterEqual(fresh_block["stale_note_count"], 1)
        self.assertTrue(fresh_block["recall_degraded"])
        # (4) every emitted ranking row for a non-stale note sorts above
        #     every stale row (hard demote is total, not just pairwise).
        ranking = result["ranking"]["notes"]
        last_non_stale = max(
            (r["rank"] for r in ranking if not r["is_stale"]), default=-1)
        first_stale = min(
            (r["rank"] for r in ranking if r["is_stale"]), default=10**9)
        self.assertLess(last_non_stale, first_stale)

    def test_stale_note_not_dropped(self):
        # synthetic_fixture: true
        # Demote, do not drop - the stale note is still present in the pack.
        result = self.query.vault_resume_context()
        paths = [n["path"] for n in result["notes"]]
        self.assertIn("NEXT_LOOP.md", paths)


if __name__ == "__main__":
    unittest.main()
