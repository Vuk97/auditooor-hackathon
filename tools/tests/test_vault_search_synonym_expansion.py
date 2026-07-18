"""Tests for vault_search_synonyms loader + query expansion (lane SP-A).

Plan 09 §5: vault_search must expand the user query across the canonical→
synonym map at reference/vault_search_synonyms.yaml so notes that mention
only synonyms still fire when the query uses the canonical phrase.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_server_module():
    """Load tools/vault-mcp-server.py as importable module ``vmcp_synonym_test``.

    The hyphen in the filename + the @dataclass requirement that the module
    be registered in sys.modules forces this dance.
    """
    name = "vmcp_synonym_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SERVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


VMCP = _load_server_module()


class LoaderTests(unittest.TestCase):
    def test_loader_reads_yaml_returns_nonempty_map(self) -> None:
        """Loader returns ≥10 canonical entries from the real YAML."""
        synonyms = VMCP._load_search_synonyms()
        self.assertIsInstance(synonyms, dict)
        self.assertGreaterEqual(
            len(synonyms),
            10,
            f"expected ≥10 canonical entries, got {len(synonyms)}",
        )
        # spot-check that values are list[str]
        for canonical, synlist in list(synonyms.items())[:5]:
            self.assertIsInstance(canonical, str)
            self.assertIsInstance(synlist, list)
            for s in synlist:
                self.assertIsInstance(s, str)

    def test_loader_caches_on_mtime(self) -> None:
        """Second call against unchanged file does not re-read from disk."""
        # Reset cache to known state
        VMCP._SYNONYM_CACHE["path"] = None
        VMCP._SYNONYM_CACHE["mtime"] = None
        VMCP._SYNONYM_CACHE["map"] = None

        first = VMCP._load_search_synonyms()
        second = VMCP._load_search_synonyms()
        # Both calls should return the SAME object (cache hit), not just
        # equal dicts.
        self.assertIs(first, second, "cache should return same dict instance on hit")

    def test_loader_handles_missing_file(self) -> None:
        """Loader returns {} (does not raise) when YAML file is missing."""
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "does-not-exist.yaml"
            result = VMCP._load_search_synonyms(missing)
            self.assertEqual(result, {})


class ExpansionTests(unittest.TestCase):
    def test_expand_with_canonical_substring_returns_variants(self) -> None:
        """Query containing a canonical phrase returns ≥2 variants."""
        # "think like a hacker" is row 1 of the YAML with 5 synonyms.
        variants = VMCP._expand_query_with_synonyms(
            "how do I think like a hacker on this drop?"
        )
        self.assertGreaterEqual(
            len(variants),
            2,
            f"expected ≥2 variants, got {variants!r}",
        )
        # Original query MUST be first.
        self.assertEqual(variants[0], "how do I think like a hacker on this drop?")
        # At least one variant should differ from the original.
        self.assertTrue(any(v != variants[0] for v in variants[1:]))

    def test_expand_caps_at_8_variants(self) -> None:
        """A query that matches many synonym substitutions is capped."""
        # Use a synthetic synonym map with one canonical and 20 synonyms
        # so we can deterministically force the cap.
        fake = {"foo bar": [f"syn{i}" for i in range(20)]}
        variants = VMCP._expand_query_with_synonyms(
            "this is a foo bar query",
            synonyms=fake,
        )
        self.assertLessEqual(
            len(variants),
            VMCP.MAX_SYNONYM_QUERY_VARIANTS,
            f"expected ≤{VMCP.MAX_SYNONYM_QUERY_VARIANTS} variants, got {len(variants)}",
        )
        self.assertEqual(
            len(variants),
            VMCP.MAX_SYNONYM_QUERY_VARIANTS,
            "with 20 synonyms available the cap should be hit exactly",
        )

    def test_expand_no_match_returns_only_original(self) -> None:
        """Query with no canonical substring returns just [query]."""
        # Use a synthetic map so we don't accidentally hit a real canonical.
        fake = {"think like a hacker": ["adversarial"]}
        variants = VMCP._expand_query_with_synonyms(
            "totally unrelated random words zzz",
            synonyms=fake,
        )
        self.assertEqual(variants, ["totally unrelated random words zzz"])

    def test_expand_empty_query_returns_empty(self) -> None:
        """Empty query short-circuits without crashing."""
        self.assertEqual(VMCP._expand_query_with_synonyms(""), [""])
        self.assertEqual(VMCP._expand_query_with_synonyms("   "), ["   "])


class VaultSearchEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        # Build a minimal vault dir with one note that mentions the synonym
        # but not the canonical phrase. The query will use the canonical
        # phrase; expansion must let us still fire.
        self._tmp = tempfile.TemporaryDirectory()
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir()
        (self.vault / "playbooks").mkdir()
        # Note body uses the synonym "adversarial" — NOT "think like a hacker".
        note_text = textwrap.dedent(
            """\
            ---
            title: Adversarial Counter-Brief Pattern
            ---

            # Adversarial Counter-Brief Pattern

            This note covers the adversarial copilot loop. The adversarial
            counter-brief is the canonical mechanism for kill-the-FPs work.
            """
        )
        (self.vault / "playbooks" / "adversarial.md").write_text(
            note_text, encoding="utf-8"
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_vault_search_envelope_includes_synonym_expansion(self) -> None:
        """Envelope exposes synonym_expansion with non-empty expanded_variants
        and the synonym-only note fires via expansion (canonical-phrase query)."""
        query = "think like a hacker"
        vq = VMCP.VaultQuery(self.vault, repo_root=REPO_ROOT)
        result = vq.vault_search(query=query, limit=10)

        # Envelope shape
        self.assertIn("synonym_expansion", result)
        envelope = result["synonym_expansion"]
        self.assertEqual(envelope["original"], query)
        self.assertIn("expanded_variants", envelope)
        self.assertGreaterEqual(
            len(envelope["expanded_variants"]),
            2,
            f"expected ≥2 variants for canonical-phrase query, got {envelope['expanded_variants']!r}",
        )
        self.assertIn("hits_per_variant", envelope)

        # The note in the synthetic vault uses the synonym "adversarial"
        # (NOT the canonical phrase), so we should ONLY get hits because
        # the canonical phrase was expanded into "adversarial". This proves
        # expansion is wired into vault_search.
        self.assertGreaterEqual(
            len(result["hits"]),
            1,
            "expected synonym-only note to fire via canonical-phrase query expansion",
        )
        hit_paths = [h["path"] for h in result["hits"]]
        self.assertTrue(
            any("adversarial" in p for p in hit_paths),
            f"expected adversarial note in hits, got {hit_paths!r}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
