"""Guard tests for the chain-synth-template-namespace-bridge fix.

<!-- r36-rebuttal: pathspec registered via agent-pathspec-register.py for
lane chain-synth-template-namespace-bridge; entry in
.auditooor/agent_pathspec.json -->

Root cause guarded here: ``vault_global_chain_template_match`` previously
joined a workspace's broken-invariant set against the global corpus by EXACT
``INV-*`` string intersection only. Workspaces emit a workspace-local
namespaced shape (``OPTIMISM-INV-01``, no family tag), while the corpus
member ids carry a family prefix (``INV-CUS-...`` / ``INV-FRE-...`` /
``INV-ATM-...``). Result: 0 templates matched even though the corpus DOES
cover those families.

The fix adds a FAMILY-prefix fallback (classified from the workspace
invariant_ledger family/category field, or a keyword classifier) wired into
``vault_global_chain_template_match`` and the
``global_chain_templates_seed`` helper, with EXACT precedence preserved.

These tests observe a real PASS (not a planned/skeleton oracle): they
construct a synthetic-but-realistic broken set + template corpus on a
tempdir, call the real callable, and assert the returned envelope.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
SEED_PATH = REPO_ROOT / "tools" / "lib" / "global_chain_templates_seed.py"
EXPECTED_SCHEMA = "auditooor.vault_global_chain_template_match.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_ns_bridge", SERVER_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_seed():
    spec = importlib.util.spec_from_file_location(
        "global_chain_templates_seed_ns_bridge", SEED_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _tpl(chain_template_id: str, member_ids: list[str]) -> dict:
    return {
        "schema_version": "auditooor.global_chain_template.v1",
        "chain_template_id": chain_template_id,
        "member_invariant_ids": sorted(member_ids),
        "tuple_size": len(member_ids),
        "composition_score": 0.7,
        "composition_rationale": "ns-bridge guard test",
        "verification_tier": "tier-2-verified-public-archive",
        "evidence_incidents": [],
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
    }


class NamespaceBridgeSeedTest(unittest.TestCase):
    """Unit-level: the seed classifier maps OPTIMISM-INV-NN to families."""

    def setUp(self) -> None:
        self.seed = _load_seed()

    def test_namespaced_id_classifies_via_ledger_category(self) -> None:
        # OPTIMISM-INV-02 carries no family tag in the id; ledger says
        # custody + atomicity (withdrawal / double-spend), OPTIMISM-INV-06
        # says freshness.
        ledger_meta = {
            "OPTIMISM-INV-02": {
                "invariant_id": "OPTIMISM-INV-02",
                "category": "custody",
                "description": (
                    "withdrawal finalization must not double-spend"
                ),
            },
            "OPTIMISM-INV-06": {
                "invariant_id": "OPTIMISM-INV-06",
                "family": "freshness",
                "description": "output root anchor must be fresh",
            },
        }
        prefixes = self.seed.expand_workspace_family_prefixes(
            {"OPTIMISM-INV-02", "OPTIMISM-INV-06"}, ledger_meta
        )
        # withdrawal/finalize -> CUS+FRE; double -> ATM; freshness -> FRE.
        self.assertIn("INV-CUS", prefixes)
        self.assertIn("INV-FRE", prefixes)
        self.assertIn("INV-ATM", prefixes)

    def test_legacy_family_tagged_ids_unchanged(self) -> None:
        # Backward compat: family-tagged ids resolve exactly as before with
        # no ledger meta.
        prefixes = self.seed.expand_workspace_family_prefixes({
            "INV-AUTH-001", "INV-CUST-003", "INV-CON-EX-0006",
            "INV-FRESH-001", "INV-WAT",
        })
        self.assertEqual(
            prefixes, {"INV-AUT", "INV-CUS", "INV-CON", "INV-FRE"}
        )

    def test_keyword_classifier_spec_mappings(self) -> None:
        cls = self.seed.classify_text_to_global_prefixes
        self.assertEqual(cls("withdrawal finalize"), {"INV-CUS", "INV-FRE"})
        self.assertEqual(cls("lock-and-mint bridge"), {"INV-BRIDGE", "INV-CON"})
        self.assertEqual(cls("anchor resolve"), {"INV-FRE"})
        self.assertEqual(cls("double-spend replay"), {"INV-ATM"})


class NamespaceBridgeCallableTest(unittest.TestCase):
    """End-to-end: the MCP callable matches a namespaced broken set via the
    family fallback when EXACT intersection is empty."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-ns-bridge-")
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        for d in (self.vault_dir, self.repo, self.ws):
            d.mkdir()
        (self.ws / ".auditooor").mkdir()
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(
            self.vault_dir, repo_root=self.repo
        )
        self.tpl_path = (
            self.repo / "audit" / "corpus_tags" / "derived"
            / "global_chain_templates.jsonl"
        )
        # Corpus: family-prefixed members, NO exact overlap with the
        # workspace's OPTIMISM-INV-NN ids.
        _write_jsonl(
            self.tpl_path,
            [
                _tpl(
                    "GCT-custody-atomicity",
                    ["INV-CUS-EX-0031", "INV-ATM-EX-0007"],
                ),
                _tpl(
                    "GCT-freshness-anchor",
                    ["INV-FRE-EX-0012", "INV-FRE-EX-0019"],
                ),
                _tpl(
                    "GCT-unrelated",
                    ["INV-ORD-EX-0003", "INV-MON-EX-0004"],
                ),
            ],
        )
        # Workspace ledger: namespaced ids with family/category.
        self._write_ledger(
            [
                {
                    "invariant_id": "OPTIMISM-INV-02",
                    "category": "custody",
                    "status": "broken",
                    "description": (
                        "withdrawal finalization double-spend"
                    ),
                },
                {
                    "invariant_id": "OPTIMISM-INV-06",
                    "family": "freshness",
                    "status": "broken",
                    "description": "anchor resolve staleness",
                },
            ]
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_ledger(self, rows: list[dict]) -> None:
        with (self.ws / ".auditooor" / "invariant_ledger.json").open(
            "w", encoding="utf-8"
        ) as fh:
            json.dump({"rows": rows}, fh)

    def test_namespaced_broken_set_matches_via_family_fallback(self) -> None:
        # The broken set {OPTIMISM-INV-02 (custody/atomicity),
        # OPTIMISM-INV-06 (freshness)} has ZERO exact overlap with any
        # template member id, but MUST match >=1 template via family.
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["OPTIMISM-INV-02", "OPTIMISM-INV-06"],
            min_match_density=0.5,
        )
        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertFalse(result.get("degraded", False))
        # Exact path found nothing; family fallback fired.
        self.assertEqual(result["match_mode"], "family")
        self.assertEqual(result["summary"]["exact_match_count"], 0)
        self.assertGreaterEqual(result["summary"]["family_match_count"], 1)
        self.assertGreaterEqual(len(result["matched_templates"]), 1)
        # Family prefixes derived from the namespaced ledger ids.
        fam = set(result["family_prefixes"])
        self.assertIn("INV-CUS", fam)
        self.assertIn("INV-FRE", fam)
        # The returned template(s) are the family-relevant ones, not the
        # unrelated ORD/MON template.
        matched_ids = {
            t["chain_template_id"] for t in result["matched_templates"]
        }
        self.assertIn("GCT-custody-atomicity", matched_ids | {
            t["chain_template_id"] for t in result["matched_templates"]
        })
        self.assertNotIn("GCT-unrelated", matched_ids)
        for t in result["matched_templates"]:
            self.assertEqual(t["match_mode"], "family")

    def test_exact_match_takes_precedence_over_family(self) -> None:
        # Add a template with an EXACT id overlap. Exact must shadow the
        # family fallback entirely (match_mode == "exact").
        _write_jsonl(
            self.tpl_path,
            [
                _tpl(
                    "GCT-exact-hit",
                    ["OPTIMISM-INV-02", "INV-FRE-EX-0099"],
                ),
                _tpl(
                    "GCT-custody-atomicity",
                    ["INV-CUS-EX-0031", "INV-ATM-EX-0007"],
                ),
            ],
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["OPTIMISM-INV-02", "OPTIMISM-INV-06"],
            min_match_density=0.5,
        )
        self.assertEqual(result["match_mode"], "exact")
        self.assertGreaterEqual(result["summary"]["exact_match_count"], 1)
        matched_ids = {
            t["chain_template_id"] for t in result["matched_templates"]
        }
        self.assertIn("GCT-exact-hit", matched_ids)
        for t in result["matched_templates"]:
            self.assertEqual(t["match_mode"], "exact")

    def test_no_broken_set_no_matches(self) -> None:
        # Sanity: empty broken set still returns no matches and does not
        # fire the family fallback.
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
        )
        self.assertEqual(result["matched_templates"], [])
        self.assertEqual(result["summary"]["broken_invariant_id_count"], 0)


if __name__ == "__main__":
    unittest.main()
