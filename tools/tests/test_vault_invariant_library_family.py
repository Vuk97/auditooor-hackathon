# <!-- r36-rebuttal: lane FIX-INVARIANT-FAMILY-LIBRARY registered via agent-pathspec-register.py -->
"""Guard: vault_invariant_library ingests invariant_family_*.jsonl templates and
supports a protocol_family filter (the corpus-driven harness-design query).

Pins:
  - family templates load + are filterable by protocol_family (substring);
  - they surface even in the DEFAULT audited_primary mode (not gated behind
    include_pilot) - the regression where a bare family query returned 0;
  - include_family=false opts out;
  - protocol_family filter excludes other families.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_family_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _row(inv_id: str, family: str, category: str = "conservation") -> dict:
    return {
        "schema_version": "auditooor.invariant_pilot.v1",
        "invariant_id": inv_id,
        "category": category,
        "protocol_family": family,
        "statement": f"{inv_id} statement for {family}",
        "target_lang": "solidity",
        "abstraction_level": "protocol-invariant",
        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
    }


class VaultInvariantLibraryFamilyTest(unittest.TestCase):
    def _setup(self, tmp: Path):
        # audited subset is NON-EMPTY so quality_mode=audited_primary does NOT
        # auto-enable include_pilot - this is the exact condition under which the
        # family rows must STILL surface.
        vault_dir = tmp / "obsidian-vault"; vault_dir.mkdir()
        audited = tmp / "audited.jsonl"
        audited.write_text(json.dumps(_row("INV-AUDITED-1", "misc")) + "\n", encoding="utf-8")
        empty = tmp / "empty.jsonl"; empty.write_text("", encoding="utf-8")
        fam_dir = tmp / "fam"; fam_dir.mkdir()
        (fam_dir / "invariant_family_amm_x.jsonl").write_text(
            "\n".join(json.dumps(_row(f"INV-AMM-X-{i}", "amm-constant-product")) for i in range(1, 4)),
            encoding="utf-8")
        (fam_dir / "invariant_family_bridge_y.jsonl").write_text(
            json.dumps(_row("INV-BRG-Y-1", "bridge-lock-mint")) + "\n", encoding="utf-8")
        return vault_dir, audited, empty, fam_dir

    def _call(self, mod, vault_dir, tmp, audited, empty, fam_dir, **extra):
        return mod.VaultQuery(vault_dir, tmp).vault_invariant_library(
            pilot_audited_path=str(audited), pilot_path=str(empty),
            extracted_path=str(empty), workspace_extracted_path=str(empty),
            family_dir=str(fam_dir), limit=50, **extra)

    def test_family_filtered_query_surfaces_templates_in_audited_primary(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="fam-") as t:
            tmp = Path(t); vault_dir, audited, empty, fam_dir = self._setup(tmp)
            res = self._call(mod, vault_dir, tmp, audited, empty, fam_dir,
                             protocol_family="amm")
            ids = sorted(r["invariant_id"] for r in res["invariants"])
            self.assertEqual(ids, ["INV-AMM-X-1", "INV-AMM-X-2", "INV-AMM-X-3"],
                             "amm family templates must surface under a family-filtered query")
            self.assertTrue(all(r["_source"] == "family" for r in res["invariants"]))

    def test_protocol_family_filter_excludes_other_families(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="fam-") as t:
            tmp = Path(t); vault_dir, audited, empty, fam_dir = self._setup(tmp)
            res = self._call(mod, vault_dir, tmp, audited, empty, fam_dir,
                             protocol_family="bridge")
            ids = [r["invariant_id"] for r in res["invariants"]]
            self.assertEqual(ids, ["INV-BRG-Y-1"])

    def test_include_family_false_opts_out(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="fam-") as t:
            tmp = Path(t); vault_dir, audited, empty, fam_dir = self._setup(tmp)
            res = self._call(mod, vault_dir, tmp, audited, empty, fam_dir,
                             protocol_family="amm", include_family=False)
            self.assertEqual(res.get("invariants", []), [],
                             "include_family=false must not load family templates")


if __name__ == "__main__":
    unittest.main(verbosity=2)
