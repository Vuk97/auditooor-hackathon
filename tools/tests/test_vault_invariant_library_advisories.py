import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_advisory_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


class VaultInvariantLibraryAdvisoryTest(unittest.TestCase):
    def test_nested_advisory_records_are_returned_as_invariants(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="vault-advisory-") as tmp:
            root = Path(tmp)
            vault_dir = root / "obsidian-vault"
            vault_dir.mkdir()
            empty = root / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            advisory = root / "invariants_dydx_fork_divergence_advisories.jsonl"
            _write_jsonl(
                advisory,
                [
                    {
                        "verification_tier": "tier-2-verified-public-archive",
                        "content": {
                            "invariant_id": "INV-FORKDIV-cometbft-fork-lag-blocksync",
                            "attack_class": "fork-divergence-missing-upstream-fix",
                            "bug_class": "upstream-security-fix-not-backported-to-pinned-fork",
                            "invariant_text": "Forks must backport upstream verification fixes.",
                            "target_language": "go",
                        },
                    },
                    {
                        "fixture_role": "negative-control",
                        "content": {
                            "invariant_id": "INV-FORKDIV-clean-control",
                            "attack_class": "fork-divergence-missing-upstream-fix",
                        },
                    },
                ],
            )
            vault = mod.VaultQuery(vault_dir, root)
            result = vault.vault_invariant_library(
                workspace_path="/Users/wolf/audits/dydx",
                pilot_audited_path=str(empty),
                pilot_path=str(empty),
                extracted_path=str(empty),
                workspace_extracted_path=str(empty),
                include_pilot=False,
                include_extracted=False,
                advisory_invariants_path=str(advisory),
                target_lang="go",
                limit=10,
            )
            self.assertFalse(result["degraded"])
            ids = [row["invariant_id"] for row in result["invariants"]]
            self.assertEqual(ids, ["INV-FORKDIV-cometbft-fork-lag-blocksync"])
            row = result["invariants"][0]
            self.assertEqual(row["category"], "fork-divergence-missing-upstream-fix")
            self.assertEqual(row["target_lang"], "go")
            self.assertEqual(row["_source"], "advisory")
            self.assertNotIn("INV-FORKDIV-clean-control", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
