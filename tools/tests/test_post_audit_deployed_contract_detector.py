"""
Tests for tools/post-audit-deployed-contract-detector.py (CAP-MORPHO-C)

Cases covered:
  1. pin_resolvable=True, contract in src/ -> IN-SCOPE-AT-PIN
  2. pin_resolvable=True, contract NOT in src/ (post-audit deployed) -> POST-AUDIT-DEPLOYED
  3. pin_resolvable=False -> PIN-UNRESOLVABLE
  4. no local repo -> NO-LOCAL-REPO
  5. parse_scope_md extracts all pinned contracts from SCOPE.md table rows
  6. ERC20WrapperAdapter not in src/ at bundler3 pin -> POST-AUDIT-DEPLOYED (morpho dogfood)
  7. contract name with bold markdown (**Name**) parsed correctly
  8. main() writes JSON sidecar on success
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Load module with hyphenated filename
# ---------------------------------------------------------------------------

_TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "post-audit-deployed-contract-detector.py"
_spec = importlib.util.spec_from_file_location("post_audit_deployed_contract_detector", _TOOL_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

VERDICT_IN_SCOPE = _mod.VERDICT_IN_SCOPE
VERDICT_NO_LOCAL_REPO = _mod.VERDICT_NO_LOCAL_REPO
VERDICT_PIN_UNRESOLVABLE = _mod.VERDICT_PIN_UNRESOLVABLE
VERDICT_POST_AUDIT = _mod.VERDICT_POST_AUDIT
_contract_name_to_filename = _mod._contract_name_to_filename
_repo_name_from_url = _mod._repo_name_from_url
check_contract = _mod.check_contract
main = _mod.main
parse_scope_md = _mod.parse_scope_md


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_scope_md(path: Path, rows: list[str]) -> None:
    lines = [
        "# Scope",
        "",
        "## Contracts",
        "",
        "| Contract | Address | Repo | Pinned commit |",
        "|---|---|---|---|",
    ]
    lines.extend(rows)
    path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Unit tests — parse_scope_md
# ---------------------------------------------------------------------------


class TestParseScopeMd(unittest.TestCase):
    def test_parses_basic_row(self):
        with tempfile.TemporaryDirectory() as td:
            scope = Path(td) / "SCOPE.md"
            _write_scope_md(
                scope,
                [
                    "| VaultV2Factory | 0xA1D9 | github.com/morpho-org/vault-v2 | `2f0c4a3885160371369362f624d2a6e9c94c399a` |",
                ],
            )
            contracts = parse_scope_md(scope)
        self.assertEqual(len(contracts), 1)
        c = contracts[0]
        self.assertEqual(c["name"], "VaultV2Factory")
        self.assertEqual(c["pin"], "2f0c4a3885160371369362f624d2a6e9c94c399a")
        self.assertEqual(c["repo_name"], "vault-v2")

    def test_parses_bold_markdown_name(self):
        with tempfile.TemporaryDirectory() as td:
            scope = Path(td) / "SCOPE.md"
            _write_scope_md(
                scope,
                [
                    "| **Morpho Blue** ★ | 0xBBBB | github.com/morpho-org/morpho-blue | `55d2d99304fb3fb930c688462ae2ccabb1d533ad` |",
                ],
            )
            contracts = parse_scope_md(scope)
        self.assertEqual(contracts[0]["name"], "Morpho Blue")

    def test_parses_morpho_scope_md(self):
        scope = Path("/Users/wolf/audits/morpho/SCOPE.md")
        if not scope.exists():
            self.skipTest("Morpho workspace not available")
        contracts = parse_scope_md(scope)
        names = [c["name"] for c in contracts]
        self.assertIn("Morpho Registry", names)
        self.assertIn("ERC20WrapperAdapter", names)


# ---------------------------------------------------------------------------
# Unit tests — check_contract (mocked git)
# ---------------------------------------------------------------------------


class TestCheckContractMocked(unittest.TestCase):
    def _make_contract(
        self,
        name="FooAdapter",
        pin="abc123def456abc123def456abc123def456abc1",
        repo_name="foo-repo",
    ) -> dict:
        return {
            "name": name,
            "address": "0x1234",
            "repo": f"github.com/org/{repo_name}",
            "pin": pin,
            "repo_name": repo_name,
        }

    def test_no_local_repo(self):
        c = self._make_contract(repo_name="does-not-exist")
        with tempfile.TemporaryDirectory() as td:
            result = check_contract(c, Path(td))
        self.assertEqual(result["verdict"], VERDICT_NO_LOCAL_REPO)

    def test_pin_unresolvable(self):
        """Pin does not resolve -> PIN-UNRESOLVABLE."""
        c = self._make_contract(repo_name="myrepo")
        with tempfile.TemporaryDirectory() as td:
            repo_dir = Path(td) / "myrepo"
            repo_dir.mkdir()
            # No git repo, so cat-file will fail
            result = check_contract(c, Path(td))
        self.assertEqual(result["verdict"], VERDICT_PIN_UNRESOLVABLE)
        self.assertFalse(result["pin_resolvable"])

    def test_contract_in_src_at_pin(self):
        """Contract file found in src/ at pin -> IN-SCOPE-AT-PIN."""
        c = self._make_contract(name="FooAdapter", repo_name="myrepo")
        with (
            patch.object(_mod, "pin_resolvable", return_value=True),
            patch.object(
                _mod,
                "files_at_pin",
                return_value=["src/FooAdapter.sol", "test/FooAdapterTest.sol"],
            ),
            tempfile.TemporaryDirectory() as td,
        ):
            repo_dir = Path(td) / "myrepo"
            repo_dir.mkdir()
            result = check_contract(c, Path(td))
        self.assertEqual(result["verdict"], VERDICT_IN_SCOPE)
        self.assertEqual(result["matched_path"], "src/FooAdapter.sol")
        self.assertTrue(result["contract_at_pin"])

    def test_contract_not_in_src_at_pin(self):
        """Contract absent from src/ at pin -> POST-AUDIT-DEPLOYED."""
        c = self._make_contract(name="ERC20WrapperAdapter", repo_name="bundler3")
        with (
            patch.object(_mod, "pin_resolvable", return_value=True),
            patch.object(
                _mod,
                "files_at_pin",
                return_value=[
                    "src/adapters/CoreAdapter.sol",
                    "src/adapters/GeneralAdapter1.sol",
                    "test/ERC20WrapperAdapterLocalTest.sol",  # test-only
                ],
            ),
            tempfile.TemporaryDirectory() as td,
        ):
            repo_dir = Path(td) / "bundler3"
            repo_dir.mkdir()
            result = check_contract(c, Path(td))
        self.assertEqual(result["verdict"], VERDICT_POST_AUDIT)
        self.assertFalse(result["contract_at_pin"])
        self.assertIsNone(result["matched_path"])


# ---------------------------------------------------------------------------
# Unit tests — helper functions
# ---------------------------------------------------------------------------


class TestHelpers(unittest.TestCase):
    def test_contract_name_to_filename(self):
        self.assertEqual(_contract_name_to_filename("VaultV2Factory"), "VaultV2Factory.sol")
        self.assertEqual(
            _contract_name_to_filename("ERC20WrapperAdapter"), "ERC20WrapperAdapter.sol"
        )
        self.assertEqual(_contract_name_to_filename("Morpho Blue★"), "MorphoBlue.sol")

    def test_repo_name_from_url(self):
        self.assertEqual(
            _repo_name_from_url("github.com/morpho-org/vault-v2"), "vault-v2"
        )
        self.assertEqual(
            _repo_name_from_url("github.com/morpho-org/vault-v2-adapter-registries"),
            "vault-v2-adapter-registries",
        )


# ---------------------------------------------------------------------------
# Integration tests — main() writes JSON sidecar
# ---------------------------------------------------------------------------


class TestMainIntegration(unittest.TestCase):
    def test_writes_json_sidecar_on_no_local_repos(self):
        """main() should exit 0 (NO-LOCAL-REPO is not failing) and write sidecar."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            scope = ws / "SCOPE.md"
            # Single contract row - no local repo, verdict NO-LOCAL-REPO
            _write_scope_md(
                scope,
                [
                    "| FooAdapter | 0x1234 | github.com/org/foo-repo | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |",
                ],
            )
            src_dir = ws / "src"
            src_dir.mkdir()
            # No repo dir -> NO-LOCAL-REPO, not a hard error
            rc = main(["--workspace", str(ws), "--quiet"])
            sidecar = ws / ".auditooor" / "scope_pin_audit.json"
            self.assertTrue(sidecar.exists(), "Sidecar should be written")
            data = json.loads(sidecar.read_text())
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["no_local_repo"], 1)
            # NO-LOCAL-REPO is not in the failing categories -> exit 0
            self.assertEqual(rc, 0)


# ---------------------------------------------------------------------------
# Dogfood test — Morpho workspace (skipped if not available)
# ---------------------------------------------------------------------------


class TestMorphoDogfood(unittest.TestCase):
    MORPHO_WS = Path("/Users/wolf/audits/morpho")

    def setUp(self):
        if not self.MORPHO_WS.exists():
            self.skipTest("Morpho workspace not available")
        scope = self.MORPHO_WS / "SCOPE.md"
        if not scope.exists():
            self.skipTest("SCOPE.md not found in morpho workspace")

    def test_erc20_wrapper_adapter_post_audit(self):
        """ERC20WrapperAdapter should be flagged as POST-AUDIT-DEPLOYED."""
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "audit.json"
            rc = main(
                [
                    "--workspace",
                    str(self.MORPHO_WS),
                    "--output",
                    str(output),
                    "--quiet",
                ]
            )
            data = json.loads(output.read_text())
            post_audit_names = data["post_audit_names"]
            self.assertIn(
                "ERC20WrapperAdapter",
                post_audit_names,
                f"ERC20WrapperAdapter should be POST-AUDIT-DEPLOYED, got: {data['contracts']}",
            )
            # There are post-audit contracts so exit code should be 1
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
