"""Tests for `tools/ccia.py --emit-callgraph` (Kimi 20/10 Step 3a).

Covers:
  * Schema shape + version + required keys.
  * Single-contract fixture (cross-function reentrancy `Bank`): node IDs +
    storage list emitted, no cross-contract edges.
  * Two-contract fixture: cross-contract edges resolved to known dst
    nodes; `kind` classification for external + library calls.
  * `shared_storage_keys` overlap on a known shared mapping.
  * `shared_storage_keys` empty on name-collision-only contracts (the
    A-RACE drop signal Kimi expects in PR-B).
  * Inheritance: child inherits parent's storage in the overlay.
  * Idempotent overwrite.
  * `contract_storage` populated for every parsed contract.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "ccia.py"
FIXTURES = REPO / "detectors" / "test_fixtures"


def _run(workspace: Path) -> subprocess.CompletedProcess:
    """Run ccia.py --emit-callgraph and return the completed proc."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(workspace), "--emit-callgraph"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _load(workspace: Path) -> dict:
    return json.loads((workspace / "ccia" / "callgraph.json").read_text())


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


class CciaCallgraphSchemaTest(unittest.TestCase):
    """Schema invariants that must hold for every workspace."""

    def test_schema_shape_and_required_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws / "src" / "Tiny.sol",
                """
                pragma solidity ^0.8.20;
                contract Tiny {
                    uint256 public x;
                    function bump() external { x += 1; }
                }
                """,
            )
            proc = _run(ws)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            data = _load(ws)
            for key in ("schema_version", "nodes", "edges",
                        "contract_storage", "stats", "workspace", "source_root"):
                self.assertIn(key, data, f"missing top-level key '{key}'")
            self.assertEqual(data["schema_version"], 1)
            self.assertIsInstance(data["nodes"], list)
            self.assertIsInstance(data["edges"], list)
            self.assertIsInstance(data["contract_storage"], dict)
            for node in data["nodes"]:
                for k in ("id", "contract", "function", "visibility",
                          "is_constructor", "is_modifier", "file", "line"):
                    self.assertIn(k, node, f"node missing '{k}': {node}")

    def test_json_report_includes_advisory_callgraph_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws / "src" / "System.sol",
                """
                pragma solidity ^0.8.20;
                contract Target {
                    uint256 public shared;
                    function update() external { shared += 1; }
                }
                contract Caller {
                    uint256 public shared;
                    function poke(Target target) external {
                        shared += 1;
                        target.update();
                    }
                }
                """,
            )
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(ws), "--json"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout[proc.stdout.index("{"):])
            summary = payload["callgraph_summary"]
            self.assertEqual(summary["coverage_claim"], "none_regex_source_shape_only")
            self.assertIn("stats", summary)
            self.assertIn("edge_worklist", summary)

    def test_idempotent_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws / "src" / "Tiny.sol",
                """
                pragma solidity ^0.8.20;
                contract Tiny { uint256 public x; }
                """,
            )
            self.assertEqual(_run(ws).returncode, 0)
            first = (ws / "ccia" / "callgraph.json").read_text()
            self.assertEqual(_run(ws).returncode, 0)
            second = (ws / "ccia" / "callgraph.json").read_text()
            self.assertEqual(first, second)


class CciaCallgraphCrossFnReentrancyFixtureTest(unittest.TestCase):
    """The cross-function-reentrancy fixture is the canonical 'should
    NOT show a cross-contract edge' regression — Bank only calls itself.
    Used downstream by PR-B's composer test."""

    def test_bank_single_contract_no_cross_edges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            shutil.copy(
                FIXTURES / "cross_function_reentrancy_vulnerable.sol",
                ws / "src" / "Bank.sol",
            )
            self.assertEqual(_run(ws).returncode, 0)
            data = _load(ws)
            self.assertEqual(data["stats"]["contracts"], 1)
            self.assertIn("Bank", data["contract_storage"])
            self.assertIn("balances", data["contract_storage"]["Bank"])
            # Bank's only external call is `msg.sender.call{value:..}(...)`
            # to an unknown target — must not resolve as a cross-contract edge.
            cross_edges = [e for e in data["edges"]
                           if e["src"].split(".")[0] != e["dst"].split(".")[0]]
            self.assertEqual(cross_edges, [])
            # Node ids include the canonical `Bank.withdraw()` form.
            ids = {n["id"] for n in data["nodes"]}
            self.assertIn("Bank.withdraw()", ids)
            self.assertIn("Bank.deposit()", ids)


class CciaCallgraphTwoContractTest(unittest.TestCase):
    """Two-contract fixture exercising the cross-contract edge + storage
    overlap paths."""

    @staticmethod
    def _two_contracts(ws: Path) -> None:
        # Layout chosen so the regex parser resolves the cross-contract
        # call: `Vault.deposit(...)` is a contract-name-prefixed call,
        # which `find_external_calls` lifts directly. Typed-local-var
        # calls like `vault.deposit()` are a known regex-parser
        # limitation (documented in the module docstring) and are
        # resolved by a future Slither-IR upgrade — out of scope here.
        _write(
            ws / "src" / "Vault.sol",
            """
            pragma solidity ^0.8.20;
            contract Vault {
                mapping(address => uint256) public balances;
                uint256 public total;
                function deposit(address user, uint256 amt) external {
                    balances[user] += amt;
                    total += amt;
                }
            }
            """,
        )
        _write(
            ws / "src" / "Liquidator.sol",
            """
            pragma solidity ^0.8.20;
            import "./Vault.sol";
            contract Liquidator {
                Vault public vaultRef;
                uint256 public total;
                function pushDeposit(address user, uint256 amt) external {
                    Vault.deposit(user, amt);
                }
            }
            """,
        )

    def test_cross_contract_edge_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._two_contracts(ws)
            proc = _run(ws)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            data = _load(ws)
            self.assertEqual(data["stats"]["contracts"], 2)
            cross = [e for e in data["edges"]
                     if e["src"].startswith("Liquidator.")
                     and e["dst"].startswith("Vault.")]
            self.assertGreater(len(cross), 0,
                               f"expected Liquidator→Vault edge; edges={data['edges']}")
            kinds = {e["kind"] for e in cross}
            self.assertTrue(kinds & {"external_call", "low_level_call"},
                            f"unexpected kinds={kinds}")
            # Edge points at the resolved Vault.deposit() node, not a stub.
            dst_ids = {e["dst"] for e in cross}
            self.assertIn("Vault.deposit()", dst_ids)

    def test_shared_storage_keys_overlap_on_name_collision(self) -> None:
        """Both contracts declare a state var `total`. The composer
        consumes `contract_storage` to determine whether two contracts
        can possibly race — this test pins the overlap shape."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._two_contracts(ws)
            self.assertEqual(_run(ws).returncode, 0)
            data = _load(ws)
            liq = set(data["contract_storage"]["Liquidator"])
            vlt = set(data["contract_storage"]["Vault"])
            self.assertIn("total", liq)
            self.assertIn("total", vlt)
            self.assertIn("balances", vlt)
            # `vaultRef` (the Liquidator field) is its own var; not in Vault.
            self.assertIn("vaultRef", liq)
            self.assertNotIn("vaultRef", vlt)
            # Direct overlap check — what the composer keys on.
            self.assertEqual(liq & vlt, {"total"})

    def test_no_shared_storage_for_unrelated_contracts(self) -> None:
        """A-RACE drop signal: when two contracts share NO state-var
        names, the composer will drop name-collision hits between them."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws / "src" / "Alpha.sol",
                """
                pragma solidity ^0.8.20;
                contract Alpha { uint256 public alphaCounter; }
                """,
            )
            _write(
                ws / "src" / "Beta.sol",
                """
                pragma solidity ^0.8.20;
                contract Beta { address public betaOwner; }
                """,
            )
            self.assertEqual(_run(ws).returncode, 0)
            data = _load(ws)
            shared = (set(data["contract_storage"]["Alpha"]) &
                      set(data["contract_storage"]["Beta"]))
            self.assertEqual(shared, set(),
                             f"unrelated contracts must not share keys; got {shared}")


class CciaCallgraphInheritanceTest(unittest.TestCase):
    def test_child_inherits_parent_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws / "src" / "Tree.sol",
                """
                pragma solidity ^0.8.20;
                contract Base {
                    uint256 public baseVar;
                    address public owner;
                }
                contract Child is Base {
                    uint256 public childVar;
                }
                """,
            )
            self.assertEqual(_run(ws).returncode, 0)
            data = _load(ws)
            child = set(data["contract_storage"]["Child"])
            # Child inherits Base — must surface baseVar + owner alongside childVar.
            self.assertIn("baseVar", child)
            self.assertIn("owner", child)
            self.assertIn("childVar", child)


class CciaCallgraphLibraryEdgeKindTest(unittest.TestCase):
    def test_library_call_kind(self) -> None:
        """Calls into a `library` resolve to kind=library_call."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Note: function name avoids find_external_calls()'s
            # built-in blacklist (length/push/pop/add/sub/mul/div/concat)
            # so the call site is preserved as a graph edge.
            _write(
                ws / "src" / "MathLib.sol",
                """
                pragma solidity ^0.8.20;
                library MathLib {
                    function combine(uint256 a, uint256 b) internal pure returns (uint256) {
                        return a + b;
                    }
                }
                """,
            )
            _write(
                ws / "src" / "User.sol",
                """
                pragma solidity ^0.8.20;
                import "./MathLib.sol";
                contract User {
                    uint256 public total;
                    function bump(uint256 x) external {
                        total = MathLib.combine(total, x);
                    }
                }
                """,
            )
            self.assertEqual(_run(ws).returncode, 0)
            data = _load(ws)
            lib_edges = [e for e in data["edges"] if e["kind"] == "library_call"]
            self.assertGreater(len(lib_edges), 0,
                               f"expected library_call edge; edges={data['edges']}")


if __name__ == "__main__":
    unittest.main()
