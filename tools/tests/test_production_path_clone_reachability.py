"""P0-2 burn-down regression tests.

These tests pin the clone/proxy reachability slice that was added on top of
the conservative source-shape relation edges:

  * ``semantic-graph.py`` records ``target_var`` (the first-arg variable name
    passed to ``new <Proxy>(varname, ...)`` and ``Clones.clone(varname)``)
    on every ``clone-deploy`` and ``proxy-deploy`` edge.
  * ``lib/production_path_dossier.py`` exposes a new
    ``proven_via_clone_factory`` external-actor-path verdict. It clears
    ``external_actor_path_missing`` only when the candidate explicitly
    declares the ``implementation_var`` it sits behind AND the graph contains
    a permissionless factory function whose clone/proxy-deploy edge points
    at that exact variable name.

The Base-Azul-FN1 finding is the canonical motivating case: a factory
deploys child games via a proxy, and the bug is on the cloned implementation.
The pre-burn-down dossier reported ``external_actor_path: missing`` because
direct entrypoint matching only saw the implementation's own functions,
missing the factory hop. After the burn-down, candidates that explicitly
cite ``implementation_var`` get a ``proven_via_clone_factory`` verdict;
candidates that do NOT cite the pointer are still blocked, and privileged
factories still produce ``privileged-only``.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SEMANTIC = ROOT / "tools" / "semantic-graph.py"
LIB = ROOT / "tools" / "lib" / "production_path_dossier.py"


def _load_lib():
    spec = importlib.util.spec_from_file_location(
        "production_path_dossier_clone_reach", LIB
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _candidate(**overrides):
    """Build a candidate that targets the ChildGame implementation contract.

    Defaults match the cloned-implementation shape: files point at the
    cloned contract, claim/trigger/impact describe the bug on that
    implementation, and ``lane_payload.implementation_var`` cites the
    state-variable name on the factory that holds the implementation
    pointer.
    """
    doc = {
        "schema_version": "deep_candidate.v1",
        "lane": "source_mine",
        "candidate_id": "fn1-clone-reach",
        "files": ["src/ChildGame.sol:5-8"],
        "claim": "ChildGame.resolveParentLoss pays the wrong recipient.",
        "trigger": "Anyone can call resolveParentLoss after parent settles.",
        "impact": "Bond reward funds are misrouted to the wrong actor.",
        "reproduction": "forge test --match-test test_parentLossFactoryReachability",
        "confidence": "high",
        "blocking_questions": [],
        "promotion_status": "needs_poc",
        "lane_payload": {
            "contract": "ChildGame",
            "function": "resolveParentLoss",
            "target_contract": "ChildGame",
            "implementation_var": "childImplementation",
        },
    }
    doc.update(overrides)
    return doc


def _permissionless_factory_workspace(ws: Path) -> None:
    """Permissionless ``createGame`` deploys child via ``ERC1967Proxy``.

    The bug is on ``ChildGame`` (a proxy-cloned implementation). ChildGame's
    own functions are ``internal`` so the implementation contract has NO
    permissionless entrypoint that direct entrypoint-matching can latch
    onto. The dossier therefore must prove reachability through the
    factory hop, not via direct match.

    The factory is in a separate file so candidate ``files`` scoped to
    ``src/ChildGame.sol`` cannot accidentally match the factory's
    entrypoint either.
    """
    (ws / "src").mkdir()
    (ws / "src" / "Factory.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            contract ERC1967Proxy {
                constructor(address implementation, bytes memory data) {}
            }

            contract DisputeGameFactory {
                address public childImplementation;

                function createGame(bytes calldata data) external {
                    new ERC1967Proxy(childImplementation, data);
                }
            }
            """
        ),
        encoding="utf-8",
    )
    (ws / "src" / "ChildGame.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            contract ChildGame {
                uint256 public bond;
                function resolveParentLoss(address recipient) internal {
                    bond = 0;
                    payable(recipient).transfer(1 ether);
                }
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(SEMANTIC), "--workspace", str(ws)], check=True)


def _privileged_factory_workspace(ws: Path) -> None:
    """``createGame`` is gated by ``onlyOwner`` — clone-target reachability
    must NOT clear ``missing`` because the factory hop itself is privileged.

    We deliberately omit a ``returns (...)`` clause from the signature: the
    repo's lightweight ``FUNCTION_RE`` swallows the trailing ``returns`` tuple
    and would not record the ``onlyOwner`` modifier on the function. That is
    a separate, known limitation of the v1 graph (see KNOWN_LIMITATIONS P0-2)
    and is orthogonal to the slice this PR exercises.
    """
    (ws / "src").mkdir()
    (ws / "src" / "Factory.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            contract ERC1967Proxy {
                constructor(address implementation, bytes memory data) {}
            }

            contract DisputeGameFactory {
                address public childImplementation;
                modifier onlyOwner() { _; }

                function createGame(bytes calldata data) external onlyOwner {
                    new ERC1967Proxy(childImplementation, data);
                }
            }
            """
        ),
        encoding="utf-8",
    )
    (ws / "src" / "ChildGame.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            contract ChildGame {
                uint256 public bond;
                function resolveParentLoss(address recipient) internal {
                    bond = 0;
                    payable(recipient).transfer(1 ether);
                }
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(SEMANTIC), "--workspace", str(ws)], check=True)


def _clones_library_factory_workspace(ws: Path) -> None:
    """Permissionless factory uses ``Clones.clone(implementation)`` instead
    of ``new ERC1967Proxy(...)`` — ``target_var`` plumbing must work for both
    deploy shapes.
    """
    (ws / "src").mkdir()
    (ws / "src" / "Factory.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            library Clones {
                function clone(address implementation) internal returns (address) {}
            }

            contract VaultFactory {
                address public vaultImplementation;

                function spawn() external {
                    Clones.clone(vaultImplementation);
                }
            }
            """
        ),
        encoding="utf-8",
    )
    (ws / "src" / "ChildGame.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            contract ChildGame {
                uint256 public bond;
                function resolveParentLoss(address recipient) internal {
                    bond = 0;
                    payable(recipient).transfer(1 ether);
                }
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(SEMANTIC), "--workspace", str(ws)], check=True)


class SemanticGraphTargetVarTests(unittest.TestCase):
    """Confirm ``semantic-graph.py`` records ``target_var`` on clone/proxy
    edges so the dossier has the link it needs."""

    def test_proxy_deploy_records_first_arg_variable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _permissionless_factory_workspace(ws)
            graph = json.loads(
                (ws / ".auditooor" / "semantic_graph.json").read_text(encoding="utf-8")
            )
            proxy_edges = [
                e for e in graph["relation_edges"] if e.get("kind") == "proxy-deploy"
            ]
            self.assertTrue(proxy_edges, graph["relation_edges"])
            self.assertTrue(
                all(e.get("target_var") == "childImplementation" for e in proxy_edges),
                proxy_edges,
            )
            # Permissionless source role survives onto the edge.
            self.assertTrue(
                all(e.get("role") == "permissionless" for e in proxy_edges),
                proxy_edges,
            )

    def test_clone_deploy_records_first_arg_variable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _clones_library_factory_workspace(ws)
            graph = json.loads(
                (ws / ".auditooor" / "semantic_graph.json").read_text(encoding="utf-8")
            )
            clone_edges = [
                e for e in graph["relation_edges"] if e.get("kind") == "clone-deploy"
            ]
            self.assertTrue(clone_edges, graph["relation_edges"])
            self.assertTrue(
                all(e.get("target_var") == "vaultImplementation" for e in clone_edges),
                clone_edges,
            )

    def test_privileged_factory_role_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _privileged_factory_workspace(ws)
            graph = json.loads(
                (ws / ".auditooor" / "semantic_graph.json").read_text(encoding="utf-8")
            )
            proxy_edges = [
                e for e in graph["relation_edges"] if e.get("kind") == "proxy-deploy"
            ]
            self.assertTrue(proxy_edges, graph["relation_edges"])
            self.assertTrue(
                all(e.get("role") == "privileged" for e in proxy_edges),
                proxy_edges,
            )


class CloneFactoryReachabilityTests(unittest.TestCase):
    """Pin the new ``proven_via_clone_factory`` external-actor-path verdict."""

    def test_permissionless_proxy_factory_clears_missing_to_proven(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _permissionless_factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(_candidate(), workspace=ws, graph=graph)
            self.assertEqual(
                dossier["external_actor_path"],
                "proven_via_clone_factory",
                dossier,
            )
            self.assertEqual(dossier["submit_verdict"], "poc_ready")
            self.assertNotIn(
                "external_actor_path_missing", dossier["blockers"]
            )
            self.assertIn(
                "permissionless factory clone/proxy-deploy edges",
                dossier["blocker_explanation"],
            )
            edge_kinds = {
                e["kind"]
                for e in dossier["state_transition"]["matched_relation_edges"]
            }
            self.assertIn("proxy-deploy", edge_kinds)

    def test_permissionless_clones_library_factory_also_proves_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _clones_library_factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    files=["src/ChildGame.sol:5-8"],
                    lane_payload={
                        "contract": "ChildGame",
                        "function": "resolveParentLoss",
                        "target_contract": "ChildGame",
                        "implementation_var": "vaultImplementation",
                    },
                ),
                workspace=ws,
                graph=graph,
            )
            self.assertEqual(
                dossier["external_actor_path"],
                "proven_via_clone_factory",
                dossier,
            )
            edge_kinds = {
                e["kind"]
                for e in dossier["state_transition"]["matched_relation_edges"]
            }
            self.assertIn("clone-deploy", edge_kinds)

    def test_missing_implementation_var_still_blocks(self) -> None:
        """Negative case: when the candidate does NOT declare its
        ``implementation_var``, the heuristic cannot prove the factory link
        and the dossier must keep blocking on ``missing``. This is the
        guardrail against accidentally promoting unrelated candidates that
        merely happen to live in a workspace containing factories."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _permissionless_factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            cand = _candidate()
            # Drop the implementation_var key; everything else identical.
            cand["lane_payload"] = {
                key: value
                for key, value in cand["lane_payload"].items()
                if key != "implementation_var"
            }
            dossier = lib.build_dossier(cand, workspace=ws, graph=graph)
            self.assertEqual(dossier["external_actor_path"], "missing", dossier)
            self.assertIn("external_actor_path_missing", dossier["blockers"])

    def test_privileged_factory_does_not_clear_missing(self) -> None:
        """Negative case: ``createGame`` is gated by ``onlyOwner``. Even if
        the candidate declares the implementation pointer, the factory hop
        is privileged so reachability stays unproven."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _privileged_factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(_candidate(), workspace=ws, graph=graph)
            self.assertEqual(dossier["external_actor_path"], "missing", dossier)
            self.assertIn("external_actor_path_missing", dossier["blockers"])
            # The dossier must not silently switch to proven_via_clone_factory.
            self.assertNotEqual(
                dossier["external_actor_path"], "proven_via_clone_factory"
            )

    def test_unknown_implementation_var_does_not_match_unrelated_factory(self) -> None:
        """Negative case: the candidate declares ``implementation_var`` but
        no edge in the graph points to that name. The dossier must stay on
        ``missing`` instead of grabbing a random factory edge."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _permissionless_factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            cand = _candidate()
            cand["lane_payload"]["implementation_var"] = "totallyDifferentImpl"
            dossier = lib.build_dossier(cand, workspace=ws, graph=graph)
            self.assertEqual(dossier["external_actor_path"], "missing", dossier)
            self.assertIn("external_actor_path_missing", dossier["blockers"])

    def test_text_level_privileged_signal_still_wins(self) -> None:
        """Even when the factory hop is permissionless, prose-level
        privileged signals (``onlyGuardian``, ``mock``, ``project inaction``)
        must keep dominating: those reflect real preconditions the dossier
        should not paper over with a clone-factory bypass."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _permissionless_factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            cand = _candidate(
                trigger=(
                    "Reachable only after a guardian blacklistDisputeGame admin "
                    "action sets the parent invalid."
                )
            )
            dossier = lib.build_dossier(cand, workspace=ws, graph=graph)
            self.assertEqual(dossier["external_actor_path"], "privileged-only")
            self.assertIn("precondition_privileged", dossier["blockers"])


class HelperUnitTests(unittest.TestCase):
    """Direct unit tests on ``_clone_factory_reachability`` so the
    selection/filtering logic is pinned without going through the full
    dossier pipeline."""

    def setUp(self) -> None:
        self.lib = _load_lib()

    def test_helper_returns_empty_when_no_implementation_var(self) -> None:
        graph = {
            "relation_edges": [
                {
                    "kind": "clone-deploy",
                    "role": "permissionless",
                    "target_var": "implementation",
                }
            ]
        }
        self.assertEqual(
            self.lib._clone_factory_reachability({"lane_payload": {}}, graph),
            [],
        )

    def test_helper_filters_privileged_edges(self) -> None:
        graph = {
            "relation_edges": [
                {
                    "kind": "clone-deploy",
                    "role": "privileged",
                    "target_var": "implementation",
                    "file": "src/F.sol",
                    "line": 1,
                },
                {
                    "kind": "proxy-deploy",
                    "role": "permissionless",
                    "target_var": "implementation",
                    "file": "src/F.sol",
                    "line": 2,
                },
            ]
        }
        candidate = {"lane_payload": {"implementation_var": "implementation"}}
        result = self.lib._clone_factory_reachability(candidate, graph)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["role"], "permissionless")

    def test_helper_only_matches_clone_or_proxy_kinds(self) -> None:
        graph = {
            "relation_edges": [
                {
                    "kind": "registry-write",
                    "role": "permissionless",
                    "target_var": "implementation",
                },
                {
                    "kind": "verifier-adapter-call",
                    "role": "permissionless",
                    "target_var": "implementation",
                },
            ]
        }
        candidate = {"lane_payload": {"implementation_var": "implementation"}}
        self.assertEqual(self.lib._clone_factory_reachability(candidate, graph), [])

    def test_helper_match_is_case_insensitive(self) -> None:
        graph = {
            "relation_edges": [
                {
                    "kind": "proxy-deploy",
                    "role": "permissionless",
                    "target_var": "ChildImplementation",
                    "file": "src/F.sol",
                    "line": 1,
                }
            ]
        }
        candidate = {"lane_payload": {"implementation_var": "childimplementation"}}
        result = self.lib._clone_factory_reachability(candidate, graph)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
