from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-chain-unify.py"
CHAIN_TOOL = REPO_ROOT / "tools" / "hackerman-chain-candidates.py"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_json(tag_dir: Path, *extra: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--tag-dir", str(tag_dir), "--json", *extra],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


# A 3-step exploit chain in one repo:
#   step-1 access-control -> produces privileged-caller-context + unvetted-call
#   step-2 reentrancy     -> requires reentrant ctx (callback), produces accounting skew;
#                            also requires privileged-caller via attacker_role
#   step-3 theft          -> requires accounting skew (share/accounting keyword)
STEP_ACCESS = """schema_version: auditooor.hackerman_record.v1.1
record_id: rec-access-1
source_audit_ref: audit:demoproto:cluster-a
target_repo: demo-org/demo-proto
target_language: solidity
bug_class: missing-access-control
attack_class: access-control-bypass
attacker_role: arbitrary-user
attacker_action_sequence: Call the unguarded initializer that is reachable by any caller.
required_preconditions:
- The function is reachable without an owner check.
impact_class: privilege-escalation
severity_at_finding: high
"""

STEP_REENTRANCY = """schema_version: auditooor.hackerman_record.v1.1
record_id: rec-reentrancy-2
source_audit_ref: audit:demoproto:cluster-b
target_repo: demo-org/demo-proto
target_language: solidity
bug_class: reentrancy-on-withdraw
attack_class: reentrancy
attacker_role: privileged
attacker_action_sequence: Use the callback hook to reenter before accounting settles.
required_preconditions:
- Attacker can trigger an external callback on the withdraw path.
- The accounting share state is mutated after the external call.
impact_class: precision-loss
severity_at_finding: high
"""

STEP_THEFT = """schema_version: auditooor.hackerman_record.v1.1
record_id: rec-theft-3
source_audit_ref: audit:demoproto:cluster-c
target_repo: demo-org/demo-proto
target_language: solidity
bug_class: share-accounting-drain
attack_class: rounding-manipulation
attacker_role: arbitrary-user
attacker_action_sequence: Exploit the broken share accounting to drain protocol funds.
required_preconditions:
- The accounting invariant on share balances can be skewed.
impact_class: theft
severity_at_finding: critical
"""

# An isolated step in a DIFFERENT repo - must not chain cross-scope.
STEP_OTHER_REPO = """schema_version: auditooor.hackerman_record.v1.1
record_id: rec-otherrepo-1
source_audit_ref: audit:otherproto:cluster-a
target_repo: other-org/other-proto
target_language: solidity
bug_class: reentrancy-elsewhere
attack_class: reentrancy
attacker_role: arbitrary-user
attacker_action_sequence: Reenter on a callback in an unrelated repo.
required_preconditions:
- Attacker can trigger a callback.
impact_class: theft
severity_at_finding: high
"""

# A step with no usable precondition/postcondition signal -> unchainable.
STEP_UNCHAINABLE = """schema_version: auditooor.hackerman_record.v1.1
record_id: rec-unchainable-1
source_audit_ref: audit:demoproto:cluster-z
target_repo: demo-org/demo-proto
target_language: solidity
bug_class: documentation-typo
attack_class: code-quality
attacker_role: none
attacker_action_sequence: ""
required_preconditions: []
impact_class: ""
severity_at_finding: info
"""


class ChainUnifyTest(unittest.TestCase):
    def _fixture(self, tmp: Path) -> Path:
        tag_dir = tmp / "tags"
        _write(tag_dir / "access.yaml", STEP_ACCESS)
        _write(tag_dir / "reentrancy.yaml", STEP_REENTRANCY)
        _write(tag_dir / "theft.yaml", STEP_THEFT)
        _write(tag_dir / "otherrepo.yaml", STEP_OTHER_REPO)
        _write(tag_dir / "unchainable.yaml", STEP_UNCHAINABLE)
        return tag_dir

    def test_multi_hop_chain_constructed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            payload = _run_json(tag_dir, "--limit", "20", "--max-hops", "4")
        self.assertEqual(payload["schema"], "auditooor.hackerman.chain_unify.v1")
        self.assertTrue(payload["chains"], "expected at least one chain")
        # the longest chain should be the 3-step access -> reentrancy -> theft path
        top = payload["chains"][0]
        members = [s["record_id"] for s in top["steps"]]
        self.assertEqual(members, ["rec-access-1", "rec-reentrancy-2", "rec-theft-3"])
        self.assertEqual(top["hop_count"], 2)
        self.assertEqual(top["scope"], "demo-org/demo-proto")

    def test_hops_name_the_unifying_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            payload = _run_json(tag_dir, "--limit", "20", "--max-hops", "4")
        top = payload["chains"][0]
        self.assertEqual(len(top["hops"]), 2)
        for hop in top["hops"]:
            self.assertTrue(hop["unifying_state"], "every hop must name a unifying state")
        # access -> reentrancy unifies on the privileged-caller / reentrant ctx
        hop1 = top["hops"][0]
        self.assertIn("rec-access-1", hop1["from_record"])
        self.assertIn("rec-reentrancy-2", hop1["to_record"])
        # reentrancy -> theft unifies on the accounting-skew token
        hop2 = top["hops"][1]
        self.assertIn(
            "state:accounting-invariant-broken", hop2["unifying_state"]
        )

    def test_cross_scope_does_not_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            payload = _run_json(tag_dir, "--limit", "20")
        for chain in payload["chains"]:
            ids = {s["record_id"] for s in chain["steps"]}
            self.assertNotIn(
                "rec-otherrepo-1",
                ids,
                "other-repo step must not join a demo-proto chain",
            )

    def test_unchainable_step_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            payload = _run_json(tag_dir, "--limit", "20")
        self.assertIn("rec-unchainable-1", payload["unchainable_sample"])
        self.assertGreaterEqual(payload["unchainable_steps"], 1)
        for chain in payload["chains"]:
            ids = {s["record_id"] for s in chain["steps"]}
            self.assertNotIn("rec-unchainable-1", ids)

    def test_deterministic_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            first = _run_json(tag_dir, "--limit", "20")
            second = _run_json(tag_dir, "--limit", "20")
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["chains"], second["chains"])

    def test_empty_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tag_dir = Path(td) / "empty"
            tag_dir.mkdir()
            payload = _run_json(tag_dir)
        self.assertEqual(payload["total_chains"], 0)
        self.assertEqual(payload["chains"], [])

    def test_markdown_render(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--tag-dir", str(tag_dir), "--limit", "5"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
        self.assertIn("Hackerman Exploit-Chain Unifier", proc.stdout)
        self.assertIn("Hops:", proc.stdout)


# --- W6-9 depth tests -------------------------------------------------------


def _load_cu():
    """Import the chain-unify module for in-process unit tests."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_cu_test", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_cu_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_hcc():
    import importlib.util

    spec = importlib.util.spec_from_file_location("_hcc_test", str(CHAIN_TOOL))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_hcc_test"] = mod
    spec.loader.exec_module(mod)
    return mod


class ChainUnifyDepthTest(unittest.TestCase):
    """W6-9: indexed edges, incremental cache, richer ranking, predicates."""

    def _fixture(self, tmp: Path) -> Path:
        tag_dir = tmp / "tags"
        _write(tag_dir / "access.yaml", STEP_ACCESS)
        _write(tag_dir / "reentrancy.yaml", STEP_REENTRANCY)
        _write(tag_dir / "theft.yaml", STEP_THEFT)
        _write(tag_dir / "otherrepo.yaml", STEP_OTHER_REPO)
        _write(tag_dir / "unchainable.yaml", STEP_UNCHAINABLE)
        return tag_dir

    def test_indexed_edges_match_brute_force_on_larger_corpus(self) -> None:
        """The token-indexed edge builder must produce the SAME adjacency map
        as the original O(n^2) brute-force scan, on a corpus large enough that
        the difference matters (200 synthetic steps across 4 repos)."""
        cu = _load_cu()
        with tempfile.TemporaryDirectory() as td:
            tag_dir = Path(td) / "big"
            classes = [
                ("access-control-bypass", "privilege-escalation", "high"),
                ("reentrancy", "precision-loss", "high"),
                ("rounding-manipulation", "theft", "critical"),
                ("oracle-manipulation", "theft", "high"),
                ("dos-griefing", "dos", "medium"),
            ]
            for repo in range(4):
                for i in range(50):
                    ac, ic, sev = classes[i % len(classes)]
                    _write(
                        tag_dir / f"r{repo}-rec{i}.yaml",
                        "schema_version: auditooor.hackerman_record.v1.1\n"
                        f"record_id: r{repo}-rec{i}\n"
                        f"source_audit_ref: audit:proto{repo}:cluster\n"
                        f"target_repo: org/proto-{repo}\n"
                        "target_language: solidity\n"
                        f"bug_class: bug-{ac}\n"
                        f"attack_class: {ac}\n"
                        "attacker_role: arbitrary-user\n"
                        "attacker_action_sequence: "
                        "Trigger callback and skew share accounting via oracle price.\n"
                        "required_preconditions:\n"
                        "- The accounting share state and oracle price are reachable.\n"
                        f"impact_class: {ic}\n"
                        f"severity_at_finding: {sev}\n",
                    )
            steps, _ = cu.load_steps(tag_dir)
            chainable = [s for s in steps if s.chainable]
            self.assertGreaterEqual(len(chainable), 200)

            def brute(scope_steps):
                e = {}
                for p in scope_steps:
                    if not p.postconditions:
                        continue
                    for c in scope_steps:
                        if c.record_id == p.record_id or not c.preconditions:
                            continue
                        if cu._scope_key(p) != cu._scope_key(c):
                            continue
                        u = p.postconditions & c.preconditions
                        if u:
                            e.setdefault(p.record_id, []).append(
                                (c.record_id, frozenset(u))
                            )
                for k in e:
                    e[k].sort(key=lambda item: (item[0],))
                return e

            by_scope: dict = {}
            for s in chainable:
                by_scope.setdefault(cu._scope_key(s), []).append(s)
            for sk, ss in by_scope.items():
                ss = sorted(ss, key=lambda s: s.record_id)
                self.assertEqual(
                    cu.build_edges(ss), brute(ss), f"edge mismatch in scope {sk}"
                )

    def test_incremental_cache_speeds_reparse(self) -> None:
        """A warm cache must yield 100% cache hits and an identical hash."""
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            cache = Path(td) / "cache.json"
            cold = _run_json(tag_dir, "--cache", str(cache))
            self.assertEqual(cold["cache_hits"], 0)
            self.assertGreater(cold["cache_misses"], 0)
            self.assertTrue(cache.is_file())
            warm = _run_json(tag_dir, "--cache", str(cache))
            self.assertEqual(warm["cache_misses"], 0)
            self.assertEqual(warm["cache_hits"], cold["cache_misses"])
            # cache must not change results
            self.assertEqual(cold["context_pack_hash"], warm["context_pack_hash"])
            self.assertEqual(cold["chains"], warm["chains"])

    def test_build_payload_from_chain_candidate_rows_matches_direct(self) -> None:
        cu = _load_cu()
        hcc = _load_hcc()
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            steps, _ = hcc.load_records(tag_dir)
            rows = [asdict(step) for step in steps]
            direct = cu.build_payload(tag_dir, limit=20, max_hops=4)
            via_sidecar_rows = cu.build_payload_from_chain_candidate_rows(
                tag_dir,
                rows,
                limit=20,
                max_hops=4,
            )
        self.assertEqual(
            [chain["chain_id"] for chain in via_sidecar_rows["chains"]],
            [chain["chain_id"] for chain in direct["chains"]],
        )
        self.assertEqual(
            [chain["score"] for chain in via_sidecar_rows["chains"]],
            [chain["score"] for chain in direct["chains"]],
        )

    def test_cache_invalidates_on_file_change(self) -> None:
        """Editing a tag file must produce a cache miss for that file."""
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            cache = Path(td) / "cache.json"
            _run_json(tag_dir, "--cache", str(cache))
            # mutate one file -> mtime/size change -> at least one miss
            edited = STEP_THEFT.replace("severity_at_finding: critical", "severity_at_finding: high")
            _write(tag_dir / "theft.yaml", edited + "\n# touched\n")
            second = _run_json(tag_dir, "--cache", str(cache))
            self.assertGreaterEqual(second["cache_misses"], 1)

    def test_severity_escalation_rewarded(self) -> None:
        """A chain whose final step is the most severe must carry a positive
        escalation bonus in its score breakdown."""
        with tempfile.TemporaryDirectory() as td:
            tag_dir = self._fixture(Path(td))
            payload = _run_json(tag_dir, "--limit", "20", "--max-hops", "4")
        top = payload["chains"][0]
        self.assertIn("score_breakdown", top)
        bd = top["score_breakdown"]
        # access(high) -> reentrancy(high) -> theft(critical): non-decreasing,
        # last step is most severe.
        self.assertGreater(bd["escalation_bonus"], 0.0)
        self.assertEqual(bd["escalating_hops"], 2)

    def test_outcome_confirmed_weighting(self) -> None:
        """An ACCEPTED triager outcome must lift a chain above an otherwise
        identical chain of unconfirmed candidates."""
        cu = _load_cu()
        with tempfile.TemporaryDirectory() as td:
            tag_dir = Path(td) / "tags"
            base = (
                "schema_version: auditooor.hackerman_record.v1.1\n"
                "target_repo: org/proto\n"
                "target_language: solidity\n"
                "attacker_role: arbitrary-user\n"
            )
            # confirmed 2-step chain
            _write(
                tag_dir / "c1.yaml",
                base
                + "record_id: c1\nsource_audit_ref: audit:proto:a\n"
                "bug_class: access\nattack_class: access-control-bypass\n"
                "attacker_action_sequence: reachable unguarded call\n"
                "required_preconditions:\n- reachable without owner check\n"
                "impact_class: privilege-escalation\nseverity_at_finding: high\n"
                "triager_outcome: ACCEPTED\n",
            )
            _write(
                tag_dir / "c2.yaml",
                base
                + "record_id: c2\nsource_audit_ref: audit:proto:b\n"
                "bug_class: reentrancy\nattack_class: reentrancy\n"
                "attacker_action_sequence: callback reenter, skew share accounting\n"
                "required_preconditions:\n- external callback on withdraw, share state\n"
                "impact_class: theft\nseverity_at_finding: critical\n"
                "triager_outcome: ACCEPTED\n",
            )
            payload_confirmed = json.loads(
                subprocess.run(
                    [sys.executable, str(TOOL), "--tag-dir", str(tag_dir), "--json"],
                    cwd=REPO_ROOT, text=True, capture_output=True, check=True,
                ).stdout
            )
            confirmed_score = payload_confirmed["chains"][0]["score"]
            self.assertEqual(
                payload_confirmed["chains"][0]["score_breakdown"]["confirmed_steps"], 2
            )
            # now strip the outcomes -> candidates only
            for name in ("c1.yaml", "c2.yaml"):
                txt = (tag_dir / name).read_text()
                _write(tag_dir / name, txt.replace("triager_outcome: ACCEPTED\n", ""))
            payload_candidate = json.loads(
                subprocess.run(
                    [sys.executable, str(TOOL), "--tag-dir", str(tag_dir), "--json"],
                    cwd=REPO_ROOT, text=True, capture_output=True, check=True,
                ).stdout
            )
            candidate_score = payload_candidate["chains"][0]["score"]
        self.assertGreater(confirmed_score, candidate_score)
        _ = cu  # module load smoke

    def test_predicate_step_joins_chain(self) -> None:
        """A W5-F4 composable predicate node, fed via --predicates, must be
        able to sit on a chain edge between two findings."""
        with tempfile.TemporaryDirectory() as td:
            tag_dir = Path(td) / "tags"
            # two findings that do NOT directly chain: head yields
            # privileged-caller-context, tail requires accounting-skew.
            _write(
                tag_dir / "head.yaml",
                "schema_version: auditooor.hackerman_record.v1.1\n"
                "record_id: head-1\nsource_audit_ref: audit:proto:a\n"
                "target_repo: org/proto\ntarget_language: solidity\n"
                "bug_class: access\nattack_class: access-control-bypass\n"
                "attacker_role: arbitrary-user\n"
                "attacker_action_sequence: reachable unguarded call\n"
                "required_preconditions:\n- reachable without owner check\n"
                "impact_class: privilege-escalation\nseverity_at_finding: high\n",
            )
            _write(
                tag_dir / "tail.yaml",
                "schema_version: auditooor.hackerman_record.v1.1\n"
                "record_id: tail-1\nsource_audit_ref: audit:proto:c\n"
                "target_repo: org/proto\ntarget_language: solidity\n"
                "bug_class: drain\nattack_class: rounding-manipulation\n"
                "attacker_role: arbitrary-user\n"
                "attacker_action_sequence: exploit broken share accounting to drain\n"
                "required_preconditions:\n- accounting share invariant can be skewed\n"
                "impact_class: theft\nseverity_at_finding: critical\n",
            )
            # predicate node: requires privileged-caller, yields accounting-skew.
            pred = Path(td) / "preds.jsonl"
            pred.write_text(
                json.dumps(
                    {
                        "predicate_id": "predcompose:bridge1",
                        "record_id": "predcompose:bridge1",
                        "target_repo": "org/proto",
                        "target_language": "solidity",
                        "bug_class": "predicate-bridge",
                        "attack_class": "oracle-manipulation",
                        "impact_class": "",
                        "attacker_role": "arbitrary-user",
                        "requires_state": ["state:privileged-caller-context"],
                        "yields_state": ["state:accounting-invariant-broken"],
                        "composable": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = _run_json(tag_dir, "--predicates", str(pred), "--max-hops", "4")
        self.assertGreaterEqual(payload["predicate_steps_loaded"], 1)
        # a chain must exist that routes head -> predicate -> tail
        routed = [
            c
            for c in payload["chains"]
            if [s["record_id"] for s in c["steps"]]
            == ["head-1", "predcompose:bridge1", "tail-1"]
        ]
        self.assertTrue(routed, "predicate node should bridge head -> tail")
        chain = routed[0]
        self.assertEqual(chain["predicate_steps"], 1)
        self.assertIn("predicate", chain["node_kinds"])

    def test_predicate_respects_scope_isolation(self) -> None:
        """A predicate node in a different repo must not bridge a chain."""
        with tempfile.TemporaryDirectory() as td:
            tag_dir = Path(td) / "tags"
            _write(
                tag_dir / "head.yaml",
                "schema_version: auditooor.hackerman_record.v1.1\n"
                "record_id: head-1\nsource_audit_ref: audit:proto:a\n"
                "target_repo: org/proto\ntarget_language: solidity\n"
                "bug_class: access\nattack_class: access-control-bypass\n"
                "attacker_role: arbitrary-user\n"
                "attacker_action_sequence: reachable unguarded call\n"
                "required_preconditions:\n- reachable without owner check\n"
                "impact_class: privilege-escalation\nseverity_at_finding: high\n",
            )
            pred = Path(td) / "preds.jsonl"
            pred.write_text(
                json.dumps(
                    {
                        "predicate_id": "predcompose:elsewhere",
                        "record_id": "predcompose:elsewhere",
                        "target_repo": "other/repo",
                        "requires_state": ["state:privileged-caller-context"],
                        "yields_state": ["state:accounting-invariant-broken"],
                        "composable": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = _run_json(tag_dir, "--predicates", str(pred))
        for chain in payload["chains"]:
            ids = {s["record_id"] for s in chain["steps"]}
            self.assertNotIn("predcompose:elsewhere", ids)


if __name__ == "__main__":
    unittest.main()
