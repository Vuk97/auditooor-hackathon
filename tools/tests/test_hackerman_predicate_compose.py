from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-predicate-compose.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_predicate_compose", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanPredicateComposeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory(prefix="hackerman-predicate-compose-")
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, body: str) -> Path:
        path = self.tag_dir / name
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return path

    # --- fixture records ----------------------------------------------------

    _ACCESS_RECORD = """
        schema_version: auditooor.hackerman_record.v1.1
        record_id: solodit:access-2024-01-01:1:aaaa0001
        source_audit_ref: solodit:access-2024-01-01:1
        target_domain: lending
        target_language: solidity
        target_repo: example/vault
        target_component: Vault.setOperator
        function_shape:
          raw_signature: "function setOperator(address op) external"
          shape_tags:
            - external-privileged-write
        bug_class: missing-access-control
        attack_class: access-control-bypass
        attacker_role: unprivileged
        attacker_action_sequence: "Step 1: call the unprotected setter."
        required_preconditions:
          - setter is externally reachable
        impact_class: privilege-escalation
        impact_actor: arbitrary-user
        impact_dollar_class: non-financial
        fix_pattern: add onlyOwner modifier
        fix_anti_pattern_avoided: unguarded external setter
        severity_at_finding: high
        year: 2024
        cross_language_analogues: []
        related_records: []
        """

    _THEFT_RECORD = """
        schema_version: auditooor.hackerman_record.v1.1
        record_id: solodit:theft-2024-02-02:2:bbbb0002
        source_audit_ref: solodit:theft-2024-02-02:2
        target_domain: lending
        target_language: solidity
        target_repo: example/vault
        target_component: Vault.privilegedDrain
        function_shape:
          raw_signature: "function privilegedDrain() external"
          shape_tags:
            - external-privileged-fund-move
        bug_class: privileged-fund-drain
        attack_class: privilege-escalation-fund-theft
        attacker_role: privileged
        attacker_action_sequence: "Step 1: as owner, move protocol balance out."
        required_preconditions:
          - caller holds the owner role
          - protocol funds present in the vault
        impact_class: theft
        impact_actor: depositor-class
        impact_dollar_class: "$100K-$1M"
        fix_pattern: timelock privileged fund moves
        fix_anti_pattern_avoided: instant privileged drain
        severity_at_finding: critical
        year: 2024
        cross_language_analogues: []
        related_records: []
        """

    _NON_COMPOSABLE_RECORD = """
        schema_version: auditooor.hackerman_record.v1.1
        record_id: solodit:plain-2024-03-03:3:cccc0003
        source_audit_ref: solodit:plain-2024-03-03:3
        target_domain: misc
        target_language: solidity
        target_repo: example/misc
        target_component: Misc.doThing
        function_shape:
          raw_signature: "function doThing() external"
          shape_tags:
            - external-misc
        bug_class: typo
        attack_class: documentation-mismatch
        attacker_role: observer
        attacker_action_sequence: "Step 1: read the contract."
        required_preconditions:
          - contract is deployed
        impact_class: informational
        impact_actor: none
        impact_dollar_class: non-financial
        fix_pattern: fix the comment
        fix_anti_pattern_avoided: misleading comment
        severity_at_finding: info
        year: 2024
        cross_language_analogues: []
        related_records: []
        """

    # --- tests --------------------------------------------------------------

    def test_predicate_carries_typed_state_tokens(self) -> None:
        self._write("access.yaml", self._ACCESS_RECORD)
        payload = self.tool.build_payload(self.tag_dir)

        self.assertEqual(payload["total_records"], 1)
        node = payload["predicates"][0]
        # access-control attack class yields privileged-caller + unvetted-call.
        self.assertIn("state:privileged-caller-context", node["produces_state"])
        self.assertIn("state:privileged-caller-context", node["yields_state"])
        self.assertEqual(node["yields_state"], node["produces_state"])
        self.assertEqual(
            node["state_vocabulary_source"],
            "tools/hackerman-chain-unify.py:ALL_TOKENS:derive_preconditions:derive_postconditions",
        )
        self.assertTrue(node["composable"])
        # structural predicate rows are preserved verbatim (additive, lossless).
        self.assertTrue(node["structural_predicates"])
        self.assertTrue(node["predicate_id"].startswith("predcompose:"))

    def test_vocabulary_is_shared_with_chain_unify(self) -> None:
        # The composable predicate vocabulary MUST be the exact chain-unify
        # token set so predicates and exploit-chain steps speak one language.
        chain_spec = importlib.util.spec_from_file_location(
            "_cu_vocab_check", str(REPO_ROOT / "tools" / "hackerman-chain-unify.py")
        )
        chain = importlib.util.module_from_spec(chain_spec)
        assert chain_spec.loader
        # register before exec so @dataclass classes resolve cls.__module__
        sys.modules["_cu_vocab_check"] = chain
        chain_spec.loader.exec_module(chain)
        self.assertEqual(set(self.tool.ALL_TOKENS), set(chain.ALL_TOKENS))

    def test_predicates_compose_via_shared_state_token(self) -> None:
        # Predicate A (access bypass) YIELDS privileged-caller-context.
        # Predicate B (privileged drain) REQUIRES privileged-caller-context.
        # The shared token is the composition bridge.
        self._write("access.yaml", self._ACCESS_RECORD)
        self._write("theft.yaml", self._THEFT_RECORD)
        payload = self.tool.build_payload(self.tag_dir)

        by_id = {n["record_id"]: n for n in payload["predicates"]}
        a = by_id["solodit:access-2024-01-01:1:aaaa0001"]
        b = by_id["solodit:theft-2024-02-02:2:bbbb0002"]
        bridge = set(a["produces_state"]) & set(b["requires_state"])
        self.assertIn("state:privileged-caller-context", bridge)
        self.assertEqual(a["produces_state"], a["yields_state"])

        bridge_tokens = {
            s["token"] for s in payload["token_stats"] if s["is_composition_bridge"]
        }
        self.assertIn("state:privileged-caller-context", bridge_tokens)
        self.assertGreaterEqual(payload["composition_bridge_pairs"], 1)

    def test_non_composable_record_gets_no_fabricated_tokens(self) -> None:
        self._write("plain.yaml", self._NON_COMPOSABLE_RECORD)
        payload = self.tool.build_payload(self.tag_dir)
        node = payload["predicates"][0]
        self.assertEqual(node["requires_state"], [])
        self.assertEqual(node["produces_state"], [])
        self.assertEqual(node["yields_state"], [])
        self.assertFalse(node["composable"])
        self.assertEqual(payload["non_composable_predicates"], 1)
        self.assertEqual(payload["composable_predicates"], 0)

    def test_query_requires_filters_consumers(self) -> None:
        self._write("access.yaml", self._ACCESS_RECORD)
        self._write("theft.yaml", self._THEFT_RECORD)
        payload = self.tool.build_payload(self.tag_dir)
        result = self.tool.query_payload(
            payload, requires="state:privileged-caller-context", yields=None
        )
        ids = {m["record_id"] for m in result["matches"]}
        self.assertIn("solodit:theft-2024-02-02:2:bbbb0002", ids)
        self.assertNotIn("solodit:access-2024-01-01:1:aaaa0001", ids)

    def test_query_yields_filters_producers(self) -> None:
        self._write("access.yaml", self._ACCESS_RECORD)
        payload = self.tool.build_payload(self.tag_dir)
        result = self.tool.query_payload(
            payload, requires=None, yields="state:privileged-caller-context"
        )
        ids = {m["record_id"] for m in result["matches"]}
        self.assertIn("solodit:access-2024-01-01:1:aaaa0001", ids)
        self.assertEqual(result["matches"][0]["produces_state"], result["matches"][0]["yields_state"])

    def test_cli_json_and_query_paths(self) -> None:
        self._write("access.yaml", self._ACCESS_RECORD)
        self._write("theft.yaml", self._THEFT_RECORD)

        proc = subprocess.run(
            [sys.executable, str(TOOL), "--tag-dir", str(self.tag_dir), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["total_records"], 2)
        self.assertEqual(payload["schema"], "auditooor.hackerman_predicate_compose.summary.v1")

        proc_q = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--tag-dir",
                str(self.tag_dir),
                "--query-yields",
                "state:protocol-funds-displaced",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_q.returncode, 0, proc_q.stderr)
        q = json.loads(proc_q.stdout)
        # the theft record (impact_class: theft) yields protocol-funds-displaced.
        ids = {m["record_id"] for m in q["matches"]}
        self.assertIn("solodit:theft-2024-02-02:2:bbbb0002", ids)

    def test_cli_out_writes_jsonl(self) -> None:
        self._write("access.yaml", self._ACCESS_RECORD)
        out_path = self.tmp_path / "composable.jsonl"
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--tag-dir", str(self.tag_dir), "--out", str(out_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["schema"], "auditooor.hackerman_predicate_compose.v1")
        self.assertIn("produces_state", rows[0])
        self.assertEqual(rows[0]["produces_state"], rows[0]["yields_state"])


if __name__ == "__main__":
    unittest.main()
