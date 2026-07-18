"""Tests for the persisted Hackerman chain-unify payload sidecar."""
from __future__ import annotations

import importlib.util
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-chain-unify-sidecar.py"
CHAIN_CANDIDATES = REPO_ROOT / "tools" / "hackerman-chain-candidates-sidecar.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_RECORD = """
schema_version: auditooor.hackerman_record.v1
record_id: {rid}
source_audit_ref: audit:test:{n}
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function {fn}(uint256 assets) external"
  shape_tags:
    - {fn}
bug_class: {bug_class}
attack_class: {attack_class}
attacker_role: unprivileged
attacker_action_sequence: "{action}"
required_preconditions:
  - {precondition}
impact_class: {impact}
impact_actor: users
impact_dollar_class: "$10K-$100K"
fix_pattern: apply guard
fix_anti_pattern_avoided: no guard
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
"""


class HackermanChainUnifySidecarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_test_hackerman_chain_unify_sidecar")
        self.chain_sidecar_tool = _load(CHAIN_CANDIDATES, "_test_hackerman_chain_candidates_sidecar_for_unify")
        self.tmp = tempfile.TemporaryDirectory(prefix="hcu-sidecar-")
        self.root = Path(self.tmp.name)
        self.tag_dir = self.root / "tags"
        self.tag_dir.mkdir()
        self.chain_sidecar = self.root / "derived" / "chain_candidates.jsonl"
        self.unify_sidecar = self.root / "derived" / "chain_unify_payload.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_record(
        self,
        n: int,
        *,
        rid: str,
        fn: str,
        bug_class: str,
        attack_class: str,
        precondition: str,
        action: str,
        impact: str = "theft",
    ) -> None:
        (self.tag_dir / f"rec{n}.yaml").write_text(
            textwrap.dedent(
                _RECORD.format(
                    n=n,
                    rid=rid,
                    fn=fn,
                    bug_class=bug_class,
                    attack_class=attack_class,
                    precondition=precondition,
                    action=action,
                    impact=impact,
                )
            ).lstrip(),
            encoding="utf-8",
        )

    def _write_chainable_fixture(self) -> None:
        self._write_record(
            0,
            rid="rec/access",
            fn="claimRole",
            bug_class="access-control",
            attack_class="access-control-missing-modifier",
            precondition="unprivileged caller reaches shared surface",
            action="attacker reaches an unvetted call path",
        )
        self._write_record(
            1,
            rid="rec/theft",
            fn="drain",
            bug_class="privileged-drain",
            attack_class="privilege-drain",
            precondition="requires privileged caller context",
            action="privileged caller moves protocol funds",
        )

    def _build_inputs(self) -> None:
        self._write_chainable_fixture()
        self.chain_sidecar_tool.build_sidecar(self.tag_dir, self.chain_sidecar)

    def test_build_and_load_summary_matches_direct_payload(self) -> None:
        self._build_inputs()
        self.tool.build_sidecar(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=4,
        )
        cached = self.tool.load_unify_summary(
            self.tag_dir,
            chain_sidecar_path=self.chain_sidecar,
            sidecar_path=self.unify_sidecar,
            limit=5,
            max_hops=4,
        )
        chain_mod = self.chain_sidecar_tool
        _, rows = chain_mod.load_sidecar(self.chain_sidecar)
        unify_mod = self.tool._load_unify_tool()
        direct = unify_mod.build_payload_from_chain_candidate_rows(self.tag_dir.resolve(), rows, 5, 4)

        self.assertTrue(cached["chain_unify_payload_sidecar_used"])
        self.assertEqual(cached["chain_unify_payload_sidecar_status"], "fresh")
        self.assertEqual(
            [row["chain_id"] for row in cached["chains"]],
            [row["chain_id"] for row in direct["chains"]],
        )
        self.assertEqual(cached["context_pack_hash"], direct["context_pack_hash"])

    def test_fresh_summary_avoids_live_chain_build_paths(self) -> None:
        self._build_inputs()
        self.tool.build_sidecar(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=4,
        )
        unify_mod = self.tool._load_unify_tool()
        original_rows = unify_mod.build_payload_from_chain_candidate_rows
        original_full = unify_mod.build_payload

        def _should_not_call(*_args, **_kwargs):
            raise AssertionError("fresh chain-unify sidecar should avoid live chain build")

        unify_mod.build_payload_from_chain_candidate_rows = _should_not_call
        unify_mod.build_payload = _should_not_call
        try:
            cached = self.tool.load_unify_summary(
                self.tag_dir,
                chain_sidecar_path=self.chain_sidecar,
                sidecar_path=self.unify_sidecar,
                limit=1,
                max_hops=4,
            )
        finally:
            unify_mod.build_payload_from_chain_candidate_rows = original_rows
            unify_mod.build_payload = original_full
        self.assertTrue(cached["chain_unify_payload_sidecar_used"])
        self.assertEqual(len(cached["chains"]), 1)

    def test_chain_candidates_content_change_invalidates(self) -> None:
        self._build_inputs()
        self.tool.build_sidecar(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=4,
        )
        self.assertTrue(
            self.tool.sidecar_is_fresh(
                self.tag_dir,
                self.unify_sidecar,
                chain_sidecar_path=self.chain_sidecar,
                max_hops=4,
            )[0]
        )
        with self.chain_sidecar.open("a", encoding="utf-8") as fh:
            fh.write('{"record_id":"tampered"}\n')
        fresh, reason = self.tool.sidecar_is_fresh(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=4,
        )
        self.assertFalse(fresh)
        self.assertIn("chain_candidates_sidecar_sha256", reason)

    def test_max_hops_change_invalidates(self) -> None:
        self._build_inputs()
        self.tool.build_sidecar(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=4,
        )
        fresh, reason = self.tool.sidecar_is_fresh(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=5,
        )
        self.assertFalse(fresh)
        self.assertIn("max_hops", reason)

    def test_corrupt_sidecar_falls_back_when_allowed(self) -> None:
        self._build_inputs()
        self.unify_sidecar.parent.mkdir(parents=True, exist_ok=True)
        self.unify_sidecar.write_text("not json\n", encoding="utf-8")
        payload = self.tool.load_unify_summary(
            self.tag_dir,
            chain_sidecar_path=self.chain_sidecar,
            sidecar_path=self.unify_sidecar,
            limit=3,
            max_hops=4,
        )
        self.assertFalse(payload["chain_unify_payload_sidecar_used"])
        self.assertEqual(payload["chain_unify_payload_sidecar_status"], "fallback")
        self.assertGreaterEqual(payload["total_records_loaded"], 2)

    def test_corpus_change_invalidates(self) -> None:
        self._build_inputs()
        self.tool.build_sidecar(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=4,
        )
        time.sleep(0.01)
        self._write_record(
            2,
            rid="rec/new",
            fn="newPath",
            bug_class="stale-state",
            attack_class="stale-state",
            precondition="requires stale state",
            action="state becomes stale",
        )
        fresh, reason = self.tool.sidecar_is_fresh(
            self.tag_dir,
            self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar,
            max_hops=4,
        )
        self.assertFalse(fresh)
        self.assertIn("corpus", reason)


class HackermanChainUnifySidecarShardedInputTests(unittest.TestCase):
    """J3e: unify-sidecar consumer must work when chain-candidates sidecar is sharded."""

    def setUp(self) -> None:
        self.tool = _load(TOOL, "_test_hackerman_chain_unify_sidecar_sharded")
        self.chain_sidecar_tool = _load(CHAIN_CANDIDATES, "_test_hackerman_chain_candidates_sidecar_sharded")
        self.tmp = tempfile.TemporaryDirectory(prefix="hcu-sidecar-sharded-")
        self.root = Path(self.tmp.name)
        self.tag_dir = self.root / "tags"
        self.tag_dir.mkdir()
        self.chain_sidecar = self.root / "derived" / "chain_candidates.jsonl"
        self.unify_sidecar = self.root / "derived" / "chain_unify_payload.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_record(self, n: int, *, rid: str, fn: str, bug_class: str,
                      attack_class: str, precondition: str, action: str) -> None:
        (self.tag_dir / f"rec{n}.yaml").write_text(
            textwrap.dedent(
                _RECORD.format(
                    n=n, rid=rid, fn=fn, bug_class=bug_class, attack_class=attack_class,
                    precondition=precondition, action=action, impact="theft",
                )
            ).lstrip(),
            encoding="utf-8",
        )

    def _write_chainable_fixture(self) -> None:
        self._write_record(
            0, rid="rec/access", fn="claimRole", bug_class="access-control",
            attack_class="access-control-missing-modifier",
            precondition="unprivileged caller reaches shared surface",
            action="attacker reaches an unvetted call path",
        )
        self._write_record(
            1, rid="rec/theft", fn="drain", bug_class="privileged-drain",
            attack_class="privilege-drain",
            precondition="requires privileged caller context",
            action="privileged caller moves protocol funds",
        )

    def _build_sharded_chain_inputs(self, shard_target_bytes: int = 300) -> None:
        """Write fixture records and build a sharded chain-candidates sidecar."""
        self._write_chainable_fixture()
        self.chain_sidecar_tool.build_sharded_sidecar(
            self.tag_dir, self.chain_sidecar, shard_target_bytes=shard_target_bytes
        )

    def test_load_chain_sidecar_meta_reads_sharded_manifest(self) -> None:
        """J3e: _load_chain_sidecar_meta must read the manifest when sharded."""
        self._build_sharded_chain_inputs()
        manifest_path = self.chain_sidecar.with_name("chain_candidates.manifest.json")
        self.assertTrue(manifest_path.exists(), "sharded manifest should exist")
        # Monolith .jsonl must NOT exist (sharded-only layout)
        self.assertFalse(self.chain_sidecar.is_file(), "monolith should not exist when sharded")

        meta = self.tool._load_chain_sidecar_meta(self.chain_sidecar)
        self.assertIn("schema_version", meta)
        self.assertIn("records_emitted", meta)
        self.assertGreater(int(meta["records_emitted"]), 0)

    def test_build_sidecar_works_with_sharded_chain_candidates(self) -> None:
        """J3e: build_sidecar must succeed when chain-candidates sidecar is sharded."""
        self._build_sharded_chain_inputs()
        meta = self.tool.build_sidecar(
            self.tag_dir, self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar, max_hops=4,
        )
        self.assertIn("chain_candidates_records_emitted", meta)
        self.assertGreater(int(meta["chain_candidates_records_emitted"]), 0)
        self.assertTrue(self.unify_sidecar.exists())

    def test_load_unify_summary_uses_sharded_chain_candidates(self) -> None:
        """J3e: load_unify_summary must produce a valid payload from sharded input."""
        self._build_sharded_chain_inputs()
        self.tool.build_sidecar(
            self.tag_dir, self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar, max_hops=4,
        )
        summary = self.tool.load_unify_summary(
            self.tag_dir,
            chain_sidecar_path=self.chain_sidecar,
            sidecar_path=self.unify_sidecar,
            limit=5, max_hops=4,
        )
        self.assertTrue(summary["chain_unify_payload_sidecar_used"])
        self.assertEqual(summary["chain_unify_payload_sidecar_status"], "fresh")
        self.assertGreaterEqual(summary["total_records_loaded"], 2)

    def test_sharded_chain_freshness_matches_direct_payload(self) -> None:
        """J3e: payload built from sharded chain-candidates matches direct build."""
        self._build_sharded_chain_inputs()
        self.tool.build_sidecar(
            self.tag_dir, self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar, max_hops=4,
        )
        cached = self.tool.load_unify_summary(
            self.tag_dir,
            chain_sidecar_path=self.chain_sidecar,
            sidecar_path=self.unify_sidecar,
            limit=5, max_hops=4,
        )
        chain_mod = self.chain_sidecar_tool
        _, rows = chain_mod.load_sidecar(self.chain_sidecar)
        unify_mod = self.tool._load_unify_tool()
        direct = unify_mod.build_payload_from_chain_candidate_rows(
            self.tag_dir.resolve(), rows, 5, 4
        )
        self.assertEqual(
            [row["chain_id"] for row in cached["chains"]],
            [row["chain_id"] for row in direct["chains"]],
        )

    def test_monolith_back_compat_still_works(self) -> None:
        """J3e back-compat: monolith chain-candidates sidecar still loads correctly."""
        self._write_chainable_fixture()
        # Explicitly build monolith layout.
        self.chain_sidecar_tool.build_sidecar(self.tag_dir, self.chain_sidecar)
        self.assertTrue(self.chain_sidecar.is_file(), "monolith .jsonl should exist")
        meta = self.tool._load_chain_sidecar_meta(self.chain_sidecar)
        self.assertIn("schema_version", meta)
        self.assertGreater(int(meta["records_emitted"]), 0)

        # Full round-trip with monolith still works.
        self.tool.build_sidecar(
            self.tag_dir, self.unify_sidecar,
            chain_sidecar_path=self.chain_sidecar, max_hops=4,
        )
        summary = self.tool.load_unify_summary(
            self.tag_dir,
            chain_sidecar_path=self.chain_sidecar,
            sidecar_path=self.unify_sidecar,
            limit=5, max_hops=4,
        )
        self.assertTrue(summary["chain_unify_payload_sidecar_used"])

    def test_chain_sidecar_stable_path_returns_manifest_when_sharded(self) -> None:
        """J3e: _chain_sidecar_stable_path returns manifest path for sharded layout."""
        self._build_sharded_chain_inputs()
        stable = self.tool._chain_sidecar_stable_path(self.chain_sidecar)
        expected = self.chain_sidecar.with_name("chain_candidates.manifest.json")
        self.assertEqual(stable, expected)

    def test_chain_sidecar_stable_path_returns_monolith_when_not_sharded(self) -> None:
        """J3e: _chain_sidecar_stable_path returns monolith path for monolith layout."""
        self._write_chainable_fixture()
        self.chain_sidecar_tool.build_sidecar(self.tag_dir, self.chain_sidecar)
        stable = self.tool._chain_sidecar_stable_path(self.chain_sidecar)
        self.assertEqual(stable, self.chain_sidecar)


if __name__ == "__main__":
    unittest.main()
