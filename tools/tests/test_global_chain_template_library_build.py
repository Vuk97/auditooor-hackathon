"""Tests for tools/global-chain-template-library-build.py (Phase 3 P3.1).

<!-- r36-rebuttal: pathspec registered via agent-pathspec-register.py for lane LIFT-PHASE-3-CODEX-TAKEOVER -->

Schema asserted: auditooor.global_chain_template.v1
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "global-chain-template-library-build.py"
EXPECTED_SCHEMA = "auditooor.global_chain_template.v1"
EXPECTED_MANIFEST_SCHEMA = "auditooor.global_chain_template_manifest.v1"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "global_chain_template_library_build", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_invariant(
    inv_id: str,
    *,
    category: str = "atomicity",
    attack_signature: str = "callback-reentrancy",
    target_lang: str = "solidity",
    commit_point_pattern: str = "post-state-write pre-callback",
    defense_layer: str = "checks-effects-interactions",
    tier: str = "tier-2-verified-public-archive",
    statement: str = "Default invariant statement",
    source_count: int = 3,
    source_refs: list[str] | None = None,
    source_finding_ids: list[str] | None = None,
    state_token: str = "state:shared-chain-token",
) -> dict:
    refs = source_refs if source_refs is not None else [f"fixtures/{inv_id}.sol:1"]
    return {
        "schema_version": "auditooor.invariant_pilot.v1",
        "invariant_id": inv_id,
        "category": category,
        "attack_signature": attack_signature,
        "target_lang": target_lang,
        "commit_point_pattern": commit_point_pattern,
        "defense_layer": defense_layer,
        "verification_tier": tier,
        "statement": statement,
        "audit_verdict": "TRUE-POSITIVE",
        "source_count": source_count,
        "source_refs": refs,
        "producer_source_refs": refs,
        "consumer_source_refs": refs,
        "produces_state": [state_token],
        "requires_state": [state_token],
        "source_finding_ids": (
            source_finding_ids
            if source_finding_ids is not None
            else [f"lead:{inv_id}"]
        ),
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _make_nested_advisory(inv_id: str, *, bug_class: str) -> dict:
    return {
        "schema_version": "auditooor.invariant.v1",
        "record_id": f"forkdiv-inv:{inv_id}",
        "verification_tier": "tier-2-verified-public-archive",
        "content": {
            "invariant_id": inv_id,
            "attack_class": "fork-divergence-missing-upstream-fix",
            "bug_class": bug_class,
            "impact_class": "state-divergence",
            "invariant_text": "Forks must backport upstream verification fixes.",
            "missing_upstream_fix": "fork pin lacks upstream verification commit on block acceptance path",
            "target_language": "go",
            "source_findings": ["upstream #1 | fork-pin abc123"],
        },
    }


def _write_incident_yaml(path: Path, *, attack_class: str, target_component: str, attack_text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        f"schema_version: auditooor.hackerman_record.v1.1\n"
        f"record_id: test-incident:{path.stem}\n"
        f"verification_tier: tier-2-verified-public-archive\n"
        f"attack_class: {attack_class}\n"
        f"target_component: {target_component}\n"
        f"attack_vector_summary: '{attack_text}'\n"
    )
    path.write_text(body, encoding="utf-8")


def _write_zetachain_anchor_yaml(path: Path, *, inv_id: str, attack_class: str, lang: str = "solidity") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        f"schema_version: auditooor.invariant.v1\n"
        f"record_id: '{inv_id}'\n"
        f"verification_tier: tier-2-verified-public-archive\n"
        f"content:\n"
        f"  invariant_id: '{inv_id}'\n"
        f"  invariant_text: |\n"
        f"    Invariant statement for {inv_id}.\n"
        f"  target_language: {lang}\n"
        f"  attack_class: {attack_class}\n"
        f"  bug_class: {attack_class}\n"
        f"  source_refs:\n"
        f"    - 'fixtures/{inv_id}.sol:1'\n"
        f"  producer_source_refs:\n"
        f"    - 'fixtures/{inv_id}.sol:1'\n"
        f"  consumer_source_refs:\n"
        f"    - 'fixtures/{inv_id}.sol:1'\n"
        f"  produces_state:\n"
        f"    - 'state:bridge-shared-link'\n"
        f"  requires_state:\n"
        f"    - 'state:bridge-shared-link'\n"
        f"  source_findings:\n"
        f"    - 'zetachain:2026-04-26-{attack_class}'\n"
    )
    path.write_text(body, encoding="utf-8")


class GlobalChainTemplateLibraryBuildTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="gct-build-")
        self.base = Path(self.tmp.name)
        self.mod = _load_module()
        self.out = self.base / "out.jsonl"
        self.manifest = self.base / "out.manifest.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *, invariants: list[dict], incidents: list[tuple[str, str, str]] | None = None,
             anchors: list[tuple[str, str]] | None = None, **overrides) -> dict:
        inv_path = self.base / "inv.jsonl"
        _write_jsonl(inv_path, invariants)
        inc_dir = self.base / "incidents"
        inc_dir.mkdir(exist_ok=True)
        for i, (a_class, comp, text) in enumerate(incidents or []):
            _write_incident_yaml(
                inc_dir / f"incident-{i:03d}.yaml",
                attack_class=a_class,
                target_component=comp,
                attack_text=text,
            )
        anchor_dir = self.base / "anchors"
        anchor_dir.mkdir(exist_ok=True)
        for inv_id, a_class in (anchors or []):
            _write_zetachain_anchor_yaml(
                anchor_dir / f"{inv_id}.yaml",
                inv_id=inv_id,
                attack_class=a_class,
            )
        anti_dir = self.base / "anti_patterns"
        anti_dir.mkdir(exist_ok=True)
        argv = [
            "--invariants-jsonl", str(inv_path),
            "--predicates-jsonl", str(self.base / "preds.jsonl"),
            "--anti-patterns-dir", str(anti_dir),
            "--incident-corpus-dirs", str(inc_dir),
            "--zetachain-anchors-dir", str(anchor_dir),
            "--output", str(self.out),
            "--manifest", str(self.manifest),
            "--max-tuple-size", str(overrides.get("max_tuple_size", 4)),
            "--min-composition-score", str(overrides.get("min_composition_score", 0.6)),
        ]
        if overrides.get("no_manual_anchor"):
            argv.append("--no-manual-anchor")
        if overrides.get("max_invariants"):
            argv += ["--max-invariants", str(overrides["max_invariants"])]
        if overrides.get("advisory_invariants_glob"):
            argv += ["--advisory-invariants-glob", str(overrides["advisory_invariants_glob"])]
        if overrides.get("workspace"):
            argv += ["--workspace", str(overrides["workspace"])]
        rc = self.mod.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(self.manifest.read_text(encoding="utf-8"))

    def _read_templates(self) -> list[dict]:
        if not self.out.exists():
            return []
        return [json.loads(line) for line in self.out.read_text(encoding="utf-8").splitlines() if line.strip()]

    # --- Test 1: empty inputs ---
    def test_empty_inputs_emit_empty_output(self) -> None:
        manifest = self._run(invariants=[], no_manual_anchor=True)
        self.assertEqual(manifest["template_count_total"], 0)
        self.assertEqual(self._read_templates(), [])

    # --- Test 2: pair emission with shared commit_point keyword ---
    def test_pair_with_strong_commit_point_match(self) -> None:
        invariants = [
            _make_invariant("INV-AAA-001", commit_point_pattern="nonce increment before signature"),
            _make_invariant("INV-AAA-002", commit_point_pattern="nonce increment before downstream"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        templates = self._read_templates()
        self.assertGreaterEqual(manifest["template_count_total"], 1)
        # Tuple_size 2 templates.
        pair = [t for t in templates if t["tuple_size"] == 2]
        self.assertGreaterEqual(len(pair), 1)
        self.assertEqual(pair[0]["schema_version"], EXPECTED_SCHEMA)
        shared = pair[0]["composition_breakdown"]["shared_commit_point_keywords"]
        self.assertIn("nonce", shared)

    # --- Test 3: score threshold filter ---
    def test_score_threshold_drops_weak_tuples(self) -> None:
        invariants = [
            _make_invariant("INV-WEAK-001", commit_point_pattern="abc", target_lang="solidity"),
            _make_invariant("INV-WEAK-002", commit_point_pattern="xyz", target_lang="rust",
                            defense_layer="something_else"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True,
                             min_composition_score=0.9)
        self.assertEqual(manifest["template_count_total"], 0)

    # --- Test 4: triple (k=3) emission ---
    def test_triple_emission(self) -> None:
        invariants = [
            _make_invariant("INV-T-001", commit_point_pattern="callback before state finality"),
            _make_invariant("INV-T-002", commit_point_pattern="callback before checks effects interactions"),
            _make_invariant("INV-T-003", commit_point_pattern="callback before write commit"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True, max_tuple_size=3)
        templates = self._read_templates()
        triples = [t for t in templates if t["tuple_size"] == 3]
        self.assertEqual(len(triples), 1)
        self.assertEqual(len(triples[0]["member_invariant_ids"]), 3)

    # --- Test 5: 4-tuple emission ---
    def test_4tuple_emission(self) -> None:
        invariants = [
            _make_invariant(f"INV-Q-{i:03d}",
                            commit_point_pattern="callback before state final commit write")
            for i in range(1, 5)
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True, max_tuple_size=4)
        templates = self._read_templates()
        quads = [t for t in templates if t["tuple_size"] == 4]
        self.assertEqual(len(quads), 1)

    # --- Test 6: weakest tier propagation ---
    def test_weakest_tier_propagation(self) -> None:
        invariants = [
            _make_invariant("INV-W-001", commit_point_pattern="shared keyword token",
                            tier="tier-2-verified-public-archive"),
            _make_invariant("INV-W-002", commit_point_pattern="shared keyword token here",
                            tier="tier-3-synthetic-taxonomy-anchored"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        templates = self._read_templates()
        self.assertGreaterEqual(len(templates), 1)
        # Weakest = tier-3
        self.assertEqual(templates[0]["verification_tier"], "tier-3-synthetic-taxonomy-anchored")

    # --- Test 7: cross-incident co-occurrence increases score ---
    def test_cross_incident_co_occurrence(self) -> None:
        invariants = [
            _make_invariant("INV-COOC-001",
                            commit_point_pattern="bridge proof domain consume",
                            attack_signature="bridge-proof-consume-once"),
            _make_invariant("INV-COOC-002",
                            commit_point_pattern="bridge replay nonce",
                            attack_signature="bridge-replay-prevention"),
        ]
        incidents = [
            ("bridge-attack", "bridge",
             "bridge proof domain consume gap allowed nonce replay attack"),
            ("bridge-attack", "bridge",
             "another incident: bridge replay nonce missing, proof consumed twice"),
            ("bridge-attack", "bridge",
             "bridge proof consume bug, nonce reused, drained funds"),
        ]
        manifest = self._run(invariants=invariants, incidents=incidents, no_manual_anchor=True)
        templates = self._read_templates()
        self.assertEqual(len(templates), 1)
        breakdown = templates[0]["composition_breakdown"]
        self.assertGreaterEqual(breakdown["co_occurrence_incident_count"], 1)
        # evidence_incidents populated
        self.assertGreaterEqual(len(templates[0]["evidence_incidents"]), 1)

    # --- Test 8: ZetaChain 4-tuple manual anchor recognized ---
    def test_zetachain_4tuple_recognition(self) -> None:
        anchors = [
            ("INV-BRIDGE-ALLOWANCE-001", "erc20-allowance-residue-on-bridge"),
            ("INV-BRIDGE-ARBCALL-001", "bridge-arbitrary-call-with-allowance-residue-drain"),
            ("INV-BRIDGE-SELECTOR-DENY-001", "selector-deny-list-incomplete"),
            ("INV-BRIDGE-SENDER-ZEROING-001", "msg-sender-zeroing-downstream-authorization-uplift"),
        ]
        manifest = self._run(invariants=[], anchors=anchors)
        templates = self._read_templates()
        zeta = [t for t in templates if t.get("_manual_anchor") is True]
        self.assertEqual(len(zeta), 1)
        self.assertEqual(zeta[0]["tuple_size"], 4)
        self.assertEqual(
            sorted(zeta[0]["member_invariant_ids"]),
            sorted([a[0] for a in anchors]),
        )
        self.assertEqual(zeta[0]["verification_tier"], "tier-2-verified-public-archive")

    # --- Test 9: deterministic chain_template_id (hash of sorted member ids) ---
    def test_deterministic_chain_template_id(self) -> None:
        invariants = [
            _make_invariant("INV-DET-002", commit_point_pattern="ordering token shared"),
            _make_invariant("INV-DET-001", commit_point_pattern="ordering token shared"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        templates = self._read_templates()
        tpl1 = templates[0]
        # Re-run with different input ordering - id must be identical.
        self.tearDown()
        self.setUp()
        invariants_reverse = list(reversed(invariants))
        self._run(invariants=invariants_reverse, no_manual_anchor=True)
        templates_again = self._read_templates()
        tpl2 = templates_again[0]
        self.assertEqual(tpl1["chain_template_id"], tpl2["chain_template_id"])

    # --- Test 10: state_machine ordering deterministic (by invariant_id) ---
    def test_state_machine_deterministic_ordering(self) -> None:
        invariants = [
            _make_invariant("INV-SM-003", commit_point_pattern="state machine token a"),
            _make_invariant("INV-SM-001", commit_point_pattern="state machine token a"),
            _make_invariant("INV-SM-002", commit_point_pattern="state machine token a"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True, max_tuple_size=3)
        templates = self._read_templates()
        tri = [t for t in templates if t["tuple_size"] == 3][0]
        ids = [s["invariant_id"] for s in tri["state_machine"]]
        self.assertEqual(ids, sorted(ids))

    # --- Test 11: manifest schema asserted ---
    def test_manifest_schema(self) -> None:
        invariants = [
            _make_invariant("INV-MAN-001", commit_point_pattern="shared shared"),
            _make_invariant("INV-MAN-002", commit_point_pattern="shared shared"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        self.assertEqual(manifest["schema_version"], EXPECTED_MANIFEST_SCHEMA)
        self.assertIn("inputs", manifest)
        self.assertIn("config", manifest)
        self.assertGreater(manifest["template_count_total"], 0)

    # --- Test 12: SIBLING and NEEDS-RESEARCH skipped ---
    def test_sibling_and_needs_research_filtered(self) -> None:
        invariants = [
            {**_make_invariant("INV-SIB-001"), "audit_verdict": "SIBLING"},
            {**_make_invariant("INV-NR-001"), "audit_verdict": "NEEDS-RESEARCH"},
            _make_invariant("INV-OK-001", commit_point_pattern="shared shared"),
            _make_invariant("INV-OK-002", commit_point_pattern="shared shared"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        templates = self._read_templates()
        # SIBLING and NEEDS-RESEARCH should be excluded.
        all_member_ids = set()
        for t in templates:
            all_member_ids.update(t["member_invariant_ids"])
        self.assertNotIn("INV-SIB-001", all_member_ids)
        self.assertNotIn("INV-NR-001", all_member_ids)
        self.assertIn("INV-OK-001", all_member_ids)
        self.assertIn("INV-OK-002", all_member_ids)

    def test_nested_advisory_invariants_are_not_promoted(self) -> None:
        advisory_path = self.base / "derived" / "invariants_dydx_fork_divergence_advisories.jsonl"
        _write_jsonl(
            advisory_path,
            [
                _make_nested_advisory("INV-FORKDIV-A", bug_class="missing-fix-a"),
                _make_nested_advisory("INV-FORKDIV-B", bug_class="missing-fix-b"),
                {
                    "fixture_role": "negative-control",
                    "content": {
                        "invariant_id": "INV-FORKDIV-CLEAN",
                        "attack_class": "fork-divergence-missing-upstream-fix",
                    },
                },
            ],
        )
        manifest = self._run(
            invariants=[],
            no_manual_anchor=True,
            advisory_invariants_glob=str(advisory_path),
        )
        templates = self._read_templates()
        self.assertEqual(manifest["inputs"]["advisory_invariants_paths"], [str(advisory_path)])
        all_member_ids = set()
        for template in templates:
            all_member_ids.update(template["member_invariant_ids"])
        self.assertNotIn("INV-FORKDIV-A", all_member_ids)
        self.assertNotIn("INV-FORKDIV-B", all_member_ids)
        self.assertNotIn("INV-FORKDIV-CLEAN", all_member_ids)

    def test_blocked_stale_and_source_unbacked_rows_are_not_promoted(self) -> None:
        cases = [
            {
                **_make_invariant("INV-BLOCKED-001"),
                "submission_posture": "NOT_SUBMIT_READY",
            },
            {
                **_make_invariant("INV-STALE-001"),
                "freshness": "STALE",
            },
            _make_invariant("INV-UNBACKED-001", source_refs=[]),
        ]
        for row in cases:
            with self.subTest(row=row["invariant_id"]):
                self.tearDown()
                self.setUp()
                peer = _make_invariant(
                    f"{row['invariant_id']}-PEER",
                    commit_point_pattern="shared token peer",
                )
                manifest = self._run(
                    invariants=[row, peer],
                    no_manual_anchor=True,
                )
                self.assertEqual(manifest["template_count_total"], 0)

    def test_missing_producer_consumer_linkage_is_not_promoted(self) -> None:
        missing_producer = {
            **_make_invariant("INV-LINK-001", commit_point_pattern="shared token"),
            "produces_state": [],
        }
        peer = _make_invariant("INV-LINK-002", commit_point_pattern="shared token")
        manifest = self._run(
            invariants=[missing_producer, peer],
            no_manual_anchor=True,
        )
        self.assertEqual(manifest["template_count_total"], 0)

    def test_single_lead_restatement_is_not_promoted(self) -> None:
        invariants = [
            _make_invariant(
                "INV-SAMELEAD-001",
                commit_point_pattern="shared token",
                source_finding_ids=["lead:single"],
            ),
            _make_invariant(
                "INV-SAMELEAD-002",
                commit_point_pattern="shared token",
                source_finding_ids=["lead:single"],
            ),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        self.assertEqual(manifest["template_count_total"], 0)

    def test_linkage_requires_matching_producer_consumer_state(self) -> None:
        invariants = [
            _make_invariant(
                "INV-NOLINK-001",
                commit_point_pattern="shared token",
                state_token="state:producer-a-only",
            ),
            _make_invariant(
                "INV-NOLINK-002",
                commit_point_pattern="shared token",
                state_token="state:consumer-b-only",
            ),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        self.assertEqual(manifest["template_count_total"], 0)

    def test_workspace_source_refs_must_resolve_to_file_line(self) -> None:
        workspace = self.base / "workspace"
        source = workspace / "src" / "Valid.sol"
        source.parent.mkdir(parents=True)
        source.write_text("line one\nline two\n", encoding="utf-8")
        valid_rows = [
            _make_invariant(
                "INV-WS-001",
                commit_point_pattern="shared token",
                source_refs=["src/Valid.sol:2"],
            ),
            _make_invariant(
                "INV-WS-002",
                commit_point_pattern="shared token",
                source_refs=["src/Valid.sol:2"],
            ),
        ]
        manifest = self._run(
            invariants=valid_rows,
            no_manual_anchor=True,
            workspace=workspace,
        )
        self.assertGreaterEqual(manifest["template_count_total"], 1)
        templates = self._read_templates()
        self.assertIn("producer_consumer_links", templates[0])
        self.assertEqual(templates[0]["source_refs"], ["src/Valid.sol:2"])

        self.tearDown()
        self.setUp()
        workspace = self.base / "workspace"
        (workspace / "src").mkdir(parents=True)
        (workspace / "src" / "Valid.sol").write_text("line one\n", encoding="utf-8")
        invalid_rows = [
            _make_invariant(
                "INV-WS-BAD-001",
                commit_point_pattern="shared token",
                source_refs=["src/Valid.sol:9"],
            ),
            _make_invariant(
                "INV-WS-BAD-002",
                commit_point_pattern="shared token",
                source_refs=["src/Missing.sol:1"],
            ),
        ]
        manifest = self._run(
            invariants=invalid_rows,
            no_manual_anchor=True,
            workspace=workspace,
        )
        self.assertEqual(manifest["template_count_total"], 0)

    # --- Test 13: shared defense-layer keyword contributes score ---
    def test_defense_layer_coupling(self) -> None:
        invariants = [
            _make_invariant("INV-DEF-001", commit_point_pattern="abc shared",
                            defense_layer="reentrancy guard with nonce mapping"),
            _make_invariant("INV-DEF-002", commit_point_pattern="abc shared",
                            defense_layer="nonce mapping bump pattern"),
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True)
        templates = self._read_templates()
        self.assertGreaterEqual(len(templates), 1)
        breakdown = templates[0]["composition_breakdown"]
        self.assertIn("nonce", breakdown["defense_layer_keywords_shared"])

    # --- Test 14: tuple-size cap honored ---
    def test_max_tuple_size_cap(self) -> None:
        invariants = [
            _make_invariant(f"INV-CAP-{i:03d}", commit_point_pattern="shared shared shared")
            for i in range(1, 5)
        ]
        manifest = self._run(invariants=invariants, no_manual_anchor=True, max_tuple_size=2)
        templates = self._read_templates()
        for t in templates:
            self.assertLessEqual(t["tuple_size"], 2)

    # --- Test 15: _load_incidents returns sorted output regardless of rglob order ---
    def test_load_incidents_sorted_by_incident_id(self) -> None:
        """_load_incidents must return records sorted by incident_id.

        We create incident YAML files in reverse-alphabetical filename order
        so that a naive rglob iteration (inode / creation order) would yield
        them in the wrong sequence. The fix sorts by incident_id, so the
        returned list must always be lexicographically ordered regardless of
        how the filesystem hands back the paths.
        """
        inc_dir = self.base / "inc_sort_test"
        inc_dir.mkdir()
        # Names deliberately written high-to-low so inode order is Z..A.
        stems_reversed = ["zzz-incident", "mmm-incident", "aaa-incident"]
        for stem in stems_reversed:
            lines_yaml = [
                "schema_version: auditooor.hackerman_record.v1.1",
                f"record_id: '{stem}'",
                "verification_tier: tier-2-verified-public-archive",
                "attack_class: test-class",
                "target_component: test-comp",
                f"attack_vector_summary: 'test text for {stem}'",
                "",
            ]
            body = "\n".join(lines_yaml)
            (inc_dir / f"{stem}.yaml").write_text(body, encoding="utf-8")

        incidents = self.mod._load_incidents([inc_dir])
        ids = [inc["incident_id"] for inc in incidents]
        self.assertEqual(ids, sorted(ids), msg=f"_load_incidents not sorted: {ids}")
        # Confirm all three records are present.
        self.assertEqual(set(ids), set(stems_reversed))

    # --- Test 16: deterministic evidence_incidents under --max-incidents truncation ---
    def test_incident_truncation_is_deterministic(self) -> None:
        """evidence_incidents must be identical across two runs that use the
        same incidents but written to the filesystem in reverse creation order.

        Without the sort fix, --max-incidents can truncate a different set of
        incidents when inode order differs, producing different evidence_incidents
        in the output chain_templates.jsonl.
        """
        # Two invariants whose commit-point tokens both appear in the incident text.
        invariants = [
            _make_invariant(
                "INV-TRUNC-001",
                commit_point_pattern="bridge proof consume nonce",
                attack_signature="bridge-proof-consume",
            ),
            _make_invariant(
                "INV-TRUNC-002",
                commit_point_pattern="bridge replay proof nonce",
                attack_signature="bridge-replay-nonce",
            ),
        ]

        # 6 incidents that all match both invariants tokens,
        # plus 3 that do NOT match (padding so a cap of 5 would truncate
        # differently depending on iteration order if unsorted).
        matching_stems = [f"inc-match-{chr(ord('a') + i)}" for i in range(6)]
        non_matching_stems = [f"inc-nomatch-{i}" for i in range(3)]

        def make_incident_body(stem: str) -> str:
            if "nomatch" in stem:
                text = "completely unrelated text about something else entirely"
            else:
                text = "bridge proof consume nonce replay missing check"
            body_lines = [
                "schema_version: auditooor.hackerman_record.v1.1",
                f"record_id: '{stem}'",
                "verification_tier: tier-2-verified-public-archive",
                "attack_class: bridge-attack",
                "target_component: bridge",
                f"attack_vector_summary: '{text}'",
                "",
            ]
            return "\n".join(body_lines)

        def write_incidents_to_dir(inc_dir: Path, stems_order: list) -> None:
            inc_dir.mkdir(exist_ok=True)
            for stem in stems_order:
                (inc_dir / f"{stem}.yaml").write_text(
                    make_incident_body(stem), encoding="utf-8"
                )

        all_stems = matching_stems + non_matching_stems

        # Run A: files created in forward alphabetical order.
        dir_a = self.base / "incidents_a"
        write_incidents_to_dir(dir_a, all_stems)

        # Run B: files created in reverse alphabetical order (different inode ordering).
        dir_b = self.base / "incidents_b"
        write_incidents_to_dir(dir_b, list(reversed(all_stems)))

        inv_path = self.base / "inv_trunc.jsonl"
        _write_jsonl(inv_path, invariants)
        anti_dir = self.base / "anti_trunc"
        anti_dir.mkdir(exist_ok=True)
        anchor_dir = self.base / "anchors_trunc"
        anchor_dir.mkdir(exist_ok=True)

        def run_with_dir(inc_dir: Path, out_suffix: str) -> list:
            out_path = self.base / f"out_trunc_{out_suffix}.jsonl"
            manifest_path = self.base / f"manifest_trunc_{out_suffix}.json"
            argv = [
                "--invariants-jsonl", str(inv_path),
                "--predicates-jsonl", str(self.base / "preds_trunc.jsonl"),
                "--anti-patterns-dir", str(anti_dir),
                "--incident-corpus-dirs", str(inc_dir),
                "--zetachain-anchors-dir", str(anchor_dir),
                "--output", str(out_path),
                "--manifest", str(manifest_path),
                "--max-tuple-size", "2",
                "--min-composition-score", "0.6",
                "--no-manual-anchor",
                # Cap to 5: with sorting, always picks inc-match-a..e (sorted first).
                # Without sorting, reverse-inode order could mix in nomatch files.
                "--max-incidents", "5",
            ]
            rc = self.mod.main(argv)
            self.assertEqual(rc, 0)
            if not out_path.exists():
                return []
            return [
                json.loads(line)
                for line in out_path.read_text("utf-8").splitlines()
                if line.strip()
            ]

        templates_a = run_with_dir(dir_a, "a")
        templates_b = run_with_dir(dir_b, "b")

        # Both runs must produce identical evidence_incidents because _load_incidents
        # now sorts by incident_id before the max-incidents slice is applied.
        self.assertEqual(
            len(templates_a),
            len(templates_b),
            msg="Template count differs between run A and run B",
        )
        for ta, tb in zip(
            sorted(templates_a, key=lambda t: t.get("chain_template_id", "")),
            sorted(templates_b, key=lambda t: t.get("chain_template_id", "")),
        ):
            self.assertEqual(
                sorted(ta.get("evidence_incidents", [])),
                sorted(tb.get("evidence_incidents", [])),
                msg=(
                    f"evidence_incidents differ for {ta.get('chain_template_id')}: "
                    f"{ta.get('evidence_incidents')} vs {tb.get('evidence_incidents')}"
                ),
            )

    # --- Test 17: full live-fire on real corpus (smoke test, capped) ---
    def test_live_corpus_smoke_capped(self) -> None:
        """Smoke-test the real corpus paths with --max-invariants 50."""
        inv_path = REPO_ROOT / "audit/corpus_tags/derived/invariants_pilot_audited.jsonl"
        if not inv_path.exists():
            self.skipTest("Real corpus invariants_pilot_audited.jsonl missing")
        argv = [
            "--invariants-jsonl", str(inv_path),
            "--output", str(self.out),
            "--manifest", str(self.manifest),
            "--max-tuple-size", "2",
            "--min-composition-score", "0.6",
            "--max-invariants", "50",
            "--max-incidents", "50",
            "--no-manual-anchor",
        ]
        rc = self.mod.main(argv)
        self.assertEqual(rc, 0)
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertGreaterEqual(manifest["template_count_total"], 0)
        self.assertIn("inputs", manifest)


if __name__ == "__main__":
    unittest.main()
