"""Unit tests for Rule 30 production-profile preflight."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "production_profile_preflight",
    ROOT / "tools" / "production-profile-preflight-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="dydx_r30_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    return root


def _write_case(
    draft_body: str,
    go_body: str | None,
    poc_dir: str = "case",
    filename: str = "draft-HIGH.md",
) -> Path:
    root = _workspace()
    if go_body is not None:
        d = root / "poc-tests" / poc_dir
        d.mkdir(parents=True)
        (d / "poc_test.go").write_text(go_body, encoding="utf-8")
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(draft_body, encoding="utf-8")
    return draft


def _draft(
    severity: str = "HIGH",
    impact: str = "matching engine degradation",
    poc_dir: str = "case",
    extra: str = "",
) -> str:
    return (
        f"Severity: {severity}\n\n"
        f"Selected impact: {impact}\n\n"
        f"PoC: `poc-tests/{poc_dir}`\n\n"
        f"{extra}\n"
    )


def _write_case_lang(
    draft_body: str,
    src_body: str,
    src_name: str = "poc_test.rs",
    poc_dir: str = "case",
    filename: str = "draft-HIGH.md",
) -> Path:
    """Like _write_case but writes a source file with an arbitrary suffix."""
    root = _workspace()
    d = root / "poc-tests" / poc_dir
    d.mkdir(parents=True)
    (d / src_name).write_text(src_body, encoding="utf-8")
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(draft_body, encoding="utf-8")
    return draft


def _run(draft: Path) -> tuple[int, dict]:
    return mod.run(draft)


class ScopeTests(unittest.TestCase):
    def test_medium_severity_memdb_out_of_scope(self):
        draft = _write_case(
            _draft(severity="MEDIUM"),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _ = dbm.NewMemDB() }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "out-of-scope")

    def test_no_severity_header_out_of_scope(self):
        draft = _write_case(
            "Selected impact: network-level downtime\nPoC: `poc-tests/case`\n",
            "package poc\n",
            filename="draft.md",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "out-of-scope")

    def test_no_rubric_keyword_out_of_scope(self):
        draft = _write_case(
            "Severity: HIGH\n\nPoC: `poc-tests/case`\n\nNo liveness claim here.\n",
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _ = dbm.NewMemDB() }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "out-of-scope")

    def test_missing_poc_dir_is_loud_fail_not_silent_skip(self):
        # No-silent-skip: a HIGH+ scoped claim with no resolvable PoC dir used
        # to return rc=2 (treated as a non-blocking pass by pre-submit-check).
        # It must now be a real blocking failure.
        root = _workspace()
        draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
        draft.write_text(_draft(), encoding="utf-8")
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-production-profile-evidence")
        self.assertIn("PoC dir", payload["error"])

    def test_missing_poc_dir_with_rebuttal_passes(self):
        root = _workspace()
        draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
        draft.write_text(
            _draft(extra="<!-- r30-rebuttal: production-profile proof out of scope here -->"),
            encoding="utf-8",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-with-rebuttal")

    def test_poc_dir_with_no_recognised_source_is_loud_fail(self):
        # PoC dir resolves but contains no .go/.rs/.sol/.ts file -> loud fail,
        # never a silent rc=2 skip.
        root = _workspace()
        d = root / "poc-tests" / "case"
        d.mkdir(parents=True)
        (d / "notes.md").write_text("just prose, no source\n", encoding="utf-8")
        draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
        draft.write_text(_draft(), encoding="utf-8")
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-production-profile-evidence")


class ClauseATests(unittest.TestCase):
    def test_high_memdb_no_rebuttal_fails_a(self):
        draft = _write_case(
            _draft(),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _ = dbm.NewMemDB() }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["failed_constraints"][0]["constraint"], "a")

    def test_high_goleveldb_passes_a(self):
        draft = _write_case(
            _draft(impact="liveness failure"),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", t.TempDir()) }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_memdb_setup_plus_goleveldb_passes_a(self):
        root = _workspace()
        d = root / "poc-tests" / "case"
        d.mkdir(parents=True)
        (d / "setup_test.go").write_text(
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc setup(){ _ = dbm.NewMemDB() }\n",
            encoding="utf-8",
        )
        (d / "profile_test.go").write_text(
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc prod(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
            encoding="utf-8",
        )
        draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
        draft.write_text(_draft(), encoding="utf-8")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_cantina_201_v2_fixture_fails_a(self):
        draft = _write_case(
            _draft(extra="Race window depends on disk latency."),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "type slowBatchDB struct{ dbm.DB }\n"
                "func f(){ _ = dbm.NewMemDB() }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        constraints = {f["constraint"] for f in payload["failed_constraints"]}
        self.assertIn("a", constraints)


class ClauseBTests(unittest.TestCase):
    def test_slow_batch_wrapper_fails_b(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "type slowBatchDB struct{ dbm.DB }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("b", {f["constraint"] for f in payload["failed_constraints"]})

    def test_sleep_inside_db_method_fails_b(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport \"time\"\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "type MyDB struct{ dbm.DB }\n"
                "func (m *MyDB) Set(k, v []byte) error { time.Sleep(time.Millisecond); return nil }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("b", {f["constraint"] for f in payload["failed_constraints"]})

    def test_sleep_inside_embedded_db_wrapper_method_fails_b(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport \"time\"\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "type Throttle struct{ dbm.DB }\n"
                "func (t *Throttle) Apply(){ time.Sleep(time.Millisecond) }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("b", {f["constraint"] for f in payload["failed_constraints"]})

    def test_sleep_in_testmain_setup_passes_b(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport \"time\"\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func TestMain(){ time.Sleep(time.Millisecond) }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_no_shims_with_disclosure_passes_b(self):
        draft = _write_case(
            _draft(extra="No timing shim. Real backend, no delay wrappers."),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")


class ClauseCTests(unittest.TestCase):
    def test_reflection_private_field_write_fails_c(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport \"reflect\"\nimport \"unsafe\"\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func setLegacyLatestVersionField(nodeDB any){ "
                "_ = unsafe.Pointer(nil); reflect.ValueOf(nodeDB).Elem().FieldByName(\"legacyLatestVersion\").SetInt(48) }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("c", {f["constraint"] for f in payload["failed_constraints"]})

    def test_reflection_read_only_passes_c(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport \"reflect\"\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func inspect(nodeDB any){ _ = reflect.ValueOf(nodeDB).Elem().FieldByName(\"legacyLatestVersion\") }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_reflection_on_local_test_type_passes_c(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport \"reflect\"\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "type localHarness struct{ field int }\n"
                "func mutate(h *localHarness){ reflect.ValueOf(h).Elem().FieldByName(\"field\").SetInt(1) }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_direct_batch_set_internal_key_fails_c(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func seed(batch Batch){ batch.Set([]byte(\"iavl/legacyLatestVersion\"), []byte{1}) }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("c", {f["constraint"] for f in payload["failed_constraints"]})

    def test_internal_key_variable_then_batch_set_fails_c(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func seed(batch Batch){\n"
                "  key := []byte(\"rootmulti/internal-key/latestVersion\")\n"
                "  batch.Set(key, []byte{1})\n"
                "}\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("c", {f["constraint"] for f in payload["failed_constraints"]})

    def test_normal_user_key_set_passes_c(self):
        draft = _write_case(
            _draft(),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func seed(kv Store){ kv.Set([]byte(\"user-balance\"), []byte{1}) }\n"
                "func f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")


class ClauseDTests(unittest.TestCase):
    def test_network_level_claim_single_app_fails_d(self):
        draft = _write_case(
            _draft(extra="This is a network-level halt claim."),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func TestOne(){ app.Setup(false); _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("d", {f["constraint"] for f in payload["failed_constraints"]})

    def test_network_level_claim_four_validator_passes_d(self):
        draft = _write_case(
            _draft(extra="This is a network-level halt claim."),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func TestFour(){ cfg.NumValidators = 4; _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_single_validator_halt_wording_passes_d(self):
        draft = _write_case(
            _draft(impact="liveness failure", extra="This is a single-validator halt claim."),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc TestOne(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_cantina_202_v2_fixture_fails_d(self):
        draft = _write_case(
            _draft(extra="Network-level consensus halt."),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func TestRootmulti(){ rootmulti.NewStore(dbm.NewMemDB(), nil, nil) }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("d", {f["constraint"] for f in payload["failed_constraints"]})

    def test_cantina_202_v3_fixture_passes_d(self):
        draft = _write_case(
            _draft(extra="Network-level consensus halt. Bug class unchanged."),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "func TestProd(){ cfg.NumValidators = 4; _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")


class ClauseETests(unittest.TestCase):
    def test_timing_claim_without_envelope_fails_e(self):
        draft = _write_case(
            _draft(extra="Bug fires at >=10ms latency."),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("e", {f["constraint"] for f in payload["failed_constraints"]})

    def test_timing_claim_with_walkback_envelope_passes_e(self):
        draft = _write_case(
            _draft(
                severity="HIGH",
                extra=(
                    "Bug fires at >=10ms latency. Hardware envelope: dydx "
                    "validator hardware envelope recommends NVMe p99 <2ms; "
                    "outside envelope -> walk back to MEDIUM."
                ),
            ),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_no_timing_language_passes_e(self):
        draft = _write_case(
            _draft(impact="liveness failure"),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_cantina_201_v3_fixture_medium_out_of_scope(self):
        draft = _write_case(
            _draft(
                severity="MEDIUM",
                extra=(
                    "Bug fires at >=10ms latency. Hardware envelope: dydx "
                    "validator hardware envelope recommends NVMe p99 <2ms; "
                    "outside envelope -> walk back to MEDIUM."
                ),
            ),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "out-of-scope")


class ClauseFTests(unittest.TestCase):
    def test_bug_class_shift_without_disclosure_fails_f(self):
        draft = _write_case(
            _draft(extra="MemDB deadlock; GoLevelDB unlock of unlocked mutex."),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("f", {f["constraint"] for f in payload["failed_constraints"]})

    def test_bug_class_shift_with_disclosure_passes_f(self):
        draft = _write_case(
            _draft(
                extra=(
                    "MemDB deadlock; GoLevelDB unlock of unlocked mutex. "
                    "Bug class is unchanged: same root cause, same call-site, "
                    "trigger conditions are preserved, impact is preserved."
                ),
            ),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _, _ = dbm.NewGoLevelDB(\"x\", \"/tmp/x\") }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")


class RebuttalTests(unittest.TestCase):
    def test_rebuttal_can_cover_specific_clause_only(self):
        draft = _write_case(
            _draft(extra="<!-- r30-rebuttal: clause a acceptable for this fixture -->"),
            "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\nfunc f(){ _ = dbm.NewMemDB() }\n",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-with-rebuttal")

    def test_rebuttal_does_not_cover_unmentioned_clause(self):
        draft = _write_case(
            _draft(extra="<!-- r30-rebuttal: clause a acceptable -->"),
            (
                "package poc\nimport dbm \"github.com/cosmos/cosmos-db\"\n"
                "type slowBatchDB struct{ dbm.DB }\nfunc f(){ _ = dbm.NewMemDB() }\n"
            ),
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("b", {f["constraint"] for f in payload["failed_constraints"]})


class SubstrateTests(unittest.TestCase):
    def test_substrate_test_externalities_is_weak_backend_fails_a(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            (
                "use sp_io::TestExternalities;\n"
                "fn poc() { let mut ext = TestExternalities::new_empty(); "
                "ext.execute_with(|| {}); }\n"
            ),
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail")
        self.assertIn("a", {f["constraint"] for f in payload["failed_constraints"]})
        self.assertIn("rust", payload["poc_languages"])

    def test_substrate_new_test_ext_is_weak_backend_fails_a(self):
        draft = _write_case_lang(
            _draft(impact="halt the chain"),
            "fn poc() { new_test_ext().execute_with(|| { assert!(true); }); }\n",
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("a", {f["constraint"] for f in payload["failed_constraints"]})

    def test_substrate_rocksdb_backend_passes_a(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            (
                "use sc_client_db::Backend;\n"
                "fn poc() { let db = kvdb_rocksdb::Database::open(&cfg, path).unwrap(); "
                "let _ = sc_client_db::Backend::new(settings); }\n"
            ),
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_substrate_unsafe_transmute_fails_c(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            (
                "fn poc() {\n"
                "  let db = kvdb_rocksdb::Database::open(&cfg, path).unwrap();\n"
                "  unsafe { let p: *mut u64 = std::mem::transmute(&private_field); *p = 42; }\n"
                "}\n"
            ),
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("c", {f["constraint"] for f in payload["failed_constraints"]})


class EvmClientTests(unittest.TestCase):
    def test_evm_in_memory_memorydb_is_weak_backend_fails_a(self):
        draft = _write_case_lang(
            _draft(impact="apphash divergence"),
            (
                "fn poc() { let mut db = revm::db::CacheDB::new(revm::db::EmptyDB::default()); "
                "let _ = db; }\n"
            ),
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("a", {f["constraint"] for f in payload["failed_constraints"]})

    def test_evm_reth_db_backend_passes_a(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            "fn poc() { let db = reth_db::open_db(path, args).unwrap(); let _ = db; }\n",
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")

    def test_foundry_forked_mainnet_is_real_backend_passes_a(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            (
                "contract PoC {\n"
                "  function test() public {\n"
                "    uint256 fork = vm.createSelectFork(MAINNET_RPC);\n"
                "  }\n"
                "}\n"
            ),
            src_name="PoC.t.sol",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")
        self.assertIn("solidity", payload["poc_languages"])

    def test_foundry_vm_store_slot_seeding_fails_c(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            (
                "contract PoC {\n"
                "  function test() public {\n"
                "    uint256 fork = vm.createSelectFork(MAINNET_RPC);\n"
                "    vm.store(target, bytes32(uint256(3)), bytes32(uint256(1)));\n"
                "  }\n"
                "}\n"
            ),
            src_name="PoC.t.sol",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("c", {f["constraint"] for f in payload["failed_constraints"]})


class SolanaTests(unittest.TestCase):
    def test_solana_bank_new_for_tests_is_weak_backend_fails_a(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            (
                "fn poc() { let bank = Bank::new_for_tests(&genesis_config); "
                "let _ = AccountsDb::new_for_tests(); }\n"
            ),
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("a", {f["constraint"] for f in payload["failed_constraints"]})


class NodeBinaryTests(unittest.TestCase):
    def test_network_claim_geth_binary_spawns_pass_d(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure", extra="This is a network-level halt claim."),
            (
                "fn poc() {\n"
                "  let db = reth_db::open_db(path, args).unwrap();\n"
                "  let _a = Command::new(\"geth\").arg(\"--datadir\").spawn();\n"
                "  let _b = Command::new(\"geth\").arg(\"--datadir2\").spawn();\n"
                "}\n"
            ),
            src_name="poc.rs",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")


class TypeScriptTests(unittest.TestCase):
    def test_ts_object_defineproperty_private_field_fails_c(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            (
                "function poc() {\n"
                "  const db = reth_db.openDb(path);\n"
                "  Object.defineProperty(node, '_privateState', { value: 42 });\n"
                "}\n"
            ),
            src_name="poc.ts",
        )
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("c", {f["constraint"] for f in payload["failed_constraints"]})
        self.assertIn("typescript", payload["poc_languages"])


def _load_mod_with_env(env: dict[str, str]):
    """Re-exec the tool module under a temporary env so env-driven _compile()
    defaults are re-read. Returns a fresh module object."""
    import os

    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location(
            "production_profile_preflight_env",
            ROOT / "tools" / "production-profile-preflight-check.py",
        )
        fresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fresh)  # type: ignore[union-attr]
        return fresh
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class EnvOverrideTests(unittest.TestCase):
    def test_env_memdb_pattern_extends_defaults(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            "fn poc() { let db = ProjectMockBackend::new(); let _ = db; }\n",
            src_name="poc.rs",
        )
        # Without override: ProjectMockBackend is unrecognised; no real backend
        # either -> loud no-evidence fail (clause a), not a silent pass.
        rc0, payload0 = _run(draft)
        self.assertEqual(rc0, 1)
        # With override the custom weak-backend pattern is recognised -> still
        # clause-a fail, but now via the MemDB family.
        fresh = _load_mod_with_env({"AUDITOOOR_R30_MEMDB_PATTERNS": r"\bProjectMockBackend\b"})
        rc, payload = fresh.run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("a", {f["constraint"] for f in payload["failed_constraints"]})

    def test_env_real_backend_pattern_extends_defaults(self):
        draft = _write_case_lang(
            _draft(impact="liveness failure"),
            "fn poc() { let db = ProjectMockBackend::new(); let _ = db; }\n",
            src_name="poc.rs",
        )
        fresh = _load_mod_with_env(
            {"AUDITOOOR_R30_REAL_BACKEND_PATTERNS": r"\bProjectMockBackend\b"}
        )
        rc, payload = fresh.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")


if __name__ == "__main__":
    unittest.main()
