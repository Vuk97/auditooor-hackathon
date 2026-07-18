"""Tests for tools/access-control-coverage.py (ACL-COV lane).

All tests are hermetic - they mock subprocess calls so no real Slither,
Go toolchain, or Rust compiler is needed.

Test cases:
  (a) Adapter normalizes a fake Go-sentinel JSON into needs-fuzz records.
  (b) Slither-absent -> Solidity arm skipped cleanly (no crash, typed-skip note).
  (c) Every emitted record has verdict=needs-fuzz (except typed-skip notes).
  (d) An OOS/test-file hit is dropped by scope_exclusion.
  (e) auto-coverage-closer fold produces an [ACL-COV] question.
  (f) REGEX-FALLBACK: Slither timeout -> fallback fires, clearly labeled.
  (g) REGEX-FALLBACK: unguarded setFeeRecipient is flagged.
  (h) REGEX-FALLBACK: onlyOwner setFeeRecipient is NOT flagged.
  (i) REGRESSION: upgradeTo delegating to _authorizeUpgrade is NOT flagged.
  (j) REGRESSION: view getter is NOT flagged.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure the tools/ directory is importable.
# ---------------------------------------------------------------------------
_TOOLS = Path(__file__).resolve().parent.parent   # tools/
_REPO  = _TOOLS.parent                            # repo root
for _p in [str(_TOOLS), str(_REPO)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

import importlib.util as _ilu
_acl_spec = _ilu.spec_from_file_location(
    "access_control_coverage", _TOOLS / "access-control-coverage.py"
)
acl_cov = _ilu.module_from_spec(_acl_spec)  # type: ignore
_acl_spec.loader.exec_module(acl_cov)  # type: ignore
# Register under a stable name so patch() can find the subprocess attribute.
sys.modules["access_control_coverage"] = acl_cov  # type: ignore


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
def _make_ws(tmp: Path, *, go: bool = False, sol: bool = False, rs: bool = False) -> Path:
    """Create a minimal workspace directory with the requested language stubs."""
    ws = tmp / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor").mkdir(exist_ok=True)
    if go:
        (ws / "x").mkdir(exist_ok=True)
        (ws / "x" / "keeper.go").write_text("package x\n", encoding="utf-8")
    if sol:
        (ws / "src").mkdir(exist_ok=True)
        (ws / "src" / "Vault.sol").write_text("// SPDX\n", encoding="utf-8")
    if rs:
        (ws / "src").mkdir(exist_ok=True)
        (ws / "src" / "lib.rs").write_text("// rust\n", encoding="utf-8")
    return ws


def _fake_go_sentinel_payload(ws: Path, count: int = 2) -> dict:
    sentinels = []
    for i in range(count):
        sentinels.append({
            "file": str(ws / "x" / "keeper.go"),
            "method": f"SetParam{i}",
            "pattern": "A",
            "evidence": f"k.SetParams(ctx, params) at line {10 + i}",
            "severity_hint": "HIGH",
        })
    return {
        "schema": "auditooor.go_permissionless_admin_key_sentinel.v1",
        "root": str(ws),
        "count": count,
        "sentinels": sentinels,
    }


# ---------------------------------------------------------------------------
# Test (a): adapter normalizes fake Go-sentinel JSON into needs-fuzz records.
# ---------------------------------------------------------------------------
class TestGoArmNormalization(unittest.TestCase):
    def test_go_hits_normalized_to_needs_fuzz(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), go=True)
            payload = _fake_go_sentinel_payload(ws, count=2)

            # Patch subprocess.run to return a successful go-sentinel call.
            fake_result = MagicMock()
            fake_result.returncode = 0
            fake_result.stderr = ""

            def fake_subprocess_run(cmd, **kwargs):
                # The Go arm writes --out to a temp file; capture that path.
                out_idx = cmd.index("--out") + 1
                out_path = Path(cmd[out_idx])
                out_path.write_text(json.dumps(payload), encoding="utf-8")
                return fake_result

            with patch("access_control_coverage.subprocess.run", side_effect=fake_subprocess_run):
                # Also patch away the Solidity arm (no .sol files, so it won't
                # run, but we patch _has_language for solidity to be safe).
                summary = acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")

            out = ws / ".auditooor" / "access_control_hypotheses.jsonl"
            self.assertTrue(out.is_file(), "sidecar JSONL not written")
            lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            hypothesis_records = [r for r in lines if r.get("verdict") == "needs-fuzz"]
            self.assertEqual(len(hypothesis_records), 2, f"expected 2 needs-fuzz records, got {len(hypothesis_records)}: {lines}")
            for rec in hypothesis_records:
                self.assertEqual(rec["verdict"], "needs-fuzz")
                self.assertEqual(rec["source"], "ACL-COV")
                self.assertEqual(rec["attack_class"], "missing-authorization-privilege-escalation")
                self.assertIn("guard_check", rec)
                self.assertEqual(rec["guard_check"], "UNGUARDED")
                self.assertEqual(rec["language"], "go")


# ---------------------------------------------------------------------------
# Test (b): Slither absent -> Solidity arm skipped cleanly, no crash.
# ---------------------------------------------------------------------------
class TestSolidityArmSlitherAbsent(unittest.TestCase):
    def test_slither_absent_skipped_with_typed_skip_note(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), sol=True)

            # acl-matrix.py exits non-zero and prints "[err] Slither required"
            fake_result = MagicMock()
            fake_result.returncode = 1
            fake_result.stderr = "[err] Slither required"
            fake_result.stdout = ""

            with patch("access_control_coverage.subprocess.run", return_value=fake_result):
                # Should not raise.
                try:
                    summary = acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")
                except Exception as exc:
                    self.fail(f"run() raised unexpectedly: {exc}")

            out = ws / ".auditooor" / "access_control_hypotheses.jsonl"
            self.assertTrue(out.is_file(), "sidecar JSONL not written even for skip")
            lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            skip_records = [r for r in lines if r.get("_acl_skip") or r.get("verdict") == "typed-skip"]
            self.assertGreaterEqual(len(skip_records), 1, "expected at least one typed-skip note")
            # The skip note must mention Slither or the language.
            skip_reasons = [r.get("reason", "") + r.get("language", "") for r in skip_records]
            self.assertTrue(
                any("lither" in r or "solidity" in r for r in skip_reasons),
                f"skip note should mention Slither/solidity: {skip_records}",
            )
            # summary should not crash - arms key exists.
            self.assertIn("arms", summary)

    def test_slither_absent_does_not_crash_no_sol_files(self):
        """When there are no .sol files the Solidity arm is simply skipped - no subprocess call."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td))  # no languages
            with patch("access_control_coverage.subprocess.run") as mock_run:
                summary = acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")
                mock_run.assert_not_called()
            self.assertEqual(summary["hypotheses"], 0)


# ---------------------------------------------------------------------------
# Test (c): every emitted non-skip record has verdict=needs-fuzz.
# ---------------------------------------------------------------------------
class TestAllRecordsNeedsFuzz(unittest.TestCase):
    def test_all_hypothesis_records_needs_fuzz(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), go=True)
            payload = _fake_go_sentinel_payload(ws, count=3)

            fake_result = MagicMock()
            fake_result.returncode = 0
            fake_result.stderr = ""

            def fake_subprocess_run(cmd, **kwargs):
                out_idx = cmd.index("--out") + 1
                Path(cmd[out_idx]).write_text(json.dumps(payload), encoding="utf-8")
                return fake_result

            with patch("access_control_coverage.subprocess.run", side_effect=fake_subprocess_run):
                acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")

            out = ws / ".auditooor" / "access_control_hypotheses.jsonl"
            lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            for rec in lines:
                if rec.get("_acl_skip") or rec.get("verdict") == "typed-skip":
                    continue
                self.assertEqual(
                    rec["verdict"], "needs-fuzz",
                    f"record has unexpected verdict: {rec}"
                )


# ---------------------------------------------------------------------------
# Test (d): OOS/test-file hits are dropped by scope_exclusion.
# ---------------------------------------------------------------------------
class TestOOSFilesDropped(unittest.TestCase):
    def test_test_file_hit_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), go=True)
            # Fabricate a sentinel whose file is under tests/ (OOS).
            oos_file = str(ws / "tests" / "keeper_test.go")
            payload = {
                "schema": "auditooor.go_permissionless_admin_key_sentinel.v1",
                "root": str(ws),
                "count": 1,
                "sentinels": [{
                    "file": oos_file,
                    "method": "SetOOSParam",
                    "pattern": "A",
                    "evidence": "k.SetParams(ctx, params)",
                    "severity_hint": "HIGH",
                }],
            }

            fake_result = MagicMock()
            fake_result.returncode = 0
            fake_result.stderr = ""

            def fake_subprocess_run(cmd, **kwargs):
                out_idx = cmd.index("--out") + 1
                Path(cmd[out_idx]).write_text(json.dumps(payload), encoding="utf-8")
                return fake_result

            with patch("access_control_coverage.subprocess.run", side_effect=fake_subprocess_run):
                summary = acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")

            self.assertEqual(summary["hypotheses"], 0, "OOS hit should have been dropped")
            self.assertGreaterEqual(summary["oos_dropped"], 1)

    def test_auditooor_dir_hit_dropped(self):
        """A hit whose file is inside .auditooor/ must be dropped."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), go=True)
            internal_file = str(ws / ".auditooor" / "some_gen.go")
            payload = {
                "schema": "auditooor.go_permissionless_admin_key_sentinel.v1",
                "root": str(ws),
                "count": 1,
                "sentinels": [{
                    "file": internal_file,
                    "method": "SomeGenFn",
                    "pattern": "A",
                    "evidence": "k.Set(ctx, v)",
                    "severity_hint": "HIGH",
                }],
            }

            fake_result = MagicMock()
            fake_result.returncode = 0
            fake_result.stderr = ""

            def fake_subprocess_run(cmd, **kwargs):
                out_idx = cmd.index("--out") + 1
                Path(cmd[out_idx]).write_text(json.dumps(payload), encoding="utf-8")
                return fake_result

            with patch("access_control_coverage.subprocess.run", side_effect=fake_subprocess_run):
                summary = acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")

            self.assertEqual(summary["hypotheses"], 0, ".auditooor hit should be dropped")


# ---------------------------------------------------------------------------
# Test (d2): Go arm passes --entrypoints-only to D8 sentinel subprocess.
# ---------------------------------------------------------------------------
class TestGoArmPassesEntrypointsOnly(unittest.TestCase):
    def test_go_arm_invokes_d8_with_entrypoints_only(self):
        """The Go arm must invoke go_permissionless_admin_key_sentinel with
        --entrypoints-only so the adapter drops bare Keeper helper false positives."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), go=True)
            payload = _fake_go_sentinel_payload(ws, count=1)

            captured_cmds: list[list] = []

            fake_result = MagicMock()
            fake_result.returncode = 0
            fake_result.stderr = ""

            def fake_subprocess_run(cmd, **kwargs):
                captured_cmds.append(list(cmd))
                out_idx = cmd.index("--out") + 1
                Path(cmd[out_idx]).write_text(json.dumps(payload), encoding="utf-8")
                return fake_result

            with patch("access_control_coverage.subprocess.run", side_effect=fake_subprocess_run):
                acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")

            # Find the go-sentinel invocation.
            go_invocations = [c for c in captured_cmds if "go_permissionless_admin_key_sentinel" in " ".join(c)]
            self.assertGreaterEqual(len(go_invocations), 1,
                                    f"expected at least one go-sentinel invocation; got cmds: {captured_cmds}")
            go_cmd = go_invocations[0]
            self.assertIn("--entrypoints-only", go_cmd,
                          f"Go arm must pass --entrypoints-only to D8 sentinel; cmd was: {go_cmd}")


# ---------------------------------------------------------------------------
# Test (d3): Solidity arm passes narrowed in-scope root to acl-matrix.
# ---------------------------------------------------------------------------
class TestSolArmNarrowedRoot(unittest.TestCase):
    def test_sol_arm_passes_narrowed_root_to_acl_matrix(self):
        """When resolve_source_roots returns a narrowed src/ root, the Solidity
        arm invokes acl-matrix with that root rather than the whole workspace,
        so Slither avoids compiling node_modules/lib/test."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), sol=True)
            # Create a src/ subdir with a .sol file (simulating a narrowed root).
            src_dir = ws / "src"
            src_dir.mkdir(exist_ok=True)
            (src_dir / "Protocol.sol").write_text("// SPDX\n", encoding="utf-8")

            captured_cmds: list[list] = []

            fake_result = MagicMock()
            fake_result.returncode = 1
            fake_result.stderr = "[err] Slither required"  # Slither absent - honest skip
            fake_result.stdout = ""

            def fake_subprocess_run(cmd, **kwargs):
                captured_cmds.append(list(cmd))
                return fake_result

            # Patch resolve_source_roots to return the narrowed src/ root.
            with patch("access_control_coverage.resolve_source_roots", return_value=[src_dir]):
                with patch("access_control_coverage.subprocess.run", side_effect=fake_subprocess_run):
                    summary = acl_cov.run(ws, ws / ".auditooor" / "access_control_hypotheses.jsonl")

            sol_invocations = [c for c in captured_cmds if "acl-matrix" in " ".join(c)]
            self.assertGreaterEqual(len(sol_invocations), 1,
                                    f"expected acl-matrix invocation; cmds: {captured_cmds}")
            sol_cmd = sol_invocations[0]
            # The path passed to acl-matrix should be the narrowed src/ root, not ws.
            passed_root = sol_cmd[-1]
            self.assertEqual(
                passed_root, str(src_dir),
                f"acl-matrix should be called with narrowed src/ root; got: {passed_root}"
            )
            self.assertNotEqual(
                passed_root, str(ws),
                "acl-matrix should NOT be called with the whole workspace when a narrowed root exists"
            )


# ---------------------------------------------------------------------------
# Test (e): auto-coverage-closer fold produces an [ACL-COV] question.
# ---------------------------------------------------------------------------
class TestAutoCoverageCloserFold(unittest.TestCase):
    """Verify that _fold_lane_hypotheses_into_corpus synthesizes [ACL-COV] questions."""

    def _find_fold_fn(self):
        """Import auto-coverage-closer and extract the fold function."""
        spec_path = _TOOLS / "auto-coverage-closer.py"
        import importlib.util
        spec = importlib.util.spec_from_file_location("auto_coverage_closer", spec_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_acl_cov_question_synthesized(self):
        mod = self._find_fold_fn()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)

            # Write a fake ACL-COV hypotheses JSONL.
            acl_jsonl = ws / ".auditooor" / "access_control_hypotheses.jsonl"
            record = {
                "file": "x/keeper/msg_server.go",
                "function": "UpdateParams",
                "language": "go",
                "admin_action": "pattern=A; k.SetParams(ctx, params)",
                "guard_check": "UNGUARDED",
                "guard_reason": "MsgServer method writes state without authority check (Pattern A)",
                "attack_class": "missing-authorization-privilege-escalation",
                "source": "ACL-COV",
                "verdict": "needs-fuzz",
                "fuzz_oracle_hint": "Write a test...",
            }
            acl_jsonl.write_text(json.dumps(record) + "\n", encoding="utf-8")

            # Call the fold function.
            result = mod._fold_lane_hypotheses_into_corpus(ws, "test-run-id")
            self.assertIn("appended", result)
            self.assertGreaterEqual(result["appended"], 1, f"expected >=1 appended record: {result}")

            # Check the output corpus contains an [ACL-COV] question.
            pfhq_path = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
            self.assertTrue(pfhq_path.is_file(), "per_fn_hacker_questions.jsonl not written")
            lines = [json.loads(l) for l in pfhq_path.read_text().splitlines() if l.strip()]
            acl_questions = [r for r in lines if "[ACL-COV]" in r.get("question", "")]
            self.assertGreaterEqual(len(acl_questions), 1, f"no [ACL-COV] question in corpus: {lines}")
            q = acl_questions[0]
            self.assertEqual(q["verdict"], "needs-fuzz")
            self.assertEqual(q["source"], "ACL-COV")
            self.assertIn("UpdateParams", q["question"])

    def test_acl_cov_typed_skip_note_not_synthesized(self):
        """Typed-skip records in the JSONL must NOT produce a question."""
        mod = self._find_fold_fn()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)

            acl_jsonl = ws / ".auditooor" / "access_control_hypotheses.jsonl"
            skip_note = {
                "_acl_skip": True,
                "language": "solidity",
                "reason": "Slither not installed",
                "source": "ACL-COV",
                "verdict": "typed-skip",
            }
            acl_jsonl.write_text(json.dumps(skip_note) + "\n", encoding="utf-8")

            result = mod._fold_lane_hypotheses_into_corpus(ws, "test-run-id")
            # 0 appended - skip notes are filtered.
            self.assertEqual(result.get("appended", 0), 0,
                             f"typed-skip should not produce a question: {result}")


# ---------------------------------------------------------------------------
# Helpers for regex fallback tests - write minimal Solidity files to a tmpdir.
# ---------------------------------------------------------------------------

def _write_sol(ws: Path, rel_path: str, content: str) -> Path:
    """Write a Solidity source file under ws and return its Path."""
    p = ws / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Test (f): Slither timeout -> fallback fires, records clearly labeled.
# ---------------------------------------------------------------------------
class TestRegexFallbackOnTimeout(unittest.TestCase):
    def test_timeout_triggers_fallback_with_label(self):
        """When acl-matrix times out, the fallback runs and records carry
        source=ACL-COV-REGEX-FALLBACK, plus a typed-skip note is still written."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), sol=True)
            # Write a .sol file with an unguarded admin fn.
            _write_sol(ws, "src/Fee.sol", """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract FeeManager {
    address public feeRecipient;
    function setFeeRecipient(address _r) external {
        feeRecipient = _r;
    }
}
""")

            import subprocess as _sp

            def fake_subprocess_run(cmd, **kwargs):
                raise _sp.TimeoutExpired(cmd, timeout=300)

            with patch("access_control_coverage.subprocess.run", side_effect=fake_subprocess_run):
                summary = acl_cov.run(
                    ws, ws / ".auditooor" / "access_control_hypotheses.jsonl"
                )

            out = ws / ".auditooor" / "access_control_hypotheses.jsonl"
            self.assertTrue(out.is_file())
            lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

            # Must have at least one typed-skip note.
            skip_records = [r for r in lines if r.get("verdict") == "typed-skip"]
            self.assertGreaterEqual(len(skip_records), 1, "expected typed-skip note")
            skip_reasons = " ".join(r.get("reason", "") for r in skip_records)
            self.assertIn("regex fallback", skip_reasons.lower(),
                          "skip note should mention regex fallback")

            # Must have at least one fallback hypothesis record.
            fallback_records = [
                r for r in lines
                if r.get("source") == "ACL-COV-REGEX-FALLBACK"
                and r.get("verdict") == "needs-fuzz"
            ]
            self.assertGreaterEqual(
                len(fallback_records), 1,
                f"expected >=1 ACL-COV-REGEX-FALLBACK record; got: {lines}"
            )
            # Every fallback record must have DEGRADED in guard_reason.
            for rec in fallback_records:
                self.assertIn(
                    "DEGRADED", rec.get("guard_reason", ""),
                    f"fallback record must be labeled DEGRADED: {rec}"
                )

            # summary must report fallback in the solidity arm entry.
            self.assertIn("arms", summary)
            sol_status = summary["arms"].get("solidity", "")
            self.assertIn("regex-fallback", sol_status.lower(),
                          f"arm summary should mention regex-fallback: {sol_status}")


# ---------------------------------------------------------------------------
# Test (g): unguarded setFeeRecipient is flagged by the regex fallback.
# ---------------------------------------------------------------------------
class TestRegexFallbackFlagsUnguarded(unittest.TestCase):
    def test_unguarded_setFeeRecipient_flagged(self):
        """An unguarded setFeeRecipient must appear in fallback results."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            _write_sol(ws, "src/Fee.sol", """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract FeeManager {
    address public feeRecipient;
    function setFeeRecipient(address _r) external {
        feeRecipient = _r;
    }
}
""")
            hits = acl_cov._run_solidity_regex_fallback(ws)
            fn_names = [h["function"] for h in hits]
            self.assertIn(
                "setFeeRecipient", fn_names,
                f"expected setFeeRecipient flagged; got: {fn_names}"
            )


# ---------------------------------------------------------------------------
# Test (h): onlyOwner setFeeRecipient is NOT flagged by the regex fallback.
# ---------------------------------------------------------------------------
class TestRegexFallbackSkipsOnlyOwner(unittest.TestCase):
    def test_onlyOwner_setFeeRecipient_not_flagged(self):
        """A setFeeRecipient guarded by onlyOwner must NOT be flagged."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            _write_sol(ws, "src/Fee.sol", """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
contract FeeManager is Ownable {
    address public feeRecipient;
    function setFeeRecipient(address _r) external onlyOwner {
        feeRecipient = _r;
    }
}
""")
            hits = acl_cov._run_solidity_regex_fallback(ws)
            fn_names = [h["function"] for h in hits]
            self.assertNotIn(
                "setFeeRecipient", fn_names,
                f"onlyOwner setFeeRecipient should NOT be flagged; got: {fn_names}"
            )


# ---------------------------------------------------------------------------
# Test (i): REGRESSION - upgradeTo delegating to _authorizeUpgrade NOT flagged.
# ---------------------------------------------------------------------------
class TestRegexFallbackUpgradeToNotFlagged(unittest.TestCase):
    def test_upgradeTo_authorizeUpgrade_delegation_not_flagged(self):
        """upgradeTo that calls _authorizeUpgrade() in its body must NOT be
        flagged - this is the UUPS delegation pattern (the FP that caused the
        original revert)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            _write_sol(ws, "src/WellUpgradeable.sol", """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {UUPSUpgradeable} from "ozu/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "ozu/access/OwnableUpgradeable.sol";
contract WellUpgradeable is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address newImplementation)
        internal view override onlyOwner
    {
        // real guard lives here
    }
    function upgradeTo(address newImplementation) public override {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
    }
    function upgradeToAndCall(address newImplementation, bytes memory data)
        public payable override
    {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data, true);
    }
}
""")
            hits = acl_cov._run_solidity_regex_fallback(ws)
            fn_names = [h["function"] for h in hits]
            self.assertNotIn(
                "upgradeTo", fn_names,
                f"upgradeTo delegating to _authorizeUpgrade must NOT be flagged; got: {fn_names}"
            )
            self.assertNotIn(
                "upgradeToAndCall", fn_names,
                f"upgradeToAndCall delegating to _authorizeUpgrade must NOT be flagged; got: {fn_names}"
            )

    def test_upgradeTo_without_delegation_flagged(self):
        """upgradeTo that does NOT call _authorizeUpgrade and has no guard
        modifier SHOULD be flagged (the true positive case)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            _write_sol(ws, "src/BadUpgrade.sol", """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract BadUpgrade {
    function upgradeTo(address newImplementation) public {
        // no guard at all - should be flagged
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
    }
}
""")
            hits = acl_cov._run_solidity_regex_fallback(ws)
            fn_names = [h["function"] for h in hits]
            self.assertIn(
                "upgradeTo", fn_names,
                f"upgradeTo without any guard must be flagged; got: {fn_names}"
            )


# ---------------------------------------------------------------------------
# Test (j): view getter is NOT flagged.
# ---------------------------------------------------------------------------
class TestRegexFallbackSkipsViewGetter(unittest.TestCase):
    def test_view_getter_not_flagged(self):
        """A view/pure function must never be flagged even if name matches."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            _write_sol(ws, "src/Getter.sol", """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MyContract {
    uint256 public fee;
    function getFee() external view returns (uint256) {
        return fee;
    }
    function setFeeView(uint256 f) external view returns (uint256) {
        return f;
    }
}
""")
            hits = acl_cov._run_solidity_regex_fallback(ws)
            fn_names = [h["function"] for h in hits]
            self.assertNotIn(
                "setFeeView", fn_names,
                f"view function must NOT be flagged; got: {fn_names}"
            )


if __name__ == "__main__":
    unittest.main()
