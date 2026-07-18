#!/usr/bin/env python3
# <!-- r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json -->
"""Regression tests for the 8 fail-closed fixes in audit-completeness-check.py.

Each test exercises exactly the hollow path that was previously WARN-passing and
asserts that it now returns ok=False (or a non-pass-audit-complete verdict) under
the relevant strict / enforcement env.

Tests are driven via the CLI (subprocess) wherever possible.  For tests that
require module-level monkeypatching (honesty/depth-cert tooling absence, function-
coverage bad-return), the module is imported with sys.modules registration (required
for Python 3.14 @dataclass resolution) and patched in-process.

These tests do NOT modify any tool file.  They build ephemeral tmp workspace
fixtures and clean them up in tearDown.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit-completeness-check.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(ws: Path, env_extra: dict | None = None, extra_args: list[str] | None = None):
    """Run the CLI and return (returncode, parsed-json-payload)."""
    env = {**os.environ, **(env_extra or {})}
    proc = subprocess.run(
        [sys.executable, str(_TOOL), str(ws), "--json"] + (extra_args or []),
        capture_output=True, text=True, env=env,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"verdict": "error", "raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
    return proc.returncode, payload


def _run_strict(ws: Path, env_extra: dict | None = None):
    """Run the CLI with --strict flag."""
    return _run(ws, env_extra=env_extra, extra_args=["--strict"])


def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def _mk_bare_ws() -> Path:
    """Minimal workspace: just the .auditooor dir and a Solidity source file."""
    ws = Path(tempfile.mkdtemp(prefix="l37_strict_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(parents=True, exist_ok=True)
    (ws / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Vault {}\n", encoding="utf-8"
    )
    return ws


def _load_acc_module():
    """Import audit-completeness-check.py with sys.modules registration.

    Python 3.14 requires the module to be registered before exec_module so
    @dataclass resolution can find the owning module dict via sys.modules.
    """
    mod_name = "_acc_strict_test_mod"
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    spec = importlib.util.spec_from_file_location(mod_name, _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fix 1: --strict CLI flag now sets AUDITOOOR_L37_STRICT=1
# ---------------------------------------------------------------------------

class TestStrictFlagSetsGlobalEnv(unittest.TestCase):
    """Bug L6771: --strict did not set AUDITOOOR_L37_STRICT so _l37_gate_strict()
    returned False for all deep signals (tier6-mining, chain-synth, ...).
    After fix: --strict implicitly enables AUDITOOOR_L37_STRICT=1."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix1_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_strict_flag_propagates_to_l37_global(self):
        """Under --strict, a hollow chain-synth artifact must fail (tier6 is
        the first signal so we use tier6-mining as a proxy)."""
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws")
        ws = self._tmp / "ws"

        # Create a mining_rounds dir with a round that has only a hollow stub
        rd = ws / "mining_rounds" / "round1"
        rd.mkdir(parents=True)
        # No CLOSEOUT.md, no JSON - hollow by design
        # Without fix: --strict would WARN-pass and the signal would be ok=True.
        # After fix: _l37_gate_strict("TIER6_MINING") returns True and the
        #            hollow-mining branch fails closed.

        rc, out = _run_strict(ws)
        # The workspace should NOT pass (tier6-mining or other signals will fail).
        self.assertNotEqual(
            out.get("verdict"), "pass-audit-complete",
            f"--strict on hollow workspace must not pass; got: {out.get('verdict')}",
        )
        # Under strict mode, tier6-mining signal must be ok=False (not WARN-pass)
        tier6_sigs = [s for s in out.get("signals", []) if s["signal"] == "tier6-mining"]
        if tier6_sigs:
            self.assertFalse(
                tier6_sigs[0]["ok"],
                "tier6-mining must fail closed under --strict with hollow mining_rounds",
            )
            reason = tier6_sigs[0].get("reason", "")
            self.assertNotIn(
                "WARN:", reason,
                "Strict-mode tier6-mining reason must not contain WARN:",
            )


# ---------------------------------------------------------------------------
# Fix 2: honesty / depth-cert tooling absence must fail closed under strict
# ---------------------------------------------------------------------------

class TestToolingAbsenceFailsClosedUnderStrict(unittest.TestCase):
    """Bug L5898: check_honesty and check_depth_certificate returned ok=True
    unconditionally when their sub-tool was absent, even under STRICT mode."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix2_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws(self) -> Path:
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws")
        return self._tmp / "ws"

    def test_honesty_tooling_absent_fails_in_strict_mode(self):
        """check_honesty must return ok=False when audit-honesty-check.py is
        absent and AUDITOOOR_L37_STRICT=1."""
        ws = self._ws()
        acc = _load_acc_module()
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_audit_honesty_module",
            return_value=None,
        ):
            with mock.patch.dict(os.environ, {"AUDITOOOR_L37_STRICT": "1"}):
                result = acc.check_honesty(ws)
        self.assertFalse(
            result.ok,
            "check_honesty must fail closed (ok=False) when audit-honesty-check.py "
            "is absent under AUDITOOOR_L37_STRICT=1",
        )
        self.assertIn(
            "STRICT", result.reason,
            "Reason must mention STRICT when failing due to tooling absence in strict mode",
        )

    def test_honesty_tooling_absent_warn_passes_outside_strict(self):
        """Non-regression: absent honesty tool must still WARN-pass without strict."""
        ws = self._ws()
        acc = _load_acc_module()
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_HONESTY_STRICT",
                         "ENFORCE_AUTONOMOUS_PROOF_CONVERSION")
        }
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_audit_honesty_module",
            return_value=None,
        ):
            with mock.patch.dict(os.environ, clean_env, clear=True):
                result = acc.check_honesty(ws)
        self.assertTrue(
            result.ok,
            "check_honesty must WARN-pass (ok=True) when tooling absent and NOT in strict",
        )

    def test_depth_cert_tooling_absent_fails_in_strict_mode(self):
        """check_depth_certificate must return ok=False when depth-certificate-check.py
        is absent and AUDITOOOR_L37_STRICT=1."""
        ws = self._ws()
        acc = _load_acc_module()
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_depth_cert_module",
            return_value=None,
        ):
            with mock.patch.dict(os.environ, {"AUDITOOOR_L37_STRICT": "1"}):
                result = acc.check_depth_certificate(ws)
        self.assertFalse(
            result.ok,
            "check_depth_certificate must fail closed when depth tool absent under STRICT=1",
        )
        self.assertIn("STRICT", result.reason)

    def test_depth_cert_tooling_absent_warn_passes_outside_strict(self):
        """Non-regression: absent depth tool must WARN-pass without strict."""
        ws = self._ws()
        acc = _load_acc_module()
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_DEPTH_CERTIFICATE_STRICT",
                         "ENFORCE_AUTONOMOUS_PROOF_CONVERSION")
        }
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_depth_cert_module",
            return_value=None,
        ):
            with mock.patch.dict(os.environ, clean_env, clear=True):
                result = acc.check_depth_certificate(ws)
        self.assertTrue(result.ok, "depth-cert must WARN-pass when absent and not strict")

    def test_depth_cert_stale_verdict_fails_unconditionally(self):
        """Bug (strata 2026-07-01, loop-caught): fail-depth-stale must FAIL
        check_depth_certificate unconditionally (matching its sibling verdicts
        fail-depth-pending/fail-depth-not-run/etc, none of which are strict-
        gated) - NOT warn-pass. The tool's own docstring names this exact
        scenario "the ~537x-stale-cert failure mode that kept a workspace
        silently at depth-pending while the cert claimed otherwise"."""
        ws = self._ws()
        acc = _load_acc_module()
        fake_mod = mock.Mock()
        fake_mod.check_depth = mock.Mock(return_value={
            "verdict": "fail-depth-stale",
            "reason": "depth_certificate.json is STALE: built before its inputs "
                      "were last regenerated",
            "cert_path": str(ws / ".auditooor" / "depth_certificate.json"),
        })
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_depth_cert_module",
            return_value=fake_mod,
        ):
            clean_env = {
                k: v for k, v in os.environ.items()
                if k not in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_DEPTH_CERTIFICATE_STRICT",
                             "ENFORCE_AUTONOMOUS_PROOF_CONVERSION")
            }
            with mock.patch.dict(os.environ, clean_env, clear=True):
                result = acc.check_depth_certificate(ws)
        self.assertFalse(
            result.ok,
            "fail-depth-stale must FAIL check_depth_certificate unconditionally "
            "(not warn-pass), even outside strict",
        )
        self.assertIn("stale", result.reason.lower())


# ---------------------------------------------------------------------------
# Fix 3: CLOSEOUT.md boilerplate must not certify mining as genuine
# ---------------------------------------------------------------------------

class TestTier6CloseoutBoilerplate(unittest.TestCase):
    """Bug L777: any 200+ char text in CLOSEOUT.md certified a round as genuine.
    After fix: requires at least one real mining marker (SHA / commits_scanned /
    security_fix_count / targets_processed) and must not contain boilerplate."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix3_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws(self) -> Path:
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws")
        return self._tmp / "ws"

    def test_boilerplate_closeout_does_not_certify_genuine(self):
        """A CLOSEOUT.md that contains known boilerplate phrases must NOT
        certify the round as genuinely ran, even if it is 200+ chars."""
        ws = self._ws()
        acc = _load_acc_module()
        rd = ws / "mining_rounds" / "round1"
        rd.mkdir(parents=True)
        boilerplate = (
            "This is a placeholder mining round closeout document. "
            "No targets were processed. No commits were scanned. "
            "This text is over two hundred characters long to pass the naive "
            "length check and should not be accepted as genuine mining evidence "
            "under any strict reading of the validator."
        )
        assert len(boilerplate.strip()) >= 200
        (rd / "CLOSEOUT.md").write_text(boilerplate, encoding="utf-8")

        # ENFORCE_AUTONOMOUS_PROOF_CONVERSION drives strict for tier6
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            result = acc.check_tier6_mining(ws)
        self.assertFalse(
            result.ok,
            f"Boilerplate CLOSEOUT.md must not certify genuine mining; got ok=True. "
            f"Reason: {result.reason}",
        )

    def test_real_sha_in_closeout_certifies_genuine(self):
        """A CLOSEOUT.md with a real 40-hex SHA must pass as genuine."""
        ws = self._ws()
        acc = _load_acc_module()
        rd = ws / "mining_rounds" / "round1"
        rd.mkdir(parents=True)
        real_content = (
            "Mining round 1 completed.\n"
            "Commit analyzed: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
            "Found 3 security-relevant commits. All patterns checked against "
            "the corpus. No novel bypass patterns found in this range."
        )
        (rd / "CLOSEOUT.md").write_text(real_content, encoding="utf-8")

        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            result = acc.check_tier6_mining(ws)
        self.assertTrue(
            result.ok,
            f"CLOSEOUT.md with a real SHA must pass; got ok=False. Reason: {result.reason}",
        )

    def test_commits_scanned_line_certifies_genuine(self):
        """A CLOSEOUT.md with 'commits_scanned: N' where N>0 must pass (with
        sufficient length to meet the 200-char threshold too).
        r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json"""
        ws = self._ws()
        acc = _load_acc_module()
        rd = ws / "mining_rounds" / "round1"
        rd.mkdir(parents=True)
        real_content = (
            "Mining summary for target: foo-protocol v2.3.1\n"
            "commits_scanned: 47\n"
            "security_fix_count: 2\n"
            "Range: v1.0.0..v1.2.3\n"
            "Status: complete\n"
            "Notes: Bidirectional scan completed. Forward mining from pinned commit to HEAD "
            "found 2 security-relevant patches. Backward mining across 47 commits found no "
            "additional reverted guards. All findings indexed."
        )
        assert len(real_content.strip()) >= 200, f"test content too short: {len(real_content)}"
        (rd / "CLOSEOUT.md").write_text(real_content, encoding="utf-8")

        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            result = acc.check_tier6_mining(ws)
        self.assertTrue(
            result.ok,
            f"CLOSEOUT.md with commits_scanned: N>0 must pass; got ok=False. "
            f"Reason: {result.reason}",
        )

    def test_200_char_random_text_no_marker_does_not_certify(self):
        """A 200+ char CLOSEOUT.md without any mining marker must NOT certify."""
        ws = self._ws()
        acc = _load_acc_module()
        rd = ws / "mining_rounds" / "round1"
        rd.mkdir(parents=True)
        # 200+ chars of non-boilerplate, non-marker text (no SHA, no commits line)
        filler = "x" * 210
        (rd / "CLOSEOUT.md").write_text(filler, encoding="utf-8")

        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            result = acc.check_tier6_mining(ws)
        self.assertFalse(
            result.ok,
            f"200-char filler text without a mining marker must not certify genuine; "
            f"got ok=True. Reason: {result.reason}",
        )


# ---------------------------------------------------------------------------
# Fix 4: require( in src/ must not certify a stub harness as genuine
# ---------------------------------------------------------------------------

class TestSrcRequireDoesNotCertifyHarnessGenuine(unittest.TestCase):
    """Bug L1238: require( in src/ (imported contract) falsely certified a
    stub harness as genuine in _authored_harnesses_genuinely_executed_completeness.
    After fix: only test/ is scanned for genuine assertions."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix4_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_require_in_src_does_not_certify_stub_harness(self):
        """A harness root with only assert(true) in test/ must NOT be certified
        as genuine even if src/ contains require()."""
        acc = _load_acc_module()
        harness_root = self._tmp / "harness"
        harness_root.mkdir()
        src = harness_root / "src"
        src.mkdir()
        (src / "Counter.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Counter {\n"
            "    uint256 public count;\n"
            "    function inc() external { require(count < 100, 'max'); count++; }\n"
            "}\n",
            encoding="utf-8",
        )
        test = harness_root / "test"
        test.mkdir()
        (test / "TestCounter.t.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract TestCounter {\n"
            "    function testStub() public { assert(true); }\n"
            "}\n",
            encoding="utf-8",
        )
        result = acc._authored_harnesses_genuinely_executed_completeness_for_root(
            harness_root
        ) if hasattr(acc, "_authored_harnesses_genuinely_executed_completeness_for_root") else None

        if result is None:
            # Fall back to the manifest-based path by building a minimal
            # engine-harness-execution.json and calling the full function.
            # The function reads from .auditooor/solidity-deep-audit/engine-harness-execution.json
            # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
            ws = _mk_bare_ws()
            ws.rename(self._tmp / "ws")
            ws = self._tmp / "ws"
            aud = ws / ".auditooor"
            _write_json(aud / "solidity-deep-audit" / "engine-harness-execution.json", {
                "schema": "auditooor.engine_harness_execution.v1",
                "executed_engine_harness_count": 1,
                "harnesses": [{
                    "root": str(harness_root),
                    "tests_passed": 1,
                    "status": "pass",
                }],
            })
            result = acc._authored_harnesses_genuinely_executed_completeness(ws)

        self.assertFalse(
            result,
            "A stub harness (assert(true) only in test/) must NOT be certified "
            "genuine even when src/ contains require() calls",
        )

    def test_asserteq_in_test_certifies_genuine(self):
        """A harness with assertEq in test/ must be certified as genuine.
        r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json"""
        acc = _load_acc_module()
        harness_root = self._tmp / "harness_real"
        harness_root.mkdir()
        src = harness_root / "src"
        src.mkdir()
        (src / "Counter.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Counter { uint256 public count; }\n",
            encoding="utf-8",
        )
        test = harness_root / "test"
        test.mkdir()
        (test / "TestCounter.t.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract TestCounter {\n"
            "    function testReal() public {\n"
            "        uint256 x = 1;\n"
            "        assertEq(x, 1);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws_real")
        ws = self._tmp / "ws_real"
        aud = ws / ".auditooor"
        # The function reads from .auditooor/solidity-deep-audit/engine-harness-execution.json
        _write_json(aud / "solidity-deep-audit" / "engine-harness-execution.json", {
            "schema": "auditooor.engine_harness_execution.v1",
            "executed_engine_harness_count": 1,
            "harnesses": [{
                "root": str(harness_root),
                "tests_passed": 1,
                "status": "pass",
            }],
        })
        result = acc._authored_harnesses_genuinely_executed_completeness(ws)
        self.assertTrue(
            result,
            "A harness with assertEq in test/ must be certified as genuine",
        )


# ---------------------------------------------------------------------------
# Fix 5: hollow exploit_queue.json must fail unconditionally
# ---------------------------------------------------------------------------

class TestHollowExploitQueueFailsUnconditionally(unittest.TestCase):
    """Bug L2254: a hollow exploit_queue.json WARN-passed under non-strict mode.
    After fix: it fails closed unconditionally (ok=False) regardless of strict."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix5_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws(self) -> Path:
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws")
        return self._tmp / "ws"

    def test_hollow_exploit_queue_fails_in_default_mode(self):
        """A hollow exploit_queue.json ({}) must fail in default (non-strict) mode."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "exploit_queue.json", {})
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_EXPLOIT_QUEUE_STRICT",
                         "ENFORCE_AUTONOMOUS_PROOF_CONVERSION")
        }
        with mock.patch.dict(os.environ, clean_env, clear=True):
            result = acc.check_exploit_queue(ws)
        self.assertFalse(
            result.ok,
            f"Hollow exploit_queue.json must fail closed in default mode; "
            f"got ok=True. Reason: {result.reason}",
        )
        self.assertNotIn(
            "WARN:", result.reason,
            "Hollow exploit-queue reason must not contain WARN: after fix",
        )

    def test_hollow_exploit_queue_fails_under_strict(self):
        """A hollow exploit_queue.json must also fail under --strict."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "exploit_queue.json", {})
        with mock.patch.dict(os.environ, {"AUDITOOOR_L37_STRICT": "1"}):
            result = acc.check_exploit_queue(ws)
        self.assertFalse(result.ok, "Hollow exploit_queue must fail under strict too")

    def test_real_exploit_queue_passes(self):
        """An exploit_queue.json with a non-empty queue list must pass."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "exploit_queue.json", {
            "queue": [{"id": "lead-1", "severity": "High"}],
        })
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in ("AUDITOOOR_L37_STRICT", "ENFORCE_AUTONOMOUS_PROOF_CONVERSION")
        }
        with mock.patch.dict(os.environ, clean_env, clear=True):
            result = acc.check_exploit_queue(ws)
        self.assertTrue(
            result.ok,
            f"Non-hollow exploit_queue must pass; got ok=False. Reason: {result.reason}",
        )

    def test_hollow_exploit_queue_in_overall_verdict(self):
        """End-to-end: hollow exploit_queue.json must prevent pass-audit-complete."""
        ws = self._ws()
        # Supply minimal artifacts to pass everything except exploit_queue
        aud = ws / ".auditooor"
        _write_json(aud / "exploit_queue.json", {})  # hollow
        # The verdict will fail on exploit-queue (and other missing signals,
        # but what matters is exploit-queue is in failures)
        rc, out = _run(ws)
        self.assertNotEqual(out.get("verdict"), "pass-audit-complete")
        self.assertIn("fail-no-exploit-queue", out.get("failures", []),
                      f"fail-no-exploit-queue must be in failures; got: {out.get('failures')}")


# ---------------------------------------------------------------------------
# Fix 6: advisory_corpus must respect ENFORCE_AUTONOMOUS_PROOF_CONVERSION
# ---------------------------------------------------------------------------

class TestAdvisoryCorpusEnforceConversion(unittest.TestCase):
    """Bug L3806: check_advisory_corpus used _l37_gate_strict only - it ignored
    ENFORCE_AUTONOMOUS_PROOF_CONVERSION for the 0/0 hollow path.
    After fix: either env triggers the strict branch."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix6_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws(self) -> Path:
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws")
        return self._tmp / "ws"

    def test_hollow_0_0_fails_under_enforce_conversion(self):
        """A 0/0 advisory_corpus_parity.json with no scan evidence must fail
        when ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "published_advisory_count": 0,
            "corpus_advisory_record_count": 0,
        })
        with mock.patch.dict(os.environ,
                             {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"},
                             clear=False):
            result = acc.check_advisory_corpus(ws)
        self.assertFalse(
            result.ok,
            f"0/0 hollow advisory_corpus must fail under ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1; "
            f"got ok=True. Reason: {result.reason}",
        )

    def test_hollow_0_0_warn_passes_outside_enforcement(self):
        """0/0 advisory_corpus_parity.json must still WARN-pass without enforcement."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "published_advisory_count": 0,
            "corpus_advisory_record_count": 0,
        })
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in ("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", "AUDITOOOR_L37_STRICT",
                         "AUDITOOOR_L37_ADVISORY_CORPUS_STRICT")
        }
        with mock.patch.dict(os.environ, clean_env, clear=True):
            result = acc.check_advisory_corpus(ws)
        self.assertTrue(
            result.ok,
            f"0/0 hollow without enforcement should WARN-pass; got ok=False",
        )
        self.assertIn("WARN:", result.reason)

    def test_0_0_with_strong_scan_evidence_passes(self):
        """0/0 with source_files_used (strong evidence) must pass even under enforcement."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "published_advisory_count": 0,
            "corpus_advisory_record_count": 0,
            "source_files_used": ["SECURITY.md"],
        })
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            result = acc.check_advisory_corpus(ws)
        self.assertTrue(
            result.ok,
            f"0/0 WITH source_files_used must pass; got ok=False. Reason: {result.reason}",
        )


# ---------------------------------------------------------------------------
# Fix 7: timestamp-only scan evidence must not satisfy the 0/0 hollow guard
# ---------------------------------------------------------------------------

class TestAdvisoryCorpusTimestampOnlyInsufficient(unittest.TestCase):
    """Bug L3854: _has_scan_evidence returned True for a bare generated_at_utc
    timestamp, letting a 0/0 stub pass silently.
    After fix: timestamps are weak evidence only; strong evidence requires
    source_files_used / source_summary / advisories_scanned > 0."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix7_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws(self) -> Path:
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws")
        return self._tmp / "ws"

    def test_timestamp_only_triggers_warn_under_enforcement(self):
        """0/0 with only generated_at_utc must NOT pass silently; must WARN or fail."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "published_advisory_count": 0,
            "corpus_advisory_record_count": 0,
            "generated_at_utc": "2026-01-01T00:00:00Z",
        })
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            result = acc.check_advisory_corpus(ws)
        # Under enforcement + timestamp-only: must fail (strict path)
        self.assertFalse(
            result.ok,
            f"0/0 with timestamp-only must fail under enforcement; "
            f"got ok=True. Reason: {result.reason}",
        )

    def test_timestamp_only_warn_passes_outside_enforcement(self):
        """0/0 with only a timestamp and no enforcement: must WARN (not silently pass)."""
        ws = self._ws()
        acc = _load_acc_module()
        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "published_advisory_count": 0,
            "corpus_advisory_record_count": 0,
            "generated_at_utc": "2026-01-01T00:00:00Z",
        })
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in ("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", "AUDITOOOR_L37_STRICT",
                         "AUDITOOOR_L37_ADVISORY_CORPUS_STRICT")
        }
        with mock.patch.dict(os.environ, clean_env, clear=True):
            result = acc.check_advisory_corpus(ws)
        # Must WARN-pass (ok=True but reason contains WARN) or fail -
        # either is acceptable; what must NOT happen is a silent clean pass.
        if result.ok:
            self.assertIn(
                "WARN", result.reason,
                "0/0 timestamp-only without enforcement must at least WARN, not silently pass",
            )

    def test_has_scan_evidence_strong_fields(self):
        """_has_scan_evidence must return True only for strong evidence fields."""
        acc = _load_acc_module()
        # Strong: source_files_used
        self.assertTrue(acc._has_scan_evidence({"source_files_used": ["SECURITY.md"]}))
        # Strong: source_summary dict
        self.assertTrue(acc._has_scan_evidence({"source_summary": {"foo": "bar"}}))
        # Strong: advisories_scanned > 0
        self.assertTrue(acc._has_scan_evidence({"advisories_scanned": 5}))
        # Weak (timestamp only): must return False
        self.assertFalse(
            acc._has_scan_evidence({"generated_at_utc": "2026-01-01T00:00:00Z"}),
            "_has_scan_evidence must return False for timestamp-only fields",
        )
        self.assertFalse(
            acc._has_scan_evidence({"scanned_at_utc": "2026-01-01T00:00:00Z"}),
            "_has_scan_evidence must return False for scanned_at_utc alone",
        )
        # Empty or missing: False
        self.assertFalse(acc._has_scan_evidence({}))
        self.assertFalse(acc._has_scan_evidence({"source_files_used": []}))
        self.assertFalse(acc._has_scan_evidence({"advisories_scanned": 0}))


# ---------------------------------------------------------------------------
# Fix 8: function-coverage non-dict result must be distinct from no-entry-point
# ---------------------------------------------------------------------------

class TestFunctionCoverageNonDictResult(unittest.TestCase):
    """Bug L6249: when _call_function_coverage_gate returned None (entry-point
    found but returned non-dict), the reason incorrectly said 'no recognized
    reusable entry-point' and detail said 'no-entry-point'.
    After fix: a distinct sentinel _NO_ENTRY_POINT separates the two cases;
    a None return from a real entry-point is treated as a tool error (fail under
    strict, WARN-pass outside strict)."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="l37_fix8_"))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ws(self) -> Path:
        ws = _mk_bare_ws()
        ws.rename(self._tmp / "ws")
        return self._tmp / "ws"

    def _make_bad_return_mod(self, return_value=None):
        """Build a mock function-coverage module whose evaluate() returns None."""
        mod = type(sys)("_mock_fc_mod")
        mod.evaluate = lambda ws, **kw: return_value
        return mod

    def _make_no_entrypoint_mod(self):
        """Build a mock function-coverage module with no recognized entry-point."""
        mod = type(sys)("_mock_fc_no_ep_mod")
        # No check_function_coverage, no check, no evaluate
        mod.something_else = lambda: None
        return mod

    def test_none_return_fails_closed_under_strict(self):
        """An evaluate() that returns None must fail closed under STRICT mode."""
        ws = self._ws()
        acc = _load_acc_module()
        bad_mod = self._make_bad_return_mod(return_value=None)
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_function_coverage_module",
            return_value=bad_mod,
        ):
            with mock.patch.dict(os.environ, {"AUDITOOOR_L37_STRICT": "1"}):
                result = acc.check_function_coverage(ws)
        self.assertFalse(
            result.ok,
            "check_function_coverage must fail closed under STRICT when evaluate() returns None",
        )
        self.assertNotEqual(
            result.detail.get("function_coverage_tool"), "no-entry-point",
            "detail must not say 'no-entry-point' when entry-point WAS found but returned None",
        )
        self.assertEqual(
            result.detail.get("function_coverage_tool"), "bad-return-type",
            "detail must say 'bad-return-type' when evaluate() returned None",
        )

    def test_none_return_warn_passes_outside_strict(self):
        """An evaluate() returning None must WARN-pass outside strict mode."""
        ws = self._ws()
        acc = _load_acc_module()
        bad_mod = self._make_bad_return_mod(return_value=None)
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_FUNCTION_COVERAGE_STRICT",
                         "ENFORCE_AUTONOMOUS_PROOF_CONVERSION")
        }
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_function_coverage_module",
            return_value=bad_mod,
        ):
            with mock.patch.dict(os.environ, clean_env, clear=True):
                result = acc.check_function_coverage(ws)
        self.assertTrue(result.ok, "None return from evaluate must WARN-pass outside strict")
        self.assertIn("WARN:", result.reason)
        self.assertEqual(result.detail.get("function_coverage_tool"), "bad-return-type")

    def test_no_entry_point_still_warn_passes(self):
        """A module with no recognized entry-point must still WARN-pass (unchanged)."""
        ws = self._ws()
        acc = _load_acc_module()
        no_ep_mod = self._make_no_entrypoint_mod()
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_function_coverage_module",
            return_value=no_ep_mod,
        ):
            with mock.patch.dict(os.environ, {"AUDITOOOR_L37_STRICT": "1"}):
                result = acc.check_function_coverage(ws)
        self.assertTrue(
            result.ok,
            "A module with no recognized entry-point must still WARN-pass "
            "(tooling-interface mismatch, not tool error)",
        )
        self.assertEqual(
            result.detail.get("function_coverage_tool"), "no-entry-point",
            "detail must say 'no-entry-point' when module has no recognized entry-point",
        )

    def test_reason_text_distinguishes_bad_return_from_no_entrypoint(self):
        """The reason string for bad-return must not mention 'no recognized reusable
        entry-point' - that wording is reserved for the genuine no-entry-point case."""
        ws = self._ws()
        acc = _load_acc_module()
        bad_mod = self._make_bad_return_mod(return_value=None)
        with mock.patch.object(
            sys.modules["_acc_strict_test_mod"],
            "_load_function_coverage_module",
            return_value=bad_mod,
        ):
            with mock.patch.dict(os.environ, {"AUDITOOOR_L37_STRICT": "1"}):
                result = acc.check_function_coverage(ws)
        self.assertNotIn(
            "no recognized reusable entry-point",
            result.reason,
            "Bad-return reason must NOT say 'no recognized reusable entry-point'",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
