#!/usr/bin/env python3
"""Tests for tools/audit/universal_fp_runner.py (Wave-4).

Stdlib + PyYAML. All fixtures are synthetic in-tempdir. The
synthetic FP YAMLs carry ``synthetic_fixture:true`` to keep
them distinguishable from the canonical corpus YAMLs.

Coverage matrix:
  1. FP YAML loader: synthetic FP YAML round-trips via
     ``load_fp_definitions``.
  2. FP-01 positive: storage assignment without guard fires.
  3. FP-01 negative: same assignment with ``require(`` does not
     fire.
  4. FP-01 modifier walks confidence high -> medium.
  5. Multiple FPs in same source: FP-01 + FP-05 both surface
     their respective hits.
  6. Target-language filter: ``--target-language go`` skips
     ``.sol`` files.
  7. Quarantine subtree (``_archive``) excluded from walk.
  8. ``--strict`` exit code: total_hits > 0 returns 1.
  9. ``--fps FP-XX`` filter restricts to the requested FP.
 10. FP-04 git-history-only strategy returns 0 hits by design.
 11. W6-4: FP-01 OZ-base-primitive refinement - internal
     leading-underscore base mutators suppressed; genuine
     missing-validation shapes preserved.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit" / "universal_fp_runner.py"


def _run(args, expect_rc=None):
    proc = subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if expect_rc is not None:
        assert proc.returncode == expect_rc, (
            "rc=%d stdout=%s stderr=%s"
            % (proc.returncode, proc.stdout[-400:], proc.stderr[-400:])
        )
    return proc


def _write_fp_yaml(
    target_dir: Path,
    fp_id: str,
    target_language: str,
    bug_class: str,
    slug: str,
    extra_tags=(),
) -> Path:
    path = (
        target_dir
        / ("dsl_pattern_universal_fp_%s_%s.yaml" % (fp_id.split("-")[1], slug))
    )
    tags = [
        bug_class,
        "universal-fingerprint",
        "fingerprint_id:" + fp_id,
        "universality:synthetic-test",
        "workspace:test",
        "seed:SYN-PAT-001",
        "synthetic_fixture:true",
    ]
    tags.extend(extra_tags)
    body = textwrap.dedent(
        """\
        schema_version: auditooor.hackerman_record.v1
        record_id: {slug}
        target_language: {lang}
        bug_class: {bc}
        attack_class: {bc}
        function_shape:
          raw_signature: "synthetic FP {fp_id}"
          shape_tags:
        """
    ).format(slug=slug, lang=target_language, bc=bug_class, fp_id=fp_id)
    for t in tags:
        body += "    - %s\n" % t
    body += "attacker_action_sequence: |-\n"
    body += "  Synthetic pattern shape for test of " + fp_id + "\n"
    path.write_text(body, encoding="utf-8")
    return path


class UniversalFPRunnerTest(unittest.TestCase):
    def test_01_fp_yaml_loader_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "missing-validation",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "a.sol").write_text("pragma solidity ^0.8.0;\n")
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["schema"], "auditooor.universal_fp_runner.v1")
            self.assertEqual(len(doc["fps_evaluated"]), 1)
            self.assertEqual(doc["fps_evaluated"][0]["fp_id"], "FP-01")
            self.assertTrue(doc["fps_evaluated"][0]["synthetic_fixture"])

    def test_02_fp01_positive_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Vuln.sol").write_text(
                textwrap.dedent(
                    """\
                    pragma solidity ^0.8.0;
                    contract V {
                        uint256 public x;
                        function setX(uint256 _v) public {
                            x = _v;
                        }
                    }
                    """
                )
            )
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--fps",
                    "FP-01",
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 1)
            self.assertEqual(doc["hits"][0]["function"], "setX")
            self.assertEqual(doc["hits"][0]["confidence"], "high")

    def test_03_fp01_negative_with_require(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Safe.sol").write_text(
                textwrap.dedent(
                    """\
                    pragma solidity ^0.8.0;
                    contract S {
                        address public owner;
                        uint256 public x;
                        function setX(uint256 _v) public {
                            require(msg.sender == owner, "auth");
                            x = _v;
                        }
                    }
                    """
                )
            )
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--fps",
                    "FP-01",
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 0)

    def test_04_fp01_modifier_walks_confidence_to_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "ModGuarded.sol").write_text(
                textwrap.dedent(
                    """\
                    pragma solidity ^0.8.0;
                    contract G {
                        address public owner;
                        function setOwner(address _o) public onlyOwner {
                            owner = _o;
                        }
                    }
                    """
                )
            )
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--fps",
                    "FP-01",
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 1)
            self.assertEqual(doc["hits"][0]["confidence"], "medium")

    def test_05_multiple_fps_same_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            _write_fp_yaml(
                fp_dir,
                "FP-05",
                "solidity",
                "enum-or-rename-stale-reference",
                "rename",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Mix.sol").write_text(
                textwrap.dedent(
                    """\
                    pragma solidity ^0.8.0;
                    contract M {
                        uint256 public x;
                        function setX(uint256 _v) public {
                            x = _v;
                        }
                        function legacyName() public pure returns (string memory) {
                            return "NO_ALLOCATION";
                        }
                    }
                    """
                )
            )
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertGreaterEqual(doc["hits_per_fp"].get("FP-01", 0), 1)
            self.assertGreaterEqual(doc["hits_per_fp"].get("FP-05", 0), 1)

    def test_06_target_language_filter_skips_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "V.sol").write_text(
                "contract V { uint256 public x; function s(uint256 _v) public { x = _v; } }\n"
            )
            (ws / "src" / "v.go").write_text(
                "package x\nfunc S() {}\n"
            )
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--target-language",
                    "go",
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            # FP-01 is solidity-only; with go-only scan, no .sol
            # files are walked, so no FP-01 hits.
            self.assertEqual(doc["total_hits"], 0)
            self.assertEqual(doc["target_languages"], ["go"])

    def test_07_quarantine_subtree_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "_archive").mkdir(parents=True)
            quarantined_body = (
                "contract Q { uint256 public x; "
                "function s(uint256 _v) public { x = _v; } }\n"
            )
            (ws / "_archive" / "Old.sol").write_text(quarantined_body)
            (ws / "src" / "Live.sol").write_text(quarantined_body)
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--fps",
                    "FP-01",
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 1)
            files = {h["file"] for h in doc["hits"]}
            self.assertTrue(
                all("_archive" not in f for f in files),
                "quarantine subtree leaked into hits: %s" % files,
            )

    def test_08_strict_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "V.sol").write_text(
                "contract V { uint256 public x; "
                "function s(uint256 _v) public { x = _v; } }\n"
            )
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--fps",
                    "FP-01",
                    "--strict",
                ]
            )
            self.assertEqual(proc.returncode, 1)

    def test_09_fps_filter_restricts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-01",
                "solidity",
                "missing-validation-on-state-mutation",
                "miss",
            )
            _write_fp_yaml(
                fp_dir,
                "FP-05",
                "solidity",
                "enum-or-rename-stale-reference",
                "rename",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--fps",
                    "FP-05",
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            fp_ids = [fp["fp_id"] for fp in doc["fps_evaluated"]]
            self.assertEqual(fp_ids, ["FP-05"])

    def test_10_fp04_returns_zero_hits_by_design(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = tmp_p / "tags"
            fp_dir.mkdir()
            _write_fp_yaml(
                fp_dir,
                "FP-04",
                "go",
                "loosened-guard-via-revert-or-refactor",
                "revert",
            )
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "any.go").write_text(
                "package x\nfunc Foo() { _ = 1 }\n"
            )
            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--fp-dir",
                    str(fp_dir),
                    "--fps",
                    "FP-04",
                ],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 0)
            # The fp_evaluated record must indicate the strategy
            # exists so the operator sees we did not silently skip
            # FP-04.
            self.assertTrue(doc["fps_evaluated"][0]["strategy_available"])


class CapD7BlacklistTest(unittest.TestCase):
    """CAP-D7 lane: test/mock/lib/script path-classification blacklist.

    Coverage:
      D7.1  classify_path unit: each blacklist label + production.
      D7.2  test/mock noise is classified and bucketed when a
            vulnerable file lives under a /test/ or /mock/ dir.
      D7.3  --no-blacklist disables classification (cls=unknown).
      D7.4  --blacklist-extra adds an operator path fragment.
      D7.5  production_hit_count excludes test/mock noise.
    """

    def _make_fp_dir(self, tmp_p):
        fp_dir = tmp_p / "tags"
        fp_dir.mkdir()
        _write_fp_yaml(
            fp_dir,
            "FP-01",
            "solidity",
            "missing-validation-on-state-mutation",
            "miss",
        )
        return fp_dir

    _VULN_SOL = textwrap.dedent(
        """\
        pragma solidity ^0.8.0;
        contract V {
            uint256 public x;
            function setX(uint256 _v) public {
                x = _v;
            }
        }
        """
    )

    def test_d7_1_classify_path_unit(self):
        sys.path.insert(0, str(ROOT / "tools" / "audit"))
        import importlib

        ufr = importlib.import_module("universal_fp_runner")
        self.assertEqual(ufr.classify_path("src/test/Vuln.sol"), "test")
        self.assertEqual(ufr.classify_path("contracts/Vuln.t.sol"), "test")
        self.assertEqual(ufr.classify_path("src/mocks/MockToken.sol"), "mock")
        self.assertEqual(
            ufr.classify_path("lib/forge-std/src/Std.sol"), "lib"
        )
        self.assertEqual(ufr.classify_path("script/Deploy.sol"), "script")
        self.assertEqual(ufr.classify_path("src/Vault.sol"), "production")
        # operator-supplied extra fragment classifies as test
        self.assertEqual(
            ufr.classify_path("src/legacy/Old.sol", ["legacy"]), "test"
        )

    def test_d7_2_test_mock_noise_classified(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = self._make_fp_dir(tmp_p)
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "test").mkdir(parents=True)
            (ws / "src" / "mocks").mkdir(parents=True)
            # one production hit, one test hit, one mock hit
            (ws / "src" / "Vault.sol").write_text(self._VULN_SOL)
            (ws / "test" / "VaultTest.sol").write_text(self._VULN_SOL)
            (ws / "src" / "mocks" / "MockV.sol").write_text(self._VULN_SOL)
            proc = _run(
                ["--workspace", str(ws), "--fp-dir", str(fp_dir),
                 "--fps", "FP-01"],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 3)
            cls = doc["hits_per_classification"]
            self.assertEqual(cls["production"], 1)
            self.assertEqual(cls["test"], 1)
            self.assertEqual(cls["mock"], 1)
            # production_hit_count is the de-noised signal
            self.assertEqual(doc["production_hit_count"], 1)
            self.assertTrue(doc["blacklist_enabled"])

    def test_d7_3_no_blacklist_disables_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = self._make_fp_dir(tmp_p)
            ws = tmp_p / "ws"
            (ws / "test").mkdir(parents=True)
            (ws / "test" / "VaultTest.sol").write_text(self._VULN_SOL)
            proc = _run(
                ["--workspace", str(ws), "--fp-dir", str(fp_dir),
                 "--fps", "FP-01", "--no-blacklist"],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 1)
            self.assertFalse(doc["blacklist_enabled"])
            # with the blacklist off the hit is classified 'unknown'
            self.assertEqual(doc["hits_per_classification"]["unknown"], 1)
            self.assertEqual(doc["hits_per_classification"]["test"], 0)

    def test_d7_4_blacklist_extra_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = self._make_fp_dir(tmp_p)
            ws = tmp_p / "ws"
            (ws / "src" / "legacy").mkdir(parents=True)
            (ws / "src" / "legacy" / "Old.sol").write_text(self._VULN_SOL)
            proc = _run(
                ["--workspace", str(ws), "--fp-dir", str(fp_dir),
                 "--fps", "FP-01", "--blacklist-extra", "legacy"],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["total_hits"], 1)
            # operator fragment 'legacy' demotes the hit to test bucket
            self.assertEqual(doc["hits_per_classification"]["test"], 1)
            self.assertEqual(doc["production_hit_count"], 0)
            self.assertEqual(doc["blacklist_extra"], ["legacy"])

    def test_d7_5_per_fp_classification_breakdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = self._make_fp_dir(tmp_p)
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "test").mkdir(parents=True)
            (ws / "src" / "Vault.sol").write_text(self._VULN_SOL)
            (ws / "test" / "VaultTest.sol").write_text(self._VULN_SOL)
            proc = _run(
                ["--workspace", str(ws), "--fp-dir", str(fp_dir),
                 "--fps", "FP-01"],
                expect_rc=0,
            )
            doc = json.loads(proc.stdout)
            by_cls = doc["hits_per_fp_by_classification"]["FP-01"]
            self.assertEqual(by_cls["production"], 1)
            self.assertEqual(by_cls["test"], 1)


class TestFp01W64Refinement(unittest.TestCase):
    """Lane W6-4: FP-01 OZ-base-primitive refinement.

    The W5-C2 calibration corpus measured FP-01 firing 4 false
    positives on OpenZeppelin v5.1.0 base primitives. The refinement
    suppresses internal leading-underscore base mutators that delegate
    caller-trust to a public wrapper, WITHOUT neutering genuine
    missing-validation shapes.
    """

    def _fp_dir(self, tmp_p):
        fp_dir = tmp_p / "tags"
        fp_dir.mkdir()
        _write_fp_yaml(
            fp_dir,
            "FP-01",
            "solidity",
            "missing-validation-on-state-mutation",
            "miss",
        )
        return fp_dir

    def _run_fp01(self, src):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            fp_dir = self._fp_dir(tmp_p)
            ws = tmp_p / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "T.sol").write_text(textwrap.dedent(src))
            proc = _run(
                ["--workspace", str(ws), "--fp-dir", str(fp_dir),
                 "--fps", "FP-01", "--no-blacklist"],
                expect_rc=0,
            )
            return json.loads(proc.stdout)

    def test_oz_pause_modifier_guarded_suppressed(self):
        # OZ _pause: internal, when*Paused modifier -> suppressed.
        doc = self._run_fp01(
            """\
            pragma solidity ^0.8.0;
            contract C {
                bool _paused;
                function _pause() internal virtual whenNotPaused {
                    _paused = true;
                }
            }
            """
        )
        self.assertEqual(doc["total_hits"], 0)

    def test_oz_transfer_ownership_trivial_setter_suppressed(self):
        # OZ _transferOwnership: internal, trivial base setter.
        doc = self._run_fp01(
            """\
            pragma solidity ^0.8.0;
            contract C {
                address _owner;
                function _transferOwnership(address n) internal virtual {
                    address old = _owner;
                    _owner = n;
                    emit OwnershipTransferred(old, n);
                }
            }
            """
        )
        self.assertEqual(doc["total_hits"], 0)

    def test_oz_update_validation_helper_suppressed(self):
        # OZ _update: internal, invokes _checkAuthorized helper.
        doc = self._run_fp01(
            """\
            pragma solidity ^0.8.0;
            contract C {
                mapping(address => uint256) _balances;
                function _update(address to, uint256 id, address auth)
                    internal virtual returns (address) {
                    if (auth != address(0)) {
                        _checkAuthorized(auth, id);
                    }
                    _balances[to] = id;
                    return to;
                }
            }
            """
        )
        self.assertEqual(doc["total_hits"], 0)

    def test_public_unguarded_setter_still_fires(self):
        # TP: public, no guard - genuine missing-validation, must fire.
        doc = self._run_fp01(
            """\
            pragma solidity ^0.8.0;
            contract C {
                uint256 public x;
                function setX(uint256 v) public { x = v; }
            }
            """
        )
        self.assertEqual(doc["total_hits"], 1)
        self.assertEqual(doc["hits"][0]["confidence"], "high")

    def test_internal_underscore_with_external_call_still_fires(self):
        # TP: internal underscore BUT non-trivial (value transfer) -
        # not a pure base-setter primitive, must still fire.
        doc = self._run_fp01(
            """\
            pragma solidity ^0.8.0;
            contract C {
                mapping(address => uint256) bal;
                function _payout(address to, uint256 amt) internal {
                    bal[to] = amt;
                    payable(to).transfer(amt);
                }
            }
            """
        )
        self.assertEqual(doc["total_hits"], 1)

    def test_internal_non_underscore_not_suppressed(self):
        # An internal function WITHOUT a leading underscore is not an
        # OZ base-primitive shape - the refinement must not suppress.
        doc = self._run_fp01(
            """\
            pragma solidity ^0.8.0;
            contract C {
                uint256 x;
                function bumpState(uint256 v) internal { x = v; }
            }
            """
        )
        self.assertEqual(doc["total_hits"], 1)


if __name__ == "__main__":
    unittest.main()
