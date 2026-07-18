#!/usr/bin/env python3
"""MQ-C03 randomness-unbiasability-screen - non-vacuous regression.

Pins tools/randomness-unbiasability-screen.py: for a value TRUSTED fair/random and
CONSUMED by a selection / ordering / lottery / tie-break / leader-election decision,
it flags (verdict="needs-fuzz") when the SOURCE is predictable or post-commit-
biasable - EVM on-chain global entropy (block.timestamp / block.number /
blockhash(...) / block.prevrandao / block.difficulty / block.coinbase, or a keccak of
those), a commit-reveal with NO binding penalty for non-reveal, or a Go non-VRF weak
seed (time.Now, math/rand) feeding a leader/validator/shuffle selection. A VRF /
drand / crypto-rand source, or a commit-reveal made unbiasable by a binding penalty,
is the SILENT true-negative.

Non-vacuity is enforced (HARD RULE 6):
  (1) PLANTED POSITIVES fire across the source families (EVM block globals, EVM
      blockhash, commit-reveal-no-penalty over block entropy, Go time.Now, Go
      math/rand) and across the three consumer signals (selection-named value,
      modulo-into-a-set-count, index-into-a-participant-set) - a general invariant
      class, not one hard-coded shape.
  (2) STRONG-SOURCE / bound-commit-reveal negatives are SILENT: a VRF callback
      (randomWords), a Go crypto/rand seed, and a commit-reveal with slash/burn.
  (3) NEUTRALIZE each core-predicate half -> the positive assertion FAILS:
      (a) monkeypatching `_sources`/`_weak_source_label` to empty is not how the
          join is keyed; instead the two real halves are neutralized:
            * force `_consumer` -> None      => every positive goes silent
              (the selection-consumer join is load-bearing); and
            * force the weak-source regex to never match (patch `scan_file`'s
              `weak_re` via `_EVM_WEAK`/`_GO_WEAK`) => every positive goes silent
              (the weak-source half is load-bearing); and
            * force `_suppressed` -> a reason => every positive goes silent
              (the strong-source suppression is load-bearing).
  (4) FALSE-POSITIVE guards seen on real code stay silent: a block.timestamp used
      only as a timelock deadline, a time-based reward accrual, a time-of-day modulo
      (`block.timestamp % 86400`, divisor is not a set count), a comment mentioning
      'winner'/'random', and a Go time.Now used only as a feature-gate timestamp.

The advisory-first contract (verdict=needs-fuzz, advisory=True, auto_credit=False,
default exit 0, --strict exit 1) and the .auditooor sidecar emission (firing
hypotheses only, with file/line/function/randomness_source/consumer/capability) are
pinned too.

REAL-FLEET mutation-verify (HARD RULE 5) is reproduced end-to-end against ACTUAL
fleet source WITHOUT mutating any ws file: the tool is SILENT on the real source
(MetaMorpho.sol uses block.timestamp only for timelocks; op-batcher service.go uses
time.Now only for a feature-gate timestamp), and FIRES on an in-memory TEMP COPY into
which a block-entropy / math-rand SELECTION is planted. It SKIPs when the source is
absent (no faked pass). Most fleet workspaces have NO randomness-driven selection and
are correctly SILENT - that healthy true-negative is asserted directly.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "randomness_unbiasability_screen_t",
        TOOLS / "randomness-unbiasability-screen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MOD = _load_tool()


def _rows(text, name="T.sol"):
    return MOD.scan_file(pathlib.Path(name), name, file_text=text)


def _fired(text, fn, name="T.sol"):
    return [r for r in _rows(text, name) if r["fires"] and r["function"] == fn]


# ---------------------------------------------------------------------------
# Planted positives - across source families and consumer signals.
# ---------------------------------------------------------------------------
# EVM: keccak of block globals, modulo into a set count + selection-named value.
EVM_BLOCK_POS = (
    'contract C{function pick(address[] players) external{'
    'uint256 winnerIndex=uint256(keccak256(abi.encodePacked('
    'block.timestamp,block.prevrandao)))%players.length;'
    'emit W(players[winnerIndex]);}}')
# EVM: blockhash seed named `seed`, index into a participant set.
EVM_BLOCKHASH_POS = (
    'contract C{function draw() external{'
    'uint256 seed=uint256(blockhash(block.number-1));'
    'address chosen=candidates[seed%candidates.length];emit W(chosen);}}')
# EVM: commit-reveal that mixes block.prevrandao WITHOUT a binding penalty.
EVM_COMMIT_REVEAL_NOPEN_POS = (
    'contract C{function reveal(uint256 s) external{'
    'require(keccak256(abi.encode(s))==commit[msg.sender]);'
    'uint256 seed=uint256(keccak256(abi.encodePacked(block.prevrandao,s)));'
    'winner=players[seed%players.length];}}')
# Go: math/rand shuffle over validators.
GO_RAND_POS = (
    'package p\nimport "math/rand"\n'
    'func SelectLeader(validators []Val) Val {\n'
    'rand.Shuffle(len(validators), func(i,j int){'
    'validators[i],validators[j]=validators[j],validators[i]})\n'
    'return validators[0]\n}')
# Go: a clock-seeded math/rand PRNG picking a proposer (the canonical weak seed - a
# bare time.Now read is NOT a source, but seeding rand.NewSource with it is).
GO_TIMENOW_POS = (
    'package p\nimport ("math/rand"; "time")\n'
    'func Proposer(nodes []Node) Node {\n'
    'r := rand.New(rand.NewSource(time.Now().UnixNano()))\n'
    'idx := r.Intn(len(nodes))\n'
    'return nodes[idx]\n}')


class TestPlantedPositivesFireAcrossFamilies(unittest.TestCase):
    def test_evm_block_global_fires(self):
        fr = _fired(EVM_BLOCK_POS, "pick")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["lang"], "solidity")
        self.assertEqual(fr[0]["capability"], "MQ-C03-randomness-unbiasability")
        self.assertIn("block", fr[0]["randomness_source"])
        self.assertTrue(fr[0]["consumer"])

    def test_evm_blockhash_fires(self):
        fr = _fired(EVM_BLOCKHASH_POS, "draw")
        self.assertEqual(len(fr), 1, fr)
        self.assertIn(fr[0]["consumer"],
                      ("selection-named:seed", "index-into-participant-set",
                       "modulo-into-set-count"))

    def test_evm_commit_reveal_no_penalty_fires(self):
        fr = _fired(EVM_COMMIT_REVEAL_NOPEN_POS, "reveal")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["randomness_source"], "block.prevrandao")

    def test_go_math_rand_fires(self):
        fr = _fired(GO_RAND_POS, "SelectLeader", "x.go")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["lang"], "go")
        self.assertIn("rand", fr[0]["randomness_source"])

    def test_go_clock_seeded_prng_fires(self):
        fr = _fired(GO_TIMENOW_POS, "Proposer", "x.go")
        self.assertEqual(len(fr), 1, fr)
        self.assertIn("rand", fr[0]["randomness_source"])


# ---------------------------------------------------------------------------
# Strong-source / bound-commit-reveal negatives - SILENT true-negatives.
# ---------------------------------------------------------------------------
class TestStrongSourceSilent(unittest.TestCase):
    def test_vrf_callback_silent(self):
        src = ('contract C{function fulfillRandomWords(uint256 id,'
               'uint256[] randomWords) internal{'
               'uint256 winnerIndex=randomWords[0]%players.length;'
               'emit W(players[winnerIndex]);}}')
        self.assertEqual(_fired(src, "fulfillRandomWords"), [])

    def test_go_crypto_rand_silent(self):
        src = ('package p\nimport "crypto/rand"\n'
               'func PickLeader(validators []Val) Val {\n'
               'b:=make([]byte,8); rand.Read(b);\n'
               'seed:=binary.BigEndian.Uint64(b)\n'
               'return validators[seed%uint64(len(validators))]\n}')
        self.assertEqual(_fired(src, "PickLeader", "x.go"), [])

    def test_commit_reveal_with_binding_penalty_silent(self):
        # same block-entropy commit-reveal as the positive, but a non-reveal SLASH
        # makes the committed seed unbiasable -> the row is kept but does NOT fire.
        src = ('contract C{function reveal(uint256 s) external{'
               'if(keccak256(abi.encode(s))!=commit[msg.sender]) slash(msg.sender);'
               'uint256 seed=uint256(keccak256(abi.encodePacked(block.prevrandao,s)));'
               'winner=players[seed%players.length];}}')
        rows = [r for r in _rows(src) if r["function"] == "reveal"]
        self.assertEqual(len(rows), 1, rows)
        self.assertFalse(rows[0]["fires"])
        self.assertEqual(rows[0]["suppressed_reason"],
                         "commit-reveal-with-binding-penalty")
        self.assertEqual(_fired(src, "reveal"), [])


# ---------------------------------------------------------------------------
# Go-arm precision regressions (real-fleet FP classes) - must stay SILENT, while a
# GENUINE weak-RNG selection still FIRES.
# ---------------------------------------------------------------------------
# FIX 1 + FIX 2: op-node/p2p/discovery.go shufflePeers - a math/rand generator SEEDED
# from an ALIASED crypto/rand import (`secureRand "crypto/rand"` -> secureRand.Reader).
# The seed is unpredictable -> SILENT. (Under a per-FUNCTION ";"-split this loose
# co-occurrence would fire; per-NEWLINE locality + aliased-strong resolution kills it.)
GO_ALIASED_CRYPTO_SEED_FP = (
    'package p\n'
    'import (\n\tsecureRand "crypto/rand"\n\t"encoding/binary"\n\t"io"\n'
    '\t"math/rand"\n)\n'
    'func shufflePeers(ids []int) error {\n'
    'var x [8]byte\n'
    'if _, err := io.ReadFull(secureRand.Reader, x[:]); err != nil {\nreturn err\n}\n'
    'rng := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(x[:]))))\n'
    'rng.Shuffle(len(ids), func(i, j int){ids[i], ids[j] = ids[j], ids[i]})\n'
    'return nil\n}')
# FIX 3: op-conductor/conductor/service.go - rand.Intn feeding a retry BACKOFF
# Duration is a benign randomized backoff, not a fairness selection -> SILENT.
GO_BACKOFF_JITTER_FP = (
    'package p\nimport ("math/rand"; "time")\n'
    'func newConductor() *Cfg {\n'
    'return &Cfg{\n'
    'retryBackoff: func() time.Duration { '
    'return time.Duration(rand.Intn(2000)) * time.Millisecond },\n'
    '}\n}')
# FIX 3: sei sei-db pruning manager - rand.Float64 feeding a sleep DELAY, and even a
# `random`-named timing var must NOT satisfy the selection-named signal -> SILENT.
GO_SLEEP_DELAY_FP = (
    'package p\nimport ("math/rand"; "time")\n'
    'func (m *Manager) prune() {\n'
    'randomDelay := time.Duration(rand.Float64() * float64(m.interval))\n'
    'time.Sleep(randomDelay)\n}')
# FIX 3 (cross-statement): the exact sei pruning shape - a `random`-named percentage
# is assigned on one line and only reaches the sleep Duration two statements later.
# The generic-random selection-named signal must be suppressed function-wide -> SILENT.
GO_SLEEP_DELAY_XSTMT_FP = (
    'package p\nimport ("math/rand"; "time")\n'
    'func (m *Manager) pruneLoop() {\n'
    'randomPercentage := rand.Float64()\n'
    'randomDelay := int64(float64(m.pruneInterval) * randomPercentage)\n'
    'sleepDuration := time.Duration(m.pruneInterval+randomDelay) * time.Millisecond\n'
    'time.Sleep(sleepDuration)\n}')


class TestGoArmPrecisionRegressions(unittest.TestCase):
    def test_aliased_crypto_rand_seed_silent(self):
        # the row is a candidate (math/rand present) but suppressed as strong-seeded.
        rows = [r for r in _rows(GO_ALIASED_CRYPTO_SEED_FP, "discovery.go")
                if r["function"] == "shufflePeers"]
        self.assertEqual([r for r in rows if r["fires"]], [],
                         "math/rand seeded from aliased crypto/rand must be SILENT")

    def test_backoff_jitter_duration_silent(self):
        self.assertEqual(_fired(GO_BACKOFF_JITTER_FP, "newConductor", "service.go"), [],
                         "rand feeding a retry backoff Duration is not a selection")

    def test_sleep_delay_random_named_var_silent(self):
        self.assertEqual(_fired(GO_SLEEP_DELAY_FP, "prune", "manager.go"), [],
                         "rand feeding a sleep delay (even a 'random'-named var) is "
                         "not a selection")

    def test_sleep_delay_cross_statement_random_percentage_silent(self):
        self.assertEqual(_fired(GO_SLEEP_DELAY_XSTMT_FP, "pruneLoop", "manager.go"), [],
                         "a 'random'-named jitter that reaches a sleep two statements "
                         "later must be suppressed function-wide")

    def test_time_now_seeded_peer_pick_still_fires(self):
        # a time.Now-seeded math/rand PRNG picking a peer with NO timing sink is a
        # GENUINE weak-RNG selection (sei pool.go pickIncrAvailablePeer) - must FIRE
        # even though its consumer is the generic-random `rng` name.
        src = ('package p\nimport ("math/rand"; "time")\n'
               'func pickPeer(goodPeers []Peer) Peer {\n'
               'rng := rand.New(rand.NewSource(time.Now().UnixNano()))\n'
               'index := rng.Intn(len(goodPeers))\n'
               'return goodPeers[index]\n}')
        fr = _fired(src, "pickPeer", "pool.go")
        self.assertEqual(len(fr), 1, fr)
        self.assertIn("rand", fr[0]["randomness_source"])

    def test_genuine_weak_rng_selection_still_fires(self):
        # a math/rand generator SEEDED BY time.Now feeding a leader/shuffle pick (NOT a
        # jitter) is the genuine weak-RNG selection and MUST still fire - FIX 3 must not
        # over-suppress. Distinct from GO_TIMENOW_POS: a leader shuffle, no timing token.
        genuine = (
            'package p\nimport ("math/rand"; "time")\n'
            'func electLeader(validators []Val) Val {\n'
            'r := rand.New(rand.NewSource(time.Now().UnixNano()))\n'
            'winner := r.Intn(len(validators))\n'
            'return validators[winner]\n}')
        fr = _fired(genuine, "electLeader", "leader.go")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["lang"], "go")
        self.assertIn("rand", fr[0]["randomness_source"])


# ---------------------------------------------------------------------------
# Neutralize each core-predicate half -> the positives must FAIL.
# ---------------------------------------------------------------------------
POSITIVES = ((EVM_BLOCK_POS, "pick", "T.sol"),
             (EVM_BLOCKHASH_POS, "draw", "T.sol"),
             (GO_RAND_POS, "SelectLeader", "x.go"),
             (GO_TIMENOW_POS, "Proposer", "x.go"))


class TestNeutralizeCorePredicate(unittest.TestCase):
    def test_neutralize_consumer_join_kills_all_fires(self):
        orig = MOD._consumer
        try:
            MOD._consumer = lambda stmt, weak_re, tainted: None
            for src, fn, name in POSITIVES:
                self.assertEqual(_fired(src, fn, name), [],
                                 "selection-consumer join must be load-bearing")
        finally:
            MOD._consumer = orig

    def test_neutralize_weak_source_kills_all_fires(self):
        # replace both weak-source regexes with one that never matches -> the
        # candidate filter (`if not weak_re.search(body): continue`) drops every fn.
        never = re.compile(r"(?!x)x")
        oe, og = MOD._EVM_WEAK, MOD._GO_WEAK
        try:
            MOD._EVM_WEAK = never
            MOD._GO_WEAK = never
            for src, fn, name in POSITIVES:
                self.assertEqual(_fired(src, fn, name), [],
                                 "weak-source detection must be load-bearing")
        finally:
            MOD._EVM_WEAK, MOD._GO_WEAK = oe, og

    def test_neutralize_suppression_open_makes_all_silent(self):
        # force every enforcement point to be treated as strong-sourced -> no fires.
        orig = MOD._suppressed
        try:
            MOD._suppressed = lambda fn, body, lang: "forced-strong"
            for src, fn, name in POSITIVES:
                self.assertEqual(_fired(src, fn, name), [],
                                 "strong-source suppression must be load-bearing")
        finally:
            MOD._suppressed = orig


# ---------------------------------------------------------------------------
# False-positive guards - regressions for benign uses of a weak token.
# ---------------------------------------------------------------------------
class TestFalsePositiveGuards(unittest.TestCase):
    def test_timelock_deadline_silent(self):
        src = ('contract C{function acceptTimelock() external{'
               'if(block.timestamp<validAt) revert TimelockNotElapsed();}}')
        self.assertEqual(_fired(src, "acceptTimelock"), [])

    def test_time_reward_accrual_silent(self):
        # `reward` is NOT a selection segment: time-based accrual carries no consumer.
        src = ('contract C{function claim() external{'
               'reward=rate*(block.timestamp-lastUpdate);payout(reward);}}')
        self.assertEqual(_fired(src, "claim"), [])

    def test_time_of_day_modulo_silent(self):
        # modulo by a time constant (not a set count) is not a selection index.
        src = ('contract C{function bucket() external{'
               'uint256 day=block.timestamp%86400;emit D(day);}}')
        self.assertEqual(_fired(src, "bucket"), [])

    def test_comment_and_string_selection_words_masked(self):
        # a selection word inside a comment / string must not create a consumer.
        src = ('contract C{function tick() external{'
               '// choose the winner using randomness later\n'
               'string memory note="winner random seed lottery";'
               'if(block.timestamp<deadline) revert X();}}')
        self.assertEqual(_fired(src, "tick"), [])

    def test_go_time_now_feature_gate_silent(self):
        src = ('package p\nimport "time"\n'
               'func IsActive(cfg Cfg) bool {\n'
               'return cfg.IsEcotone(uint64(time.Now().Unix()))\n}')
        self.assertEqual(_fired(src, "IsActive", "x.go"), [])


# ---------------------------------------------------------------------------
# Advisory-first contract + sidecar emission + exit codes.
# ---------------------------------------------------------------------------
class TestAdvisoryContractAndSidecar(unittest.TestCase):
    def test_rows_are_advisory_needs_fuzz_with_required_fields(self):
        r = _fired(EVM_BLOCK_POS, "pick")[0]
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        for k in ("file", "line", "function", "randomness_source", "consumer",
                  "capability"):
            self.assertIn(k, r)

    def test_workspace_emits_sidecar_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "Lottery.sol").write_text(EVM_BLOCK_POS)
            (src / "leader.go").write_text(GO_RAND_POS)
            (src / "Ok.sol").write_text(
                'contract C{function acceptTimelock() external{'
                'if(block.timestamp<validAt) revert X();}}')
            # default (advisory) -> exit 0 even though hypotheses fired
            self.assertEqual(MOD.main(["--workspace", str(ws)]), 0)
            side = ws / ".auditooor" / MOD._SIDE_NAME
            self.assertTrue(side.exists(), "sidecar must be emitted under .auditooor/")
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(rows), 2)
            langs = {r["lang"] for r in rows}
            self.assertEqual(langs, {"solidity", "go"})
            for r in rows:
                self.assertTrue(r["fires"])
                self.assertEqual(r["capability"], "MQ-C03-randomness-unbiasability")
                self.assertEqual(r["verdict"], "needs-fuzz")
                for k in ("line", "function", "randomness_source", "consumer"):
                    self.assertIn(k, r)
            # the benign timelock file must NOT appear among the firing rows
            self.assertFalse(any("Ok.sol" in r["file"] for r in rows))
            # --strict -> exit 1 when a hypothesis fired
            self.assertEqual(MOD.main(["--workspace", str(ws), "--strict"]), 1)
            # --check re-reads the sidecar (advisory), default exit 0
            self.assertEqual(MOD.main(["--workspace", str(ws), "--check"]), 0)

    def test_dev_tooling_dirs_are_skipped(self):
        # FIX 4: CLI entrypoints / e2e-smoke / fake-consensus dev-tooling trees seed
        # math/rand on purpose and must be pruned even with a planted selection.
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            for sub in ("cmd/workload", "interopsmoke", "op-e2e/e2eutils",
                        "fakepos"):
                d = src / sub
                d.mkdir(parents=True)
                (d / "g.go").write_text(GO_RAND_POS)
            # a genuine production file DOES fire, proving the scan is not vacuous.
            (src / "leader.go").write_text(GO_RAND_POS)
            self.assertEqual(MOD.main(["--workspace", str(ws)]), 0)
            side = ws / ".auditooor" / MOD._SIDE_NAME
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            files = {r["file"].replace("\\", "/") for r in rows}
            # the root production file fires (non-vacuous), the dev-tooling ones do not.
            self.assertEqual(files, {"leader.go"}, files)
            for bad in ("cmd/", "interopsmoke", "e2eutils", "fakepos",
                        "filtertestgen"):
                self.assertFalse(any(bad in f for f in files),
                                 f"{bad} tree must be skipped: {files}")

    def test_clean_workspace_exit_zero_and_silent(self):
        # a workspace with NO randomness-driven selection is a healthy true-negative:
        # empty sidecar, exit 0 even under --strict.
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "src").mkdir()
            (ws / "src" / "Ok.sol").write_text(
                'contract C{function claim() external{'
                'reward=rate*(block.timestamp-lastUpdate);payout(reward);}}')
            self.assertEqual(MOD.main(["--workspace", str(ws), "--strict"]), 0)
            side = ws / ".auditooor" / MOD._SIDE_NAME
            self.assertTrue(side.exists())
            self.assertEqual(side.read_text().strip(), "")


# ---------------------------------------------------------------------------
# HARD RULE 5 - real-fleet mutation-verify (read-only; temp copy in memory).
# ---------------------------------------------------------------------------
class TestRealFleetMutationVerifyEVM(unittest.TestCase):
    ANCHOR = pathlib.Path(
        "/Users/wolf/audits/morpho/src/metamorpho/src/MetaMorpho.sol")

    def test_metamorpho_timelock_silent_then_fires_when_selection_planted(self):
        if not self.ANCHOR.exists():
            self.skipTest("morpho MetaMorpho fleet source not present")
        real = self.ANCHOR.read_text(encoding="utf-8", errors="ignore")
        # the real file uses block.timestamp ONLY for timelock deadlines -> SILENT
        # (no randomness-driven selection anywhere).
        self.assertEqual(
            [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name, file_text=real)
             if r["fires"]], [],
            "MetaMorpho block.timestamp is a deadline, not a selection - must be SILENT")
        # TEMP COPY (in memory - the ws file is never mutated): plant a block-entropy
        # lottery selection just before the final closing brace -> must FIRE.
        planted = (
            '\nfunction _pickWinner(address[] memory players) internal view '
            'returns (address){uint256 winnerIndex='
            'uint256(keccak256(abi.encodePacked(block.timestamp,block.prevrandao)))'
            '%players.length;return players[winnerIndex];}\n')
        idx = real.rstrip().rfind("}")
        mutated = real[:idx] + planted + real[idx:]
        self.assertNotEqual(mutated, real, "mutation must plant a selection")
        mrows = [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name,
                                          file_text=mutated)
                 if r["fires"] and r["function"] == "_pickWinner"]
        self.assertEqual(len(mrows), 1, mrows)
        self.assertIn("block", mrows[0]["randomness_source"])


class TestRealFleetMutationVerifyGo(unittest.TestCase):
    ANCHOR = pathlib.Path(
        "/Users/wolf/audits/optimism/src/op-batcher/batcher/service.go")

    def test_service_time_now_silent_then_fires_when_selection_planted(self):
        if not self.ANCHOR.exists():
            self.skipTest("optimism op-batcher service.go fleet source not present")
        real = self.ANCHOR.read_text(encoding="utf-8", errors="ignore")
        # the real file uses time.Now ONLY for feature-gate timestamps -> SILENT.
        self.assertEqual(
            [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name, file_text=real)
             if r["fires"]], [],
            "op-batcher time.Now is a timestamp, not a selection - must be SILENT")
        # TEMP COPY: append a math/rand leader-selection function -> must FIRE.
        planted = (
            '\nfunc pickLeader(validators []string) string {\n'
            'rand.Shuffle(len(validators), func(i, j int){'
            'validators[i], validators[j] = validators[j], validators[i]})\n'
            'return validators[0]\n}\n')
        mutated = real + planted
        mrows = [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name,
                                          file_text=mutated)
                 if r["fires"] and r["function"] == "pickLeader"]
        self.assertEqual(len(mrows), 1, mrows)
        self.assertEqual(mrows[0]["lang"], "go")
        self.assertIn("rand", mrows[0]["randomness_source"])


if __name__ == "__main__":
    unittest.main()
