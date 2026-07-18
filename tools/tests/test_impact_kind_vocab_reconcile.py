#!/usr/bin/env python3
"""Regression: contract-kind vocabulary reconciliation (kind-family normalize).

Root cause (measured on main a03dac820a): the impact-hunting-methodology corpus
(audit/corpus_tags/impact_hunting_methodology.yaml) uses a FINE
`applies_to_contract_kinds` vocabulary of 129 kinds, but
hacker_question_renderer.classify_impact_target only ever EMITTED a coarse set
of 10. 119 fine kinds were never produced, so the attach predicate
`tgt_kind in applies_to_contract_kinds` could never fire for a playbook whose
every fine kind sat outside the coarse set. EIGHT impacts were therefore
kind-unreachable (they could only attach by shape, never by kind):

  liquidation-abuse, oracle-manipulation, signature-replay-forgery,
  unauthorized-upgrade-impl-swap, crypto-key-recovery-leak,
  bc-direct-loss-of-funds, bc-node-resource-exhaustion, bc-rpc-api-crash.

The fix:
  (1) `_KIND_FAMILY` normalizes BOTH the target kind and a playbook's
      applies_to_contract_kinds to a canonical family; attach becomes a
      family-intersection.
  (2) `_CONTRACT_KIND_RULES` gains six new emittable families
      (oracle, proxy, perp, distributor, crypto-signer, dex) so a real
      oracle/proxy/perp/distributor/signer/dex target infers the right family.

These assertions FAIL if the reconciliation is reverted (a fine kind stops
normalizing, a new classifier family stops emitting), OR if the fix over-reaches
and collapses the partition (a vault acquires chain-halt, a token acquires
perp/consensus).

To isolate the KIND axis from the (pre-existing) SHAPE-union axis, the partition
assertions drive attach with a NEUTRAL function (name/signature the shape
classifier does not map to any sharp impact shape), so the only attach channel
is the contract-kind family.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hacker_question_renderer.py"
_s = importlib.util.spec_from_file_location("hacker_question_renderer", _T)
_m = importlib.util.module_from_spec(_s)
# Python 3.14: register before exec so dataclass / typing self-refs resolve.
sys.modules["hacker_question_renderer"] = _m
_s.loader.exec_module(_m)

# A VALUE-BEARING function the shape classifier maps only to the generic
# fallback shapes ({external-state-mutating-fn, cross-contract-call}) - it
# intersects NONE of the impact playbooks' *sharp* applies_to_shape_classes, so
# any attach is purely via the contract-kind family (isolating the kind channel;
# guarded by test_neutral_probe_has_no_sharp_shape). The `uint256 amount` param
# makes it value-BEARING (_function_is_value_moving_ish True) WITHOUT adding a
# sharp shape - required because the kind-only rescue arm correctly attaches a
# kind's value-impacts (direct-theft/insolvency/liquidation/...) to VALUE-bearing
# functions, not to no-op/view functions. (A bare `zzNeutralProbeFn() external`
# is neither value-bearing nor sharply-shaped, so the corrected renderer, which
# will not spray fund-theft methodology onto a pure no-op, would attach nothing -
# that is correct behaviour, not the kind-reachability this suite measures.)
_NEUTRAL_FN = "zzNeutralProbeFn"
_NEUTRAL_SIG = "function zzNeutralProbeFn(uint256 amount) external"

# The 8 impacts that were kind-unreachable on main.
_PREVIOUSLY_DEAD = [
    "liquidation-abuse",
    "oracle-manipulation",
    "signature-replay-forgery",
    "unauthorized-upgrade-impl-swap",
    "crypto-key-recovery-leak",
    "bc-direct-loss-of-funds",
    "bc-node-resource-exhaustion",
    "bc-rpc-api-crash",
]


def _ids(rows):
    return {r.get("impact_id") for r in rows if isinstance(r, dict)}


def _kind_only_ids(contract_kind: str, language: str = ""):
    """Impact ids that attach to a NEUTRAL fn purely via contract-kind family."""
    return _ids(
        _m.render_impact_questions(
            _NEUTRAL_FN,
            _NEUTRAL_SIG,
            language=language,
            contract_kind=contract_kind,
        )
    )


class KindFamilyMapTest(unittest.TestCase):
    def test_neutral_probe_has_no_sharp_shape(self):
        # Guard: the neutral fn must not match any sharp impact shape, else the
        # partition assertions below would be measuring the shape channel.
        shapes = set(_m.classify_function_shape(_NEUTRAL_FN, _NEUTRAL_SIG))
        # only the generic fallback (+ maybe external-call) is acceptable
        self.assertTrue(
            shapes <= {"external-state-mutating-fn", "cross-contract-call",
                       "view-getter-fn"},
            f"neutral probe leaked a sharp shape: {sorted(shapes)}",
        )

    def test_family_map_covers_every_corpus_kind(self):
        try:
            import yaml  # type: ignore
        except Exception:  # pragma: no cover - yaml always present in repo
            self.skipTest("yaml unavailable")
        data = yaml.safe_load(open(_m._IMPACT_PLAYBOOKS_PATH)) or {}
        corpus_kinds = set()
        for b in data.get("playbooks", []) or []:
            for k in (b.get("applies_to_contract_kinds") or []):
                corpus_kinds.add(str(k).strip().lower())
        unmapped = sorted(k for k in corpus_kinds if k not in _m._KIND_FAMILY)
        self.assertEqual(unmapped, [], f"corpus kinds with no family: {unmapped}")
        # Every family a corpus kind normalizes to must be classifier-emittable,
        # else an impact could still be kind-unreachable.
        fams = {_m.kind_family(k) for k in corpus_kinds}
        non_emittable = sorted(f for f in fams
                               if f not in _m._EMITTABLE_KIND_FAMILIES)
        self.assertEqual(
            non_emittable, [],
            f"corpus families the classifier cannot emit: {non_emittable}",
        )

    def test_unknown_kind_passes_through_not_widened(self):
        # An unknown fine kind must map to itself (so it matches only its own
        # literal), never to a catch-all that would attach everything.
        self.assertEqual(_m.kind_family("totally-made-up-kind-xyz"),
                         "totally-made-up-kind-xyz")
        self.assertEqual(_m.kind_family(""), "")


class NewClassifierFamiliesTest(unittest.TestCase):
    """Part (2): the classifier can now EMIT the six new families."""

    def test_emits_oracle(self):
        c = _m.classify_impact_target(
            "getPrice", "function getPrice() returns(uint256)",
            scope_text="chainlink price feed oracle adapter",
        )
        self.assertEqual(c["contract_kind"], "oracle")

    def test_emits_proxy(self):
        c = _m.classify_impact_target(
            "upgradeTo", "function upgradeTo(address impl) external",
            scope_text="proxy-admin upgradeable implementation slot",
        )
        self.assertEqual(c["contract_kind"], "proxy")

    def test_emits_perp(self):
        c = _m.classify_impact_target(
            "openPosition", "function openPosition() external",
            scope_text="perpetuals funding rate margin account",
        )
        self.assertEqual(c["contract_kind"], "perp")

    def test_emits_distributor(self):
        c = _m.classify_impact_target(
            "claim", "function claim(bytes32[] proof) external",
            scope_text="merkle claim reward distributor gauge emissions",
        )
        self.assertEqual(c["contract_kind"], "distributor")

    def test_emits_crypto_signer(self):
        c = _m.classify_impact_target(
            "Sign", "func Sign(msg []byte) ([]byte, error)",
            scope_text="mpc tss threshold signature keystore hd-wallet",
        )
        self.assertEqual(c["contract_kind"], "crypto-signer")

    def test_emits_dex(self):
        c = _m.classify_impact_target(
            "placeOrder", "function placeOrder() external",
            scope_text="orderbook matching engine dex",
        )
        self.assertEqual(c["contract_kind"], "dex")

    def test_plain_token_not_misrouted(self):
        # Conservative: a plain ERC20 must stay token, not bleed into a new
        # family (first-match order must not swallow it).
        c = _m.classify_impact_target(
            "transfer", "function transfer(address,uint256) external",
            scope_text="erc20 token totalSupply balanceOf",
        )
        self.assertEqual(c["contract_kind"], "token")

    def test_plain_vault_not_misrouted(self):
        c = _m.classify_impact_target(
            "deposit", "function deposit(uint256) external",
            scope_text="erc4626 vault convertToShares totalAssets",
        )
        self.assertEqual(c["contract_kind"], "vault")


class EightDeadNowReachableTest(unittest.TestCase):
    """Each of the 8 previously-dead impacts is reachable by KIND for at least
    one classifier-emittable family."""

    def test_liquidation_abuse_reachable(self):
        # lending/perp/cdp/auction/stability all normalize to lending|perp.
        self.assertIn("liquidation-abuse",
                      _kind_only_ids("lending", "solidity"))
        self.assertIn("liquidation-abuse", _kind_only_ids("perp", "solidity"))

    def test_oracle_manipulation_reachable(self):
        # via the new oracle family AND via lending/vault/perp/amm/staking.
        self.assertIn("oracle-manipulation",
                      _kind_only_ids("oracle", "solidity"))
        self.assertIn("oracle-manipulation",
                      _kind_only_ids("vault", "solidity"))

    def test_signature_replay_forgery_reachable(self):
        # via crypto-signer (eip712/eip1271/multisig/tss) and distributor (merkle).
        self.assertIn("signature-replay-forgery",
                      _kind_only_ids("crypto-signer", "solidity"))

    def test_unauthorized_upgrade_reachable(self):
        # via the new proxy family (proxy-admin/upgradeable/dispute-game).
        self.assertIn("unauthorized-upgrade-impl-swap",
                      _kind_only_ids("proxy", "solidity"))

    def test_crypto_key_recovery_reachable(self):
        # via crypto-signer (signer/keystore/hd-wallet/mpc/prf-kdf/ring-sig).
        self.assertIn("crypto-key-recovery-leak",
                      _kind_only_ids("crypto-signer", "rust"))

    def test_bc_direct_loss_reachable(self):
        # via consensus (consensus-state-transition) / cosmos-module (bank-keeper).
        ids = _kind_only_ids("cosmos-module", "go")
        self.assertIn("bc-direct-loss-of-funds", ids)

    def test_bc_node_resource_exhaustion_reachable(self):
        # via consensus (node-daemon/p2p/mempool/abci/vm-runtime/state-store).
        self.assertIn("bc-node-resource-exhaustion",
                      _kind_only_ids("consensus", "go"))

    def test_bc_rpc_api_crash_reachable(self):
        # rpc-handler/query-server/api-gateway/mempool-rpc fold to consensus;
        # light-client folds to zk-circuit. Either makes it reachable.
        self.assertIn("bc-rpc-api-crash", _kind_only_ids("consensus", "go"))

    def test_none_of_the_eight_is_kind_unreachable(self):
        # End-to-end: across the classifier-emittable families (lang-permissive
        # within each impact's languages), every one of the 8 attaches by kind.
        reachable = set()
        for fam in sorted(_m._EMITTABLE_KIND_FAMILIES):
            for lang in ("solidity", "go", "rust", "zk", ""):
                reachable |= _kind_only_ids(fam, lang) & set(_PREVIOUSLY_DEAD)
        still_dead = sorted(set(_PREVIOUSLY_DEAD) - reachable)
        self.assertEqual(still_dead, [],
                         f"still kind-unreachable: {still_dead}")


class PartitionHoldsTest(unittest.TestCase):
    """FAIL-CLOSED: the reconciliation must NOT make every impact attach to
    every target. Asserted on the KIND-only channel (neutral shape)."""

    def test_vault_has_no_chain_halt_or_bc_impact(self):
        ids = _kind_only_ids("vault", "solidity")
        self.assertNotIn("chain-halt-shutdown", ids)
        self.assertFalse(any(i.startswith("bc-") for i in ids),
                         f"vault leaked a bc-* impact: {sorted(ids)}")
        self.assertNotIn("chain-split-fork", ids)
        # but a vault DOES legitimately get the DeFi acceptance impacts
        self.assertIn("direct-theft-funds", ids)
        self.assertIn("oracle-manipulation", ids)

    def test_token_has_no_perp_or_consensus_impact(self):
        # A pure token (kind axis) must not get perp-funding/liquidation or any
        # chain-level impact. This is the brief's headline partition.
        ids = _kind_only_ids("token", "solidity")
        self.assertNotIn("liquidation-abuse", ids)
        self.assertNotIn("oracle-manipulation", ids)
        self.assertFalse(any(i.startswith("bc-") for i in ids),
                         f"token leaked a bc-* impact: {sorted(ids)}")
        self.assertNotIn("chain-halt-shutdown", ids)
        self.assertNotIn("chain-split-fork", ids)

    def test_consensus_has_chain_impacts_but_not_vault_only(self):
        ids = _kind_only_ids("consensus", "go")
        # gets the chain-level methodology
        self.assertIn("chain-halt-shutdown", ids)
        self.assertTrue(any(i.startswith("bc-") for i in ids))
        # but NOT vault-only DeFi impacts it does not legitimately share
        self.assertNotIn("share-supply-inflation", ids)
        self.assertNotIn("direct-theft-funds", ids)
        self.assertNotIn("protocol-insolvency", ids)
        self.assertNotIn("liquidation-abuse", ids)

    def test_price_oracle_does_not_inherit_key_recovery(self):
        # Precision guard: `randomness-beacon` is the ONLY non-crypto-signer kind
        # in crypto-key-recovery-leak.applies_to_contract_kinds. It must NOT fold
        # into the generic `oracle` family, or every plain price-feed oracle
        # would wrongly inherit the seed/signing-key-recovery methodology.
        # (Regression: folding randomness-beacon -> oracle caused exactly this.)
        for lang in ("solidity", "rust", "go", ""):
            ids = _kind_only_ids("oracle", lang)
            self.assertNotIn(
                "crypto-key-recovery-leak", ids,
                f"price oracle ({lang or 'any'}) leaked key-recovery: "
                f"{sorted(ids)}",
            )

    def test_randomness_beacon_keeps_key_recovery_dual_nature(self):
        # The flip side: a REAL randomness beacon (VRF/RANDAO/seed) must still
        # reach crypto-key-recovery-leak (the corpus author put it there), so the
        # split is a re-home, not a drop.
        self.assertIn("crypto-key-recovery-leak",
                      _kind_only_ids("randomness-beacon", "rust"))
        # ... and a randomness beacon is classifier-emittable, not an unknown.
        c = _m.classify_impact_target(
            "getRandomNumber", "function getRandomNumber() returns(uint256)",
            scope_text="chainlink vrf randomness beacon",
        )
        self.assertEqual(c["contract_kind"], "randomness-beacon")

    def test_language_still_excludes_zk_only_from_solidity(self):
        # Language stays an exclusion guard even after the kind reconciliation:
        # a go/rust-only consensus playbook must not attach to a solidity vault.
        ids = _kind_only_ids("vault", "solidity")
        self.assertNotIn("chain-split-fork", ids)
        self.assertNotIn("bc-consensus-transient-failure", ids)


class ShapeFamilyMapTest(unittest.TestCase):
    """G1: SHAPE-axis twin of the kind-vocab gap.

    classify_function_shape EMITS only 20 shape classes; the corpus authors
    `applies_to_shape_classes` against 51. 37 corpus shapes were never emittable,
    so their shape attach arm was dead. `_SHAPE_FAMILY` re-homes each onto an
    emittable family; attach becomes a family-intersection.
    """

    def test_every_corpus_shape_maps_to_an_emittable_family(self):
        try:
            import yaml  # type: ignore
        except Exception:  # pragma: no cover - yaml always present in repo
            self.skipTest("yaml unavailable")
        with open(_m._IMPACT_PLAYBOOKS_PATH) as fh:
            data = yaml.safe_load(fh) or {}
        corpus_shapes = set()
        for b in data.get("playbooks", []) or []:
            for s in (b.get("applies_to_shape_classes") or []):
                corpus_shapes.add(str(s).strip().lower())
        # Every corpus shape must normalize to an EMITTABLE family - else its
        # shape arm stays dead (the exact bug this fix closes).
        non_emittable = sorted(
            s for s in corpus_shapes
            if _m.shape_family(s) not in _m._EMITTABLE_SHAPE_FAMILIES
        )
        self.assertEqual(
            non_emittable, [],
            f"corpus shapes that still normalize to a NON-emittable family: "
            f"{non_emittable}",
        )

    def test_shape_family_values_are_all_emittable(self):
        bad = sorted(
            v for v in _m._SHAPE_FAMILY.values()
            if v not in _m._EMITTABLE_SHAPE_FAMILIES
        )
        self.assertEqual(bad, [], f"non-emittable shape-family targets: {bad}")

    def test_emittable_shape_is_self_mapping(self):
        for s in _m._EMITTABLE_SHAPE_FAMILIES:
            self.assertEqual(_m.shape_family(s), s)

    def test_unknown_shape_passes_through_not_widened(self):
        self.assertEqual(_m.shape_family("totally-made-up-shape-xyz"),
                         "totally-made-up-shape-xyz")
        self.assertEqual(_m.shape_family(""), "")

    def test_dead_shape_only_impact_now_attaches_via_shape_family(self):
        # NON-VACUOUS: bc-rpc-api-crash's every shape is in the 37-dead set
        # (rpc-query-handler-fn / grpc-query-service-fn / json-rpc-method-fn /
        # light-client-query-fn / api-deserialization-fn). A go view fn
        # (isReady -> view-getter-fn) must now attach it via the shape-family
        # arm, with the contract-kind arm disabled (a never-seen kind).
        fn, sig = "isReady", "func isReady() bool"
        self.assertEqual(
            set(_m.classify_function_shape(fn, sig)), {"view-getter-fn"},
            "fixture fn must classify to view-getter-fn only",
        )
        ids_with = _ids(
            _m.render_impact_questions(
                fn, sig, language="go", contract_kind="__never-seen-kind__"
            )
        )
        self.assertIn("bc-rpc-api-crash", ids_with)

        # WITHOUT family normalization (identity), the same fn must NOT attach
        # it - proving the family arm is load-bearing, not vacuous.
        orig = _m.shape_family
        try:
            _m.shape_family = lambda s: str(s or "").strip().lower().replace("_", "-")
            ids_without = _ids(
                _m.render_impact_questions(
                    fn, sig, language="go", contract_kind="__never-seen-kind__"
                )
            )
        finally:
            _m.shape_family = orig
        self.assertNotIn(
            "bc-rpc-api-crash", ids_without,
            "shape-family arm did nothing - the attach was already there",
        )

    def test_shape_family_does_not_collapse_partition(self):
        # FAIL-CLOSED: re-homing dead shapes must not give a solidity vault the
        # go-only chain/bc impacts (language exclusion still partitions).
        ids = _ids(
            _m.render_impact_questions(
                "withdraw", "function withdraw(uint256) external",
                language="solidity", contract_kind="vault",
            )
        )
        self.assertFalse(any(i.startswith("bc-") for i in ids),
                         f"solidity vault leaked a bc-* impact: {sorted(ids)}")
        self.assertNotIn("chain-halt-shutdown", ids)
        self.assertNotIn("chain-split-fork", ids)
        # but still gets its legitimate DeFi impacts
        self.assertIn("direct-theft-funds", ids)


class SeverityHintCoverageTest(unittest.TestCase):
    """G2: _impact_severity_hint read only severity_hint/severity_source, so
    26 of 32 playbooks rendered an EMPTY hint. It must read ALL seven corpus
    field-name variants and report the ceiling tier."""

    def test_at_most_two_playbooks_have_empty_hint(self):
        # Measured: only dispute-game-resolution and oracle-manipulation carry
        # NO severity field at all in the corpus (a grounding gap, not a read
        # gap). Every other playbook must now render a non-empty hint - up from
        # the 6/32 the old two-field read produced.
        books = _m.load_impact_playbooks()
        empty = sorted(b["impact_id"] for b in books
                       if not _m._impact_severity_hint(b))
        self.assertLessEqual(
            len(empty), 2,
            f"too many empty severity hints ({len(empty)}): {empty}",
        )
        self.assertGreaterEqual(
            len(books) - len(empty), 30,
            "fewer than 30 playbooks render a severity hint",
        )

    def test_each_variant_field_is_read(self):
        # NON-VACUOUS: one fixture per corpus field-name variant. The old code
        # returned "" for all but severity_hint/severity_source.
        cases = [
            ({"impact_id": "x", "severity_hint": "High"}, "High"),
            ({"impact_id": "x", "severity_source": "etherfi Critical row"}, "Critical"),
            ({"impact_id": "x", "severity_ceiling": "critical"}, "Critical"),
            ({"impact_id": "x", "typical_severity": "HIGH"}, "High"),
            ({"impact_id": "x", "severity_by_program":
              {"spark": "high", "polygon": "medium"}}, "High"),
            ({"impact_id": "x", "severity_rubric_anchors":
              ["base/SEVERITY.md:145 fails to deliver - Medium"]}, "Medium"),
            ({"impact_id": "x", "severity_rows_verbatim":
              [{"row": "drain vault", "tier": "critical"}]}, "Critical"),
            ({"impact_id": "x", "severity_mapping":
              {"a": "low", "b": {"verdict": "high"}}}, "High"),
        ]
        for pb, want in cases:
            self.assertEqual(
                _m._impact_severity_hint(pb), want,
                f"field {sorted(set(pb)-{'impact_id'})} -> wrong hint",
            )

    def test_mapping_reports_ceiling_not_a_benign_branch(self):
        # A mapping with both a benign and a severe branch must surface the
        # ceiling so the hunter is not anchored low.
        pb = {"impact_id": "x", "severity_mapping": {
            "benign": "low", "worst": "critical", "mid": "medium"}}
        self.assertEqual(_m._impact_severity_hint(pb), "Critical")

    def test_no_severity_field_is_empty(self):
        self.assertEqual(_m._impact_severity_hint({"impact_id": "x"}), "")


class LanguageAliasTest(unittest.TestCase):
    """G4: the documented _DEFENSE_SOURCE_EXTS path emits `evm` for .sol/.vy,
    a token NO corpus playbook lists - wired as documented it silently ZEROED
    all solidity + vyper playbooks. `language_alias` normalizes ext-derived /
    shorthand tokens onto the corpus vocabulary; language stays an EXCLUSION
    guard (empty admits, a wrong-language playbook excludes)."""

    _FN = "withdraw"
    _SOL_SIG = "function withdraw(uint256) external"
    _VY_SIG = "def withdraw(): nonpayable"

    def _n(self, language, sig=None, kind="vault"):
        return len(_ids(_m.render_impact_questions(
            self._FN, sig or self._SOL_SIG, language=language, contract_kind=kind)))

    def test_evm_maps_to_solidity(self):
        self.assertEqual(_m.language_alias("evm"), "solidity")
        # NON-VACUOUS: evm now attaches the same set as solidity (was 0).
        self.assertEqual(self._n("evm"), self._n("solidity"))
        self.assertGreater(self._n("evm"), 0)

    def test_evm_was_silent_zero_without_alias(self):
        orig = _m.language_alias
        try:
            _m.language_alias = lambda l: str(l or "").strip().lower()
            self.assertEqual(self._n("evm"), 0,
                             "evm should silent-zero when the alias is bypassed")
        finally:
            _m.language_alias = orig

    def test_shorthand_and_ext_aliases(self):
        self.assertEqual(_m.language_alias("sol"), "solidity")
        self.assertEqual(_m.language_alias("vy"), "vyper")
        self.assertEqual(_m.language_alias("rs"), "rust")
        self.assertEqual(_m.language_alias("golang"), "go")
        self.assertEqual(_m.language_alias("starknet"), "cairo")
        self.assertEqual(_m.language_alias("aptos"), "move")
        self.assertEqual(_m.language_alias("zk-circuit"), "zk")

    def test_vyper_shorthand_attaches(self):
        # vy -> vyper attaches the vyper playbooks (was 0 without the alias).
        self.assertGreater(self._n("vy", self._VY_SIG), 0)

    def test_cairo_and_move_targets_attach(self):
        # A real cairo / move target attaches (not zeroed).
        self.assertGreater(self._n("cairo"), 0)
        self.assertGreater(self._n("move"), 0)

    def test_corpus_token_passes_through_unchanged(self):
        for tok in ("solidity", "rust", "go", "vyper", "cairo", "move", "zk",
                    "circom", "noir", "leo", "nim"):
            self.assertEqual(_m.language_alias(tok), tok)

    def test_empty_language_admits_all(self):
        self.assertEqual(_m.language_alias(""), "")
        # empty target language never excludes -> superset of any single lang.
        self.assertGreaterEqual(self._n(""), self._n("solidity"))

    def test_language_still_excludes_wrong_language(self):
        # EXCLUSION guard intact: a go/rust-only consensus playbook must not
        # attach to a solidity vault even after aliasing.
        ids = _ids(_m.render_impact_questions(
            self._FN, self._SOL_SIG, language="evm", contract_kind="vault"))
        self.assertFalse(any(i.startswith("bc-") for i in ids),
                         f"evm(solidity) vault leaked a bc-* impact: {sorted(ids)}")


if __name__ == "__main__":
    unittest.main()
