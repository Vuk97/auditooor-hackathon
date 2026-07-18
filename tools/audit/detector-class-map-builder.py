#!/usr/bin/env python3
"""detector-class-map-builder.py - build a content-derived detector-to-attack-class
map and a zero-coverage report (Wave-5 lane W5-A6).

Problem this answers
--------------------
detector-catch-rate-backtest.py derives each DSL pattern's attack_class from a
slug + tags keyword guess (derive_attack_class). On the 892 fixture-pair
patterns that guess leaves 325 (36%) "uncategorized", and across all 1,542 DSL
patterns the uncategorized share is far higher. An uncategorized bucket that
large makes the per-class recall table - and the bug-class prioritizer that
consumes it - statistically blind.

This tool builds a PROPER map. For each DSL pattern it classifies against the
canonical 103-class taxonomy in reference/attack_class_vocab.yaml, derived from
the pattern's ACTUAL content (help / wiki_title / wiki_description /
wiki_exploit_scenario / message / source) - not just the slug. The slug + tags
remain a contributing signal but the rich vuln-description text is the primary
evidence.

It then emits two artifacts:

  1. reference/detector_class_map_complete.yaml - the completed map. Every DSL
     pattern gets an explicit `attack_class` (a canonical class_id) plus the
     `evidence` (which field the classification came from) and a `confidence`.
  2. reports/detector_zero_coverage_<date>.json + .md - the coverage report:
     which canonical attack classes have ZERO detectors backing them (the true
     zero-coverage set the prioritizer needs).

Method
------
* CLASS_KEYWORDS below maps each canonical class_id (or a small alias group) to
  a list of evidence regexes. The regexes were authored against the canonical
  class `name` + `description` fields, not invented - run `--dump-vocab` to see
  the source taxonomy.
* For each pattern the classifier scans, in priority order: tags, slug,
  help+wiki_title, wiki_description+wiki_exploit_scenario+message. The first
  field that yields a class match wins; the field name is recorded as
  `evidence`. A slug/tag hit is `confidence: high`; a description-only hit is
  `confidence: medium`; the legacy 21-class fallback is `confidence: low`.
* If nothing matches, the pattern stays `uncategorized` - but the report
  measures exactly how many, before and after, so the lift is honest.

Stdlib + pyyaml. Exits 0 always (measurement / map-build tool).
"""

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
VOCAB_PATH = REPO_ROOT / "reference" / "attack_class_vocab.yaml"
DEFAULT_MAP_OUT = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
DEFAULT_REPORT_DIR = REPO_ROOT / "reports"
MAP_SCHEMA = "auditooor.detector_class_map_complete.v1"
REPORT_SCHEMA = "auditooor.detector_zero_coverage_report.v1"
ATTACK_CLASS_ALIASES_FIELD = "attack_class_aliases"

# --------------------------------------------------------------------------
# Content -> canonical-class keyword table.
#
# Each entry: (canonical_class_id, [regex, ...]). Regexes are matched
# case-insensitively against pattern content. Order is most-specific first;
# the first class whose regex hits wins. canonical_class_id MUST exist in
# reference/attack_class_vocab.yaml (verified at load time, see _verify_vocab).
# --------------------------------------------------------------------------
CLASS_KEYWORDS = [
    # --- access control / admin / proxy ---
    ("proxy-hijack", [r"delegatecall", r"proxy.{0,12}(impl|admin|upgrade)",
                      r"uups", r"authorize\W?upgrade", r"storage.{0,6}gap",
                      r"storage.{0,6}collision"]),
    ("initializer-front-run", [r"initiali[sz]", r"re-?initiali",
                               r"disable\W?initializer", r"phantom.?init"]),
    ("listing-authority-bypass", [r"list(ing)?.{0,20}authority",
                                  r"market.{0,12}creat", r"perpetual.{0,12}list"]),
    ("admin-bypass", [r"access.?control", r"only\W?owner", r"missing.{0,8}auth",
                      r"unauthor", r"privileg", r"\brole\b", r"two.?step.{0,12}owner",
                      r"ownership.{0,12}(transfer|hijack)", r"permissionless",
                      r"tx\.?origin", r"msg.?sender.{0,12}(spoof|forg)",
                      r"authz.{0,8}grant"]),
    # --- reentrancy / callback ---
    # reentrancy-during-pause MUST be checked before emergency-bypass: the
    # broad r"pause" keyword of emergency-bypass would otherwise swallow any
    # "reentrancy-during-pause" pattern. Most-specific-first ordering.
    ("reentrancy-during-pause", [r"reentran.{0,20}paus", r"paus.{0,20}reentran"]),
    # --- emergency / pause ---
    ("emergency-bypass", [r"pause", r"circuit.?breaker", r"emergency",
                          r"missing.?unpause"]),
    ("callback-hook-exploit", [r"\bhook\b", r"callback.{0,20}(drain|exploit|mid.?state)",
                               r"erc1155.?received", r"on\w+received",
                               r"lzreceive", r"flashloan.?callback"]),
    ("reentrancy-cross-contract", [r"reentran", r"cei.?violation",
                                   r"external.?call.?before.?state",
                                   r"read.?only.?reentran", r"cross.?function.?reentran"]),
    # Snowbridge-style versioned digest verifiers mention replay/signature
    # language in the description, but the defect is the bridge proof/domain
    # binding: the data tag is not selected from the caller's version flag.
    # Keep this before the generic signature/replay bucket.
    ("bridge-proof-domain-bypass", [r"version(ed)?.{0,24}(digest|tag)",
                                    r"digest.{0,24}version",
                                    r"tag.{0,24}protocol.?version",
                                    r"version.?isolation",
                                    r"iscommitmentinheaderdigest"]),
    # --- signature / replay ---
    ("approval-replay", [r"approv.{0,16}repl", r"erc.?2612.{0,16}repl",
                         r"permit.{0,16}repl"]),
    ("cross-chain-replay", [r"cross.?chain.?repl", r"replay.{0,16}(sibling|fork).?chain",
                            r"missing.?chain\W?id", r"chainid.{0,16}domain"]),
    ("signature-forgery", [r"signature.{0,16}forg", r"forg.{0,16}signature",
                           r"ecrecover.{0,16}(zero|forg)", r"malleab"]),
    ("signature-replay-cross-domain", [r"signature.?repl", r"sig(nature)?\W?replay",
                                       r"eip.?712", r"domain.?separator",
                                       r"without.?nonce", r"missing.?nonce",
                                       r"intent.?hash", r"permit2"]),
    ("replay-stale-msg", [r"stale.?msg", r"replay.{0,16}(stale|old).?message"]),
    # --- oracle ---
    ("liquidation-trigger-poison", [r"oracle.{0,20}liquidat", r"liquidat.{0,20}oracle"]),
    # share-price-manipulation MUST be checked before oracle-price-manipulation:
    # the broad r"price.?manip" keyword would otherwise swallow ERC4626
    # share-price-manipulation patterns. Most-specific-first ordering.
    ("share-price-manipulation", [r"share.?price.?manip", r"erc4626.{0,20}manip"]),
    ("oracle-price-manipulation", [r"oracle", r"price.?manip", r"spot.?price",
                                   r"\btwap\b", r"price\W?per\W?share",
                                   r"chainlink", r"stale.?price", r"price.?feed",
                                   r"feed.?decimal", r"deviation.?band"]),
    # --- liquidation / perps / insurance ---
    ("insurance-fund-drain", [r"insurance.?fund", r"insolvent.{0,20}liquidat"]),
    ("perpetual-position-stuck", [r"position.{0,12}stuck", r"unliquidatable"]),
    ("funding-rate-manipulation", [r"funding.?rate"]),
    ("matching-engine-misprice", [r"matching.?engine", r"\bclob\b",
                                  r"fill.?price", r"misprice"]),
    # Permit nonce grief is a mempool-ordering shape. Keep this above the
    # rounding bucket because prose such as "wrapped around permit" otherwise
    # matches the broad "round in" keyword.
    ("transaction-ordering-race", [r"permit.{0,32}front.?run",
                                   r"front.?run.{0,32}permit",
                                   r"permit.{0,32}nonce.{0,32}(mismatch|consum)",
                                   r"nonce.{0,32}(mismatch|consum).{0,32}permit"]),
    # --- arithmetic / rounding ---
    ("integer-overflow-clamp", [r"overflow", r"underflow", r"downcast",
                                r"truncat", r"int\d+.?cast", r"clamp"]),
    ("rounding-direction-attack", [r"round(ing)?.?(direction|favor|in\W)",
                                   r"div.?before.?mul", r"precision.?loss",
                                   r"off.?by.?one", r"division.?by.?zero",
                                   r"divide.?by.?zero"]),
    ("fund-loss-via-arithmetic", [r"arithmetic.{0,16}(bug|error).{0,16}fund",
                                  r"accounting.?error", r"stale.?accounting",
                                  r"paired.?state.{0,16}asym", r"deploy.{0,16}undeploy",
                                  r"bookkeeping.{0,24}symmetr", r"deployed.?balance.{0,16}drift"]),
    # --- erc4626 / vaults / donation ---
    # Exact `donation-attack` tags are handled before regex matching in
    # classify_pattern. Keep this content regex after arithmetic classes so
    # Silo-style "donation causes >100% utilization; missing clamp" records do
    # not get swallowed by the broader donation bucket.
    ("donation-attack", [r"donation.?attack", r"direct.{0,12}donat"]),
    ("first-depositor-inflation", [r"first.?depositor", r"inflation.?attack",
                                   r"erc4626", r"erc-4626", r"vault.?share"]),
    # --- delegation / governance ---
    ("vote-double-count", [r"vote.{0,12}double", r"double.?count.{0,12}vote"]),
    ("delegatee-overwrite", [r"delegatee.{0,12}overwrit", r"delegat.{0,20}overwrit"]),
    ("delegation-power-inflation", [r"delegation.?power", r"delegat.{0,12}inflat"]),
    ("veto-quorum-bypass", [r"veto.?quorum", r"quorum.{0,16}bypass"]),
    ("supply-inflation-denominator-skew", [r"denominator.?(skew|inflat)",
                                           r"supply.?inflat.{0,20}veto"]),
    ("governance-snapshot-mismatch", [r"snapshot.{0,16}(quorum|veto|block)",
                                      r"governance.?snapshot"]),
    ("optimistic-governor-poison", [r"optimistic.?governor"]),
    ("gov-param-injection", [r"governance.?param", r"consensus.?param.{0,16}inject"]),
    ("consensus-param-corruption", [r"consensus.?param"]),
    # --- timelock / governance generic ---
    ("delayed-msg-injection", [r"delayed.?msg", r"timelock.{0,16}bypass",
                               r"is\w*operation\w*ready"]),
    # --- token freeze / supply ---
    ("freeze-flag-flip", [r"freeze.?flag", r"freeze.{0,12}flip"]),
    ("token-freeze-bypass", [r"freeze.{0,12}bypass", r"token.?freeze"]),
    ("mint-burn-asymmetry", [r"mint.{0,12}burn.{0,16}asymm", r"unlimited.?mint"]),
    ("token-supply-inflation", [r"supply.?inflat", r"unauthor.{0,12}mint"]),
    # --- bridge / cross-domain ---
    ("bridge-proof-domain-bypass", [r"bridge.?proof", r"proof.{0,16}domain"]),
    ("cross-subaccount-theft", [r"cross.?subaccount", r"subaccount.{0,12}(theft|steal)"]),
    ("sub-account-isolation-bypass", [r"sub.?account.{0,16}isolat"]),
    # --- dos / griefing / resource ---
    ("dos-cap-weakening", [r"cap.{0,12}(weaken|exhaust)", r"unbounded.?loop",
                           r"gas.?(grief|exhaust|limit)", r"unbounded.?array",
                           r"unbounded.?(state|growth)", r"return.?bomb",
                           r"63.?64.?rule"]),
    ("relayer-griefing", [r"relayer.?grief", r"relayer.{0,16}(crafted|timeout)"]),
    ("ibc-rate-limit-bypass", [r"ibc.?rate.?limit", r"rate.?limit.{0,16}bypass"]),
    ("market-listing-griefing", [r"listing.?grief", r"market.?listing.?grief"]),
    ("exit-finalization-griefing", [r"exit.{0,16}grief", r"finaliz.{0,16}grief"]),
    # --- state corruption / race / persistence ---
    ("cache-coherence-violation", [r"cache.?coheren", r"stale.?(cache|read)"]),
    # EVM "race" usually means transaction ordering / mempool ordering, not
    # shared-state corruption. Keep this before state-corruption-via-race so
    # approve races, flag/unflag races, and L2 finalization race windows do not
    # pollute the Go/concurrency class.
    ("transaction-ordering-race", [r"approve.{0,32}(race|front.?run|non.?zero)",
                                   r"safeApprove.{0,32}non.?zero",
                                   r"non.?zero.{0,16}to.{0,16}non.?zero",
                                   r"flag.{0,16}unflag|unflag.{0,24}(race|resolve)",
                                   r"DELAY_PERIOD.{0,16}0",
                                   r"mempool.{0,32}(race|front|order)",
                                   r"transaction.?ordering",
                                   r"same.?block.{0,24}(race|front.?run|order)",
                                   r"front.?runs?.{0,32}(liquidat|repay|same.?block|mempool|settle|resolve|emergency)",
                                   r"rebase.{0,24}race|race.{0,24}rebase|negative.?rebase",
                                   r"finali[sz].{0,32}race.?window",
                                   r"withdrawal.{0,32}finali[sz].{0,32}race",
                                   r"create2.{0,32}reorg|reorg.{0,32}create2",
                                   r"factory.{0,32}new keyword"]),
    ("state-corruption-via-race", [r"goroutine.{0,16}(race|sync)",
                                   r"goroutines?.{0,48}shared.{0,16}state",
                                   r"shared.{0,16}state.{0,48}synchroni[sz]",
                                   r"concurrent.{0,16}(access|state|write)",
                                   r"data.?race",
                                   r"\bmutex\b", r"\bsync\.RW?Mutex\b",
                                   r"thread.{0,16}(race|unsafe)",
                                   r"toctou.{0,16}(state|tree|store)",
                                   r"iavl.{0,16}race"]),
    ("state-change-between-check-and-use", [r"check.{0,12}use", r"between.?check",
                                            r"state.?change.{0,16}check"]),
    ("state-persistence-corruption", [r"persist.{0,16}corrupt", r"restart.{0,16}(loss|lost)"]),
    ("root-hash-mismatch", [r"root.?hash", r"format.?migration"]),
    ("state-tree-corruption", [r"state.?tree.?corrupt", r"tree.?node.?corrupt"]),
    ("state-bloat", [r"state.?bloat", r"unbounded.?state.?growth"]),
    ("apphash-divergence", [r"apphash", r"app.?hash.?divergen"]),
    # --- shutdown / leak / panic ---
    ("graceful-shutdown-deadlock", [r"graceful.?shutdown", r"shutdown.?deadlock"]),
    ("resource-leak-on-shutdown", [r"resource.?leak", r"fd.?leak", r"goroutine.?leak"]),
    ("goleveldb-file-leak", [r"goleveldb.{0,16}leak", r"file.?descriptor.?leak"]),
    ("nil-pointer-panic", [r"nil.?pointer", r"nil.?deref"]),
    # --- arrays / oob ---
    ("missing-last-element-validation", [r"last.?element", r"off.?by.?one.{0,16}array"]),
    ("loop-invariant-bypass", [r"loop.?invariant"]),
    ("array-oob-access", [r"out.?of.?bounds", r"array.?index", r"\boob\b"]),
    # --- offchain / indexer ---
    ("postgres-injection", [r"sql.?inject", r"postgres.{0,16}inject"]),
    ("offchain-state-poisoning", [r"indexer.{0,16}poison", r"off.?chain.{0,16}poison"]),
    # --- genesis / upgrade ---
    ("genesis-state-injection", [r"genesis.?state", r"genesis.{0,16}inject"]),
    ("initgenesis-determinism-violation", [r"initgenesis", r"non.?determinis"]),
    ("upgrade-handler-malformed-state", [r"upgrade.?handler", r"post.?upgrade.{0,16}state"]),
    # --- fees / rewards / recipient ---
    ("fee-redirect", [r"fee.?redirect", r"fee.{0,16}unintended"]),
    ("fee-grant-replay", [r"fee.?grant.{0,12}repl"]),
    ("rewards-claim-replay", [r"reward.{0,12}claim.{0,12}(repl|double)",
                              r"double.?settle"]),
    ("blocked-addr-rewards-redirect", [r"reward.{0,16}blocked.?addr"]),
    ("rewards-distribution-skew", [r"reward", r"staking", r"emission",
                                   r"reward.?debt", r"reward.?index",
                                   r"reward.?per.?token", r"\byield\b",
                                   r"checkpoint", r"\bgauge\b"]),
    ("missing-recipient-validation", [r"recipient.{0,16}(not.?validat|valid)",
                                      r"zero.?address", r"zero.?addr.{0,8}check"]),
    # --- chain-watcher / statechain (Spark) ---
    ("htlc-resolution-skip", [r"htlc.{0,16}resolut"]),
    ("chain-watcher-bypass", [r"chain.?watcher", r"exit.?validation"]),
    ("commit-resume-failure", [r"commit.?resume"]),
    ("key-tweak-state-loss", [r"key.?tweak"]),
    ("statechain-permafreeze", [r"statechain.{0,16}freeze", r"leaf.{0,16}freeze"]),
    ("permafreeze-on-restart", [r"permafreeze.{0,16}restart", r"restart.{0,16}freeze"]),
    ("module-account-permafreeze", [r"module.?account.{0,16}freeze"]),
    # --- selector / authz ---
    ("selector-registration-bypass", [r"selector.{0,16}regist"]),
    ("authz-grant-bypass", [r"authz"]),
    # --- mev / sequencing ---
    ("rounding-direction-attack", [r"\bmev\b", r"sandwich", r"slippage"]),
    # --- fork / upstream divergence ---
    ("fork-lag-divergence", [r"fork.{0,12}(lag|behind)", r"upstream.?fix",
                             r"backport"]),
    ("blocksync-poisoning", [r"blocksync"]),
    ("cross-repo-divergence", [r"sibling.?repo", r"cross.?repo"]),
    ("fix-not-applied-to-sibling", [r"fix.{0,16}not.?(applied|propagat)",
                                    r"sibling.{0,16}(fix|module)"]),
    ("reverted-guard-still-live", [r"reverted.?guard", r"guard.?reverted"]),
    # --- generic deadline / timestamp ---
    ("timestamp-manipulation", [r"block.?timestamp", r"deadline.{0,16}block",
                                r"timestamp.?manip"]),
    ("oracle-update-race", [r"oracle.?update.?race"]),
]

# legacy 21-class fallback used by detector-catch-rate-backtest.py. Kept as the
# lowest-priority signal so a pattern is never WORSE classified than today.
LEGACY_FALLBACK = {
    "reentrancy": "reentrancy-cross-contract",
    "access-control": "admin-bypass",
    "signature-replay": "signature-replay-cross-domain",
    "oracle-manipulation": "oracle-price-manipulation",
    "flashloan": "callback-hook-exploit",
    "bridge-cross-chain": "bridge-proof-domain-bypass",
    "erc4626-vault": "first-depositor-inflation",
    "liquidation": "liquidation-trigger-poison",
    "reward-accounting": "rewards-distribution-skew",
    "rounding-precision": "rounding-direction-attack",
    "dos-griefing": "dos-cap-weakening",
    "upgradeability": "proxy-hijack",
    "governance": "gov-param-injection",
    "token-transfer": "missing-recipient-validation",
    "input-validation": "missing-recipient-validation",
    "mev-ordering": "transaction-ordering-race",
    "nft-asset": "callback-hook-exploit",
    "zk-crypto": "signature-forgery",
    "accounting-state": "fund-loss-via-arithmetic",
    "fee-handling": "fee-redirect",
}

LEGACY_KEYWORDS = [
    ("reentrancy", ["reentran", "cei-violation", "callback-reentran",
                    "readonly-reentran"]),
    ("access-control", ["access-control", "onlyowner", "missing-access",
                        "unauthorized", "privileged", "role-", "permission"]),
    ("signature-replay", ["replay", "signature", "ecrecover", "ecdsa",
                          "eip712", "eip-712", "nonce", "permit"]),
    ("oracle-manipulation", ["oracle", "price-manip", "twap", "chainlink",
                             "stale-price"]),
    ("flashloan", ["flashloan", "flash-loan"]),
    ("bridge-cross-chain", ["bridge", "cross-chain", "layerzero", "ccip"]),
    ("erc4626-vault", ["erc4626", "erc-4626", "first-depositor", "share-price"]),
    ("liquidation", ["liquidat", "bad-debt", "undercollateral"]),
    ("reward-accounting", ["reward", "staking", "emission", "gauge", "yield"]),
    ("rounding-precision", ["rounding", "precision", "truncat", "division",
                            "off-by-one", "overflow", "underflow"]),
    ("dos-griefing", ["dos", "griefing", "unliquidatable", "frontrun"]),
    ("upgradeability", ["upgrade", "uups", "proxy", "delegatecall", "initiali"]),
    ("governance", ["governance", "governor", "quorum", "voting", "timelock"]),
    ("token-transfer", ["transferfrom", "safetransfer", "erc20", "rebasing",
                        "fee-on-transfer", "unchecked-return"]),
    ("input-validation", ["zero-address", "input-valid", "unvalidated",
                          "missing-validation", "unchecked"]),
    ("mev-ordering", ["mev", "sandwich", "slippage"]),
    ("nft-asset", ["nft", "erc721", "erc1155", "erc6909", "seaport"]),
    ("zk-crypto", ["zk-", "fiat-shamir", "constraint", "merkle", "frost",
                   "schnorr", "proof-"]),
    ("accounting-state", ["accounting", "stale", "snapshot", "duplicate"]),
    ("fee-handling", ["fee-", "protocol-fee", "premium"]),
]


def load_vocab(vocab_path: Path):
    """Return (set of canonical class_ids, list of full entries)."""
    import yaml
    entries = yaml.safe_load(vocab_path.read_text()) or []
    ids = {e["class_id"] for e in entries if isinstance(e, dict) and "class_id" in e}
    return ids, entries


def _verify_keyword_table(vocab_ids):
    """Every class referenced by CLASS_KEYWORDS / LEGACY_FALLBACK must exist."""
    bad = []
    for cls, _ in CLASS_KEYWORDS:
        if cls not in vocab_ids:
            bad.append(cls)
    for cls in LEGACY_FALLBACK.values():
        if cls not in vocab_ids:
            bad.append(cls)
    return sorted(set(bad))


def _compile_class_keywords():
    """Pre-compile CLASS_KEYWORDS regexes once."""
    out = []
    for cls, regexes in CLASS_KEYWORDS:
        out.append((cls, [re.compile(r, re.IGNORECASE) for r in regexes]))
    return out


_COMPILED = None
_VOCAB_IDS_CACHE = None


def _known_class_ids():
    """Return canonical class ids from the vocab, best-effort for imports/tests."""
    global _VOCAB_IDS_CACHE
    if _VOCAB_IDS_CACHE is None:
        try:
            _VOCAB_IDS_CACHE, _ = load_vocab(VOCAB_PATH)
        except Exception:
            _VOCAB_IDS_CACHE = set()
    return _VOCAB_IDS_CACHE


def classify_pattern(spec, slug):
    """Classify one DSL pattern spec to a canonical attack_class.

    Returns dict: {attack_class, evidence, confidence}. attack_class is a
    canonical class_id or 'uncategorized'.
    """
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = _compile_class_keywords()

    tags = spec.get("tags") or []
    tag_text = " ".join(str(t) for t in tags)
    slug_text = (slug or "").replace("_", "-")
    title_text = " ".join(str(spec.get(k, "")) for k in ("help", "wiki_title",
                                                          "message"))
    desc_text = " ".join(str(spec.get(k, "")) for k in (
        "wiki_description", "wiki_exploit_scenario", "wiki_recommendation",
        "source"))

    normalized_tags = {str(tag).strip().lower().replace("_", "-") for tag in tags}
    if "donation-attack" in normalized_tags:
        return {"attack_class": "donation-attack", "evidence": "tags",
                "confidence": "high"}
    if "fund-loss-via-arithmetic" in normalized_tags:
        return {"attack_class": "fund-loss-via-arithmetic", "evidence": "tags",
                "confidence": "high"}

    # priority-ordered (field_label, text, confidence)
    fields = [
        ("tags", tag_text, "high"),
        ("slug", slug_text, "high"),
        ("help-title", title_text, "medium"),
        ("description", desc_text, "medium"),
    ]
    for label, text, conf in fields:
        if not text.strip():
            continue
        for cls, regexes in _COMPILED:
            for rx in regexes:
                if rx.search(text):
                    return {"attack_class": cls, "evidence": label,
                            "confidence": conf}

    # legacy fallback - slug + tags only, then map the legacy class onto a
    # canonical class via LEGACY_FALLBACK.
    legacy_hay = (slug_text + " " + tag_text).lower()
    for legacy_cls, kws in LEGACY_KEYWORDS:
        for kw in kws:
            if kw in legacy_hay:
                return {"attack_class": LEGACY_FALLBACK[legacy_cls],
                        "evidence": "legacy-fallback", "confidence": "low"}

    return {"attack_class": "uncategorized", "evidence": "none",
            "confidence": "none"}


def normalize_class_id(raw):
    """Normalize an explicit class id or legacy class alias to canonical form."""
    cls = str(raw or "").strip().lower().replace("_", "-")
    if not cls:
        return ""
    return LEGACY_FALLBACK.get(cls, cls)


def explicit_attack_class_aliases(spec, primary_attack_class):
    """Return explicit secondary attack classes declared by a DSL pattern.

    The primary classifier is intentionally single-label so the map stays
    stable and explainable. A small number of patterns are semantically
    multi-class though: e.g. a missing signed-action deadline is both
    signature replay and timestamp/deadline manipulation. Those cases should
    be opt-in and auditable instead of inferred by broad keyword matching.
    """
    raw = spec.get(ATTACK_CLASS_ALIASES_FIELD) or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    primary = normalize_class_id(primary_attack_class)
    if primary == "uncategorized":
        return []
    known_ids = _known_class_ids()
    aliases = []
    for item in raw:
        cls = normalize_class_id(item)
        if cls and cls != "uncategorized" and cls != primary \
                and (not known_ids or cls in known_ids):
            aliases.append(cls)
    return sorted(set(aliases))


def legacy_derive_attack_class(slug, tags):
    """Reproduce detector-catch-rate-backtest.derive_attack_class for the
    before/after comparison - the 21-class legacy taxonomy."""
    hay = (slug or "").lower().replace("_", "-")
    tag_hay = " ".join(str(t).lower() for t in (tags or []))
    for cls, kws in LEGACY_KEYWORDS:
        for kw in kws:
            if kw in tag_hay:
                return cls
    for cls, kws in LEGACY_KEYWORDS:
        for kw in kws:
            if kw in hay:
                return cls
    return "uncategorized"


def discover_patterns(patterns_dir: Path, fixture_only: bool):
    """Yield (slug, spec, has_fixture_pair) for every DSL pattern."""
    import yaml
    out = []
    for yf in sorted(patterns_dir.glob("*.yaml")):
        try:
            spec = yaml.safe_load(yf.read_text())
        except Exception:
            continue
        if not isinstance(spec, dict):
            continue
        slug = spec.get("pattern") or yf.stem
        fx = spec.get("fixtures") or {}
        has_pair = bool(fx.get("vuln") and fx.get("clean"))
        if fixture_only and not has_pair:
            continue
        out.append((slug, spec, has_pair))
    return out


def build_map(patterns):
    """Classify every pattern. Return (mappings list, stats dict)."""
    mappings = []
    before = Counter()
    after = Counter()
    confidence = Counter()
    for slug, spec, has_pair in patterns:
        legacy = legacy_derive_attack_class(slug, spec.get("tags"))
        before[legacy] += 1
        result = classify_pattern(spec, slug)
        aliases = explicit_attack_class_aliases(spec, result["attack_class"])
        after[result["attack_class"]] += 1
        confidence[result["confidence"]] += 1
        row = {
            "pattern": slug,
            "attack_class": result["attack_class"],
            "evidence": result["evidence"],
            "confidence": result["confidence"],
            "severity": str(spec.get("severity", "")).upper() or "UNKNOWN",
            "has_fixture_pair": has_pair,
        }
        if aliases:
            row[ATTACK_CLASS_ALIASES_FIELD] = aliases
        mappings.append(row)
    stats = {
        "patterns_total": len(patterns),
        "before_uncategorized": before["uncategorized"],
        "after_uncategorized": after["uncategorized"],
        "before_distinct_classes": len([c for c in before if c != "uncategorized"]),
        "after_distinct_classes": len([c for c in after if c != "uncategorized"]),
        "confidence_breakdown": dict(confidence),
    }
    return mappings, stats


def build_coverage_report(mappings, vocab_ids, vocab_entries):
    """Return (covered list, zero_coverage list) of canonical classes."""
    primary_by_class = defaultdict(list)
    alias_by_class = defaultdict(list)
    for m in mappings:
        if m["attack_class"] != "uncategorized":
            primary_by_class[m["attack_class"]].append(m["pattern"])
        for cls in sorted(set(m.get(ATTACK_CLASS_ALIASES_FIELD) or [])):
            alias_by_class[cls].append(m["pattern"])
    name_by_id = {e["class_id"]: e.get("name", "")
                  for e in vocab_entries if isinstance(e, dict)}
    parent_by_id = {e["class_id"]: e.get("parent_class")
                    for e in vocab_entries if isinstance(e, dict)}
    covered, zero = [], []
    for cid in sorted(vocab_ids):
        n = len(primary_by_class.get(cid, []))
        alias_n = len(alias_by_class.get(cid, []))
        row = {"class_id": cid, "name": name_by_id.get(cid, ""),
               "parent_class": parent_by_id.get(cid),
               "detector_count": n,
               "primary_detector_count": n,
               "alias_detector_count": alias_n,
               "alias_patterns": sorted(alias_by_class.get(cid, []))[:20]}
        (covered if n > 0 else zero).append(row)
    covered.sort(key=lambda r: -r["detector_count"])
    return covered, zero


def render_report_md(stats, covered, zero):
    L = []
    L.append("# Detector-to-attack-class coverage report (W5-A6)")
    L.append("")
    L.append(f"_generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}_")
    L.append(f"_schema: {REPORT_SCHEMA}_")
    L.append("")
    L.append("## Map-completion lift")
    L.append("")
    L.append(f"- DSL patterns classified: **{stats['patterns_total']}**")
    L.append(f"- uncategorized BEFORE (slug+tag heuristic): "
             f"**{stats['before_uncategorized']}** "
             f"({100*stats['before_uncategorized']/max(stats['patterns_total'],1):.0f}%)")
    L.append(f"- uncategorized AFTER (content-derived map): "
             f"**{stats['after_uncategorized']}** "
             f"({100*stats['after_uncategorized']/max(stats['patterns_total'],1):.0f}%)")
    L.append(f"- distinct canonical classes covered: "
             f"**{stats['after_distinct_classes']}** "
             f"(was {stats['before_distinct_classes']} legacy classes)")
    L.append(f"- confidence breakdown: {stats['confidence_breakdown']}")
    L.append("")
    L.append("## Zero-coverage canonical attack classes")
    L.append("")
    L.append(f"**{len(zero)}** of {len(covered)+len(zero)} canonical classes "
             f"have ZERO detectors. These are the true zero-coverage set the "
             f"bug-class prioritizer must treat as detector-writing priorities.")
    L.append("")
    L.append("| class_id | parent | alias-backed detectors | name |")
    L.append("|----------|--------|------------------------|------|")
    for r in zero:
        L.append(f"| {r['class_id']} | {r['parent_class'] or '-'} | "
                 f"{r['alias_detector_count']} | {r['name']} |")
    L.append("")
    L.append("## Covered classes (detector count, descending)")
    L.append("")
    L.append("| class_id | primary detectors | alias-backed detectors |")
    L.append("|----------|-------------------|------------------------|")
    for r in covered:
        L.append(f"| {r['class_id']} | {r['detector_count']} | "
                 f"{r['alias_detector_count']} |")
    L.append("")
    return "\n".join(L)


def write_map_yaml(path: Path, mappings, stats):
    import yaml
    by_pattern = {}
    for m in sorted(mappings, key=lambda x: x["pattern"]):
        by_pattern[m["pattern"]] = {
            "attack_class": m["attack_class"],
            "evidence": m["evidence"],
            "confidence": m["confidence"],
            "severity": m["severity"],
            "has_fixture_pair": m["has_fixture_pair"],
        }
        if m.get(ATTACK_CLASS_ALIASES_FIELD):
            by_pattern[m["pattern"]][ATTACK_CLASS_ALIASES_FIELD] = (
                m[ATTACK_CLASS_ALIASES_FIELD]
            )
    doc = {
        "schema": MAP_SCHEMA,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": "content-derived (help/wiki/tags/slug) classified against "
                  "reference/attack_class_vocab.yaml canonical taxonomy",
        "stats": stats,
        "mappings": by_pattern,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False, width=100,
                                   default_flow_style=False))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patterns-dir", default=str(DEFAULT_PATTERNS_DIR))
    ap.add_argument("--vocab", default=str(VOCAB_PATH))
    ap.add_argument("--map-out", default=str(DEFAULT_MAP_OUT))
    ap.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    ap.add_argument("--fixture-only", action="store_true",
                    help="classify only patterns with a fixture pair (the "
                         "backtest's scorable corpus)")
    ap.add_argument("--dump-vocab", action="store_true",
                    help="print the canonical taxonomy and exit")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    vocab_path = Path(args.vocab)
    if not vocab_path.exists():
        sys.stderr.write(f"vocab not found: {vocab_path}\n")
        return 0
    vocab_ids, vocab_entries = load_vocab(vocab_path)

    if args.dump_vocab:
        for e in vocab_entries:
            if isinstance(e, dict):
                print(f"{e['class_id']:40} {e.get('name','')}")
        return 0

    bad = _verify_keyword_table(vocab_ids)
    if bad:
        sys.stderr.write(f"ERROR: keyword table references non-canonical "
                          f"classes: {bad}\n")
        return 0

    patterns_dir = Path(args.patterns_dir)
    if not patterns_dir.exists():
        sys.stderr.write(f"patterns dir not found: {patterns_dir}\n")
        return 0

    patterns = discover_patterns(patterns_dir, args.fixture_only)
    if not args.quiet:
        sys.stderr.write(f"[map-builder] {len(patterns)} DSL patterns "
                         f"(fixture_only={args.fixture_only})\n")

    mappings, stats = build_map(patterns)
    covered, zero = build_coverage_report(mappings, vocab_ids, vocab_entries)

    map_out = Path(args.map_out)
    write_map_yaml(map_out, mappings, stats)

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    date = time.strftime("%Y-%m-%d", time.gmtime())
    json_path = report_dir / f"detector_zero_coverage_{date}.json"
    md_path = report_dir / f"detector_zero_coverage_{date}.md"
    json_path.write_text(json.dumps({
        "schema": REPORT_SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stats": stats,
        "covered_classes": covered,
        "zero_coverage_classes": zero,
    }, indent=2))
    md_path.write_text(render_report_md(stats, covered, zero))

    if not args.quiet:
        print(render_report_md(stats, covered, zero))
        print(f"\n[map]    {map_out}")
        print(f"[report] {json_path}")
        print(f"[report] {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
