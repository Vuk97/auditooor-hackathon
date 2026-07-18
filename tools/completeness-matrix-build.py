#!/usr/bin/env python3
"""completeness-matrix-build.py - the enumeration-floor JOIN layer.

THE GAP THIS CLOSES (workflow wf_67f3f2c3, 2026-06-27): the ~12 audit-complete
completeness signals are ANDed but each reads its own sidecar in ISOLATION -
there is no JOIN asserting the cross-product (asset x function x invariant x
impact) was ever fully ENUMERATED, and the per-unit gates WARN-PASS on
tooling-absence/no-inputs. So a cell that was NEVER ENUMERATED (an asset with no
invariant set, an impact class never dispositioned, a function never put on the
worklist) is INVISIBLE: absence produces no failure anywhere. Morpho proved it -
11/15 in-scope assets had zero enumerated invariants while coverage_report read
1.0.

This tool is the NET-NEW join (not a duplicate - it REUSES every existing
coverage authority as input and adds the two unowned pieces): a per-asset
invariant enumeration across the 10 MECE categories, and a single consolidated
matrix artifact whose --check FAILS CLOSED on absence (NOT-ENUMERATED), fixing
the absence-is-invisible class.

REUSES (reads, never rebuilds):
  .auditooor/inscope_units.jsonl                 -> asset + function denominators
  .auditooor/comprehension/*.md                  -> per-asset invariant enumeration source
  .auditooor/exploit_class_coverage.json         -> impact-class dispositions
  .auditooor/function_coverage_completeness.json -> per-function coverage status
  .auditooor/mvc_sidecar/*.json (+ mutation_verify_coverage.json) -> mutation-verified evidence

Outputs:
  .auditooor/completeness_matrix.json              (schema auditooor.completeness_matrix.v1)
  COMPLETENESS_MATRIX.md                           (human-readable sibling)
  .auditooor/completeness_enumeration_worklist.jsonl
      One actionable row PER not-enumerated value-moving cell (asset/function/
      invariant-category/impact-class) so a downstream step can author the
      missing invariant rather than merely WARN that a cell was never
      enumerated. Deterministic (rows sorted by a stable key) and idempotent
      (the file is overwritten in full each run). ALWAYS written, even when the
      matrix is complete (then it is an empty file).

Modes:
  (default)  build the matrix artifacts + the worklist, print a summary. The
             worklist is always emitted. The terminal verdict is WARN-only by
             default so this tool does not retroactively brick workspaces
             certified before the enumeration floor existed.
  --check    build + return rc 0 (pass-completeness-matrix) / rc 1
             (fail-completeness-matrix-*). Fail-closed on missing inputs and on
             never-enumerated cells.
  --json     emit the verdict JSON to stdout

Enforcement: AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE (honored identically to the
audit-completeness-check orchestrator). When set to a truthy value, a matrix
with NOT-ENUMERATED value-moving cells returns a FAIL verdict / rc 1 even
without --check; absence of the env keeps the terminal verdict a loud WARN-pass.
Never-false-pass: a fully-enumerated matrix passes regardless of the env; an
incomplete one fails ONLY under enforce (or under explicit --check, which is
strict-by-intent). The worklist is emitted in every posture.

Override: a `<!-- completeness-matrix-rebuttal: <reason> -->` marker in
<ws>/.auditooor/completeness_matrix_rebuttal.md greens genuinely-inapplicable
axes (operator-approved, audit-logged via the file).

PER-FILE floor (AUDITOOOR_MATRIX_PERFILE_STRICT, advisory-first + backward-compat):
the legacy asset denominator collapses every in-scope FILE under `src/<repo>` into a
single asset (e.g. all 19 strata files -> `src/contracts`), and marks a category
enumerated from .md prose (source comprehension) alone - hiding which files lack a
harness-backed economic invariant. Fix:
  (a) the asset denominator is the distinct in-scope FILE set from inscope_units.jsonl
      (generic across languages via a relpath key, no double-count). The real per-file
      count is ALWAYS exposed as denominators.assets_perfile + a `perfile_breakdown`
      block, even in the default posture, so the collapsed-asset gap is visible.
  (b) under AUDITOOOR_MATRIX_PERFILE_STRICT: an invariant category counts ENUMERATED
      only when backed by a RUN + mutation-verified harness (mvc_sidecar or
      fuzz_campaign_receipt); a comprehension-only cue becomes the distinct
      NON-TERMINAL status 'enumerated-comprehension-only', and the per-FILE grouping
      becomes the primary axis (fail-closed on any file with no harness-backed set).
Default (env unset) keeps the legacy per-repo grouping + comprehension crediting so
this change never retroactively bricks a workspace certified before it existed; it
only ADDS the per-file breakdown + a loud WARN when the collapsed grouping hides a gap.
"""
from __future__ import annotations

import argparse
import importlib.util as _ilu
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.completeness_matrix.v1"


def _load_non_economic_disposition():
    """Load the SINGLE-SOURCE-OF-TRUTH per-unit non-economic-surface disposition
    library (tools/lib/non_economic_disposition.py). The SAME artifact + guards
    the invariant-fuzz / cross-function / honesty gates already honor - so a
    privileged-only / OOS in-scope file that those gates credit is not left
    NOT-ENUMERATED by the per-file completeness floor alone (over-strictness).
    Returns None if the lib is absent (older checkout) - the floor then behaves
    byte-identically to before (backward-compat)."""
    tool = Path(__file__).resolve().parent / "lib" / "non_economic_disposition.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("non_economic_disposition", str(tool))
        mod = _ilu.module_from_spec(spec)
        sys.modules["non_economic_disposition"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_NED_MOD = _load_non_economic_disposition()


def _load_disposition_proof_quality():
    """Lazily import tools/lib/disposition_proof_quality.py (offline stdlib).
    Supplies ``proof_strict_enabled`` + ``reason_is_terminal_quality``: under
    AUDITOOOR_DISPOSITION_PROOF_STRICT a mechanism-axis N-A/cleared disposition is
    credited only when its reasoning PROVES the impact unreachable (code-guard
    file:line / mechanism-level absence argument / named in-protocol cap), NOT when
    it merely notes a keyword grep found 0 hits. Returns None on older checkouts
    (the mechanism reader then behaves byte-identically - backward-compat)."""
    tool = Path(__file__).resolve().parent / "lib" / "disposition_proof_quality.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("disposition_proof_quality", str(tool))
        mod = _ilu.module_from_spec(spec)
        sys.modules["disposition_proof_quality"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_DPQ_MOD = _load_disposition_proof_quality()

# The 10 MECE invariant categories (the invariant axis denominator). Sourced from
# the corpus vault_invariant_library per_category structure.
CANONICAL_INVARIANT_CATEGORIES = [
    "conservation", "monotonicity", "bounds", "authorization", "custody",
    "atomicity", "ordering", "uniqueness", "freshness", "determinism",
]

# Keyword cues per category, used to detect which categories a dossier enumerates
# for an asset. Conservative: a category counts as enumerated only when a cue is
# found near invariant language in a dossier that references the asset.
_CATEGORY_CUES = {
    "conservation": ["conserv", "sum of", "totalassets ==", "no funds left", "solven", "accounting identit", "balance ==", "no value created"],
    "monotonicity": ["monoton", "never decrease", "non-decreasing", "share price", "price per share", "pps", "only increase"],
    "bounds": ["bound", "cap ", "<= max", ">= min", "within range", "clamp", "limit enforce", "ltv", "lltv"],
    "authorization": ["authoriz", "access control", "onlyowner", "only-owner", "role", "permission", "msg.sender ==", "guard", "onlybundler", "unprivileged"],
    "custody": ["custody", "no residue", "sweep", "left in", "stuck funds", "escrow", "held funds", "approval reset"],
    "atomicity": ["atomic", "reentran", "cei", "checks-effects", "callback", "all-or-nothing", "no partial"],
    "ordering": ["ordering", "sequence", "accrue before", "before mutate", "state-machine", "lifecycle", "queue integrity", "commit/reveal", "ordered"],
    "uniqueness": ["uniqu", "no double", "double-claim", "double-spend", "nonce", "replay", "idempoten", "once"],
    "freshness": ["fresh", "stale", "timelock", "deadline", "validat", "heartbeat", "updatedat", "expiry"],
    "determinism": ["determinis", "no overflow", "underflow", "rounding direction", "no panic", "wexp", "math safe", "no revert-on-"],
}

_INV_RE = re.compile(r"\bINV[-_][A-Za-z0-9_-]+", re.IGNORECASE)
_INVARIANT_WORD_RE = re.compile(r"\binvariant", re.IGNORECASE)
_INAPPLICABLE_RE = re.compile(r"inapplicable|not applicable|\bN/?A\b", re.IGNORECASE)

# G-6 (enforcement-gap 2026-07-03): the invariant axis requires the 10 GENERIC
# CANONICAL_INVARIANT_CATEGORIES but never the PROTOCOL-FAMILY-specific invariant set
# (audit/corpus_tags/derived/invariant_family_<family>.jsonl). So "all invariants held"
# can be vacuously true over an incomplete set - the biggest false-negative surface. We
# detect the family, load its canonical categories, and surface the family-required
# categories that NO in-scope asset enumerated (advisory block); a hard-fail folds them
# into the verdict ONLY under AUDITOOOR_MATRIX_FAMILY_INVARIANTS_STRICT (advisory-first).
_FAMILY_SRC_CUES = {
    "bridge_lock_mint": ["bridge", "lock", "mint", "cross-chain", "crosschain", "wrapped", "l1", "l2", "relayer", "attestation", "message passing"],
    "cdp_liquity": ["cdp", "trove", "collateral", "liquidat", "debt", "stablecoin", "borrow", "vault ratio", "ltv", "icr", "mcr"],
    "amm_constant_product": ["swap", "liquidity pool", "constant product", "x*y", "reserve", "getamountout", "addliquidity", "removeliquidity", "k invariant"],
    "erc4626_vault": ["erc4626", "erc-4626", "converttoshares", "converttoassets", "totalassets", "previewdeposit", "previewredeem", "vault", "shares", "deposit", "redeem", "assets"],
    "tranching": ["tranche", "junior", "senior", "jrt", "srt", "subordinat", "waterfall", "cdo", "nav", "cooldown", "seniornav", "juniornav"],
    "lending": ["borrow", "repay", "collateral", "liquidat", "ltv", "healthfactor", "health factor", "ctoken", "atoken", "utilization", "accrueinterest", "collateralfactor", "borrowbalance", "reservefactor"],
    "staking": ["stake", "unstake", "reward", "rewardpertoken", "accrewardpershare", "unbonding", "cooldown", "rewarddebt", "masterchef", "earned", "getreward"],
    "oracle_pricing": ["oracle", "price", "latestrounddata", "updatedat", "heartbeat", "twap", "aggregator", "chainlink", "roundid", "answeredinround", "staleness", "getprice"],
}
# DISCRIMINATING cues: terms that genuinely identify the family and do NOT appear
# incidentally in an unrelated DeFi protocol. Generic tokens (lock/mint/wrapped,
# collateral/debt/borrow, swap/reserve) fire on nearly every yield/tranching/strategy
# codebase, so a family is claimed ONLY when at least one of its discriminating cues is
# present (in addition to the >=2 total-hit floor). This prevents an ERC-4626 CDO from
# being mis-tagged bridge/cdp/amm and fabricating a family-invariant denominator.
_FAMILY_STRONG_CUES = {
    "bridge_lock_mint": {"bridge", "cross-chain", "crosschain", "relayer", "attestation", "message passing"},
    "cdp_liquity": {"cdp", "trove", "ltv", "icr", "mcr", "vault ratio"},
    "amm_constant_product": {"liquidity pool", "constant product", "x*y", "getamountout", "addliquidity", "removeliquidity", "k invariant"},
    # ERC-4626 discriminating tokens (interface fns that do not appear in an unrelated
    # protocol); generic "vault"/"shares"/"deposit" are cues but not discriminators.
    "erc4626_vault": {"erc4626", "erc-4626", "converttoshares", "converttoassets", "previewdeposit", "previewredeem", "previewmint", "previewwithdraw"},
    # tranching discriminators (senior/junior waterfall vocabulary); generic "nav" is a
    # cue but not a discriminator.
    "tranching": {"tranche", "junior", "senior", "jrt", "srt", "subordinat", "waterfall", "seniornav", "juniornav"},
    # lending discriminators (Aave/Compound money-market tokens/fns); distinct from
    # cdp_liquity (trove/icr) - generic collateral/borrow/ltv are cues, not discriminators.
    "lending": {"healthfactor", "collateralfactor", "ctoken", "atoken", "accrueinterest", "borrowbalance", "reservefactor", "utilization"},
    "staking": {"rewardpertoken", "accrewardpershare", "unbonding", "rewarddebt", "masterchef"},
    "oracle_pricing": {"latestrounddata", "updatedat", "heartbeat", "answeredinround", "aggregator", "chainlink", "staleness"},
}


_CUE_RE_CACHE: dict[str, "re.Pattern"] = {}


def _cue_present(cue: str, blob: str) -> bool:
    """True when `cue` appears in `blob` as a WHOLE TOKEN, not as an incidental
    substring of an unrelated identifier. Root-cause fix (axelar-dlt 2026-07-13):
    naive `cue in blob` substring matching fired the cdp_liquity strong cues 'ltv'
    and 'icr' inside `defaultVoting`, `resultValidator`, `trafficRequest`,
    `sicRequest` etc. - a Cosmos cross-chain bridge with ZERO CDP/trove/collateral-
    ratio surface was mis-tagged cdp_liquity, fabricating an unsatisfiable
    authorization/bounds/monotonicity/ordering/uniqueness family-invariant
    denominator. A family must rest on POSITIVE in-scope evidence (a real
    discriminating token), never weak substring overlap. Token boundary = the cue is
    not flanked by an ASCII alphanumeric on either side (letters/digits); hyphens,
    spaces, `*`, dots, braces, etc. are all valid boundaries, so multi-word cues
    ('cross-chain', 'message passing', 'vault ratio', 'x*y', 'erc-4626') still
    match. This ALSO tightens the long bridge/lending cue lists (e.g. 'l1'/'l2' no
    longer fire inside 'html1'). Conservative: only ever removes false substring
    hits; a genuine standalone token still matches."""
    rx = _CUE_RE_CACHE.get(cue)
    if rx is None:
        rx = re.compile(r"(?<![a-z0-9])" + re.escape(cue) + r"(?![a-z0-9])")
        _CUE_RE_CACHE[cue] = rx
    return rx.search(blob) is not None


def _detect_protocol_families(ws: Path) -> list[str]:
    """Keyword-detect which protocol families the in-scope source belongs to (0..n).
    Conservative + additive: a family is claimed only on >=2 distinct cue hits so a lone
    incidental token (e.g. one 'mint') does not mis-tag; returns [] on no strong signal."""
    families = []
    blob_parts: list[str] = []
    # Authoritative source set = the IN-SCOPE manifest. Protocol-family (and thus the
    # family-invariant denominator) must be derived from in-scope Strata code ONLY -
    # never from vendored dependencies (OZ crosschain/*, crytic properties mocks) or
    # test/mock trees, which would fabricate a bridge/cdp/amm requirement.
    inscope_files: list[Path] = []
    _manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if _manifest.is_file():
        _seen_paths: set[str] = set()
        for _l in _manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            _l = _l.strip()
            if not _l:
                continue
            try:
                _rel = json.loads(_l).get("file", "")
            except Exception:
                continue
            if not _rel or _rel in _seen_paths:
                continue
            _seen_paths.add(_rel)
            _fp = (ws / _rel)
            if _fp.is_file():
                inscope_files.append(_fp)
    if inscope_files:
        for p in inscope_files[:400]:
            try:
                blob_parts.append(p.read_text(encoding="utf-8", errors="replace").lower())
            except OSError:
                continue
    else:
        # Fallback (no manifest yet): scan the tree but EXCLUDE vendored/test/mock dirs
        # so a dependency's crosschain/liquity/amm code cannot claim a family.
        _EXCL = ("/lib/", "/node_modules/", "/test/", "/tests/", "/mocks/", "/mock/",
                 "/forge-std/", "/properties/", "/out/", "/cache/", "/.git/")
        def _excluded(p: Path) -> bool:
            s = "/" + str(p).replace("\\", "/").lower() + "/"
            return any(e in s for e in _EXCL) or str(p).lower().endswith(".t.sol")
        roots = [ws / "src", ws / "contracts", ws]
        seen = 0
        for r in roots:
            if not r.is_dir():
                continue
            for p in r.rglob("*.sol"):
                if seen >= 400:
                    break
                if _excluded(p):
                    continue
                try:
                    blob_parts.append(p.read_text(encoding="utf-8", errors="replace").lower())
                    seen += 1
                except OSError:
                    continue
            for p in list(r.rglob("*.go"))[:200]:
                if _excluded(p):
                    continue
                try:
                    blob_parts.append(p.read_text(encoding="utf-8", errors="replace").lower())
                except OSError:
                    continue
            if blob_parts:
                break
    blob = "\n".join(blob_parts)
    if not blob:
        return []
    for fam, cues in _FAMILY_SRC_CUES.items():
        hits = sum(1 for c in cues if _cue_present(c, blob))
        # require >=2 total hits AND >=2 DISTINCT discriminating cues. A single strong
        # cue over-fires on large multi-domain protocols (etherfi/morpho legitimately
        # mention borrow/swap/oracle/vault once each), fabricating 5-6 family
        # requirements; a true family member almost always exposes >=2 of its own
        # discriminators (a 4626 vault has convertToShares+convertToAssets; a tranching
        # protocol has junior+senior; an Aave-style market has healthFactor+accrueInterest),
        # so >=2 strong hits keeps recall precise. (3-ws validation 2026-07-07: this cut
        # etherfi 6->fewer, Strata 5->3, without dropping a true family.)
        strong = _FAMILY_STRONG_CUES.get(fam, set())
        strong_hits = sum(1 for c in strong if _cue_present(c, blob))
        if hits >= 2 and strong_hits >= 2:
            families.append(fam)
    return families


def _family_required_categories(families: list[str]) -> dict[str, set]:
    """family -> set(canonical categories its curated invariant library spans). Reads
    audit/corpus_tags/derived/invariant_family_<family>.jsonl (category field). Empty
    dict when the lib is absent (fail-safe: no requirement invented)."""
    out: dict[str, set] = {}
    # module lives at repo-root/tools/; the family corpus is at repo-root/audit/...
    _tools_dir = Path(__file__).resolve().parent
    base = _tools_dir.parent / "audit" / "corpus_tags" / "derived"
    if not base.is_dir():
        base = _tools_dir / "audit" / "corpus_tags" / "derived"
    for fam in families:
        p = base / f"invariant_family_{fam}.jsonl"
        if not p.is_file():
            continue
        cats: set = set()
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            c = str(r.get("category") or "").strip().lower()
            if c in CANONICAL_INVARIANT_CATEGORIES:
                cats.add(c)
        if cats:
            out[fam] = cats
    return out


# invariant-NAME -> canonical category cues (conservative; matched against the harness's
# `function echidna_<name>` symbols). A name matching a cue credits that category as
# ENUMERATED for the family-recall denominator, so a mutation-verified bounds/ordering/
# custody invariant is not read as "category not enumerated".
_INVARIANT_CATEGORY_CUES = {
    "bounds": ("bound", "floor", "_cap", "min_shares", "reserve_floor", "within",
               "in_bounds", "_le_locked", "cancel_le", "no_over_release", "covers_pending"),
    "ordering": ("no_early", "waterfall", "senior_first", "before_junior", "priority",
                 "_ordered", "no_overclaim"),
    "monotonicity": ("monoton", "pps_monoton", "round_id_monoton", "never_decreas",
                     "reserve_floor"),
    "custody": ("solven", "proxy_solven", "silo_solven", "holds_zero", "backed",
                "silo_conserved", "senior_backed", "nav_le_backing"),
    "freshness": ("stale", "updatedat", "no_early_claim", "cooldown_no", "no_early",
                  "matur", "_fresh"),
    "determinism": ("symmetry", "_exact", "no_rounding", "idempoten", "determin",
                    "preview_deposit_rounding", "ring_buffer_consistency"),
    "conservation": ("conserv", "_nav", "no_value_creation", "supply_conserv", "solvency",
                     "accrue_leg_exact", "strategy_nav"),
    "uniqueness": ("no_double", "unique"),
    "atomicity": ("atomic", "all_or_nothing"),
    "authorization": ("only_owner", "only_role", "unauthoriz", "access_control", "_auth"),
}


def _classify_invariant_category(name: str) -> set:
    """ALL canonical categories a single invariant tests - an invariant like
    echidna_no_early_claim legitimately covers BOTH ordering AND freshness (a claim may
    not settle before its cooldown matures), so it credits both. Returns a set."""
    n = name.lower()
    return {cat for cat, cues in _INVARIANT_CATEGORY_CUES.items()
            if any(q in n for q in cues)}


def _verified_invariant_categories(ws: Path) -> set:
    """Canonical categories ENUMERATED by a mutation-verified harness's declared
    invariants. Scans chimera_harnesses/<D>/*.sol for `function echidna_*` symbols, gated
    on <D> being referenced by a mutation-verified (non-vacuous) mvc_sidecar - so a
    tautological / unverified harness's invariants are NEVER credited. This fixes the
    family-recall serving-join (Strata 2026-07-07): real bounds/custody/determinism/
    freshness/ordering invariants existed but the matrix never mapped them to a category,
    so the family denominator read them as 'not enumerated'."""
    import re as _re
    mv_dirs: set = set()
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if sc_dir.is_dir():
        for sc in sc_dir.glob("*.json"):
            try:
                d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            v = str(d.get("verdict") or "").strip().lower()
            if not (d.get("mutation_verified") or v == "non-vacuous"):
                continue
            blob = " ".join(str(d.get(k) or "") for k in
                            ("harness_path", "harness", "runner_command")) + " " + sc.stem
            for mm in _re.finditer(r"chimera_harnesses/([A-Za-z][\w.-]+)", blob):
                mv_dirs.add(mm.group(1).lower())
            for mm in _re.finditer(r"--match-path\s+['\"]?([A-Za-z][\w.-]+)/", blob):
                mv_dirs.add(mm.group(1).lower())
            sm = _re.match(r"mvc-(?:src-)?([A-Za-z][\w]+)", sc.stem)
            if sm:
                mv_dirs.add(sm.group(1).lower())
    cats: set = set()
    hroot = ws / "chimera_harnesses"
    if hroot.is_dir():
        for hd in hroot.iterdir():
            if not hd.is_dir():
                continue
            dn = hd.name.lower()
            if not any(dn == x or dn in x or x in dn for x in mv_dirs):
                continue
            for sol in hd.glob("*.sol"):
                try:
                    src = sol.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for name in _re.findall(r"function\s+(echidna_[A-Za-z0-9_]+)", src):
                    cats |= _classify_invariant_category(name)
    # AUTHORIZATION is a guard property, not an economic-fuzz invariant: it is verified by
    # source-level access-control (onlyRole / onlyOwner / _checkRole / an AccessControl
    # registry), not a medusa campaign. Credit it when the in-scope CUT is genuinely
    # role-gated (>= AUTH_GUARD_MIN guard sites) - honest coverage via a non-fuzz mechanism,
    # so the family denominator does not demand an unnatural 'fuzzed authorization' invariant.
    AUTH_GUARD_MIN = 3
    guard_sites = 0
    for root in ("src", "contracts"):
        rp = ws / root
        if not rp.is_dir():
            continue
        for sol in rp.rglob("*.sol"):
            if "/out/" in str(sol) or "/node_modules/" in str(sol) or "/test" in str(sol):
                continue
            try:
                guard_sites += len(_re.findall(
                    r"\bonly(?:Role|Owner)\b|\b_check(?:Role|Owner)\b|AccessControlManager|onlyRole\(",
                    sol.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
            if guard_sites >= AUTH_GUARD_MIN:
                break
    if guard_sites >= AUTH_GUARD_MIN:
        cats.add("authorization")
    return cats


def _transitive_asset_categories(ws: Path, asset_key) -> dict:
    """asset_id -> categories credited TRANSITIVELY: a mutation-verified harness that
    imports a value-moving file AND directly `new`-deploys its contract lends that file the
    categories the harness's invariants test. Mirrors the invariant-fuzz transitive credit
    (Strata 2026-07-07): the cooldown impls (Midas/sNUSD/Saturn CooldownRequestImpl) are
    `new`-deployed + driven by their StrategyConservation harness and named in its
    no-overclaim invariant, yet the per-asset enumeration keyed only on a DIRECT mvc sidecar
    -> 0/10 categories. NEVER-FALSE: only a `new <Stem>(` deploy in a mutation-verified
    harness credits the real file (a mock is `new Mock<X>(`)."""
    import re as _re
    out: dict = {}
    hroot = ws / "chimera_harnesses"
    if not hroot.is_dir():
        return out
    # mutation-verified harness dir names (same gate as _verified_invariant_categories)
    mv_dirs: set = set()
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if sc_dir.is_dir():
        for sc in sc_dir.glob("*.json"):
            try:
                d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            v = str(d.get("verdict") or "").strip().lower()
            if not (d.get("mutation_verified") or v == "non-vacuous"):
                continue
            blob = " ".join(str(d.get(k) or "") for k in
                            ("harness_path", "harness", "runner_command")) + " " + sc.stem
            for mm in _re.finditer(r"chimera_harnesses/([A-Za-z][\w.-]+)", blob):
                mv_dirs.add(mm.group(1).lower())
            for mm in _re.finditer(r"--match-path\s+['\"]?([A-Za-z][\w.-]+)/", blob):
                mv_dirs.add(mm.group(1).lower())
            sm = _re.match(r"mvc-(?:src-)?([A-Za-z][\w]+)", sc.stem)
            if sm:
                mv_dirs.add(sm.group(1).lower())
    for hd in hroot.iterdir():
        if not hd.is_dir():
            continue
        dn = hd.name.lower()
        if not any(dn == x or dn in x or x in dn for x in mv_dirs):
            continue
        cats: set = set()
        deployed_stems: set = set()
        for sol in hd.glob("*.sol"):
            try:
                src = sol.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for name in _re.findall(r"function\s+(echidna_[A-Za-z0-9_]+)", src):
                cats |= _classify_invariant_category(name)
            for stem in _re.findall(r"\bnew\s+([A-Za-z_]\w+)\s*\(", src):
                if not stem.startswith("Mock") and not stem.startswith("Fake"):
                    deployed_stems.add(stem)
        if not cats or not deployed_stems:
            continue
        # map each deployed in-scope value-moving file to its asset_id + credit cats
        for stem in deployed_stems:
            for src_root in ("src", "contracts"):
                rp = ws / src_root
                if not rp.is_dir():
                    continue
                for f in rp.rglob(f"{stem}.sol"):
                    if "/out/" in str(f) or "/test" in str(f):
                        continue
                    try:
                        rel = str(f.relative_to(ws))
                    except ValueError:
                        rel = str(f)
                    aid = asset_key(rel)
                    if aid:
                        out.setdefault(aid, set()).update(cats)
    return out


def _ws(p: str) -> Path:
    return Path(p).expanduser().resolve()


def _asset_of(rel: str) -> str | None:
    """Derive asset_id = 'src/<repo>' from a workspace-relative path."""
    parts = [s for s in str(rel).replace("\\", "/").split("/") if s]
    if "src" in parts:
        i = parts.index("src")
        if i + 1 < len(parts):
            return f"src/{parts[i + 1]}"
    return None


def _perfile_asset_of(rel: str) -> str | None:
    """Derive a PER-FILE asset id = the workspace-relative path of the in-scope
    FILE itself (normalized, forward slashes), generic across every language.

    The legacy _asset_of collapses every file under `src/<repo>` into a single
    asset_id (e.g. all 19 strata files -> `src/contracts`), which hides which
    individual files lack an economic invariant. This derives one asset PER
    distinct in-scope file so denominators.assets reflects the real file count
    without double-counting (the relpath is unique). Language-agnostic: it is a
    pure path normalization, no extension or `src/` assumption.
    """
    r = str(rel or "").replace("\\", "/").strip().strip("/")
    if not r:
        return None
    # collapse any accidental leading ./ and duplicate slashes for a stable key
    segs = [s for s in r.split("/") if s and s != "."]
    return "/".join(segs) if segs else None


def _perfile_strict() -> bool:
    """AUDITOOOR_MATRIX_PERFILE_STRICT truthiness. When set, the matrix (a) uses
    the per-FILE asset denominator (one asset per in-scope file) and (b) requires
    an invariant category to be backed by a RUN + mutation-verified harness (an
    mvc_sidecar or a fuzz_campaign_receipt) before it counts as enumerated -
    comprehension-only prose no longer terminally enumerates a category. Default
    (unset) keeps the legacy per-repo grouping + comprehension crediting so this
    change never retroactively bricks a workspace certified before it existed.
    """
    return os.environ.get("AUDITOOOR_MATRIX_PERFILE_STRICT", "") not in ("", "0", "false", "no")


def _load_inscope(ws: Path) -> dict[str, list[dict[str, Any]]]:
    """asset_id -> list of {function, file} from inscope_units.jsonl."""
    out: dict[str, list[dict[str, Any]]] = {}
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        rel = r.get("file") or r.get("path") or ""
        asset = _asset_of(rel)
        if not asset:
            continue
        out.setdefault(asset, []).append({
            "function": r.get("function") or r.get("fn") or r.get("name") or "",
            "file": rel,
        })
    return out


def _load_inscope_perfile(ws: Path) -> dict[str, list[dict[str, Any]]]:
    """per-FILE-asset_id -> list of {function, file}, keyed on the distinct in-scope
    FILE (via _perfile_asset_of) instead of the collapsed `src/<repo>` root. Generic
    across languages; the relpath key is unique so no file is double-counted. This is
    the denominator that reflects the REAL in-scope file count (strata: 19, not 1)."""
    out: dict[str, list[dict[str, Any]]] = {}
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        rel = r.get("file") or r.get("path") or ""
        asset = _perfile_asset_of(rel)
        if not asset:
            continue
        out.setdefault(asset, []).append({
            "function": r.get("function") or r.get("fn") or r.get("name") or "",
            "file": rel,
        })
    return out


def _fuzz_campaign_receipt_files(ws: Path) -> set[str]:
    """Set of per-FILE asset ids covered by a real fuzz_campaign_receipt.json (a
    coverage-guided campaign that actually RAN). Read the receipt's per-campaign
    CUT/target file references and map each to its per-file asset id. This is the
    'run + campaign-backed' evidence source that (alongside a mutation-verified
    mvc_sidecar) lets a category count as enumerated under strict, replacing prose.
    False-green-safe: only concrete file references in the receipt credit a file."""
    files: set[str] = set()
    p = ws / ".auditooor" / "fuzz_campaign_receipt.json"
    if not p.is_file():
        return files
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return files
    if not isinstance(data, dict):
        return files
    if str(data.get("schema") or "") != "auditooor.fuzz_campaign_receipt.v1":
        return files
    campaigns = data.get("campaigns") if isinstance(data.get("campaigns"), list) else []
    for c in campaigns:
        if not isinstance(c, dict):
            continue
        for key in ("cut", "cut_files", "match_path", "target", "targets",
                    "contract", "harness_path", "files"):
            v = c.get(key)
            vals: list[str] = []
            if isinstance(v, str):
                vals = [v]
            elif isinstance(v, list):
                vals = [str(x) for x in v]
            for raw in vals:
                pf = _perfile_asset_of(raw)
                if pf:
                    files.add(pf)
    return files


def _load_comprehension(ws: Path) -> list[tuple[str, str]]:
    """Return [(dossier_name, lowercased_text)] for invariant-bearing dossiers
    (the known-issues ledger is a dedup artifact, not an invariant source)."""
    out: list[tuple[str, str]] = []
    d = ws / ".auditooor" / "comprehension"
    if not d.is_dir():
        return out
    for md in sorted(d.glob("*.md")):
        if "known-issues" in md.name.lower() or "ledger" in md.name.lower():
            continue
        try:
            out.append((md.name, md.read_text(encoding="utf-8", errors="replace").lower()))
        except OSError:
            continue
    return out


def _hunt_examined_keys(ws: Path) -> set:
    """Bare-fn keys of every hunt_findings_sidecar - a real per-function R76
    examination verdict. Tolerates function_anchor stored as a dict OR a
    JSON-serialized string (NUVA 2026-07-01), and falls back to the canonical
    `hunt__<Contract>.sol__<fn>__...` filename encoding. Used to credit an
    fcc-absent in-scope fn that WAS examined by a hunt (multi-store serving-join:
    the matrix read only fcc's attack-surface set, not the hunt verdict store, so
    genuinely-examined admin/router fns fell to NOT-ENUMERATED). False-green-safe:
    still requires a real per-fn verdict sidecar for that fn name."""
    keys: set = set()
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    if not d.is_dir():
        return keys

    def _base(fn: str) -> str:
        fn = (fn or "").split("(", 1)[0].strip()
        if "::" in fn:
            fn = fn.rsplit("::", 1)[-1]
        if ":" in fn:
            fn = fn.rsplit(":", 1)[-1]
        if "." in fn and "/" not in fn:
            fn = fn.rsplit(".", 1)[-1]
        return fn.strip()

    for f in sorted(d.glob("*.json")):
        fn = ""
        try:
            r = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            r = None
        if isinstance(r, dict):
            fa = r.get("function_anchor")
            if isinstance(fa, dict):
                fn = str(fa.get("fn") or fa.get("function") or "")
            elif isinstance(fa, str) and fa.strip():
                try:
                    _fad = json.loads(fa)
                    fn = str(_fad.get("fn") or _fad.get("function") or "") if isinstance(_fad, dict) else fa
                except (ValueError, TypeError):
                    fn = fa
        base = _base(fn)
        if not base:
            # fallback: canonical filename hunt__<Contract>.sol__<fn>__<hash>...
            parts = f.name.split("__")
            if len(parts) >= 3:
                base = _base(parts[2])
        if not base and isinstance(r, dict):
            # SERVING-JOIN (strata 2026-07-07): the 753-sidecar `unit`/`file_line`
            # schema (e.g. {"unit": "StrataCDO.accrueFee", ...}, filename
            # <Contract>_<fn>.json) carries NEITHER a function_anchor NOR the
            # hunt__<Contract>.sol__<fn>__ filename encoding, so a genuinely-examined
            # fn with a real R76 verdict fell to NOT-ENUMERATED. Derive the fn from the
            # `unit` field's first token (Contract.fn [+ ...] -> fn); false-green-safe -
            # the matrix intersects keys with the in-scope fn set, so a mis-derived
            # token credits nothing, and a real per-fn verdict sidecar is still required.
            unit = str(r.get("unit") or "")
            first = unit.replace(",", "+").split("+", 1)[0].strip()
            base = _base(first)
        if base:
            keys.add(base)
    return keys


# ---------------------------------------------------------------------------
# (unit x IMPACT-FRAME) hunt crediting - brick 3.
#
# Brick 1 made the hunt sidecar filename carry a `__I-<impact>` suffix when a
# task was dispatched per-impact-frame. This lets the function-coverage axis
# credit a function ONLY when EVERY in-scope impact frame that was dispatched for
# it has a verdict sidecar (instead of the legacy "any one sidecar credits the
# whole function"). BACKWARD-COMPAT: a ws with NO per-frame sidecars (no `__I-`
# suffix anywhere) credits exactly as before - the per-frame requirement engages
# ONLY when per-frame sidecars are actually present.
# ---------------------------------------------------------------------------
_IMPACT_SUFFIX_RE = re.compile(r"__I-([A-Za-z0-9_-]+)$")


def _hunt_examined_frames(ws: Path) -> dict[str, set]:
    """bare-fn-name -> set of impact frames examined (parsed from the `__I-<impact>`
    filename suffix brick 1 emits). A function that was hunted with per-frame tasks
    thus maps to the concrete set of impacts for which a real verdict sidecar exists.
    Functions hunted only with LEGACY (frame-less) tasks do NOT appear here (their
    sidecar filename carries no `__I-` suffix) - so the caller falls back to the
    legacy any-sidecar credit for them. False-green-safe: an impact only counts when
    a real per-frame sidecar file for that (fn, impact) exists on disk."""
    frames: dict[str, set] = {}
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    if not d.is_dir():
        return frames

    def _base(fn: str) -> str:
        fn = (fn or "").split("(", 1)[0].strip()
        if "::" in fn:
            fn = fn.rsplit("::", 1)[-1]
        if ":" in fn:
            fn = fn.rsplit(":", 1)[-1]
        if "." in fn and "/" not in fn:
            fn = fn.rsplit(".", 1)[-1]
        return fn.strip()

    for f in sorted(d.glob("*.json")):
        stem = f.name[:-5] if f.name.endswith(".json") else f.name
        m = _IMPACT_SUFFIX_RE.search(stem)
        if not m:
            continue  # legacy (frame-less) sidecar - not a per-frame verdict
        impact = m.group(1).strip().lower()
        # strip the frame suffix, then recover the fn the same way as _hunt_examined_keys
        core = _IMPACT_SUFFIX_RE.sub("", stem)
        fn = ""
        try:
            r = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            r = None
        if isinstance(r, dict):
            fa = r.get("function_anchor")
            if isinstance(fa, dict):
                fn = str(fa.get("fn") or fa.get("function") or "")
            elif isinstance(fa, str) and fa.strip():
                try:
                    _fad = json.loads(fa)
                    fn = str(_fad.get("fn") or _fad.get("function") or "") if isinstance(_fad, dict) else fa
                except (ValueError, TypeError):
                    fn = fa
        base = _base(fn)
        if not base:
            # fallback: canonical filename hunt__<Contract>.sol__<fn>__...__I-<impact>
            parts = core.split("__")
            if len(parts) >= 3:
                base = _base(parts[2])
        if base and impact:
            frames.setdefault(base, set()).add(impact)
    return frames


# Seed filenames the per-fn hunt (brick 2, per-fn-mimo-batch-gen) consumes.
_SEED_FILENAMES = ("per_fn_hacker_questions.jsonl",
                   "per_fn_hacker_questions.jsonl.ranked.jsonl")


def _san_frame(s: str) -> str:
    """Sanitize an impact string to the SAME canonical `__I-<frame>` token brick 1's
    _sidecar_slug writes (so seed-derived 'required frames' compare equal to the
    filename-parsed 'examined frames')."""
    return re.sub(r"[^A-Za-z0-9_-]+", "-", str(s or "")).strip("-_").lower()[:40]


def _dispatched_frames_by_fn(ws: Path) -> dict[str, set]:
    """bare-fn-name -> set of impact FRAMES the per-fn seed DISPATCHED for it, derived
    the SAME way brick 2 (per-fn-mimo-batch-gen.build_enriched_task) does: frame =
    impact_id or impact or question_class, then sanitized the SAME way brick 1's
    _sidecar_slug sanitizes the `__I-<frame>` suffix.

    This is the AUTHORITATIVE 'required frames' per function. The old code used
    `_inscope_impact_frames_for_lang` (the mechanism-library vocabulary:
    direct-theft / insolvency / permanent-freeze / ...), which NEVER matched the
    seed's question_class vocabulary (direct-theft-funds / protocol-insolvency /
    sum-preserved / rubric-targeted / ...). Zero intersection meant EVERY per-frame-
    hunted function was permanently NOT-ENUMERATED - an unsatisfiable gate that
    enabling per-impact-frames introduced. Deriving 'required' from the same seed
    brick 2 dispatches from makes the vocabularies agree by construction: a function
    is covered when every DISPATCHED frame has a verdict sidecar (== examined)."""
    disp: dict[str, set] = {}
    d = ws / ".auditooor"

    def _base(fn: str) -> str:
        fn = (fn or "").split("(", 1)[0].strip()
        if "::" in fn:
            fn = fn.rsplit("::", 1)[-1]
        if ":" in fn:
            fn = fn.rsplit(":", 1)[-1]
        if "." in fn and "/" not in fn:
            fn = fn.rsplit(".", 1)[-1]
        return fn.strip()

    for name in _SEED_FILENAMES:
        p = d / name
        if not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                q = json.loads(line)
            except ValueError:
                continue
            if not isinstance(q, dict):
                continue
            fn = _base(str(q.get("function") or q.get("fn") or ""))
            frame = _san_frame(q.get("impact_id") or q.get("impact")
                               or q.get("question_class") or "")
            if fn and frame:
                disp.setdefault(fn, set()).add(frame)
    return disp


def _lang_of_unit_file(fileref: str) -> str:
    """Mechanism-library language of an inscope unit's file (solidity/go/rust/move/...)."""
    ext = os.path.splitext(str(fileref or ""))[1].lower()
    return _EXT_LANG.get(ext, "")


def _inscope_impact_frames_for_lang(lang: str, lib: dict[str, list[dict[str, Any]]]) -> set:
    """In-scope IMPACT FRAMES for a language, from the SAME mechanism-library seed the
    batch builder's brick 2 uses: an impact is in-scope for the language iff >=1 of its
    mechanisms lists that language. Shared source of truth so 'dispatched frames' (brick
    2) and 'required frames' (brick 3) agree. Returns lower-cased impact ids."""
    if not lang:
        return set()
    out: set = set()
    for impact, mechs in (lib or {}).items():
        for m in mechs:
            if lang in (m.get("languages") or []):
                out.add(str(impact).strip().lower())
                break
    return out


def _mvc_asset_invariant_categories(
    ws: Path, asset_key=None, credit_empty_invariants: bool = False
) -> dict[str, set]:
    """asset_id -> set(categories) enumerated by a MUTATION-VERIFIED harness on
    that asset. A category counts when a mutation-verified mvc_sidecar whose CUT
    file belongs to the asset carries an invariant whose id/name/property matches
    the category's cues. This is REAL (mutation-verified) invariant enumeration -
    strictly stronger than a prose comprehension dossier - so an asset whose
    invariants are proven by a fuzz harness is not falsely NOT-ENUMERATED. Only
    the invariant-fuzz gate's own artifacts are read; false-green-safe (a category
    with no matching mutation-verified invariant stays not-enumerated).

    asset_key: the path->asset_id mapper (default the legacy collapsed _asset_of;
    the per-file caller passes _perfile_asset_of so mvc evidence credits the exact
    in-scope file instead of the whole `src/<repo>` root).

    credit_empty_invariants: when True (the per-FILE strict caller only), a
    mutation-verified sidecar whose `invariants` array is EMPTY but which carries a
    genuine behavior-changing kill is credited (conservation, via its descriptive
    contract/cut_fn/kill_invariant_frame text) - this is how the Go Cosmos economic
    harnesses register (invariants=[], contract="...Conservation", mutants_killed>=1).
    Default False preserves the legacy behavior byte-for-byte for the per-repo grouping
    (backward-compat: a ws certified before this fix is not retroactively re-credited)."""
    asset_key = asset_key or _asset_of
    out: dict[str, set] = {}
    d = ws / ".auditooor" / "mvc_sidecar"
    if not d.is_dir():
        return out
    # HARNESS-CUT -> IN-SCOPE-SOURCE remap table (Strata 2026-07-07): a chimera fuzz
    # harness registers its CUT as the HARNESS file path (e.g. chimera_harnesses/
    # SharesCooldownFeeConservation/SharesCooldownFeeConservation.sol), not the in-scope
    # source it tests (src/.../SharesCooldown.sol). Keying on the harness path credits a
    # non-in-scope file, so a genuinely mutation-verified >=1M harness left its real
    # in-scope target reading as "NO economic invariant" (false-red). Build {in-scope
    # basename-stem -> relpath}; a resolved harness/out-of-scope CUT whose basename embeds
    # an in-scope stem also credits that in-scope file. NEVER-FALSE: only an in-scope file
    # whose exact basename the harness references is added.
    _inscope_by_stem: dict[str, str] = {}
    _man = ws / ".auditooor" / "inscope_units.jsonl"
    if _man.is_file():
        for _ln in _man.read_text(encoding="utf-8", errors="replace").splitlines():
            _ln = _ln.strip()
            if not _ln:
                continue
            try:
                _rel = str(json.loads(_ln).get("file") or "")
            except ValueError:
                continue
            if _rel.endswith(".sol"):
                _stem = re.sub(r"[^a-z0-9]", "", re.sub(r"\.sol$", "", Path(_rel).name.lower()))
                if _stem:
                    _inscope_by_stem.setdefault(_stem, _rel)
    _inscope_rels = set(_inscope_by_stem.values())
    for f in sorted(d.glob("*.json")):
        try:
            r = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(r, dict):
            continue
        # SERVING-JOIN FIX (SSV 2026-07-03): credit a genuine mutation-verify sidecar
        # even when it does not carry the literal `mutation_verified: true` flag. The
        # per-FUNCTION mutation-verify producer (tools/mutation-verify-coverage.py, and
        # its --register-manual-mvc path) records its non-vacuity witness as
        # `verdict: "non-vacuous"` + `behavior_changing_kill_count >= 1` (a real
        # behavior-changing mutant the harness caught) - NOT the `mutation_verified`
        # boolean the coverage-guided-campaign producer writes. Reading only the boolean
        # left these genuine per-function sidecars INVISIBLE to the per-file join
        # (absence-is-invisible false-red: the evidence is on disk, the reader keys on
        # the wrong field). NEVER-FALSE-PASS: a sidecar credits only when it is either
        # flagged mutation_verified OR proves a genuine behavior-changing kill; a
        # survived/vacuous/panic-only run still credits nothing.
        _bck = 0
        try:
            _bck = int(r.get("behavior_changing_kill_count") or 0)
        except (TypeError, ValueError):
            _bck = 0
        _nonvacuous_kill = (
            str(r.get("verdict") or "").strip().lower() == "non-vacuous" and _bck >= 1
        )
        if not (r.get("mutation_verified") or _nonvacuous_kill):
            continue
        cut_paths = []
        # `source_file` is the CUT key the per-function mutation-verify producer writes
        # (the real module-under-test); the campaign producer uses cut/cut_files/etc.
        # Read BOTH so a genuine per-function sidecar joins to its real in-scope file.
        for k in ("cut", "cut_files", "match_path", "contract", "harness_path", "source_file"):
            v = r.get(k)
            if isinstance(v, str):
                cut_paths.append(v)
            elif isinstance(v, list):
                cut_paths.extend(str(x) for x in v)
        # The per-function producer stores `source_file` as an ABSOLUTE path; the
        # per-file asset_key (_perfile_asset_of) keys on the workspace-relative path,
        # so an absolute CUT would never match an in-scope file. Relativize any path
        # that sits under the workspace before mapping (the legacy _asset_of already
        # handles absolutes via its 'src' segment scan, so this only helps the per-file
        # grouping; harmless for already-relative paths).
        def _rel_to_ws(p: str) -> str:
            try:
                pp = Path(p)
                if pp.is_absolute():
                    return str(pp.relative_to(ws))
            except (ValueError, OSError):
                pass
            return p
        assets = {a for a in (asset_key(_rel_to_ws(p)) for p in cut_paths) if a}
        # HARNESS-CUT -> IN-SCOPE-SOURCE remap: when a resolved CUT is a harness/out-of-
        # scope file whose basename embeds an in-scope source basename, ALSO credit that
        # in-scope file (the harness's real target). Never-false: only an in-scope file
        # whose exact basename the harness references is added.
        for p in cut_paths:
            pr = _rel_to_ws(str(p))
            if pr in _inscope_rels:
                continue
            pstem = re.sub(r"[^a-z0-9]", "", re.sub(r"\.sol$", "", Path(str(p)).name.lower()))
            if not pstem:
                continue
            for _stem, _rel in _inscope_by_stem.items():
                if _stem in pstem:
                    a = asset_key(_rel_to_ws(_rel))
                    if a:
                        assets.add(a)
        if not assets:
            continue
        invs = r.get("invariants") or []
        # SERVING-JOIN FIX (NUVA 2026-07-04): read the invariant's FULL semantic label,
        # not just id+name+property_fn. A mutation-verified invariant object also carries
        # its category language in `description` + `subsystem` (authored alongside the
        # property), e.g. name="no_free_roundtrip" description="an ATOMIC deposit->redeem
        # round trip ..." (atomicity), subsystem="AML-signer rotation access-control
        # (state-machine)" (ordering). Reading only id+name+property_fn left these
        # genuinely-proven categories NOT-ENUMERATED (absence-is-invisible false-red: the
        # mutation-verified evidence is on disk, the reader keyed on too narrow a field
        # subset). FALSE-GREEN-SAFE: this text is folded ONLY for a sidecar already gated
        # mutation_verified / non-vacuous-with-a-behavior-changing-kill (checked above); a
        # survived / vacuous / panic-only run still credits nothing.
        inv_text = " ".join(
            str(i.get("id", "")) + " " + str(i.get("name", "")) + " "
            + str(i.get("property_fn", "")) + " " + str(i.get("description", ""))
            + " " + str(i.get("subsystem", ""))
            if isinstance(i, dict) else str(i)
            for i in (invs if isinstance(invs, list) else [])
        ).lower()
        # A mutation-verified harness may carry its property NAMES not in an `invariants`
        # array but in the descriptive fields (contract/test name, cut_fn, and the
        # per-mutant kill_invariant_frame) - this is how the Go Cosmos economic harnesses
        # register (contract="TestKeeperTestSuite/TestEconomicInvariant_..._Conservation",
        # invariants=[]). Fold those descriptive fields into the category-cue text so the
        # join credits the file. FALSE-GREEN-SAFE: this text is only read when the sidecar
        # is already mutation_verified (checked above) AND (below) has a genuine
        # behavior-changing kill - it never invents categories for an unrun harness.
        desc_parts: list[str] = []
        for k in ("contract", "cut_fn", "verdict", "witness_note", "engine_reason"):
            v = r.get(k)
            if isinstance(v, str):
                desc_parts.append(v)
        for mr in (r.get("mutant_results") or []):
            if isinstance(mr, dict):
                for k in ("kill_invariant_frame", "mutation"):
                    v = mr.get(k)
                    if isinstance(v, str):
                        desc_parts.append(v)
        desc_text = " ".join(desc_parts).lower()
        # A genuine kill (a behavior-changing mutant the harness caught) is the
        # non-vacuity witness; an empty-invariants sidecar credits a category ONLY when
        # such a kill exists (mirror the invariant-fuzz gate's own crediting). This
        # empty-invariants crediting is gated to the per-FILE strict caller
        # (credit_empty_invariants) so the legacy per-repo grouping is byte-identical.
        has_kill = credit_empty_invariants and (
            int(r.get("behavior_changing_kill_count") or 0) >= 1
            or int(r.get("mutants_killed") or 0) >= 1)
        if not inv_text.strip() and not has_kill:
            # No invariant text AND no creditable attributed kill -> nothing to credit.
            continue
        # SERVING-JOIN FIX (NUVA 2026-07-04): when a sidecar HAS a non-empty `invariants`
        # array, ALSO fold its descriptive frame text (contract / cut_fn /
        # kill_invariant_frame) into the cue text. Category language often lives in the
        # mutant frame ("owner must regain exactly the escrowed shares" = custody;
        # "state-machine transition" = ordering) that the terse invariant id/name omits.
        # The pre-existing empty-invariants branch (inv_text == "") still uses desc_text
        # ONLY under the strict per-file caller (credit_empty_invariants) exactly as
        # before, so the default per-repo posture for empty-invariants sidecars stays
        # byte-identical (backward-compat). Gated identically (the sidecar is already
        # mutation_verified / has a creditable kill), so false-green-safe.
        # (empty-inv branch reaches here only when has_kill, i.e. the strict per-file
        # caller, so the default per-repo posture for empty-invariants sidecars is unchanged)
        cue_text = inv_text + " " + desc_text
        cats = {cat for cat, cues in _CATEGORY_CUES.items() if any(c in cue_text for c in cues)}
        # a mutation-verified conservation/economic harness always enumerates the
        # conservation category even when the invariant names are terse. Reached both
        # for a non-empty `invariants` array with no cue-match AND for an empty-invariants
        # sidecar whose genuine behavior-changing kill witnesses the (economic) harness.
        if not cats:
            cats = {"conservation"}
        for a in assets:
            out.setdefault(a, set()).update(cats)
    return out


def _asset_invariant_enumeration(
    asset_id: str, dossiers: list[tuple[str, str]], mvc_cats: set | None = None,
    strict: bool = False,
) -> dict[str, dict[str, Any]]:
    """For one asset, per-category status across the 10 categories.

    An asset is 'enumerated' for a category when a MUTATION-VERIFIED harness on the
    asset proves an invariant of that category (mvc_cats), OR (default posture only)
    a dossier that REFERENCES the asset AND contains invariant language carries a
    category cue. No referencing-dossier and no mutation-verified harness -> the
    category stays NOT-ENUMERATED.

    strict (AUDITOOOR_MATRIX_PERFILE_STRICT): a category is 'enumerated' ONLY when
    backed by a RUN + mutation-verified harness (mvc_cats). A comprehension-only cue
    (prose) no longer terminally enumerates the category - it becomes the distinct
    NON-TERMINAL status 'enumerated-comprehension-only' (a real category was
    described but never proven by a campaign). Default posture (strict=False) keeps
    the legacy comprehension crediting so prior audits are not retroactively bricked.
    """
    mvc_cats = mvc_cats or set()
    repo = asset_id.split("/", 1)[-1].lower()
    # repo token variants (some dossiers use 'metamorpho' for 'metamorpho-v1-1')
    repo_tokens = {repo, repo.replace("-", "_"), repo.replace("-", "")}
    base = repo.split("-")[0]
    # per-FILE asset ids are full relpaths (e.g. 'src/contracts/Tranche.sol'); a
    # dossier references such an asset by the file's stem (Tranche/tranche), so add
    # the basename stem + its variants as matching tokens (generic across languages).
    _stem = os.path.splitext(os.path.basename(repo))[0]
    if _stem and _stem != repo:
        repo_tokens |= {_stem, _stem.replace("-", "_"), _stem.replace("-", "")}
        if len(_stem.split("-")[0]) > len(base):
            base = _stem.split("-")[0]
    referencing: list[str] = []
    for name, text in dossiers:
        if not (_INV_RE.search(text) or _INVARIANT_WORD_RE.search(text)):
            continue
        if any(tok in text for tok in repo_tokens) or (len(base) > 4 and base in text):
            referencing.append(text)
    result: dict[str, dict[str, Any]] = {}
    for cat in CANONICAL_INVARIANT_CATEGORIES:
        status = "not-enumerated"
        src = ""
        if cat in mvc_cats:
            # a mutation-verified fuzz harness on this asset proves an invariant of
            # this category - real (stronger-than-prose) enumeration.
            status = "enumerated"
            src = "mvc-harness"
        elif referencing:
            cues = _CATEGORY_CUES[cat]
            hit = next((t for t in referencing if any(c in t for c in cues)), None)
            if hit is not None:
                # STRICT: comprehension prose alone no longer TERMINALLY enumerates a
                # category - only a run+mutation-verified harness does (handled above).
                # The category was DESCRIBED but never proven, so it becomes a distinct
                # NON-TERMINAL status rather than a terminal 'enumerated'. Default
                # posture keeps the legacy comprehension terminal credit (backward-compat).
                if strict:
                    status = "enumerated-comprehension-only"
                    src = "comprehension-only"
                else:
                    status = "enumerated"
                    src = "comprehension"
            else:
                # dossier exists for the asset but this category not cued: mark
                # inapplicable ONLY if an explicit marker sits near the category
                # name, else leave NOT-ENUMERATED (conservative - the floor).
                if any(_INAPPLICABLE_RE.search(t) and cat in t for t in referencing):
                    status = "inapplicable"
                    src = "comprehension:inapplicable"
        result[cat] = {"status": status, "source": src}
    return result


def _load_impact_enumeration(ws: Path) -> dict[str, Any]:
    """Impact-class dispositions from exploit_class_coverage.json. Blank/missing
    -> not-enumerated (the morpho 0/10-blank-ledger hole)."""
    p = ws / ".auditooor" / "exploit_class_coverage.json"
    if not p.is_file():
        return {"present": False, "classes": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {"present": False, "classes": {}}
    classes: dict[str, str] = {}
    rows = data.get("classes") or data.get("exploit_classes") or data.get("rows") or []
    if isinstance(rows, dict):
        rows = [{"class": k, **(v if isinstance(v, dict) else {"status": v})} for k, v in rows.items()]
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        name = r.get("class") or r.get("name") or r.get("id") or ""
        status = (r.get("status") or r.get("disposition") or r.get("verdict") or "").strip()
        if name:
            classes[name] = status if status else "not-enumerated"
    return {"present": True, "classes": classes}


def _load_function_coverage(ws: Path) -> tuple[dict[str, str], bool]:
    """(file::function) -> coverage_status from function_coverage_completeness.json,
    plus a flag: did the authoritative fcc gate reach a fully-covered terminal verdict
    with zero hollow/untouched? (used to credit fcc-scope-filtered non-entry functions
    as out-of-scope rather than NOT-ENUMERATED - a serving-join false-red otherwise:
    the matrix denominator is the RAW inscope_units (incl. internal/view/library helpers)
    while fcc - the authoritative attack-surface gate - deliberately scopes to
    external/public/entry mutators. A view getter / internal helper that fcc dropped is
    NOT an unenumerated coverage gap.)"""
    out: dict[str, str] = {}
    fcc_terminal = False
    p = ws / ".auditooor" / "function_coverage_completeness.json"
    if not p.is_file():
        return out, fcc_terminal
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return out, fcc_terminal
    verdict = str(data.get("verdict") or "").lower()
    counts = data.get("counts") or {}
    hollow = int(counts.get("hollow") or 0) if isinstance(counts, dict) else 0
    untouched = int(counts.get("untouched") or 0) if isinstance(counts, dict) else 0
    # fcc is authoritative only when it ran to a fully-covered terminal verdict with no
    # open (hollow/untouched) functions - otherwise its scope set is not trustworthy and
    # we fall back to NOT-ENUMERATED for absent functions (fail-closed).
    fcc_terminal = ("fully-covered" in verdict or verdict.startswith("pass")) and hollow == 0 and untouched == 0
    for rec in data.get("functions", []) or []:
        if not isinstance(rec, dict):
            continue
        fn = rec.get("function") or rec.get("name")
        fileref = rec.get("file") or rec.get("source_ref") or ""
        if not fn or not fileref:
            continue
        cls = str(rec.get("classification") or rec.get("verdict") or rec.get("class") or "").lower()
        ev = rec.get("evidence")
        mutation = bool(isinstance(ev, (list, tuple)) and any("mutation-killed" in str(e) for e in ev))
        if cls in ("real-attack", "real_attack"):
            status = "covered-mutation-verified" if mutation else "covered"
        elif cls in ("hollow", "untouched"):
            status = "open"
        else:
            status = "not-enumerated"
        out[f"{Path(fileref).name}::{fn}"] = status
    return out, fcc_terminal


# A function that is in inscope_units but ABSENT from fcc's terminal attack-surface set
# was dropped by fcc's authoritative scope filter (external/public/entry mutators only).
# To be NEVER-FALSE-PASS we still independently confirm the function is genuinely a
# non-entry surface (internal/private/view/pure decl, a library/constant/event/error
# unit with no callable body, or a constructor) before crediting it out-of-scope. If we
# cannot confirm non-entry, it stays NOT-ENUMERATED (fail-closed).
_NONENTRY_SOL_RE = re.compile(r"\b(internal|private)\b")
_VIEWPURE_SOL_RE = re.compile(r"\b(view|pure)\b")

# Go/Cosmos non-attack-surface files: the module SDK boilerplate + sim/testutil that
# fcc's scope filter (external message handlers / value-moving keeper mutators only)
# drops the same way it drops a Solidity interface/library. These are structural, not a
# hardcoded per-workspace list: any Cosmos module ships them under these dir/basename
# conventions (codec/errors/events/keys/expected_keepers/genesis/msgs registration
# boilerplate, module.go wiring, query_server read-only gRPC, simulation/simapp/testutil
# harness scaffolding, pure slice/tool/query utility helpers).
_GO_NONENTRY_DIR_SEGS = ("/simulation/", "/simapp/", "/testutil/", "/mocks/", "/utils/query/")
_GO_NONENTRY_BASENAMES = (
    "codec.go", "errors.go", "events.go", "keys.go", "expected_keepers.go",
    "genesis.go", "msgs.go", "module.go", "query_server.go",
    "slices.go", "tools.go", "query.go",
)


def _is_go_cosmos_nonentry(rel: str, fn: str) -> bool:
    """True when a Go/Cosmos in-scope file is module boilerplate / sim/testutil harness
    scaffolding / a pure utility - i.e. it has NO value-moving message-handler or keeper
    mutator entry-point, so fcc's attack-surface scope drops it. Structural (dir/basename
    convention), language-agnostic within the Cosmos module layout, no per-ws hardcoding.
    FALSE-GREEN-SAFE: only files matching the known non-entry conventions are credited;
    a value-moving keeper file (reconcile.go / payout.go / msg_server.go / abci.go /
    state.go / valuation_engine.go / interest.go / a queue processor) does NOT match and
    stays subject to the invariant floor."""
    low = str(rel or "").lower().replace("\\", "/")
    if not low.endswith(".go"):
        return False
    if any(seg in low for seg in _GO_NONENTRY_DIR_SEGS):
        return True
    base = low.rsplit("/", 1)[-1]
    return base in _GO_NONENTRY_BASENAMES


# Source-scan value tokens (Go + Solidity) used ONLY as a fail-closed safety net over
# the authoritative value_moving_functions.json set: if the producer under-detected a
# value-mover, any of these tokens in the file keeps it an obligation (never dropped).
# Never-false-drop: a genuine transfer / ledger-write / mint-burn file matches at least
# one of these, so the infra-file drop below can only ever remove a file that BOTH the
# producer AND this scan agree carries no value signal.
_VALUE_TOKEN_RE = re.compile(
    r"sendcoins|spendablecoins|addcoins|subunlockedcoins|mintcoins|burncoins|"
    r"bankkeeper|\.transfer\s*\(|safetransfer|delegatecoins|undelegatecoins|"
    r"setbalance|\bmsgsend\b|inputoutputcoins|\.call\s*\{\s*value|_mint\s*\(|_burn\s*\(",
    re.I)


def _value_moving_files(ws: Path) -> tuple[set[str], bool]:
    """Return (set of in-scope files with a value-moving signal, artifact_present).

    Authoritative source = .auditooor/value_moving_functions.json (the same artifact
    invariant-fuzz-completeness._value_moving_inscope_files trusts): a file is
    value-moving when it hosts >=1 function with transfer_hit OR ledger_write_hit.
    `artifact_present` is False when the producer has not run - callers must then
    fail-closed (never drop a file), because absence-from-the-set is only meaningful
    once the producer has actually scanned the tree.

    Root-cause fix (axelar-dlt 2026-07-13): pure infra files (utils/nopLogger.go,
    ante/log.go) carry no transfer_hit/ledger_write_hit yet each inflated the per-file
    invariant-floor denominator by demanding 10 categories. Reuses the value-moving
    signal instead of hand-listing filenames."""
    vm: set[str] = set()
    p = ws / ".auditooor" / "value_moving_functions.json"
    if not p.is_file():
        return vm, False
    try:
        d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return vm, False
    for fn in (d.get("functions") or []) if isinstance(d, dict) else []:
        if isinstance(fn, dict) and (fn.get("transfer_hit") or fn.get("ledger_write_hit")):
            f = str(fn.get("file") or "").strip()
            if f:
                vm.add(f)
    return vm, True


def _file_has_value_signal(ws: Path, rel: str, vm_files: set[str]) -> bool:
    """True when file `rel` moves/accounts value: it is in the authoritative
    value-moving set OR a conservative Go/Sol source-token scan finds a transfer /
    ledger-write / mint-burn token (fail-closed superset over producer misses)."""
    if rel in vm_files:
        return True
    src = ws / rel
    if not src.is_file():
        # cannot confirm non-value -> fail-closed: treat as value-bearing (keep obligation)
        return True
    try:
        txt = src.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    return bool(_VALUE_TOKEN_RE.search(txt))


def _hunt_terminal_refuted_fns(ws: Path) -> set:
    """Fn names driven to a WHOLE-FUNCTION source-cited TERMINAL REFUTED verdict.

    A per-fn hunt that reads the source and refutes the ENTIRE function (verdict
    KILL/refuted with applies_to_target=no, R76 file:line) has examined the fn
    holistically - its reasoning spans every impact class. The per-frame branch,
    however, demands a SEPARATE `__I-<impact>` sidecar for each dispatched frame,
    so a holistically-refuted fn with one dispatched frame lacking its own suffixed
    sidecar pinned NOT-ENUMERATED despite the whole-fn terminal verdict (Strata
    2026-07-07: 23 cells). This set lets the per-frame branch defer to the whole-fn
    verdict, exactly as branch-5 (hunt_examined) already does.
    NEVER-FALSE-PASS: (a) only a sidecar with NO `__I-<impact>` frame suffix in its
    filename counts (a whole-fn drill, not a single per-frame partial - a lone
    per-frame KILL can NOT credit the whole fn), AND (b) the verdict must be a real
    refuted/KILL (or applies_to_target=no) with an R76 file:line cite."""
    out: set = set()
    r76 = re.compile(r"\.\w+:L?\d+")
    # Scan BOTH the bridged store AND the workflow-drill emit dir: workflow-drill-
    # sidecar-emit writes the canonical whole-fn verdict into audit/corpus_tags/derived/
    # mimo_harness_<ws>_workflow/, and hunt-sidecar-bridge only copies a SUBSET into
    # hunt_findings_sidecars (it skips e.g. off-chain view/lens fns like IntegrationsLens),
    # so a genuinely-refuted fn's verdict lived only in the emit dir and never credited.
    dirs = [ws / ".auditooor" / "hunt_findings_sidecars"]
    _repo = Path(__file__).resolve().parent.parent  # auditooor-mcp repo root
    dirs.append(_repo / "audit" / "corpus_tags" / "derived"
                / f"mimo_harness_{ws.name}_workflow")
    files = []
    for d in dirs:
        if d.is_dir():
            files.extend(sorted(d.glob("*.json")))
    for f in files:
        if _IMPACT_SUFFIX_RE.search(f.stem):
            continue  # a per-frame partial, not a whole-fn verdict
        try:
            r = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(r, dict):
            continue
        verdict = str(r.get("verdict") or "").strip().lower()
        applies = str(r.get("applies_to_target") or "").strip().lower()
        fa = r.get("function_anchor") if isinstance(r.get("function_anchor"), dict) else {}
        res = r.get("result")
        if isinstance(res, str):
            try:
                res = json.loads(res)
            except ValueError:
                res = None
        if isinstance(res, dict):
            verdict = verdict or str(res.get("verdict") or "").strip().lower()
            applies = applies or str(res.get("applies_to_target") or "").strip().lower()
        refuted = verdict in ("kill", "killed", "refuted", "negative") or applies == "no"
        # R76 cite: gather EVERY candidate and accept if ANY carries a file.ext:LNN.
        # The workflow-drill schema puts the line in result.file_line and/or
        # function_anchor.line (NOT always start_line), while function_anchor.file is
        # a bare path with no line - keying on that alone dropped a genuine cite.
        sl = fa.get("start_line") or fa.get("line")
        cites = [str(r.get("file_line") or ""),
                 str((res or {}).get("file_line") or "") if isinstance(res, dict) else "",
                 (f"{fa.get('file')}:L{sl}" if fa.get("file") and sl else "")]
        has_cite = any(r76.search(c) for c in cites if c)
        if not (refuted and has_cite):
            continue
        fn = str(r.get("function") or r.get("fn") or fa.get("fn") or fa.get("function") or "")
        if not fn and isinstance(r.get("unit"), str):
            fn = r["unit"].replace(",", "+").split("+", 1)[0]
        fn = fn.split("(", 1)[0]
        if "::" in fn:
            fn = fn.rsplit("::", 1)[-1]
        if "." in fn and "/" not in fn:
            fn = fn.rsplit(".", 1)[-1]
        fn = fn.strip()
        if fn:
            out.add(fn)
    return out


def _mvc_covered_functions(ws: Path) -> set:
    """Set of lowercased function names carried by a MUTATION-VERIFIED mvc_sidecar.

    A per-function value-mover whose exact fn has a mutation-verified (or genuine
    non-vacuous-kill) mvc_sidecar is REALLY covered - but the per-frame branch of
    _build_function_axis never consulted mvc coverage, so such a fn (present in
    hunt_frames with residual dispatched frames) pinned NOT-ENUMERATED despite the
    on-disk mutation-verified evidence (serving-join, Strata 2026-07-07: 26 cells).
    NEVER-FALSE-PASS: mirrors the exact gate in _mvc_asset_invariant_categories -
    a sidecar credits only when flagged mutation_verified OR it proves a genuine
    behavior-changing kill (verdict==non-vacuous AND behavior_changing_kill_count>=1);
    a survived / vacuous / panic-only run credits nothing."""
    out: set = set()
    d = ws / ".auditooor" / "mvc_sidecar"
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.json")):
        try:
            r = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(r, dict):
            continue
        try:
            _bck = int(r.get("behavior_changing_kill_count") or 0)
        except (TypeError, ValueError):
            _bck = 0
        _nonvacuous_kill = (
            str(r.get("verdict") or "").strip().lower() == "non-vacuous" and _bck >= 1
        )
        if not (r.get("mutation_verified") or _nonvacuous_kill):
            continue
        fn = str(r.get("function") or "").strip().lower()
        if fn:
            out.add(fn)
    return out


def _load_fcc_entry_extractor():
    """Lazily import function-coverage-completeness's OWN entry-surface extractor
    (_extract_entry_fns + is_go_entry_point). This is the AUTHORITATIVE attack-surface
    classifier fcc used to reach its terminal verdict; reusing it here keeps the
    completeness-matrix denominator consistent with the fcc gate (the enumeration-
    universe-inconsistency root cause: a raw inscope helper that fcc's classifier drops
    was left NOT-ENUMERATED forever because the matrix's crude structural non-entry check
    diverged from fcc's real classifier). Returns the module or None (older checkout)."""
    tool = Path(__file__).resolve().parent / "function-coverage-completeness.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("_fcc_entry_extractor", str(tool))
        mod = _ilu.module_from_spec(spec)
        sys.modules["_fcc_entry_extractor"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_FCC_ENTRY_MOD = _load_fcc_entry_extractor()
_FCC_KEPT_ENTRY_CACHE: dict[str, set | None] = {}


def _fcc_kept_entry_fns(ws: Path, rel: str) -> set | None:
    """Set of function NAMES fcc's OWN classifier keeps as TRUE external entry points
    for this Go/Rust file (the authoritative attack surface). None when the file is
    missing / unparseable / the extractor is unavailable (fail-closed: the caller then
    does NOT credit the fn, leaving it flagged). NEVER-FALSE-PASS: a genuine entry point
    IS in this set -> the caller returns False -> the cell stays flagged; only a fn that
    fcc's classifier genuinely drops (internal helper / boilerplate / non-entry-exported /
    unexported / test / trait-impl plumbing) is credited out-of-scope."""
    if _FCC_ENTRY_MOD is None:
        return None
    key = rel
    if key in _FCC_KEPT_ENTRY_CACHE:
        return _FCC_KEPT_ENTRY_CACHE[key]
    low = rel.lower()
    if low.endswith(".go"):
        lang = "go"
    elif low.endswith(".rs"):
        lang = "rs"
    else:
        _FCC_KEPT_ENTRY_CACHE[key] = None
        return None
    src = ws / rel
    if not src.is_file():
        _FCC_KEPT_ENTRY_CACHE[key] = None
        return None
    try:
        # go_entry_scope mirrors fcc's Cosmos narrowing; for a confidently-detected
        # Cosmos/Go-L1 workspace the Go entry-point classifier (is_go_entry_point) runs,
        # exactly as in the fcc gate. Non-Cosmos / non-Go paths are unaffected.
        go_scope = bool(getattr(_FCC_ENTRY_MOD, "_go_entry", None)
                        and _FCC_ENTRY_MOD._go_entry.is_cosmos_go_workspace(ws)) \
            if lang == "go" else False
        fns = _FCC_ENTRY_MOD._extract_entry_fns(src, lang, rel, go_entry_scope=go_scope)
        kept = {f.name for f in fns if getattr(f, "entry_point", True)}
    except Exception:  # noqa: BLE001 - fail-closed (no credit) on any parse error
        _FCC_KEPT_ENTRY_CACHE[key] = None
        return None
    _FCC_KEPT_ENTRY_CACHE[key] = kept
    return kept


def _is_fcc_filtered_nonentry(ws: Path, rel: str, fn: str) -> bool:
    """True only if the source decl confirms the function is non-entry / read-only /
    a non-callable library unit, matching what fcc's scope filter would drop."""
    low = rel.lower()
    # ENUMERATION-UNIVERSE CONSISTENCY (Go/Rust): the authoritative attack surface is
    # fcc's OWN entry-point classifier. A raw inscope helper (from inscope_units, which
    # holds every exported+unexported unit) that is NOT in fcc's kept entry set for its
    # file was dropped by fcc's scope filter - an internal helper / hand-written module
    # boilerplate / non-entry-exported getter / unexported fn / test / serde-trait-impl
    # plumbing - so it carries no invariant obligation the fcc gate did not already
    # exempt. Delegating to fcc's real extractor (not the crude _is_go_cosmos_nonentry
    # basename convention) closes the false-red gap where 1260 Cosmos helpers were pinned
    # NOT-ENUMERATED despite fcc's terminal fully-covered verdict. FAIL-CLOSED: a genuine
    # entry point is in the kept set (returns False -> stays flagged); an unparseable /
    # missing file returns None (no credit).
    if (low.endswith(".go") or low.endswith(".rs")) and fn:
        _kept = _fcc_kept_entry_fns(ws, rel)
        if _kept is not None and fn not in _kept:
            return True
    # Go/Cosmos module boilerplate + sim/testutil scaffolding + pure utils are non-entry
    # the same way a Solidity interface/library is (no value-moving message handler /
    # keeper mutator to attack). Recognized structurally (dir/basename convention) so the
    # Solidity-shaped decl regexes below (which never match Go) do not leave every Go
    # boilerplate file pinned NOT-ENUMERATED forever.
    if _is_go_cosmos_nonentry(rel, fn):
        return True
    # imports/*Import.sol are compile-forcing re-export shims ("Force foundry to compile
    # this contract"); they declare no callable functions of their own - not attack
    # surface. interface/library/constant/error/event units likewise expose no
    # implemented mutator.
    if "/imports/" in low or low.endswith("import.sol"):
        return True
    if not fn:
        # nameless inscope row (library file body: ConstantsLib/ErrorsLib/EventsLib) -
        # no callable external surface to attack.
        _bn0 = Path(str(rel)).name  # original-case basename
        # I<Upper>.sol interface files declare only signatures (no implemented mutator)
        # even when they do not live under an /interfaces/ dir.
        if re.match(r"I[A-Z][A-Za-z0-9]*\.sol$", _bn0):
            return True
        return any(seg in low for seg in (
            "constantslib", "errorslib", "eventslib", "/interfaces/", "/libraries/",
        )) or low.endswith(("constants.sol", "errors.sol", "events.sol"))
    src = ws / rel
    if not src.is_file():
        return False
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    # constructors are not an external attack entrypoint fcc enumerates.
    if fn == "constructor":
        return True
    # empty receive()/fallback ETH sinks have no logic to attack; fcc enumerates named
    # mutators, not a bare `receive() external payable {}`. Credit only when the body is
    # empty (no statements between the braces).
    if fn in ("receive", "fallback"):
        rm = re.search(r"\b" + fn + r"\s*\([^)]*\)[^{;]*\{\s*\}", text)
        if rm:
            return True
        # PHANTOM guard (strata 2026-07-01): the in-scope function enumerator can emit a
        # `receive`/`fallback` cell from a MISPARSED comment/doc line ("...wishes to
        # receive.") when the source has NO real receive()/fallback() DECLARATION. That is
        # not an attack surface and must not pin the completeness matrix INCOMPLETE
        # forever. Credit when no genuine `receive()/fallback()` external/payable decl
        # exists. FALSE-GREEN-SAFE: a real receive() external { ...logic... } DOES match
        # this decl regex, so it still falls through and is correctly flagged for an
        # invariant.
        real_decl = re.search(r"\b" + fn + r"\s*\(\s*\)\s*(external|payable|virtual|override|public)", text)
        if not real_decl:
            return True
    # interface/library declarations: a function decl that terminates in ';' (no body)
    # is an interface signature, not an implemented attack surface. Interface files
    # follow the `I<Name>.sol` convention (leading 'I' + Uppercase) even when they do
    # NOT live under an /interfaces/ dir (NUVA: contracts/modules/utils/ICustomToken.sol,
    # modules/wormhole/ICCTPv1WithExecutor.sol) - detect by that convention too.
    _bn = Path(str(rel)).name  # original-case basename for the I<Upper> convention
    _iface_name = bool(re.match(r"I[A-Z][A-Za-z0-9]*\.sol$", _bn))
    if "/interfaces/" in low or "/libraries/" in low or _iface_name:
        msig = re.search(r"function\s+" + re.escape(fn) + r"\b[^{;]*;", text)
        if msig:
            return True  # bare interface signature, no implementation
        if _iface_name:
            # whole file is an interface (all decls are signatures) - the fn is a
            # bare signature even if the regex above missed a multiline decl.
            return True
    m = re.search(r"function\s+" + re.escape(fn) + r"\b([^{;]*)", text)
    if not m:
        # decl not found as a Solidity function (e.g. a struct-update lib fn or a
        # name only present in an interface) - treat as non-attack-surface only if it
        # lives under interfaces/libraries.
        return "/interfaces/" in low or "/libraries/" in low
    decl_window = m.group(1)
    if _NONENTRY_SOL_RE.search(decl_window):
        return True  # internal / private
    if _VIEWPURE_SOL_RE.search(decl_window):
        return True  # public/external read-only getter - not a value-moving target
    return False


def _rebuttal(ws: Path) -> str | None:
    p = ws / ".auditooor" / "completeness_matrix_rebuttal.md"
    if not p.is_file():
        return None
    txt = p.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"completeness-matrix-rebuttal:\s*(.+?)\s*-->", txt)
    return m.group(1).strip() if m else None


def _load_flow_coverage(ws: Path) -> dict[str, Any]:
    """The business-flow (cross-module combination) axis of the matrix. Reuses
    business_flow_decompose so a flow is enumerated + driven, not just each
    function. Absent tooling / no flows -> empty (never a false gap)."""
    try:
        import importlib.util as _il
        p = Path(__file__).resolve().parent / "business_flow_decompose.py"
        spec = _il.spec_from_file_location("business_flow_decompose", p)
        bf = _il.module_from_spec(spec)
        spec.loader.exec_module(bf)
        dec = bf.decompose(ws)
        cov = bf.coverage(ws, dec)
        # P2c: carry the flow-level harness target (cut_files + invariant hint) so
        # the enumeration worklist tells the harness-authoring loop exactly WHAT to
        # build for each undriven cross-module flow.
        targets_by_id = {t["flow_id"]: t for t in bf.harness_targets(ws, dec)}
        return {"present": True, "flow_count": dec["flow_count"],
                "drivable": cov["drivable_flows"], "undriven": cov["undriven_flows"],
                "undriven_count": cov["undriven_count"],
                "harness_targets": targets_by_id}
    except Exception:
        return {"present": False, "flow_count": 0, "drivable": 0,
                "undriven": [], "undriven_count": 0}


# ---------------------------------------------------------------------------
# MECHANISM AXIS (completeness-matrix v2) - primacy-of-impact completeness.
#
# The 4 legacy axes (invariant-category, function, impact-class, business-flow)
# enumerate WHAT was covered but not, per impact, EVERY MECHANISM that can PRODUCE
# that impact. A never-enumerated [impact x mechanism] pairing (e.g. chain-halt via
# consensus-hook unbounded iteration - the live NUVA miss) is therefore invisible:
# absence produced no failure. The mechanism axis materializes the
# [in-scope-asset-languages x impact x mechanism] cross-product and fails-CLOSED on
# any cell that a mechanism detector never scanned OR that has an un-dispositioned
# open finding. The impact->mechanism taxonomy is the corpus-fed library below
# (overridable/extensible via audit/corpus_tags/impact_mechanism_library.json so
# post-mortem ETL grows the denominator instead of a static hand list).
# ---------------------------------------------------------------------------
_MECHANISM_LIBRARY_SEED: dict[str, list[dict[str, Any]]] = {
    "chain-halt": [
        {"mechanism": "consensus-hook-unbounded-iteration", "languages": ["go", "rust", "move"],
         "detector": "go_ast_consensus_hook_unbounded_iteration"},
        {"mechanism": "consensus-path-arithmetic-panic", "languages": ["go", "rust"],
         "detector": "arithmetic-panic-sweep"},
        {"mechanism": "consensus-map-iteration-nondeterminism", "languages": ["go"],
         "detector": "go.consensus.map_iteration_nondeterministic_state_write"},
    ],
    "permanent-freeze": [
        {"mechanism": "unbounded-attacker-growable-iteration", "languages": ["solidity", "move", "go", "rust"],
         "detector": "sol_ast_unbounded_attacker_growable_iteration"},
        {"mechanism": "overflow-underflow-locks-withdraw", "languages": ["solidity", "go", "rust"],
         "detector": "arithmetic-freeze-sweep"},
    ],
    "insolvency": [
        {"mechanism": "accounting-conservation-break", "languages": ["solidity", "go", "rust", "move"],
         "detector": "mvc-conservation-invariant"},
        {"mechanism": "oracle-staleness-or-manipulation", "languages": ["solidity", "go", "rust"],
         "detector": "oracle-freshness-check"},
    ],
    "direct-theft": [
        {"mechanism": "recipient-not-bound-to-debited-owner", "languages": ["solidity", "go", "rust"],
         "detector": "recipient-binding-check"},
        {"mechanism": "missing-authority-gate-sibling-asymmetry", "languages": ["go", "rust"],
         "detector": "go_ast_msgserver_missing_authority_sibling_asymmetry"},
        {"mechanism": "first-depositor-donation-inflation", "languages": ["solidity", "rust", "move"],
         "detector": "inflation-invariant"},
    ],
    "temp-freeze-griefing": [
        {"mechanism": "unbounded-attacker-growable-iteration", "languages": ["solidity", "go", "rust", "move"],
         "detector": "sol_ast_unbounded_attacker_growable_iteration"},
        {"mechanism": "missing-authority-gate-sibling-asymmetry", "languages": ["go", "rust"],
         "detector": "go_ast_msgserver_missing_authority_sibling_asymmetry"},
    ],
    "governance-manipulation": [
        {"mechanism": "vote-power-double-count-or-snapshot-frontrun", "languages": ["solidity", "go", "rust"],
         "detector": "governance-detector-family"},
    ],
    "yield-gas-mev-theft": [
        {"mechanism": "cross-chain-domain-not-bound", "languages": ["solidity", "go", "rust"],
         "detector": "xchain_message_domain_binding_check"},
        {"mechanism": "first-depositor-donation-inflation", "languages": ["solidity", "rust", "move"],
         "detector": "inflation-invariant"},
    ],
}

_EXT_LANG = {".go": "go", ".sol": "solidity", ".rs": "rust", ".move": "move",
             ".cairo": "zk", ".circom": "zk", ".vy": "vyper"}


def _ws_languages(inscope: dict[str, list[dict[str, Any]]]) -> set[str]:
    langs: set[str] = set()
    for units in inscope.values():
        for u in units:
            ext = os.path.splitext(str(u.get("file", "")))[1].lower()
            if ext in _EXT_LANG:
                langs.add(_EXT_LANG[ext])
    return langs


def _load_mechanism_library(ws: Path) -> dict[str, list[dict[str, Any]]]:
    """Impact -> mechanisms taxonomy (the cell denominator source of truth).
    Seed is corpus-derived; a repo-level or ws-level JSON override lets the ETL
    grow the denominator from mined post-mortems without editing this file."""
    lib = {k: [dict(m) for m in v] for k, v in _MECHANISM_LIBRARY_SEED.items()}
    # The curated SEED (all detector-backed, high-signal) is the default denominator.
    # The repo-level corpus-ETL library (impact-mechanism-library-build.py inverts the
    # 32 impact_hunting_methodology playbooks -> ~162 mechanisms, mostly detector-less
    # roadmap) is merged ONLY under AUDITOOOR_MECHANISM_LIBRARY_FULL so it does not spam
    # every workspace's WARN worklist by default. A ws-level override always merges
    # (per-workspace curation).
    cands: list[Path] = []
    if os.environ.get("AUDITOOOR_MECHANISM_LIBRARY_FULL"):
        cands.append(Path(__file__).resolve().parent.parent / "audit" / "corpus_tags"
                     / "impact_mechanism_library.json")
    cands.append(ws / ".auditooor" / "impact_mechanism_library.json")
    for cand in cands:
        try:
            if cand.is_file():
                ext = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
                if isinstance(ext, dict):
                    for imp, mechs in ext.items():
                        if isinstance(mechs, list):
                            lib.setdefault(imp, [])
                            have = {m.get("mechanism") for m in lib[imp]}
                            for m in mechs:
                                if isinstance(m, dict) and m.get("mechanism") not in have:
                                    lib[imp].append(m)
        except (OSError, ValueError):
            continue
    return lib


def _load_mechanism_scan(ws: Path) -> dict[str, dict[str, Any]]:
    """mechanism -> {found: int, findings: [...]} from .auditooor/mechanism_scan/*.json
    (the common detector-output sidecars). A mechanism present here means a detector
    for it actually RAN on this workspace."""
    out: dict[str, dict[str, Any]] = {}
    d = ws / ".auditooor" / "mechanism_scan"
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.json")):
        try:
            r = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(r, dict):
            continue
        mech = str(r.get("mechanism") or "")
        if not mech:
            continue
        fnds = r.get("findings") if isinstance(r.get("findings"), list) else []
        cur = out.setdefault(mech, {"found": 0, "findings": []})
        cur["found"] += len(fnds)
        cur["findings"].extend(fnds)
    return out


def _load_mechanism_dispositions(ws: Path) -> set[str]:
    """Set of dispositioned finding keys 'mechanism::file::line-or-fn' from
    .auditooor/mechanism_dispositions.jsonl (an explicit scanned-clean / refuted /
    covered verdict per open mechanism finding). Un-fakeable: only a real verdict
    row closes an open finding cell.

    DISPOSITION-QUALITY (operator directive 2026-07-02, advisory-first behind
    AUDITOOOR_DISPOSITION_PROOF_STRICT): an N-A / cleared / refuted verdict is
    TERMINAL only when its ``reasoning`` PROVES the impact UNREACHABLE - a
    code-guard/structural fact at file:line, a MECHANISM-level absence argument, or
    a named in-protocol cap/recovery. A verdict whose reasoning is ONLY a keyword
    grep / "no X found" / "0 hits" does NOT close the cell under strict (the
    'killing easier than keeping' false-negative anti-pattern). Absent STRICT the
    key set is byte-identical to the legacy behaviour. A ``refuted-to-*`` /
    ``covered`` verdict that POINTS AT a real finding is a KEEP, not a KILL, and is
    exempt from the unreachability-proof bar (classify_reason handles this)."""
    keys: set[str] = set()
    p = ws / ".auditooor" / "mechanism_dispositions.jsonl"
    if not p.is_file():
        return keys
    proof_strict = bool(_DPQ_MOD is not None and _DPQ_MOD.proof_strict_enabled())
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict):
            continue
        mech = str(r.get("mechanism") or "")
        anchor = str(r.get("file") or "") + "::" + str(r.get("line") or r.get("function") or "")
        if not mech:
            continue
        # DISPOSITION-QUALITY strict: a grep-only / absence-only N-A reasoning does
        # NOT close the mechanism cell (advisory-first; off => legacy preserved).
        if proof_strict:
            reason = str(r.get("reasoning") or r.get("reason")
                         or r.get("disposition") or "").strip()
            if not _DPQ_MOD.reason_is_terminal_quality(reason):
                continue
        keys.add(mech + "::" + anchor)
    return keys


def _load_agent_mechanism_verdicts(
    ws: Path,
) -> tuple[set[tuple[str, str]], dict[tuple[str, str], list[dict[str, Any]]]]:
    """Agent-REASONED per-cell verdicts from .auditooor/agent_mechanism_verdicts/*.json.

    This closes the loop so a hunter can clear an UNSCANNED (no-detector) impact x
    mechanism cell by SOURCE-READING + REASONING, not only by a detector scan. The
    detector is a backstop; the agent's cited verdict is a first-class disposition.

    ANTI-FALSE-NEGATIVE (the load-bearing rule): closing a cell is a claim of ABSENCE
    and must be as hard as raising a finding. A `cleared` verdict credits the cell ONLY
    when it carries >=1 concrete source citation (file:line) AND substantive reasoning;
    a bare "cleared" string is IGNORED (fail-closed - the cell stays unscanned). A
    `finding` verdict OPENS the cell with an agent-sourced open finding (must then be
    filed or dispositioned), and needs a citation to be actionable.

    Returns (cleared, findings):
      cleared  = set of (impact, mechanism) cells an agent cleared with evidence
      findings = dict[(impact, mechanism)] -> list of {file,line,reasoning,source}
    """
    cleared: set[tuple[str, str]] = set()
    findings: dict[tuple[str, str], list[dict[str, Any]]] = {}
    d = ws / ".auditooor" / "agent_mechanism_verdicts"
    if not d.is_dir():
        return cleared, findings
    for fp in sorted(d.glob("*.json")):
        try:
            raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        rows = raw if isinstance(raw, list) else [raw]
        for r in rows:
            if not isinstance(r, dict):
                continue
            impact = str(r.get("impact") or "").strip()
            mech = str(r.get("mechanism") or "").strip()
            verdict = str(r.get("verdict") or "").strip().lower()
            if not impact or not mech:
                continue
            refs_raw = r.get("source_refs") or r.get("citations") or []
            refs = [str(x).strip() for x in refs_raw if isinstance(x, str) and str(x).strip()]
            reasoning = str(r.get("reasoning") or "").strip()
            cell = (impact, mech)
            if verdict == "cleared":
                # fail-closed: a cell-closure needs real evidence, not a bare verdict.
                if len(refs) >= 1 and len(reasoning) >= 40:
                    cleared.add(cell)
            elif verdict in ("finding", "open", "confirmed"):
                if refs:
                    first = refs[0]
                    file_part, _, line_part = first.partition(":")
                    findings.setdefault(cell, []).append({
                        "file": file_part,
                        "line": line_part,
                        "reasoning": reasoning,
                        "source": "agent-verdict",
                    })
    return cleared, findings


def _mech_open_findings_enforced() -> bool:
    """An OPEN mechanism finding (a detector RAN and FIRED, un-dispositioned - e.g.
    the NUVA chain-halt) is a real, actionable obligation and blocks under the main
    STRICT gate or either enforce flag. This is the surgical closure of the
    false-green: a fired-but-un-triaged Critical fails audit-complete."""
    return (_env_flag("AUDITOOOR_L37_STRICT")
            or _env_flag("AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE")
            or _env_flag("AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT")
            or _env_flag("AUDITOOOR_MECHANISM_AXIS_ENFORCE"))


def _env_flag(name: str) -> bool:
    """Truthy env-flag reader: unset / "" / 0 / false / no => False (so
    AUDITOOOR_MECHANISM_AXIS_ENFORCE=0 does NOT accidentally enforce). Matches the
    _enforce_enabled() idiom used for AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE."""
    return os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no")


def _mech_unscanned_enforced() -> bool:
    """An UNSCANNED cell (no detector exists yet for that mechanism/language) is a
    known coverage gap, not a specific finding, so it only WARNs + worklists by
    default (never mass-bricks workspaces on mechanisms we have not built a detector
    for). Under STRICT-terminal enforcement it becomes a REQUIRED terminal
    adjudication: the operator must either run the detector, source-cite an
    agent-cleared verdict, disposition it, or explicitly waive it.

    It hard-fails under ANY of:
      - AUDITOOOR_MECHANISM_AXIS_ENFORCE (the dedicated full-plane opt-in - this is
        the flag that was previously BUGGED: it parsed but the misleading top-level
        `enforce=` print read a DIFFERENT env, so operators believed it never
        gated; the flag DOES flip this predicate and now the print reflects it),
      - AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT (the 100%-all-axes umbrella), or
      - AUDITOOOR_L37_STRICT (what `make audit-complete STRICT=1` exports)."""
    return (_env_flag("AUDITOOOR_MECHANISM_AXIS_ENFORCE")
            or _env_flag("AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT")
            or _env_flag("AUDITOOOR_L37_STRICT"))


def _build_mechanism_axis(ws: Path, inscope: dict[str, list[dict[str, Any]]],
                          impact_present: set[str]) -> dict[str, Any]:
    """Materialize the [impact x mechanism] cells applicable to this ws's languages
    and mark each ENUMERATED (a detector ran clean OR every open finding is
    dispositioned) or NOT-ENUMERATED (never scanned, or open un-dispositioned
    finding). impact_present = the impact families this ws is in scope for (from
    the exploit-class ledger + always the universal liveness/theft families)."""
    lib = _load_mechanism_library(ws)
    langs = _ws_languages(inscope)
    scan = _load_mechanism_scan(ws)
    disp = _load_mechanism_dispositions(ws)
    # Agent-REASONED per-cell verdicts (the closed loop): a hunter can OPEN an
    # unscanned cell with a source-cited finding, or CLEAR it by reasoning. Detector
    # is the backstop; the agent's cited verdict is a first-class disposition.
    agent_cleared, agent_findings = _load_agent_mechanism_verdicts(ws)
    # Impact families are ALWAYS in-scope for a value-custodying protocol; we do not
    # trust an empty exploit-class ledger to prune a whole impact family (that is
    # exactly the false-green the mechanism axis exists to kill). Use the full lib.
    cells: list[dict[str, Any]] = []
    not_enum = not_open = not_unscanned = 0
    for impact, mechs in sorted(lib.items()):
        for m in mechs:
            mlangs = set(m.get("languages") or [])
            if langs and mlangs and not (langs & mlangs):
                continue  # mechanism cannot occur in this ws's languages
            mech = m["mechanism"]
            sc = scan.get(mech)
            status, open_findings = "not-enumerated-unscanned", []
            if sc is not None:
                if sc["found"] == 0:
                    status = "enumerated-scanned-clean"
                else:
                    undisp = []
                    for f in sc["findings"]:
                        anchor = str(f.get("file") or "") + "::" + str(
                            f.get("line") or f.get("function") or "")
                        if (mech + "::" + anchor) not in disp:
                            undisp.append(f)
                    if undisp:
                        status, open_findings = "not-enumerated-open-finding", undisp
                    else:
                        status = "enumerated-findings-dispositioned"
            # Agent-sourced findings for this cell OPEN it (like a detector fire):
            # an un-dispositioned agent finding is a real obligation (file or refute).
            af_undisp = []
            for f in agent_findings.get((impact, mech), []):
                anchor = str(f.get("file") or "") + "::" + str(f.get("line") or "")
                if (mech + "::" + anchor) not in disp:
                    af_undisp.append(f)
            if af_undisp:
                status = "not-enumerated-open-finding"
                open_findings = open_findings + af_undisp
            # An agent CLEARED verdict (with citations - fail-closed enforced in the
            # loader) closes an otherwise-UNSCANNED cell by reasoning, not a detector.
            elif status == "not-enumerated-unscanned" and (impact, mech) in agent_cleared:
                status = "enumerated-agent-cleared"
            if status.startswith("not-enumerated"):
                not_enum += 1
                if status == "not-enumerated-open-finding":
                    not_open += 1
                else:
                    not_unscanned += 1
            cells.append({"impact": impact, "mechanism": mech,
                          "languages": sorted(mlangs), "detector": m.get("detector"),
                          "status": status, "open_findings": len(open_findings)})
    return {"present": True, "ws_languages": sorted(langs), "cells": cells,
            "total": len(cells), "not_enumerated": not_enum,
            "not_enumerated_open": not_open, "not_enumerated_unscanned": not_unscanned,
            "open_findings_enforced": _mech_open_findings_enforced(),
            "unscanned_enforced": _mech_unscanned_enforced()}


# ---------------------------------------------------------------------------
# MECHANISM DETECTOR: cross-chain-domain-not-bound (advisory hypothesis emitter)
#
# Materializes the [yield-gas-mev-theft x cross-chain-domain-not-bound] cell as a
# real signal instead of a detector-less roadmap entry. Per keccak/abi.encode(
# Packed) digest SINK it DATAFLOW-SLICES the declared params (the message's own
# struct/msg fields + the canonical src+dst domain + nonce identity) and asks,
# per field, whether it REACHES the hashed preimage. One hypothesis row is
# emitted per UNBOUND field (a field the message omits from its digest -> a
# cross-origin / cross-domain replay seam).
#
# FP-GUARD (the load-bearing design): enumeration is by DATAFLOW-REACHABILITY into
# the sink over THIS function's real declared params - NOT a hardcoded field-name
# vocabulary. That fixed vocabulary is exactly the wave17 shape-regex subset
# (detectors/wave17/bridge_message_domain_binding_fire28.py) which misses 31 recall
# cases whose fields have non-vocabulary names. A function that binds EVERY declared
# param is the complete-binding control and is clean (this is why the canonical
# Hyperlane Message.formatMessage, which packs all 7 fields, does not fire).
#
# NO-AUTO-CREDIT: rows are verdict='needs-fuzz', advisory=True. This emitter NEVER
# writes a mechanism_scan clean-sidecar, so it can never auto-close the mechanism
# cell; a human/fuzz run must adjudicate. OFF by default behind
# AUDITOOOR_XCHAIN_DOMAIN_BIND_HYP (or an explicit force=).
#
# DEDUP (A1 lesson - do NOT re-derive covered_by): each hit is checked against the
# EXISTING wave17 detector by RUNNING its scan() on the same source; a row that
# wave17 already flags for the same function is tagged covered_by; net-new rows
# (wave17 silent) are covered_by=None. We never re-implement wave17's signal.
# ---------------------------------------------------------------------------
_XCH_ENV = "AUDITOOOR_XCHAIN_DOMAIN_BIND_HYP"
_XCH_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
# abi.encode / abi.encodePacked / bytes.concat preimage constructors (the sink the
# keccak/message digest hashes). We union every constructor's args in the body.
_XCH_ENCODE_RE = re.compile(
    r"\b(?:abi\s*\.\s*encode(?:Packed)?|bytes\s*\.\s*concat)\s*\(", re.IGNORECASE)
# A param is a CROSS-CHAIN IDENTITY field: its omission from the digest enables a
# cross-domain / cross-chain / cross-message replay. This is the must-bind set the
# spec names (src+dst domain + nonce, plus the sender/recipient identity). It is a
# semantic CLASS applied to THIS function's real declared params (reachability
# enumeration), NOT a fixed vocabulary matched over free body text - the precise
# distinction from the wave17 shape-regex that mis-anchors + misses 31 recall cases.
_XCH_IDENTITY_RE = re.compile(
    r"domain|chainid|chain_id|chainselector|\beid\b|selector|nonce|"
    r"origin|sender|recipient|\bpeer\b|sequence", re.IGNORECASE)
_XCH_IDENT_TOK_RE = re.compile(r"[A-Za-z_]\w*")
# keccak256/sha256 digest wrappers - an abi.encode inside one is a real message
# DIGEST (an identity), not incidental body/calldata construction.
_XCH_HASH_RE = re.compile(r"\b(?:keccak256|sha256)\s*\(", re.IGNORECASE)


def _xch_strip(src: str) -> str:
    """Blank out comments + string/char literals (keep newlines for line math)."""
    out = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.DOTALL)
    out = re.sub(r"//[^\n]*", "", out)
    out = re.sub(r'"(?:[^"\\]|\\.)*"', '""', out)
    out = re.sub(r"'(?:[^'\\]|\\.)*'", "''", out)
    return out


def _xch_balanced(src: str, open_idx: int, opench: str, closech: str) -> int:
    """Index just past the balanced group opening at open_idx (src[open_idx]==opench)."""
    depth = 0
    i = open_idx
    while i < len(src):
        c = src[i]
        if c == opench:
            depth += 1
        elif c == closech:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(src)


def _xch_params(header: str) -> list[str]:
    """Declared parameter NAMES from a function header (the reachability universe).
    Name = the last identifier of each top-level comma segment inside the FIRST
    paren group (handles `bytes calldata _messageBody`, `Msg calldata m`)."""
    lp = header.find("(")
    if lp < 0:
        return []
    rp = _xch_balanced(header, lp, "(", ")")
    inner = header[lp + 1:rp - 1]
    names: list[str] = []
    depth = 0
    seg = ""
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            names.append(seg)
            seg = ""
        else:
            seg += ch
    names.append(seg)
    out: list[str] = []
    for s in names:
        toks = _XCH_IDENT_TOK_RE.findall(s)
        if toks:
            out.append(toks[-1])
    return out


def _xch_functions(src: str):
    """Yield (name, header, body, fn_line, body_start_idx) for each defined fn."""
    pos = 0
    while True:
        m = _XCH_FN_RE.search(src, pos)
        if m is None:
            return
        lp = src.find("(", m.end() - 1)
        rp = _xch_balanced(src, lp, "(", ")")
        # header runs to the first '{' or ';' after the param list
        brace = src.find("{", rp)
        semi = src.find(";", rp)
        if brace < 0 or (0 <= semi < brace):
            pos = rp
            continue
        body_end = _xch_balanced(src, brace, "{", "}")
        header = src[m.start():brace]
        body = src[brace:body_end]
        fn_line = src.count("\n", 0, m.start()) + 1
        yield m.group(1), header, body, fn_line, brace
        pos = body_end


def _xch_preimage(body: str) -> tuple[str, int] | None:
    """Union of the args of every QUALIFYING message-digest sink in the body + the
    offset of the first one. A qualifying sink is an abi.encode(Packed)/bytes.concat
    that is EITHER (a) an argument of a keccak256/sha256 call (a real digest/id) OR
    (b) the operand of a `return` (the canonical message-bytes constructor, e.g.
    Hyperlane Message.formatMessage). Incidental body/calldata abi.encode (a token
    payload later dispatched, whose domain binding lives elsewhere) is NOT a sink -
    this is the load-bearing FP guard that stops transferRemote-style false rows."""
    parts: list[str] = []
    first = None
    for m in _XCH_ENCODE_RE.finditer(body):
        enc_lp = body.find("(", m.end() - 1)
        # look back over whitespace/open-paren for a keccak/sha or `return` context
        j = m.start() - 1
        while j >= 0 and body[j] in " \t\n\r(":
            j -= 1
        prev = body[max(0, j - 8):j + 1]
        wrapped = bool(_XCH_HASH_RE.search(body[max(0, m.start() - 24):m.start()])) \
            or prev.rstrip().endswith("keccak256") or prev.rstrip().endswith("sha256") \
            or re.search(r"\breturn\s*$", body[:m.start()]) is not None
        if not wrapped:
            continue
        rp = _xch_balanced(body, enc_lp, "(", ")")
        parts.append(body[enc_lp + 1:rp - 1])
        if first is None:
            first = m.start()
    if first is None:
        return None
    return ("\n".join(parts), first)


_XCH_ASSIGN_RE = re.compile(r"([A-Za-z_]\w*)\s*=\s*([^=;][^;]*);")


def _xch_reachable_tokens(preimage: str, body: str) -> set[str]:
    """Backward dataflow slice from the digest sink: the transitive closure of
    identifiers that REACH the preimage. Seeds with the preimage's own identifiers,
    then for every local assignment `lhs = rhs;` whose lhs already reaches, folds in
    rhs's identifiers (so a param bound INDIRECTLY through a helper local - e.g.
    Hyperlane CheckpointLib `_domainHash = domainHash(_origin, ...)` then packs
    _domainHash - is correctly seen as bound, killing the transitive-binding FP).
    This IS the reachability enumeration the FP-guard mandates."""
    reach = set(_XCH_IDENT_TOK_RE.findall(preimage))
    assigns = [(m.group(1), m.group(2)) for m in _XCH_ASSIGN_RE.finditer(body)]
    changed = True
    while changed:
        changed = False
        for lhs, rhs in assigns:
            if lhs in reach:
                for tok in _XCH_IDENT_TOK_RE.findall(rhs):
                    if tok not in reach:
                        reach.add(tok)
                        changed = True
    return reach


def scan_xchain_domain_binding(source: str, file_path: str = "<memory>") -> list[dict[str, Any]]:
    """Return one hypothesis dict per UNBOUND must-bind field of a cross-chain
    message digest function. Pure/read-only; no I/O. See module block above."""
    code = _xch_strip(source or "")
    hyps: list[dict[str, Any]] = []
    for name, header, body, fn_line, brace in _xch_functions(code):
        params = _xch_params(header)
        if not params:
            continue
        pre = _xch_preimage(body)
        if pre is None:
            continue  # complete-binding control: no digest sink here
        preimage, sink_off = pre
        # ANCHOR: only a function whose params carry a cross-chain identity field is
        # a cross-chain message digest (gates generic EIP712/commitment hashing out).
        if not any(_XCH_IDENTITY_RE.search(p) for p in params):
            continue
        reach = _xch_reachable_tokens(preimage, body)
        sink_line = code.count("\n", 0, brace + sink_off) + 1
        for p in params:
            # MUST-BIND set = the cross-chain identity fields (src+dst domain, nonce,
            # sender/recipient) - the fields whose omission is a replay seam. Enumerated
            # over THIS fn's real params (reachability), not a free-text vocabulary.
            if not _XCH_IDENTITY_RE.search(p):
                continue
            # REACHABILITY: bound iff the param (or a struct-field access `p.`) reaches
            # the hashed preimage, directly OR transitively through a local (def-use).
            bound = p in reach or re.search(
                r"\b" + re.escape(p) + r"\s*\.", preimage) is not None
            if bound:
                continue
            hyps.append({
                "detector": "xchain-domain-binding",
                "mechanism": "cross-chain-domain-not-bound",
                "impact": "yield-gas-mev-theft",
                "file": file_path,
                "function": name,
                "line": sink_line,
                "unbound_field": p,
                "identity_field": bool(_XCH_IDENTITY_RE.search(p)),
                "verdict": "needs-fuzz",
                "advisory": True,
                "note": (f"field '{p}' declared but not reachable into the "
                         f"abi.encode/keccak preimage of '{name}' -> cross-domain "
                         "replay candidate (NO-AUTO-CREDIT; fuzz to confirm)"),
            })
    return hyps


def _xch_wave17_covered_fns(source: str) -> set[str]:
    """DEDUP (reuse, do NOT re-derive): run the EXISTING wave17 domain-binding
    detector on the same source and return the function names it already flags, so
    our rows can be tagged covered_by without re-implementing its signal. Missing
    detector (older tree) -> empty set (dedup is a graceful no-op)."""
    det = (Path(__file__).resolve().parent.parent / "detectors" / "wave17"
           / "bridge_message_domain_binding_fire28.py")
    if not det.is_file():
        return set()
    try:
        modname = "_xch_wave17_bmdb"
        mod = sys.modules.get(modname)
        if mod is None:
            spec = _ilu.spec_from_file_location(modname, det)
            mod = _ilu.module_from_spec(spec)  # type: ignore[arg-type]
            # Register BEFORE exec: the detector's @dataclass resolves cls.__module__
            # via sys.modules, so an unregistered module raises (silent dedup no-op).
            sys.modules[modname] = mod
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return {f.function for f in mod.scan(source) if getattr(f, "function", None)}
    except Exception:  # noqa: BLE001
        return set()


def _xch_enabled(force: bool) -> bool:
    return force or os.environ.get(_XCH_ENV, "").strip().lower() not in ("", "0", "false", "no")


def emit_xchain_domain_binding_hypotheses(
    ws: Path, scan_root: Path | None = None, force: bool = False,
    max_rows: int = 2000) -> dict[str, Any]:
    """Scan in-scope .sol under scan_root (default ws) and write the advisory
    hypotheses jsonl. OFF by default (needs AUDITOOOR_XCHAIN_DOMAIN_BIND_HYP or
    force). Rows are deduped vs wave17 (covered_by) and NEVER auto-credit. Returns
    an accounting dict."""
    out = ws / ".auditooor" / "xchain_domain_binding_hypotheses.jsonl"
    if not _xch_enabled(force):
        return {"status": "off-by-default", "rows": 0, "distinct": 0, "path": str(out)}
    root = scan_root or ws
    rows: list[dict[str, Any]] = []
    distinct = 0
    files = sorted(root.rglob("*.sol")) if root.is_dir() else ([root] if root.suffix == ".sol" else [])
    for fp in files:
        try:
            src = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = scan_xchain_domain_binding(src, str(fp))
        if not hits:
            continue
        covered = _xch_wave17_covered_fns(src)
        for h in hits:
            h["covered_by"] = ("bridge-message-domain-binding-fire28"
                               if h["function"] in covered else None)
            if h["covered_by"] is None:
                distinct += 1
            rows.append(h)
        if len(rows) >= max_rows:
            rows = rows[:max_rows]
            break
    rows.sort(key=lambda r: (r["file"], r["function"], r["unbound_field"]))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    return {"status": "ok", "rows": len(rows), "distinct": distinct, "path": str(out)}


# ---------------------------------------------------------------------------
# 11th SUB-AXIS: token_behavior (advisory hypothesis emitter, NO-AUTO-CREDIT)
#
# Materializes a FAIL-CLOSED coverage CELL: per in-scope fn that calls
# safe/transferFrom on a SETTINGS/CONFIG token, an enumerated invariant must be
# BOTH measured-delta (balanceOf before/after) AND decimal-normalized. If the fn
# lacks that guard, the cell has no covering invariant -> one needs-fuzz row.
#
# NET-NEW vs the existing FOT/deflation detectors (A1-honesty, the load-bearing
# distinctness): deflation_attack.py + rust_wave1/r94_loop already flag the
# balance-delta (measured-delta) HALF. This cell is distinct on two axes they do
# not carry - (1) it ALSO requires decimal-normalization, (2) it is a fail-closed
# completeness CELL (an absent enumerated invariant is a false-GREEN gap even when
# no shape detector fired). We NEVER re-grep the FOT shape to re-derive their
# signal; we CONSUME their hits (persisted detector-family anchors in the ws) only
# to tag covered_by. A row whose fn a FOT/deflation detector already flagged is
# covered_by-tagged; a net-new cell (detectors silent) is covered_by=None. If we
# only re-emitted the FOT shape, E8 would collapse to SUBSUMED - hence the two
# extra requirements above are what make the cell distinct.
#
# FP-GUARD: the config-token ANCHOR (transferFrom receiver names a settings/config
# token) gates arbitrary ERC20 transfers out; the ETH-asset path (tokenAddress==0,
# msg.value==amount) carries NO transferFrom and therefore never fires; a fn that
# already measures the balanceOf delta AND normalizes decimals is the covered
# control and stays silent. Vendored/test/mock files are skipped.
#
# NO-AUTO-CREDIT: rows are verdict='needs-fuzz', advisory=True. OFF by default
# behind AUDITOOOR_TOKEN_BEHAVIOR_HYP (or force=). Never writes a clean-sidecar.
# ---------------------------------------------------------------------------
_TB_ENV = "AUDITOOOR_TOKEN_BEHAVIOR_HYP"
# transferFrom / safeTransferFrom call site (the value-move sink).
_TB_XFER_RE = re.compile(r"\.\s*(safeTransferFrom|transferFrom)\s*\(", re.IGNORECASE)
# The RECEIVER expression is a SETTINGS/CONFIG token: a `settings|config`-qualified
# token/asset member (settings.tokenAddress, config.stakeToken, _settings.asset).
# This is the anchor that stops arbitrary-ERC20 FPs - NOT a bare transferFrom grep.
_TB_CFG_TOKEN_RE = re.compile(
    r"(?:settings|config|_settings|_config)\s*\.\s*\w*(?:token|asset|stake|collateral)\w*",
    re.IGNORECASE)
# measured-delta invariant: two balanceOf reads with a subtraction between them, or
# an explicit before/after balance snapshot delta.
_TB_DELTA_RE = re.compile(
    r"balanceOf\s*\([^;]{0,120}\)[\s\S]{0,400}?-[\s\S]{0,120}?balanceOf\s*\(|"
    r"balance_?(?:After|Post)\s*-\s*balance_?(?:Before|Pre)|"
    r"(?:received|actual|delta)\s*=\s*[\s\S]{0,80}?balanceOf\s*\(",
    re.IGNORECASE)
# decimal-normalization: a decimals() read or an explicit scale to a common base.
_TB_DECIMALS_RE = re.compile(
    r"\.\s*decimals\s*\(|\b10\s*\*\*\s*\w*decimals|\bnormaliz|\bscaled?To|\btoWad\b|\bWAD\b",
    re.IGNORECASE)
_TB_VENDOR_RE = re.compile(r"(?:^|/)(?:test|tests|mock|mocks|node_modules|lib|vendor)/",
                           re.IGNORECASE)


def scan_token_behavior(source: str, file_path: str = "<memory>") -> list[dict[str, Any]]:
    """Return one hypothesis dict per in-scope fn that moves a SETTINGS/CONFIG
    token via safe/transferFrom without an enumerated measured-delta AND
    decimal-normalized invariant. Pure/read-only; no I/O. See module block above."""
    code = _xch_strip(source or "")
    hyps: list[dict[str, Any]] = []
    for name, header, body, fn_line, brace in _xch_functions(code):
        # ANCHOR: a config-token transferFrom must appear in the body.
        xfer = None
        for m in _TB_XFER_RE.finditer(body):
            # the receiver text is what precedes the `.transferFrom(` - scan a small
            # window back for the config-token qualifier.
            back = body[max(0, m.start() - 160):m.start()]
            if _TB_CFG_TOKEN_RE.search(back):
                xfer = m
                break
        if xfer is None:
            continue  # ETH-only / non-config-token path: never fires (FP-guard)
        # COVERED control: the fn measures the balanceOf delta AND normalizes decimals.
        has_delta = bool(_TB_DELTA_RE.search(body))
        has_decimals = bool(_TB_DECIMALS_RE.search(body))
        if has_delta and has_decimals:
            continue  # enumerated measured-delta + decimal-normalized invariant present
        missing = []
        if not has_delta:
            missing.append("measured-delta")
        if not has_decimals:
            missing.append("decimal-normalized")
        xfer_line = code.count("\n", 0, brace) + body.count("\n", 0, xfer.start()) + 1
        hyps.append({
            "detector": "token-behavior",
            "sub_axis": "token_behavior",
            "mechanism": "config-token-accounting-desync",
            "impact": "direct-theft-of-funds",
            "file": file_path,
            "function": name,
            "line": xfer_line,
            "missing_invariant": "+".join(missing),
            "verdict": "needs-fuzz",
            "advisory": True,
            "note": (f"'{name}' does safe/transferFrom on a settings/config token "
                     f"but its invariant is not [{'+'.join(missing)}] -> FOT/"
                     "deflation/decimals accounting-desync candidate (NO-AUTO-CREDIT; "
                     "fuzz to confirm)"),
        })
    return hyps


def _tb_fot_detector_covered(ws: Path) -> set[tuple[str, str]]:
    """DEDUP (A1: consume, do NOT re-derive). Return (file_basename, function)
    pairs the EXISTING FOT/deflation detector family (deflation_attack.py +
    rust_wave1/r94_loop) already flagged, read from where their hits persist in
    the ws (hunt sidecars + mechanism_scan). We NEVER re-run the FOT shape grep to
    re-derive covered_by; a missing store is a graceful empty-set no-op."""
    out: set[tuple[str, str]] = set()
    fot_kw = re.compile(r"fee.?on.?transfer|deflation|balance.?delta|fot|rebasing",
                        re.IGNORECASE)
    for sub in ("hunt_findings_sidecars", "mechanism_scan", "deep-engine-findings"):
        d = ws / ".auditooor" / sub
        if not d.is_dir():
            continue
        for fp in d.glob("*.json"):
            try:
                blob = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not fot_kw.search(blob):
                continue
            try:
                rec = json.loads(blob)
            except (json.JSONDecodeError, ValueError):
                continue
            for anc in _tb_iter_anchors(rec):
                f = anc.get("file") or ""
                fn = anc.get("function") or ""
                if f and fn:
                    out.add((Path(f).name, _tb_first_fn_token(fn)))
    return out


def _tb_iter_anchors(rec: Any):
    """Yield {file,function} anchor dicts anywhere in a sidecar record."""
    if isinstance(rec, dict):
        if "file" in rec and "function" in rec:
            yield rec
        for v in rec.values():
            yield from _tb_iter_anchors(v)
    elif isinstance(rec, list):
        for v in rec:
            yield from _tb_iter_anchors(v)


def _tb_first_fn_token(fn: str) -> str:
    """A sidecar function label may be a prose phrase ('receiveStakeAsset / challenge
    / ...') - take the first identifier so it joins to a scanned fn name."""
    m = re.search(r"[A-Za-z_]\w*", fn or "")
    return m.group(0) if m else ""


def _tb_enabled(force: bool) -> bool:
    return force or os.environ.get(_TB_ENV, "").strip().lower() not in ("", "0", "false", "no")


def emit_token_behavior_hypotheses(
    ws: Path, scan_root: Path | None = None, force: bool = False,
    max_rows: int = 2000) -> dict[str, Any]:
    """Scan in-scope .sol under scan_root (default ws) and write the advisory
    token_behavior hypotheses jsonl. OFF by default (needs AUDITOOOR_TOKEN_BEHAVIOR_HYP
    or force). Rows are deduped vs the FOT/deflation detector family (covered_by) and
    NEVER auto-credit. Returns an accounting dict."""
    out = ws / ".auditooor" / "token_behavior_hypotheses.jsonl"
    if not _tb_enabled(force):
        return {"status": "off-by-default", "rows": 0, "distinct": 0, "path": str(out)}
    root = scan_root or ws
    covered = _tb_fot_detector_covered(ws)
    rows: list[dict[str, Any]] = []
    distinct = 0
    files = sorted(root.rglob("*.sol")) if root.is_dir() else (
        [root] if root.suffix == ".sol" else [])
    for fp in files:
        rel = str(fp)
        if _TB_VENDOR_RE.search(rel):
            continue
        try:
            src = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = scan_token_behavior(src, rel)
        for h in hits:
            key = (Path(h["file"]).name, h["function"])
            h["covered_by"] = "fot-deflation-detector-family" if key in covered else None
            if h["covered_by"] is None:
                distinct += 1
            rows.append(h)
        if len(rows) >= max_rows:
            rows = rows[:max_rows]
            break
    rows.sort(key=lambda r: (r["file"], r["function"], r["line"]))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                   encoding="utf-8")
    return {"status": "ok", "rows": len(rows), "distinct": distinct, "path": str(out)}


# ---------------------------------------------------------------------------
# E10 MECHANISM DETECTOR: proof-leaf-to-message-type binding (advisory emitter)
#
# Materializes the [direct-theft x proof-leaf-type-confusion] cell. A bridge
# Merkle / tx-inclusion proof commits to a LEAF digest. If that leaf preimage
# omits the message-TYPE discriminator (leafType/messageType/kind/claimType/...),
# ONE forged leaf validates under >1 message CLASS - a deposit leaf is accepted
# as an exit/message leaf (and vice-versa), so a single proven inclusion is
# replayed across claim handlers. Per leaf-digest SINK we DATAFLOW-SLICE the
# declared params and ask, per discriminator, whether it REACHES the hashed
# preimage. FAIL-CLOSED: a discriminator that exists (the leaf IS usable under
# >1 class) but does NOT reach the preimage -> one needs-fuzz row.
#
# This is the Hexens Mar-2026 Polygon-bridge 0-day shape (rank-1 P0 recall gap
# at 36%): the leaf builder packs origin/dest/amount but drops the leafType, so
# a message leaf and an asset leaf collide.
#
# ENUMERATION BY DATAFLOW (not hardcoded): a param counts as a leaf-type
# discriminator when EITHER (a) its name matches the type-discriminator CLASS,
# OR (b) DATAFLOW-USAGE shows it is a class SELECTOR (compared against >=1
# constant / enum). Arm (b) is the net-new recall over a fixed field-name
# vocabulary - it catches a discriminator whose name is non-canonical. The
# bound/unbound decision is reachability over THIS function's real params (the
# same backward slice E3 uses), never a free-text grep.
#
# DEDUP BOUNDARY (do NOT re-derive covered_by):
#   * vs E3 digest-domain-binding (cross-chain-domain-not-bound): E3's must-bind
#     set is the DOMAIN/CHAIN/NONCE/SENDER identity. E10 EXCLUDES every param that
#     matches that identity class (_XCH_IDENTITY_RE) - E10 is strictly the TYPE
#     discriminator, disjoint by construction. Each E10 row is checked against a
#     LIVE run of scan_xchain_domain_binding on the same source; overlap (never,
#     given disjoint classes) is tagged covered_by, net-new rows are distinct.
#   * vs A5 encode/decode-seam (tools/cross-module-trust-seam.py): A5 is a
#     serialize/deserialize LAYOUT round-trip (producer *LEN* vs consumer guard).
#     E10 is not a round-trip: it is a MISSING type field inside a single leaf
#     preimage. Different tool, different sink, different failure.
#   * A17 freshness-TOCTOU vs A2/A5 (tools/cross-module-trust-seam.py --mode
#     freshness): A17 is a THIRD, disjoint seam class. A2 = a value validated to
#     a caller-identity/AC INVARIANT but re-check-bypassed (value-integrity); A5 =
#     a serialize/deserialize BYTE-LAYOUT trust; A17 = a value validated FRESH at
#     T1 (a block.timestamp/updatedAt compare) consumed as CURRENT at T2 with no
#     freshness re-check (TIME-decay). A17's producer guard is a FRESHNESS compare,
#     which A2's default caller-identity predicate never matches -> distinct
#     population. Overlap on the SAME consumer sink (file:line) is deduped by the
#     detector's own covered_by_a2 flag (consumer sink vs cross_module_trust_
#     seams.jsonl), so the matrix must not double-count a sink already carried by
#     an A2 trust-seam point.
#
# NO-AUTO-CREDIT: rows are verdict='needs-fuzz', advisory=True. This emitter
# NEVER writes a mechanism_scan clean-sidecar, so it can never auto-close the
# cell. OFF by default behind AUDITOOOR_PROOF_LEAF_TYPE_HYP (or force=).
# ---------------------------------------------------------------------------
_E10_ENV = "AUDITOOOR_PROOF_LEAF_TYPE_HYP"
# Message-TYPE / leaf-CLASS discriminator names. Deliberately EXCLUDES the E3
# identity vocabulary (domain/chain/nonce/sender) - see the dedup boundary above.
_E10_TYPE_RE = re.compile(
    r"(?:leaf|msg|message|claim|deposit|exit|withdraw|op|tx|action|node|record|"
    r"asset|item|entry|event|call)_?type\b|\bleaftype\b|\btype_?(?:id|code|flag)?\b|"
    r"\bkind\b|\bvariant\b|\bdiscriminator\b|\bclass_?(?:id)?\b",
    re.IGNORECASE)
# Function-NAME leaf/proof context (gates generic EIP712/commitment hashing out).
_E10_LEAF_CTX_RE = re.compile(
    r"leaf|proof|inclusion|merkle|\bclaim\b|deposit|exit|withdraw|\bbridge\b|"
    r"\bmessage\b|globalindex|globalexit",
    re.IGNORECASE)


def _e10_selector_usage(param: str, body: str) -> bool:
    """DATAFLOW-USAGE arm: is `param` used as a CLASS SELECTOR - compared against
    a constant literal or enum symbol (== 1, != 0, > 0x2, TYPE_MESSAGE)? This is
    the usage-based enumeration that catches a discriminator with a non-canonical
    name (recall beyond the fixed vocabulary). Constant = decimal / hex / an
    UPPER_CASE enum symbol."""
    pe = re.escape(param)
    const = r"(?:0x[0-9a-fA-F]+|\d+|[A-Z_][A-Z0-9_]{2,})"
    if re.search(r"\b" + pe + r"\s*(?:==|!=|>=|<=|>|<)\s*" + const, body):
        return True
    if re.search(const + r"\s*(?:==|!=)\s*\b" + pe + r"\b", body):
        return True
    # switch/match-style selection: `switch (param)` / `case param`.
    if re.search(r"\bswitch\s*\(\s*" + pe + r"\b", body):
        return True
    return False


def scan_proof_leaf_type_binding(source: str, file_path: str = "<memory>") -> list[dict[str, Any]]:
    """Return one hypothesis dict per UNBOUND message-type discriminator of a
    proof-leaf digest function. Pure/read-only; no I/O. See module block above."""
    code = _xch_strip(source or "")
    hyps: list[dict[str, Any]] = []
    for name, header, body, fn_line, brace in _xch_functions(code):
        params = _xch_params(header)
        if not params:
            continue
        pre = _xch_preimage(body)
        if pre is None:
            continue  # no leaf digest sink here -> not a leaf builder (control)
        preimage, sink_off = pre
        name_ctx = bool(_E10_LEAF_CTX_RE.search(name))
        # Enumerate discriminator params (dataflow-usage OR semantic class),
        # EXCLUDING E3 domain/identity fields (the dedup boundary).
        discs: list[tuple[str, bool, bool]] = []
        for p in params:
            if _XCH_IDENTITY_RE.search(p):
                continue  # domain/chain/nonce/sender = E3 cell, not E10
            by_name = bool(_E10_TYPE_RE.search(p))
            by_use = _e10_selector_usage(p, body)
            if by_name or by_use:
                discs.append((p, by_name, by_use))
        if not discs:
            continue  # leaf carries no type discriminator to bind (nothing to fire on)
        # ANCHOR: a genuine leaf/proof digest context (fn name) OR a usage-confirmed
        # class selector. Gates generic EIP712 struct-hashing that happens to carry
        # a param named 'kind' but is not a proof leaf.
        if not (name_ctx or any(u for _, _, u in discs)):
            continue
        reach = _xch_reachable_tokens(preimage, body)
        sink_line = code.count("\n", 0, brace + sink_off) + 1
        for p, by_name, by_use in discs:
            # REACHABILITY: the discriminator is BOUND iff it (or a struct-field
            # access `p.`) reaches the hashed preimage, directly OR transitively
            # through a local. Complete-binding is the clean control.
            bound = p in reach or re.search(
                r"\b" + re.escape(p) + r"\s*\.", preimage) is not None
            if bound:
                continue
            enum_by = "+".join(
                x for x, on in (("name", by_name), ("usage", by_use)) if on)
            hyps.append({
                "detector": "proof-leaf-type-binding",
                "mechanism": "proof-leaf-type-not-bound",
                "impact": "direct-theft-of-funds",
                "file": file_path,
                "function": name,
                "line": sink_line,
                "unbound_discriminator": p,
                "enumerated_by": enum_by,
                "verdict": "needs-fuzz",
                "advisory": True,
                "note": (f"discriminator '{p}' declared but not reachable into the "
                         f"leaf preimage of '{name}' -> one forged proof validates "
                         "under >1 message class (deposit vs exit); NO-AUTO-CREDIT, "
                         "fuzz to confirm cross-class collision"),
            })
    return hyps


def _e10_xchain_covered_pairs(source: str) -> set[tuple[str, str]]:
    """DEDUP (A1: consume, do NOT re-derive). Run the LIVE E3 domain-binding
    scanner on the same source and return the (function, unbound_field) pairs it
    already flags, so an E10 row that overlaps can be tagged covered_by without
    re-implementing E3's signal. By construction the field CLASSES are disjoint,
    so this is expected to be empty (proving E10 is net-new)."""
    try:
        return {(h["function"], h["unbound_field"])
                for h in scan_xchain_domain_binding(source)}
    except Exception:  # noqa: BLE001
        return set()


def _e10_enabled(force: bool) -> bool:
    return force or os.environ.get(_E10_ENV, "").strip().lower() not in ("", "0", "false", "no")


def emit_proof_leaf_type_hypotheses(
    ws: Path, scan_root: Path | None = None, force: bool = False,
    max_rows: int = 2000) -> dict[str, Any]:
    """Scan in-scope .sol under scan_root (default ws) and write the advisory
    proof-leaf-type hypotheses jsonl. OFF by default (needs
    AUDITOOOR_PROOF_LEAF_TYPE_HYP or force). Rows are deduped vs E3
    (covered_by) and NEVER auto-credit. Returns an accounting dict."""
    out = ws / ".auditooor" / "proof_leaf_type_hypotheses.jsonl"
    if not _e10_enabled(force):
        return {"status": "off-by-default", "rows": 0, "distinct": 0, "path": str(out)}
    root = scan_root or ws
    rows: list[dict[str, Any]] = []
    distinct = 0
    files = sorted(root.rglob("*.sol")) if root.is_dir() else (
        [root] if root.suffix == ".sol" else [])
    for fp in files:
        rel = str(fp)
        if _TB_VENDOR_RE.search(rel):
            continue
        try:
            src = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = scan_proof_leaf_type_binding(src, rel)
        if not hits:
            continue
        covered = _e10_xchain_covered_pairs(src)
        for h in hits:
            h["covered_by"] = ("xchain-domain-binding"
                               if (h["function"], h["unbound_discriminator"]) in covered
                               else None)
            if h["covered_by"] is None:
                distinct += 1
            rows.append(h)
        if len(rows) >= max_rows:
            rows = rows[:max_rows]
            break
    rows.sort(key=lambda r: (r["file"], r["function"], r["unbound_discriminator"]))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                   encoding="utf-8")
    return {"status": "ok", "rows": len(rows), "distinct": distinct, "path": str(out)}


# ---------------------------------------------------------------------------
# COMPILER-FEATURE AXIS (advisory sub-axis, NET-NEW, NO-AUTO-CREDIT)
#
# Materializes the (file x pinned_version x compiler-feature) coverage plane from the
# E2/E2b screen (.auditooor/compiler_feature_screen.json). Per screened row it emits ONE
# cell with a status: FLAG (pinned version sits in a known-miscompilation window), CLEAR
# (feature used but version outside every window), or UNSCREENED (no windowed advisory for
# the feature - a blind spot). A FLAG / UNSCREENED cell yields a needs-fuzz row (advisory
# hunt fuel); a CLEAR cell is report-only. This axis is REPORT-ONLY: it NEVER flips the
# matrix verdict and writes NO clean-sidecar, so it can never auto-close a cell. OFF by
# default behind AUDITOOOR_COMPLETENESS_COMPILER_FEATURE_AXIS (or force=). The GATE half
# lives in audit-completeness-check.check_compiler_feature_screen (fails-closed on a
# gate-eligible transient FLAG under L37) - this axis is only the matrix-visibility layer,
# so the two never double-count.
# ---------------------------------------------------------------------------
_CFEAT_AXIS_ENV = "AUDITOOOR_COMPLETENESS_COMPILER_FEATURE_AXIS"


def _cfeat_axis_enabled(force: bool) -> bool:
    return force or os.environ.get(_CFEAT_AXIS_ENV, "").strip().lower() not in (
        "", "0", "false", "no")


def emit_compiler_feature_axis(ws: Path, force: bool = False,
                               max_rows: int = 2000) -> dict[str, Any]:
    """Read .auditooor/compiler_feature_screen.json and emit the advisory
    (file x pinned_version x compiler-feature) coverage cells + needs-fuzz rows.
    OFF by default (AUDITOOOR_COMPLETENESS_COMPILER_FEATURE_AXIS or force). NEVER flips
    the matrix verdict, NEVER auto-credits. Returns an accounting dict."""
    out = ws / ".auditooor" / "compiler_feature_axis.jsonl"
    screen = ws / ".auditooor" / "compiler_feature_screen.json"
    if not _cfeat_axis_enabled(force):
        return {"status": "off-by-default", "cells": 0, "needs_fuzz": 0, "path": str(out)}
    try:
        doc = json.loads(screen.read_text(encoding="utf-8")) if screen.is_file() else {}
    except (OSError, ValueError):
        doc = {}
    rows_in = doc.get("rows") if isinstance(doc, dict) else []
    rows_in = rows_in if isinstance(rows_in, list) else []
    cells: list[dict[str, Any]] = []
    needs_fuzz = 0
    for r in rows_in:
        if not isinstance(r, dict):
            continue
        verdict = str(r.get("verdict") or "")
        status = verdict if verdict in ("FLAG", "CLEAR", "UNSCREENED") else "UNSCREENED"
        needs = status in ("FLAG", "UNSCREENED")
        if needs:
            needs_fuzz += 1
        cells.append({
            "sub_axis": "compiler_feature",
            "file": r.get("file"),
            "pinned_version": r.get("pinned_version"),
            "feature": r.get("feature"),
            "status": status,
            "gate_eligible": bool(r.get("gate_eligible")),
            "matched_advisory_uid": r.get("matched_advisory_uid"),
            # NO-AUTO-CREDIT: a needs-fuzz cell is an OPEN obligation, not a covered cell.
            "verdict": "needs-fuzz" if needs else "clear",
            "advisory": True,
        })
        if len(cells) >= max_rows:
            break
    cells.sort(key=lambda c: (str(c.get("file")), str(c.get("feature")),
                              str(c.get("pinned_version"))))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(c, sort_keys=True) + "\n" for c in cells),
                   encoding="utf-8")
    return {"status": "ok" if screen.is_file() else "no-screen-artifact",
            "cells": len(cells), "needs_fuzz": needs_fuzz,
            "flag": sum(1 for c in cells if c["status"] == "FLAG"),
            "unscreened": sum(1 for c in cells if c["status"] == "UNSCREENED"),
            "path": str(out)}


def _build_assets_axis(
    ws: Path,
    inscope: dict[str, list[dict[str, Any]]],
    dossiers: list[tuple[str, str]],
    mvc_cats_by_asset: dict[str, set],
    fn_cov: dict[str, str],
    fcc_terminal: bool,
    hunt_examined: set,
    hunt_frames: dict[str, set],
    per_frame_active: bool,
    dispatched_frames: dict[str, set],
    mech_lib: dict[str, list[dict[str, Any]]],
    strict: bool,
    mvc_covered_fns: set | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, int]]:
    """Build the per-asset (invariant + function) axis for a given asset grouping.

    Shared by the primary matrix (grouping = per-file under strict, else per-repo)
    and the ALWAYS-emitted per-file breakdown. `strict` toggles whether comprehension
    prose terminally enumerates a category (see _asset_invariant_enumeration). An
    asset that has ZERO terminally-enumerated categories fails the invariant floor;
    a category left only 'enumerated-comprehension-only' is NON-TERMINAL (visible but
    not counted as satisfied) under strict."""
    mvc_covered_fns = mvc_covered_fns or set()
    terminal_refuted_fns = _hunt_terminal_refuted_fns(ws)
    assets_out: list[dict[str, Any]] = []
    not_enum_assets: list[dict[str, str]] = []
    cells_total = cells_terminal = cells_open = cells_not_enum = 0
    # PER-UNIT NON-ECONOMIC DISPOSITION credit (over-strictness fix): the SAME
    # source-of-truth artifact + never-false-pass guards the invariant-fuzz /
    # cross-function / honesty gates already honor. A privileged-only / OOS in-scope
    # FILE (an onlyOwner clone factory, a config registry, an OOS view-oracle) has no
    # unprivileged fund/share conservation invariant to fuzz, so an economic harness
    # is the wrong terminal bar for it. When EVERY in-scope function of a file maps to
    # an ACCEPTED disposition (bounded classification + >=40-char rationale + on-disk +
    # NOT a transfer-hit value-mover), the file is credited terminal instead of pinned
    # NOT-ENUMERATED. Only active under strict (the per-file floor) AND only when the
    # ws ships the artifact - so the default posture / a ws without the file behaves
    # byte-identically (backward-compat). NEVER-FALSE-PASS: the shared lib REJECTS any
    # file that actually moves funds (transfer_hit), so custody can never be silenced.
    _dispositions: list[dict[str, Any]] = []
    if strict and _NED_MOD is not None:
        try:
            _dispositions = _NED_MOD.load_dispositions(ws)
        except Exception:  # noqa: BLE001
            _dispositions = []
    # INFRA-FILE value-signal set (axelar-dlt 2026-07-13): the authoritative
    # value-moving file set + artifact-present flag. A per-file asset whose every
    # file carries NO value-moving signal (no transfer_hit / ledger_write_hit and no
    # source value-token) is pure infra (logger, ante/log, non-value util) with no
    # fund/share-conservation invariant to enumerate, so it is dropped from the
    # per-file floor - the same treatment an all-non-entry / fully-dispositioned file
    # gets. Strict-only + artifact-gated (fail-closed when the producer has not run).
    _vm_files, _vm_present = _value_moving_files(ws)
    for asset_id in sorted(inscope):
        inv = _asset_invariant_enumeration(
            asset_id, dossiers, mvc_cats_by_asset.get(asset_id), strict=strict)
        enum_cats = [c for c, v in inv.items() if v["status"] == "enumerated"]
        comp_only_cats = [c for c, v in inv.items() if v["status"] == "enumerated-comprehension-only"]
        unenum_cats = [c for c, v in inv.items() if v["status"] == "not-enumerated"]
        fns_out = []
        # PER-UNIT NON-ECONOMIC DISPOSITION (over-strictness fix): is EVERY in-scope
        # file grouped under this asset covered by an accepted disposition? Under the
        # per-file grouping asset_id IS a single file path; under per-repo it collapses
        # many files, so require ALL of them dispositioned (never-false-pass: one
        # non-dispositioned file keeps the asset an obligation). A dispositioned file's
        # not-enumerated function cells become terminal (non-economic-surface-
        # dispositioned) - the SAME credit the sibling gates apply.
        _asset_files = sorted({str(u["file"]) for u in inscope[asset_id]})
        file_dispositioned = bool(_dispositions) and _NED_MOD is not None and all(
            _NED_MOD.file_is_dispositioned(f, _dispositions) is not None
            for f in _asset_files)
        # NON-ENTRY-FILE gate (never-false-pass): a file is an invariant-floor obligation
        # ONLY when it exposes >=1 real value-moving attack-surface function. We compute
        # per-function whether EVERY in-scope function is fcc-classified non-attack-surface
        # (internal/view/library/interface/boilerplate/sim) or the file has no callable
        # value-moving function at all; if so, the file has no invariant to enumerate and
        # is dropped from the per-file floor (it never counted a value-mover). A file with
        # >=1 genuine entry function stays subject to the floor (fail-closed).
        all_nonentry = True
        for u in inscope[asset_id]:
            key = f"{Path(u['file']).name}::{u['function']}"
            status = fn_cov.get(key)
            if status is None:
                fn_name = str(u["function"] or "").strip()
                if not fn_name:
                    status = "no-callable-function"
                elif fcc_terminal and _is_fcc_filtered_nonentry(ws, u["file"], u["function"]):
                    # PRECEDENCE FIX (Strata 2026-07-07): a NON-ENTRY fn (view / pure /
                    # internal - the Solidity-`internal` analog, covered transitively)
                    # is exempt from per-fn invariant enumeration and must be checked
                    # BEFORE the per-frame branch. The old order let the per-frame branch
                    # catch a hunted view/internal fn first and pin it NOT-ENUMERATED
                    # (unsatisfiable false-red - a getter never needs an invariant set),
                    # never reaching this exemption. 66 Strata cells were false-red here.
                    status = "out-of-scope-fcc-filtered"
                elif fn_name in mvc_covered_fns:
                    # A value-moving fn with a MUTATION-VERIFIED mvc_sidecar for its exact
                    # name is really covered; the per-frame branch never consulted mvc, so
                    # 26 mvc-covered Strata value-movers pinned NOT-ENUMERATED with the
                    # evidence on disk. Never-false: _mvc_covered_functions credits only a
                    # mutation-verified / non-vacuous-kill sidecar.
                    status = "covered-mvc-mutation-verified"
                elif fn_name in terminal_refuted_fns:
                    # A whole-function source-cited terminal REFUTED verdict (KILL /
                    # applies_to_target=no, R76) credits the fn regardless of per-frame
                    # membership - it examined the fn holistically across every impact
                    # class. Checked BEFORE the per-frame branch so a fn that is NOT in
                    # hunt_frames (its only verdict is the whole-fn drill, e.g. a lens
                    # fn whose sidecar the bridge did not copy) is still credited.
                    status = "covered-hunt-verdict-terminal"
                elif per_frame_active and fn_name in hunt_frames:
                    # REQUIRED frames come ONLY from what the per-fn seed actually
                    # DISPATCHED for this fn (dispatched_frames), so the required and
                    # examined vocabularies agree by construction. The old code fell
                    # back to _inscope_impact_frames_for_lang (the mechanism-library
                    # vocabulary: direct-theft / permanent-freeze / ...) whenever
                    # dispatched_frames could not be derived - but the seed / sidecar
                    # vocabulary is question_class-based (generic / rubric-targeted /
                    # sum-preserved / ...), so the two sets NEVER intersect and EVERY
                    # per-frame-hunted value-moving fn was permanently NOT-ENUMERATED
                    # (an unsatisfiable false-red; NUVA 2026-07-03: 53 fns). When the
                    # required set is empty (seed unreadable / this fn not in the seed),
                    # the fn has hunt-verdict sidecars and is credited - we do NOT
                    # invent a requirement in a vocabulary the hunt never uses.
                    _required = dispatched_frames.get(fn_name, set())
                    _examined = hunt_frames.get(fn_name, set())
                    _missing = sorted(_required - _examined) if _required else []
                    if not _missing:
                        status = "covered-hunt-verdict-all-frames"
                    elif fn_name in terminal_refuted_fns:
                        # A WHOLE-FUNCTION source-cited terminal REFUTED verdict (KILL /
                        # applies_to_target=no, R76) subsumes the per-frame requirement:
                        # the fn was examined holistically across every impact class, so
                        # a dispatched frame lacking its own __I-<impact> partial sidecar
                        # is not a real gap. Defers to the whole-fn verdict exactly as the
                        # hunt_examined branch below does. Never-false: requires a real
                        # non-frame-suffixed refuted sidecar with a file:line cite.
                        status = "covered-hunt-verdict-terminal"
                    else:
                        status = "not-enumerated"
                elif fn_name in hunt_examined:
                    status = "covered-hunt-verdict"
                elif fcc_terminal and _is_fcc_filtered_nonentry(ws, u["file"], u["function"]):
                    status = "out-of-scope-fcc-filtered"
                else:
                    status = "not-enumerated"
            # A per-unit non-economic disposition credits an otherwise NOT-ENUMERATED
            # cell as terminal (same label the invariant-fuzz / cross-function / honesty
            # gates use). Only relabels a not-enumerated cell (never downgrades a real
            # covered/open verdict) and only when the whole file is dispositioned.
            if status == "not-enumerated" and file_dispositioned:
                status = _NED_MOD.CREDIT_LABEL  # "non-economic-surface-dispositioned"
            fns_out.append({"function": u["function"], "file": u["file"], "coverage_status": status})
            # A function is non-attack-surface for the invariant-floor drop when it is an
            # empty-fn library-body row (no callable function) OR fcc's scope filter would
            # drop it (internal/view/interface/library/boilerplate/Go-Cosmos non-entry).
            # Independent of the coverage_status above (a hunt-verdict on an interface
            # signature does NOT make it a value-moving entry). Fail-closed: if we cannot
            # confirm non-entry, the file stays an obligation.
            _fnn = str(u["function"] or "").strip()
            _nonentry_fn = (not _fnn) or _is_fcc_filtered_nonentry(ws, u["file"], u["function"])
            if not _nonentry_fn:
                all_nonentry = False
            cells_total += 1
            if status == "not-enumerated":
                cells_not_enum += 1
            elif status == "open":
                cells_open += 1
            else:
                cells_terminal += 1
        # Invariant-floor obligation ONLY for files with a real value-moving surface AND
        # no terminally-enumerated category. A file whose every function is non-entry has
        # no invariant to enumerate (boilerplate / interface / pure lib / sim) -> dropped.
        # The non-entry DROP is applied only under strict (the per-file floor); default
        # posture keeps the legacy behavior byte-identical (a file with 0 categories is
        # still listed) so a workspace certified before this fix is not re-scored.
        # A fully-dispositioned file (privileged-only / OOS, documented + guard-checked)
        # has NO fund/share conservation invariant to enumerate, so an economic harness
        # is the wrong bar - drop it from the invariant floor the same way an all-non-
        # entry file is dropped. Strict-only + artifact-gated (see _dispositions).
        # PURE-INFRA (no value signal) drop: the asset's files carry NO transfer_hit /
        # ledger_write_hit and no source value-token, so there is no fund/share
        # conservation invariant to enumerate (logger / ante/log / non-value util).
        # Artifact-gated (fail-closed when the producer has not run) and never drops a
        # file with any value signal.
        _no_value_signal = (
            strict and _vm_present
            and bool(_asset_files)
            and not any(_file_has_value_signal(ws, f, _vm_files) for f in _asset_files)
        )
        _drop_nonentry_file = strict and (all_nonentry or file_dispositioned or _no_value_signal)
        if not enum_cats and not _drop_nonentry_file:
            _reason = "no invariant enumeration: 0/10 categories"
            if comp_only_cats:
                _reason = (f"no HARNESS-backed invariant: {len(comp_only_cats)}/10 "
                           "categories comprehension-only (prose, no run+mutation-verified "
                           "campaign), 0/10 terminally enumerated")
            not_enum_assets.append({"asset_id": asset_id, "reason": _reason})
        _asset_row = {
            "asset_id": asset_id,
            "invariant_enumeration": inv,
            "invariant_categories_enumerated": len(enum_cats),
            "invariant_categories_comprehension_only": comp_only_cats,
            "invariant_categories_not_enumerated": unenum_cats,
            # F1 (invariant-axis nonentry parity, 2026-07-03): expose the authoritative
            # per-file all_nonentry / file_dispositioned signals so build_enumeration_worklist
            # can tag this asset's INVARIANT-axis rows dropped_nonentry, EXACTLY as the
            # FUNCTION axis already does via _worklist_function_cell_kind. Without this, an
            # interface (IFullERC20) / vendored-crypto / cosmos-boilerplate (genesis/codec/
            # errors/events/keys) file with 0 enumerated categories emitted 10 value_moving
            # invariant rows and inflated the F1 uncovered-cell floor with files that have NO
            # value-moving surface to carry an invariant (NUVA 2026-07-03: ~220 of 467 cells
            # came from all-nonentry files). all_nonentry is True only when EVERY in-scope fn
            # is fcc-classified non-entry (handles Solidity + Go-Cosmos).
            # FAIL-CLOSED GUARD (has_real_function): all_nonentry is ALSO True when the file's
            # only in-scope "unit" is an empty-name no-callable-function PLACEHOLDER (a function-
            # ENUMERATION FAILURE - e.g. the Go/Cosmos decomposer emitting one function='' row
            # per .go file; NUVA 2026-07-03: every src/vault/*.go value-mover surfaces this way).
            # Demoting on that placeholder would GREEN-WASH a genuine Go value-mover (reconcile.go
            # ::CalculateAccruedAUMFee / valuation_engine.go::GetNAVPerShareInUnderlyingAsset). So
            # the worklist tagger demotes on all_nonentry ONLY when has_real_function is True (>=1
            # real, non-empty function name enumerated AND all fcc-nonentry = a genuine interface/
            # lib/boilerplate). A file whose non-entry rests solely on the empty placeholder stays
            # value_moving (fail-closed) until the upstream Go-enumeration bug is fixed.
            "all_nonentry": all_nonentry,
            "has_real_function": any(str(f.get("function") or "").strip() for f in fns_out),
            "file_dispositioned": bool(file_dispositioned),
            "function_count": len(fns_out),
            "functions": fns_out,
        }
        if file_dispositioned:
            _disp = _NED_MOD.file_is_dispositioned(_asset_files[0], _dispositions) or {}
            _asset_row["non_economic_disposition"] = {
                "credited": True,
                "classification": _disp.get("classification", ""),
                "rationale": _disp.get("rationale", ""),
            }
        assets_out.append(_asset_row)
    counts = {"total": cells_total, "terminal": cells_terminal,
              "open": cells_open, "not_enumerated": cells_not_enum}
    return assets_out, not_enum_assets, counts


def build_matrix(ws: Path) -> dict[str, Any]:
    strict = _perfile_strict()
    inscope_repo = _load_inscope(ws)
    inscope_file = _load_inscope_perfile(ws)
    dossiers = _load_comprehension(ws)
    impact = _load_impact_enumeration(ws)
    fn_cov, fcc_terminal = _load_function_coverage(ws)
    flow_cov = _load_flow_coverage(ws)
    mvc_cats_repo = _mvc_asset_invariant_categories(ws)
    # The per-FILE mvc join credits an empty-invariants-but-killed harness (the Go Cosmos
    # economic harnesses) ONLY under strict; default posture stays byte-identical to the
    # legacy per-repo crediting (backward-compat, no retroactive re-credit).
    mvc_cats_file = _mvc_asset_invariant_categories(
        ws, asset_key=_perfile_asset_of, credit_empty_invariants=strict)
    # A real fuzz_campaign_receipt over a file is run+campaign-backed evidence (like
    # a mutation-verified mvc harness) - credit at least the conservation/economic
    # category for that file so a genuinely-campaigned file is not comprehension-only.
    for pf in _fuzz_campaign_receipt_files(ws):
        mvc_cats_file.setdefault(pf, set()).add("conservation")
    # STRICT primary grouping = per-FILE (denominators.assets == distinct in-scope
    # files); default keeps the legacy per-repo grouping (backward-compat) but ALSO
    # emits the per-file breakdown below so the collapsed-asset gap is visible.
    inscope = inscope_file if strict else inscope_repo
    mvc_cats_by_asset = mvc_cats_file if strict else mvc_cats_repo
    # TRANSITIVE per-asset credit (Strata 2026-07-07): a value-moving file `new`-deployed +
    # driven by a mutation-verified harness inherits that harness's invariant categories, so
    # an impl covered ONLY via its strategy's conservation harness is not read as 0/10.
    _asset_key = _perfile_asset_of if strict else _asset_of
    for _aid, _cats in _transitive_asset_categories(ws, _asset_key).items():
        mvc_cats_by_asset.setdefault(_aid, set()).update(_cats)
    hunt_examined = _hunt_examined_keys(ws)
    mvc_covered_fns = _mvc_covered_functions(ws)  # per-fn mutation-verified coverage
    # (unit x IMPACT-FRAME) crediting (brick 3): bare-fn -> impacts with a per-frame
    # verdict sidecar (`__I-<impact>` suffix). per_frame_active is True ONLY when at
    # least one per-frame sidecar exists in this ws - so a ws with only legacy
    # (frame-less) sidecars credits EXACTLY as before (backward-compat, no false-red).
    hunt_frames = _hunt_examined_frames(ws)
    per_frame_active = bool(hunt_frames)
    mech_lib = _load_mechanism_library(ws) if per_frame_active else {}
    # AUTHORITATIVE required-frames-per-fn: the frames the per-fn seed actually
    # DISPATCHED (same vocabulary brick 1 writes into the sidecar suffix), NOT the
    # mechanism-library frame set (whose vocabulary never matched the seed's).
    dispatched_frames = _dispatched_frames_by_fn(ws) if per_frame_active else {}

    assets_out, not_enum_assets, _counts = _build_assets_axis(
        ws, inscope, dossiers, mvc_cats_by_asset, fn_cov, fcc_terminal,
        hunt_examined, hunt_frames, per_frame_active, dispatched_frames, mech_lib, strict,
        mvc_covered_fns=mvc_covered_fns)
    cells_total = _counts["total"]
    cells_terminal = _counts["terminal"]
    cells_open = _counts["open"]
    cells_not_enum = _counts["not_enumerated"]

    # ALWAYS-EMITTED per-FILE breakdown (backward-compat visibility): even in the
    # legacy default posture (per-repo primary grouping), compute the per-FILE axis so
    # the collapsed-asset gap (which individual files lack a harness-backed economic
    # invariant) is VISIBLE without changing the primary verdict. Under strict this is
    # the same data as the primary axis; carried separately so downstream readers can
    # always inspect the real file-level denominator regardless of posture.
    perfile_assets, perfile_not_enum, perfile_counts = _build_assets_axis(
        ws, inscope_file, dossiers, mvc_cats_file, fn_cov, fcc_terminal,
        hunt_examined, hunt_frames, per_frame_active, dispatched_frames, mech_lib, strict,
        mvc_covered_fns=mvc_covered_fns)
    perfile_breakdown = {
        "asset_key": "per-file",
        "denominator_assets": len(inscope_file),
        "assets": perfile_assets,
        "not_enumerated_assets": perfile_not_enum,
        "cells": perfile_counts,
        "strict_active": strict,
    }

    # impact axis
    impact_classes = impact["classes"]
    impact_not_enum = [k for k, v in impact_classes.items() if v in ("", "not-enumerated", "blank")]
    impact_missing = not impact["present"] or not impact_classes

    verdict = "complete"
    reasons: list[str] = []
    if not inscope:
        verdict = "incomplete"
        reasons.append("no inscope_units.jsonl (function/asset denominator missing)")
    if not_enum_assets:
        verdict = "incomplete"
        reasons.append(f"{len(not_enum_assets)} in-scope asset(s) with NO enumerated invariant set")
    if impact_missing:
        verdict = "incomplete"
        reasons.append("impact-class enumeration absent/blank (exploit_class_coverage.json)")
    elif impact_not_enum:
        verdict = "incomplete"
        reasons.append(f"{len(impact_not_enum)} impact class(es) NOT-ENUMERATED")
    if cells_not_enum:
        verdict = "incomplete"
        reasons.append(f"{cells_not_enum} function cell(s) NOT-ENUMERATED")
    # business-flow (cross-module combination) axis: a DRIVABLE flow that no
    # hunt/harness touched is an un-enumerated cross-module obligation - the
    # per-function axis alone misses it (strata insolvency loss-transition).
    if flow_cov.get("undriven_count"):
        verdict = "incomplete"
        reasons.append(f"{flow_cov['undriven_count']} business-flow(s) UNDRIVEN "
                       "(cross-module flow no hunt/harness touched)")

    # PER-FILE VISIBILITY (advisory in the default posture): when the primary grouping
    # is per-repo but the per-file breakdown shows individual files with NO
    # harness-backed invariant, surface it as a loud WARN so the collapsed-asset gap is
    # not hidden. Does NOT flip the verdict in default posture (backward-compat); under
    # strict the primary axis IS per-file so the not-enum-assets check above already
    # fails-closed. Never brings the count below the primary count under strict.
    if not strict and perfile_breakdown["not_enumerated_assets"]:
        reasons.append(
            f"WARN: per-file breakdown shows {len(perfile_breakdown['not_enumerated_assets'])} "
            f"in-scope FILE(s) with NO harness-backed invariant set (collapsed into "
            f"{len(inscope_repo)} per-repo asset(s)); set AUDITOOOR_MATRIX_PERFILE_STRICT=1 "
            "to enforce the per-file floor")

    # MECHANISM AXIS (v2): the impact x mechanism completeness plane. Flips the
    # verdict only under enforcement (loud WARN + worklist otherwise) so it never
    # retroactively bricks a pre-v2 workspace but fails-closed under STRICT/--check.
    mech_axis = _build_mechanism_axis(ws, inscope, set(impact_classes))
    # ADVISORY mechanism detector for the cross-chain-domain-not-bound cell. OFF by
    # default (AUDITOOOR_XCHAIN_DOMAIN_BIND_HYP); emits needs-fuzz hypotheses only,
    # NO-AUTO-CREDIT, so it never flips a verdict or closes the mechanism cell.
    try:
        emit_xchain_domain_binding_hypotheses(ws)
    except Exception:  # noqa: BLE001
        pass
    # ADVISORY 11th sub-axis token_behavior. OFF by default
    # (AUDITOOOR_TOKEN_BEHAVIOR_HYP); needs-fuzz rows only, NO-AUTO-CREDIT, deduped
    # vs the FOT/deflation detector family (covered_by), never flips a verdict.
    try:
        emit_token_behavior_hypotheses(ws)
    except Exception:  # noqa: BLE001
        pass
    # E10 ADVISORY: proof-leaf-to-message-type binding. OFF by default
    # (AUDITOOOR_PROOF_LEAF_TYPE_HYP); needs-fuzz rows only, NO-AUTO-CREDIT, deduped
    # vs E3 domain-binding (covered_by), never flips a verdict or closes the cell.
    try:
        emit_proof_leaf_type_hypotheses(ws)
    except Exception:  # noqa: BLE001
        pass
    # E2b ADVISORY compiler-feature sub-axis (NET-NEW). OFF by default
    # (AUDITOOOR_COMPLETENESS_COMPILER_FEATURE_AXIS); reads
    # .auditooor/compiler_feature_screen.json and enumerates (file x pinned_version x
    # feature) cells with needs-fuzz rows. REPORT-ONLY: NO-AUTO-CREDIT, NEVER flips the
    # matrix verdict (the fail-closed gate is in
    # audit-completeness-check.check_compiler_feature_screen).
    _cfeat_axis: dict[str, Any] = {"status": "off-by-default", "cells": 0, "needs_fuzz": 0}
    try:
        _cfeat_axis = emit_compiler_feature_axis(ws)
    except Exception:  # noqa: BLE001
        pass
    # OPEN findings (a detector fired, un-dispositioned) block under STRICT - the
    # surgical false-green closure. UNSCANNED cells (no detector yet) only WARN
    # unless the dedicated full-plane enforcement is opted in.
    if mech_axis["not_enumerated_open"] and mech_axis["open_findings_enforced"]:
        verdict = "incomplete"
        reasons.append(
            f"{mech_axis['not_enumerated_open']} impact x mechanism cell(s) with an OPEN "
            "un-dispositioned finding (verify -> paste-ready OR refute -> "
            "mechanism_dispositions.jsonl)")
    elif mech_axis["not_enumerated_unscanned"] and mech_axis["unscanned_enforced"]:
        verdict = "incomplete"
        reasons.append(
            f"{mech_axis['not_enumerated_unscanned']} impact x mechanism cell(s) NOT-ENUMERATED "
            "(no mechanism detector ran; full-plane enforcement is on)")
    elif mech_axis["not_enumerated"]:
        _op = mech_axis["not_enumerated_open"]
        reasons.append(
            f"WARN: {mech_axis['not_enumerated']} impact x mechanism cell(s) NOT-ENUMERATED"
            + (f" ({_op} with an OPEN finding - triage them)" if _op else
               " (mechanism axis advisory; run detectors / AUDITOOOR_MECHANISM_AXIS_ENFORCE=1)"))

    m: dict[str, Any] = {
        "schema": SCHEMA,
        "ws": str(ws),
        "denominators": {
            # STRICT: the asset denominator is the distinct in-scope FILE set (so it
            # reflects the real file count, e.g. 19, not 1 collapsed src/contracts).
            # Default keeps the legacy per-repo count for backward-compat, but the
            # true per-file count is always exposed as assets_perfile.
            "assets": len(inscope),
            "assets_perfile": len(inscope_file),
            "asset_grouping": "per-file" if strict else "per-repo",
            "functions": sum(len(v) for v in inscope.values()),
            "invariant_categories": len(CANONICAL_INVARIANT_CATEGORIES),
            "impact_classes": len(impact_classes),
            "mechanism_cells": mech_axis["total"],
        },
        "assets": assets_out,
        "perfile_breakdown": perfile_breakdown,
        "perfile_strict": strict,
        "impact_enumeration": {"present": impact["present"], "classes": impact_classes,
                               "not_enumerated": impact_not_enum, "missing": impact_missing},
        "cells": {"total": cells_total, "terminal": cells_terminal,
                  "open": cells_open, "not_enumerated": cells_not_enum},
        "flows": flow_cov,
        "mechanism_axis": mech_axis,
        # E2b advisory compiler-feature sub-axis (report-only; NEVER flips the verdict).
        "compiler_feature_axis": _cfeat_axis,
        "not_enumerated_assets": not_enum_assets,
        "verdict": verdict,
        "reasons": reasons,
    }
    # G-6: PROTOCOL-FAMILY invariant DENOMINATOR (advisory-first). The 10 CANONICAL
    # categories above are the GENERIC denominator; a bridge/CDP/AMM has a curated
    # family invariant set whose categories must ALSO be enumerated, else "all
    # invariants held" is vacuous over an incomplete set (the biggest false-negative
    # surface). We surface the family-required categories that NO in-scope asset
    # enumerated; the gap folds into the verdict ONLY under
    # AUDITOOOR_MATRIX_FAMILY_INVARIANTS_STRICT (default OFF - never retroactively reds).
    try:
        _fams = _detect_protocol_families(ws)
        _fam_req = _family_required_categories(_fams)
        _fam_req_union: set = set()
        for _c in _fam_req.values():
            _fam_req_union |= _c
        # categories enumerated by at least one in-scope asset (reuse the axis output)
        _enum_union: set = set()
        for _a in assets_out:
            _neu = set(_a.get("invariant_categories_not_enumerated") or [])
            _comp = set(_a.get("invariant_categories_comprehension_only") or [])
            _enum_union |= (set(CANONICAL_INVARIANT_CATEGORIES) - _neu - _comp)
        # SERVING-JOIN FIX (Strata 2026-07-07): also credit categories that a
        # mutation-verified harness's declared invariants actually TEST (bounds/custody/
        # ordering/determinism/freshness...) - the per-asset axis above did not map the
        # echidna_* invariants to a category, so real coverage read as a family gap.
        _verified_cats = _verified_invariant_categories(ws)
        _enum_union |= _verified_cats
        _fam_gap = sorted(_fam_req_union - _enum_union)
        m["family_invariant_denominator"] = {
            "families_detected": _fams,
            "family_required_categories": sorted(_fam_req_union),
            "categories_enumerated_somewhere": sorted(_enum_union),
            "family_required_but_not_enumerated": _fam_gap,
            "strict_env": "AUDITOOOR_MATRIX_FAMILY_INVARIANTS_STRICT",
        }
        if _fam_gap and os.environ.get("AUDITOOOR_MATRIX_FAMILY_INVARIANTS_STRICT", "").strip().lower() in ("1", "true", "yes", "on"):
            if m.get("verdict") == "complete":
                m["verdict"] = "incomplete"
            m.setdefault("reasons", []).append(
                f"family-invariant denominator: family(ies) {_fams} require category(ies) "
                f"{_fam_gap} which NO in-scope asset enumerated (vacuous 'all invariants held')")
    except Exception:
        pass  # advisory layer must never brick the matrix build
    # The actionable enumeration worklist (one row per never-enumerated value-moving
    # cell) is part of the matrix so the orchestrator can read it without re-deriving.
    m["enumeration_worklist"] = build_enumeration_worklist(m)
    m["enumeration_worklist_count"] = len(m["enumeration_worklist"])
    return m


# A cell is "value-moving" (i.e. an enumeration obligation, not background) unless
# it was credited out-of-scope by fcc's authoritative attack-surface filter. Only
# those obligations turn into worklist rows + the enforce-gated terminal fail; a
# view getter / library shim fcc dropped is NOT a never-enumerated coverage gap.
_NONVALUE_COVERAGE_STATUSES = {"out-of-scope-fcc-filtered"}

# F1 (id24,30): pure-interface / library / signature-only file shapes. The upstream
# _drop_nonentry_file already drops all-nonentry FILES from the asset floor, but the
# reader-side JOIN (audit-completeness-check.check_completeness_matrix) needs a
# per-worklist-row `cell_kind` so it can fold ONLY value-moving not-enumerated cells
# into the verdict and NEVER re-red an interface file (IFullERC20 / ECRecover). This
# path-shape check tags a function-axis row as `dropped_nonentry` (background, never
# forces incomplete) vs `value_moving` (a real obligation). Conservative: only an
# UNAMBIGUOUS interface/library path marker demotes a row; anything else stays
# value_moving (fail-closed - we never silently demote a real value-mover).
_INTERFACE_PATH_RE = re.compile(
    r"(?:^|/)(?:interfaces?|libraries|lib)/"          # under interfaces/ or libraries/
    r"|(?:^|/)I[A-Z]\w*\.sol$"                          # I<Upper>...  Solidity interface file
    r"|(?:^|/)[A-Za-z]\w*(?:Interface|Lib|Library)\.sol$",  # <X>Interface/Lib/Library.sol
    re.IGNORECASE,
)


def _worklist_function_cell_kind(file_path: str) -> str:
    """Classify a function-axis worklist row as `dropped_nonentry` (pure interface /
    library file - the trap to never re-red) or `value_moving` (a real obligation).
    Fail-closed: only an unambiguous interface/library path marker demotes."""
    p = str(file_path or "").replace("\\", "/")
    if p and _INTERFACE_PATH_RE.search(p):
        return "dropped_nonentry"
    return "value_moving"


def build_enumeration_worklist(m: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn every NOT-ENUMERATED value-moving cell of a built matrix into one
    actionable worklist row. Pure function of the matrix dict so the output is
    deterministic; rows are returned sorted by a stable key.

    Three cell axes produce rows:
      - function:  an in-scope function with coverage_status == not-enumerated
                   (out-of-scope-fcc-filtered functions are NOT obligations).
      - invariant: an (asset, invariant-category) pair left not-enumerated.
      - impact:    an impact class that is blank / not-enumerated, or the whole
                   impact-class ledger being absent.
    Each row carries enough to author the missing invariant cold: the asset, the
    cell coordinates, an impact_category hint, and a one-line action."""
    rows: list[dict[str, Any]] = []
    # PER-FILE vs PER-REPO grouping decides whether a COVERED-file's residual invariant
    # categories are an obligation. A per-REPO asset (the whole src/<repo>) legitimately
    # spans all 10 canonical invariant classes, so a partially-covered repo IS a real JOIN
    # obligation (the per-repo red the invariant-enum lane drives to full enumeration). A
    # per-FILE asset (one src file) does NOT span all 10 - a token file has no custody
    # invariant, a router no monotonicity - so a covered per-file asset's residual
    # categories are not a real gap (see _inv_file_covered below). Only relax the per-FILE
    # posture; keep the per-repo all-10-categories requirement intact.
    _per_file_grouping = str(
        (m.get("denominators", {}) or {}).get("asset_grouping", "")) == "per-file"
    for a in m.get("assets", []):
        asset_id = a.get("asset_id", "")
        for fn in a.get("functions", []):
            if fn.get("coverage_status") == "not-enumerated":
                rows.append({
                    "axis": "function",
                    "asset": asset_id,
                    "function": fn.get("function", ""),
                    "file": fn.get("file", ""),
                    "invariant_category": None,
                    "impact_category": "value-movement",
                    "status": "not-enumerated",
                    # F1: value_moving vs dropped_nonentry so the reader-side JOIN can
                    # fold ONLY value-moving cells and never re-red an interface file.
                    "cell_kind": _worklist_function_cell_kind(fn.get("file", "")),
                    "action": ("enumerate + author an invariant covering this in-scope "
                               "function (no coverage record on the attack surface)"),
                })
        # F1 nonentry parity: an (asset x invariant-category) row is value_moving ONLY
        # when the asset has a real value-moving surface. An all-nonentry file (every
        # in-scope fn is fcc-classified interface/library/view/boilerplate/Go-Cosmos-
        # plumbing) or a fully-dispositioned file (privileged-only / OOS) has NO invariant
        # to enumerate - tag its invariant rows dropped_nonentry so the reader-side JOIN
        # excludes them, EXACTLY as _worklist_function_cell_kind does for the function
        # axis. Belt-and-suspenders: also demote on an unambiguous interface/library PATH
        # shape (the asset_id is a file path in per-file mode), so a stale matrix built
        # before all_nonentry was emitted still gets the interface files demoted.
        # FAIL-CLOSED: an all_nonentry file is demoted ONLY when its non-entry is TRUSTWORTHY:
        # (a) >=1 real function was enumerated and all are fcc-nonentry (has_real_function), or
        # (b) the file is explicitly dispositioned, or (c) its PATH is an unambiguous interface/
        # library shape (enum-independent - catches IFullERC20 / *Lib.sol even on a stale matrix).
        # A file whose all_nonentry rests solely on an empty function='' placeholder (Go-enum
        # failure) is NOT demoted here - it stays value_moving until the upstream enumeration bug
        # is fixed, so a real Go value-mover is never silently green-washed.
        # PER-FILE JOIN parity with the per-file FLOOR (NUVA 2026-07-04): a value-moving
        # file that is genuinely COVERED - it carries >=1 mutation-verified enumerated
        # invariant category (a real harness proves an invariant of the categories its
        # functions can actually violate) - has a PROVEN invariant surface. The per-file
        # FLOOR already treats such a file as satisfied (it only flags files with ZERO
        # enumerated categories). The per-file invariant-axis JOIN must be CONSISTENT: it
        # was emitting a value_moving row for EACH of the residual canonical categories a
        # covered file does not have (a token file has no `custody` invariant to prove, a
        # router no `monotonicity`), demanding all 10 CANONICAL_INVARIANT_CATEGORIES on
        # every file - a structurally-unsatisfiable over-strictness that inflated the JOIN
        # (NUVA: 105 rows across 17 already-covered files). Demote a covered file's residual
        # category rows to dropped_nonentry so the reader-side JOIN does not re-red a file
        # whose invariant surface is already mutation-verified. FAIL-CLOSED: a file with
        # ZERO enumerated categories stays value_moving (it is a genuine coverage gap, e.g.
        # the per-file FLOOR's uncovered set) unless separately non-entry / dispositioned.
        # GATED to per-FILE grouping (see _per_file_grouping above): a per-REPO asset spans
        # all 10 classes and still owes every canonical category, so the per-repo JOIN the
        # invariant-enum lane drives to full enumeration is unchanged; only the per-file
        # all-10-categories over-strictness is relaxed for an already-covered file.
        _inv_file_covered = (
            _per_file_grouping
            and int(a.get("invariant_categories_enumerated") or 0) >= 1)
        _inv_nonentry = (
            (bool(a.get("all_nonentry")) and bool(a.get("has_real_function")))
            or bool(a.get("file_dispositioned"))
            or _inv_file_covered
        )
        _inv_cell_kind = (
            "dropped_nonentry"
            if (_inv_nonentry or _worklist_function_cell_kind(asset_id) == "dropped_nonentry")
            else "value_moving"
        )
        for cat in a.get("invariant_categories_not_enumerated", []):
            rows.append({
                "axis": "invariant",
                "asset": asset_id,
                "function": None,
                "file": None,
                "invariant_category": cat,
                "impact_category": cat,
                "status": "not-enumerated",
                # value_moving only for assets with a real value-moving surface; an
                # all-nonentry / dispositioned / interface-shape file is dropped_nonentry
                # (background, never forces incomplete) - see _inv_cell_kind above.
                "cell_kind": _inv_cell_kind,
                "action": (f"enumerate the '{cat}' invariant category for this asset "
                           "(no dossier cue found)"),
            })
    impact = m.get("impact_enumeration", {}) or {}
    if impact.get("missing"):
        rows.append({
            "axis": "impact",
            "asset": "*",
            "function": None,
            "file": None,
            "invariant_category": None,
            "impact_category": "*",
            "status": "absent",
            "cell_kind": "value_moving",
            "action": ("enumerate the impact-class ledger (exploit_class_coverage.json "
                       "absent/blank): disposition every impact class"),
        })
    else:
        for cls in impact.get("not_enumerated", []) or []:
            rows.append({
                "axis": "impact",
                "asset": "*",
                "function": None,
                "file": None,
                "invariant_category": None,
                "impact_category": cls,
                "status": "not-enumerated",
                "cell_kind": "value_moving",
                "action": f"disposition the '{cls}' impact class (blank/not-enumerated)",
            })
    # business-flow axis: one row per DRIVABLE cross-module flow no hunt/harness
    # touched (drive it with a per-flow hunt task or a flow-level harness).
    _flow_targets = (m.get("flows", {}) or {}).get("harness_targets", {}) or {}
    for flow_id in (m.get("flows", {}) or {}).get("undriven", []) or []:
        tgt = _flow_targets.get(flow_id, {})
        rows.append({
            "axis": "flow",
            "asset": "*",
            "function": None,
            "file": None,
            "invariant_category": None,
            "impact_category": "cross-module-flow",
            "flow_id": flow_id,
            # P2c: the concrete flow-level harness target (CUT + invariant hint).
            "cut_files": tgt.get("cut_files", []),
            "invariant_hint": tgt.get("invariant_hint", ""),
            "status": "undriven",
            "cell_kind": "value_moving",
            "action": (f"drive the '{flow_id}' cross-module business flow: seed a per-flow "
                       "hunt task over its members OR author a flow-level invariant harness "
                       f"over CUT={tgt.get('cut_files', [])} asserting: {tgt.get('invariant_hint','')}"),
        })

    # mechanism axis (v2): one row per NOT-ENUMERATED [impact x mechanism] cell -
    # either no detector ran (scan it) or an open finding is un-dispositioned
    # (verify -> finding, or refute -> disposition sidecar).
    for c in ((m.get("mechanism_axis", {}) or {}).get("cells", []) or []):
        if not str(c.get("status", "")).startswith("not-enumerated"):
            continue
        unscanned = c["status"] == "not-enumerated-unscanned"
        rows.append({
            "axis": "mechanism",
            "asset": "*",
            "function": None,
            "file": None,
            "invariant_category": None,
            "impact_category": c.get("impact"),
            "mechanism": c.get("mechanism"),
            "languages": c.get("languages", []),
            "detector": c.get("detector"),
            "open_findings": c.get("open_findings", 0),
            "status": c.get("status"),
            "cell_kind": "value_moving",
            "action": (
                f"run mechanism detector '{c.get('detector')}' for [{c.get('impact')} x "
                f"{c.get('mechanism')}] and write its .auditooor/mechanism_scan sidecar"
                if unscanned else
                f"disposition the {c.get('open_findings')} open [{c.get('impact')} x "
                f"{c.get('mechanism')}] finding(s): verify->paste-ready OR refute->"
                "mechanism_dispositions.jsonl row"),
        })

    def _key(r: dict[str, Any]) -> tuple[str, str, str, str]:
        return (
            str(r.get("axis") or ""),
            str(r.get("asset") or ""),
            str(r.get("function") or r.get("invariant_category")
                or r.get("mechanism") or r.get("impact_category") or ""),
            str(r.get("file") or ""),
        )

    rows.sort(key=_key)
    return rows


def _write_worklist(ws: Path, rows: list[dict[str, Any]]) -> Path:
    """Emit the worklist deterministically + idempotently: the file is rewritten
    in full each run (no append), rows already sorted by build_enumeration_worklist,
    each serialized with sort_keys so byte output is stable. Always written, even
    when there are zero rows (an empty file => nothing to enumerate)."""
    out = ws / ".auditooor" / "completeness_enumeration_worklist.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)
    out.write_text(body, encoding="utf-8")
    return out


def _enforce_enabled() -> bool:
    """Whether an INCOMPLETE matrix hard-FAILs (rc 1) rather than WARN-passes.
    Matches the orchestrator (tools/audit-completeness-check.py): unset / 0 / false
    / no => disabled. Enforcement is ON under ANY of the completeness enforce envs
    so setting AUDITOOOR_MECHANISM_AXIS_ENFORCE=1 (or the 100%-all-axes umbrella, or
    the global L37 STRICT the driver exports) genuinely flips enforce=True in the
    standalone print - the misleading `enforce=False` bug this closes was that the
    print read ONLY AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE while the mechanism axis
    flipped the verdict off a different env."""
    return (_env_flag("AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE")
            or _env_flag("AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT")
            or _env_flag("AUDITOOOR_MECHANISM_AXIS_ENFORCE")
            or _env_flag("AUDITOOOR_L37_STRICT"))


def _write_md(ws: Path, m: dict[str, Any]) -> Path:
    out = ws / "COMPLETENESS_MATRIX.md"
    lines = [
        "# Completeness Matrix (enumeration floor)",
        "",
        f"- verdict: **{m['verdict']}**",
        f"- assets: {m['denominators']['assets']} "
        f"(grouping: {m['denominators'].get('asset_grouping', 'per-repo')}; "
        f"per-file: {m['denominators'].get('assets_perfile', m['denominators']['assets'])}) | "
        f"functions: {m['denominators']['functions']} | "
        f"invariant-categories: {m['denominators']['invariant_categories']} | "
        f"impact-classes: {m['denominators']['impact_classes']}",
        f"- cells: {m['cells']['terminal']} terminal / {m['cells']['open']} open / "
        f"{m['cells']['not_enumerated']} NOT-ENUMERATED (of {m['cells']['total']})",
        "",
        "## Per-asset invariant enumeration (10 categories)",
        "",
        "| asset | inv-categories enumerated | function cells |",
        "|---|---|---|",
    ]
    for a in m["assets"]:
        lines.append(f"| {a['asset_id']} | {a['invariant_categories_enumerated']}/10 | {a['function_count']} |")
    if m["not_enumerated_assets"]:
        lines += ["", "## ASSETS WITH NO ENUMERATED INVARIANTS (fail-closed)", ""]
        for x in m["not_enumerated_assets"]:
            lines.append(f"- {x['asset_id']}: {x['reason']}")
    _pfb = m.get("perfile_breakdown") or {}
    _pf_neg = _pfb.get("not_enumerated_assets") or []
    if _pf_neg and not m.get("perfile_strict"):
        lines += ["", "## PER-FILE breakdown: in-scope FILES with NO harness-backed invariant "
                  "(advisory; collapsed by per-repo grouping)", ""]
        for x in _pf_neg:
            lines.append(f"- {x['asset_id']}: {x['reason']}")
    if m["reasons"]:
        lines += ["", "## Why incomplete", ""] + [f"- {r}" for r in m["reasons"]]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the enumeration-floor completeness matrix.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--check", action="store_true", help="Return rc 1 on incomplete (fail-closed).")
    ap.add_argument(
        "--enumerate-only",
        action="store_true",
        help="PRODUCER-ONLY mode (A1 pre-hunt rewire): build the completeness_matrix.json + "
             "COMPLETENESS_MATRIX.md + completeness_enumeration_worklist.jsonl artifacts and "
             "ALWAYS return rc 0. No terminal check / enforce / rebuttal verdict is computed - "
             "this is the enumerate-BEFORE-hunt step whose ONLY job is to put the worklist on "
             "disk so a downstream hunt can consume it. The terminal enumeration-floor verdict "
             "still comes later from `--check` / audit-completeness-check. Incompatible with "
             "--check (--check wins if both are passed, so enforcement is never silently dropped).")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = _ws(args.workspace)
    if not ws.is_dir():
        print(f"[completeness-matrix] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    m = build_matrix(ws)
    out_json = ws / ".auditooor" / "completeness_matrix.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
    md = _write_md(ws, m)
    # ALWAYS emit the actionable per-unit worklist (even on a complete matrix, where
    # it is an empty file). This is what turns NOT-ENUMERATED cells into work a
    # downstream step can pick up, instead of a silent WARN that nothing acts on.
    worklist_rows = m.get("enumeration_worklist", [])
    worklist_path = _write_worklist(ws, worklist_rows)

    rebuttal = _rebuttal(ws)
    enforce = _enforce_enabled()
    incomplete = m["verdict"] != "complete"
    # A1 pre-hunt rewire: --enumerate-only is a PURE PRODUCER. The matrix + worklist
    # were already written above (unconditionally); this mode's ONLY contract is
    # "artifacts on disk, rc 0". It computes NO terminal verdict and never enforces,
    # so wiring it into a pre-hunt step can never brick a pipeline. --check STILL
    # wins if both are passed (enforcement is never silently dropped by asking to
    # also enumerate). The binding enumeration-floor verdict remains --check /
    # audit-completeness-check downstream.
    if args.enumerate_only and not args.check:
        summary = {
            "tool": "completeness-matrix-build",
            "signal": "enumerate-only-produced",
            "verdict": m["verdict"],
            "enforce": False,
            "mode": "enumerate-only",
            "reasons": m["reasons"],
            "denominators": m["denominators"],
            "cells": m["cells"],
            "not_enumerated_assets": [a["asset_id"] for a in m["not_enumerated_assets"]],
            "enumeration_worklist": str(worklist_path),
            "enumeration_worklist_count": len(worklist_rows),
            "matrix_json": str(out_json),
            "matrix_md": str(md),
            "rebuttal": rebuttal,
        }
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"[completeness-matrix] enumerate-only-produced: {m['verdict']} "
                  f"(assets={m['denominators']['assets']}, "
                  f"worklist-rows={len(worklist_rows)}) "
                  f"-> {worklist_path} (no terminal verdict; producer-only)")
        return 0
    # Terminal verdict: complete -> pass. Incomplete -> ok-rebuttal if an
    # operator-approved rebuttal greens it. Otherwise it is a hard fail ONLY when
    # the caller opted into strictness (explicit --check, strict-by-intent) or the
    # AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE env is set; default posture is a loud
    # WARN-pass so workspaces certified before this floor existed are not bricked.
    # Never-false-pass: a complete matrix always passes; an incomplete one can only
    # earn rc 0 via (a) no enforce + no --check (WARN) or (b) an explicit rebuttal.
    if not incomplete:
        verdict_signal = "pass-completeness-matrix"
    elif rebuttal:
        verdict_signal = "ok-rebuttal"
    elif enforce or args.check:
        verdict_signal = "fail-completeness-matrix-uncovered-cells"
    else:
        verdict_signal = "warn-completeness-matrix-uncovered-cells"

    summary = {
        "tool": "completeness-matrix-build",
        "signal": verdict_signal,
        "verdict": m["verdict"],
        "enforce": enforce,
        "reasons": m["reasons"],
        "denominators": m["denominators"],
        "cells": m["cells"],
        "not_enumerated_assets": [a["asset_id"] for a in m["not_enumerated_assets"]],
        "enumeration_worklist": str(worklist_path),
        "enumeration_worklist_count": len(worklist_rows),
        "matrix_json": str(out_json),
        "matrix_md": str(md),
        "rebuttal": rebuttal,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[completeness-matrix] {verdict_signal}: {m['verdict']} "
              f"(assets={m['denominators']['assets']}, "
              f"not-enumerated-assets={len(m['not_enumerated_assets'])}, "
              f"cells not-enum={m['cells']['not_enumerated']}, "
              f"worklist-rows={len(worklist_rows)}, enforce={enforce})")
        for r in m["reasons"]:
            print(f"  - {r}")
        if verdict_signal == "warn-completeness-matrix-uncovered-cells":
            print("  WARN-pass: set AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE=1 (or pass --check) "
                  "to hard-fail on these never-enumerated cells")
        if rebuttal:
            print(f"  rebuttal honored: {rebuttal}")

    if verdict_signal.startswith("fail-"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
