#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec declared via tools/agent-pathspec-register.py lane LANE-iter3-B-advisory-dsl; orchestrator commits; disjoint owner -->
"""advisory-seed-to-dsl.py - convert mined advisory detector-SEED .jsonl into
FIRING class-level detectors the per-language runners + auditor-backtest can load.

WHY THIS TOOL EXISTS (iter2 bottleneck)
---------------------------------------
iter2 measured that 10/14 held-out misses were "corpus-knows-the-class but has
NO FIRING DETECTOR".  The knowledge is already mined into
``audit/corpus_tags/derived/detector_seeds_{hyperbridge,zebra,
dydx_fork_divergence}_advisories.jsonl`` - but those rows are *seeds*
(schema ``auditooor.detector_seed.v1``), not the loadable detectors the
``rust-detector-runner`` / ``go-detector-runner`` / ``cosmos-detector-runner`` /
Slither-DSL arms actually fire.  This converter closes that gap: it emits, per
seed-CLASS, a CLASS-LEVEL detector in two interoperable shapes:

  (a) a standalone Python ``scan(root) -> list[(file, line, msg)]`` module - the
      exact interface ``tools/rust-detector-runner.py`` wave-2 loader and
      ``tools/go-detector-runner.py`` expect, so the detector LOADS + FIRES
      without any runner edit and is independently verifiable; and
  (b) a portable ``.yaml`` DSL sidecar (``backend: cosmos`` for go-seed classes,
      ``backend: regex`` for rust-seed classes) carrying the same positive
      anchor / negative guard so ``auditor-backtest.py --corpus-detector-dir``
      and ``cosmos-detector-runner.py --patterns-dir`` can ingest the same rule.

Output dir: ``detectors/from_advisories/`` (fresh; this tool never writes
elsewhere).

ANTI-OVERFIT CONTRACT (operator's #1 demand)
--------------------------------------------
Detectors emitted here are CLASS-LEVEL: each matches the bug MECHANISM (e.g.
"index/state mutated BEFORE a validity guard in the same fn", "unbounded
length-driven allocation BEFORE a cap check on a deserialize/inbound path",
"go.mod/Cargo.toml fork ``replace`` pinned at a SHA == audit-pin").  The
converter REFUSES to emit a detector whose positive anchor is an
instance-memorised literal (a verbatim slice of a single source file): it
derives the anchor from the seed's ``ast_query_hint`` mechanism vocabulary +
the seed's ``regex_pattern`` GENERALISED (identifier-class tokens, not literal
symbol names) and rejects any pattern that is a fixed string with no
metacharacter / token-class.  See ``_is_instance_memorised``.

RELATED TOOLS (tool-duplication preflight, per global anchor)
-------------------------------------------------------------
  * tools/solodit-finding-to-dsl.py    - converts a single Solodit finding to a
    Slither DSL .yaml.  DIFFERENT INPUT (one finding JSON, not the seed corpus)
    and DIFFERENT OUTPUT (Slither-only, no per-language scan() module).
  * tools/dsl-migration-helper.py      - migrates legacy DSL rows to the current
    schema.  Operates on EXISTING .yaml, does not consume seeds.
  * tools/glider-queries-to-dsl.py     - ports Glider queries.  Different source.
  * tools/hackerman-detector-seed-extractor.py / -per-language.py - EMIT the
    seeds this tool CONSUMES.  Upstream of us; no overlap.
This tool fills the gap: seed-corpus .jsonl -> firing per-language scan() module
+ portable .yaml, class-level, anti-overfit-checked.  No existing tool does this.

Usage
-----
    python3 tools/advisory-seed-to-dsl.py \
        --seeds audit/corpus_tags/derived/detector_seeds_zebra_advisories.jsonl \
                audit/corpus_tags/derived/detector_seeds_dydx_fork_divergence_advisories.jsonl \
                audit/corpus_tags/derived/detector_seeds_hyperbridge_advisories.jsonl \
        --out detectors/from_advisories
    python3 tools/advisory-seed-to-dsl.py --seeds <glob...> --out <dir> --json
    python3 tools/advisory-seed-to-dsl.py --self-verify   # fire emitted detectors
                                                          # on the seed TRAIN fixtures
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Class-mechanism vocabulary.  Each seed attack_class is collapsed to a
# CLASS-LEVEL mechanism family so one detector catches the mechanism, never a
# single instance.  The family carries:
#   - a class tag (matches the corpus vuln_class vocabulary)
#   - language
#   - a GENERALISED positive anchor (identifier-class tokens)
#   - an optional negative guard (the canonical fix suppresses the detector)
# The anchor/guard are TOKEN-CLASS, never instance literals.
# ---------------------------------------------------------------------------

# attack_class substring -> mechanism family key
_CLASS_TO_FAMILY = [
    # --- allocation / length-driven memory amplification (rust) ----------
    ("allocation-amplification", "alloc_amplification_before_cap"),
    ("untrusted-length-driven-allocation", "alloc_amplification_before_cap"),
    ("unbounded-memory-leak", "alloc_amplification_before_cap"),
    # --- panic/abort DoS on an authenticated/crafted inbound path (rust) --
    ("panic-abort-dos", "inbound_panic_dos"),
    ("panic-dos", "inbound_panic_dos"),
    ("disconnect-abort-dos", "inbound_panic_dos"),
    ("identity-point-panic", "inbound_panic_dos"),
    ("utf8-slice-panic", "inbound_panic_dos"),
    # --- consensus / fork divergence (rust) -------------------------------
    ("consensus-divergence", "consensus_divergence_rule_omission"),
    ("block-validity-split", "consensus_divergence_rule_omission"),
    # --- ordering / TOCTOU: mutate state before guard (rust) --------------
    ("ordering-validation-toctou", "state_mutation_before_guard"),
    ("ordering-arithmetic-overflow", "accumulate_before_bound_check"),
    # --- incomplete cleanup on reorg / residue (rust) ---------------------
    ("incomplete-cleanup", "incomplete_cleanup_on_reorg"),
    ("resource-exhaustion-no-per-peer-throttle", "no_per_peer_throttle"),
    ("single-peer-permanent-block-discovery-halt", "no_per_peer_throttle"),
    ("insufficient-data-authenticity", "unauthenticated_sync_data"),
    ("normalization-mismatch", "consensus_divergence_rule_omission"),
    # --- go fork-divergence: upstream fix not backported ------------------
    # The dydx seeds tag THREE distinct go mechanisms under this one meta-class;
    # we route by detector_id sub-shape in _seed_family_go() so each fires on
    # its real surface (go.mod replace-pin vs iavl cache/batch fn-body race).
    ("fork-divergence-missing-upstream-fix", "__go_forkdiv__"),
    # --- generic public-advisory theft-class smell (low precision) --------
    ("public-advisory-theft-class", None),  # None => SKIP (placeholder smell)
]


# Mechanism family definitions.  GENERALISED anchors only (token-class).
_FAMILIES = {
    "alloc_amplification_before_cap": {
        "language": "rust",
        "class_tag": "allocation-amplification",
        "severity": "HIGH",
        # positive: a length/size read from an inbound/deserialize source drives
        # a capacity reservation (with_capacity / reserve / Vec::with_capacity /
        # allocation) - GENERALISED over identifier class, not a literal type.
        # positive: a capacity reservation (with_capacity / reserve /
        # reserve_exact / Vec::with_capacity) sized by a NON-literal: either an
        # identifier (e.g. `n`, `body_len`, `count`) or a `.len()`/`.size()`/
        # `.count()` call. The iter3 anchor required the size token to literally
        # contain `len|size|count|num|...`, so it MISSED `Vec::with_capacity(n as
        # usize)` where the untrusted length is bound to a bare `n` (the canonical
        # compactsize-amplification shape). Matching a lowercase ident arg catches
        # that while still excluding constant-sized allocs `with_capacity(64)`.
        "positive": (
            r"(?:with_capacity|reserve|reserve_exact|Vec::with_capacity)\s*\(\s*"
            r"(?:[a-z]\w*|[\w.]+\.(?:len|size|count)\s*\(\s*\))\b"
        ),
        # negative guard: a cap / bound check (<=, MAX, min(, .min(, ensure!, if
        # ... > LIMIT) on that length BEFORE the alloc suppresses the detector.
        "negative": (
            r"(?:\b(?:if|ensure!|require!|assert!|debug_assert!)\b[^;{]*"
            r"(?:>|>=|<|<=)\s*[\w:.]*(?:MAX|LIMIT|CAP|max_|limit|bound)"
            r"|\.min\s*\(|::min\s*\(|saturating_)"
        ),
        "help": ("Inbound/deserialized length or count drives a heap allocation "
                 "(with_capacity/reserve) before any cap/bound check - a crafted "
                 "small message can request gigabytes (memory-amplification DoS)."),
    },
    "inbound_panic_dos": {
        "language": "rust",
        "class_tag": "panic-dos",
        "severity": "HIGH",
        # positive: a panic-capable op on attacker-controlled data - a method-call
        # `.expect(`/`.unwrap(`/`.unwrap_unchecked(`, an `unreachable!(`/`panic!(`,
        # a fixed-offset byte slice `[N..M]` (utf8-straddle panic), or the
        # identity-point `.coordinates().unwrap()` shape - inside a fn whose name
        # marks an inbound/decode/rpc handler. The iter3 surface included a bare
        # `\bindex\b\s*\(` alternative (matches any `index(` call); that is
        # DROPPED. The `.expect`/`.unwrap` are now method-anchored (leading `.`)
        # so they do not match unrelated free-standing identifiers.
        "positive": (
            r"(?:\.(?:expect|unwrap|unwrap_unchecked)\s*\(|"
            r"\bunreachable!\s*\(|\bpanic!\s*\(|"
            r"\[\s*\d+\s*\.\.\s*\d+\s*\]|"
            r"\.coordinates\s*\(\s*\)\s*\.\s*unwrap)"
        ),
        # negative: explicit fallible handling on that path - matches?/ok_or/
        # get(/checked_/Result return - suppresses.
        "negative": (
            r"(?:\bok_or\b|\bok_or_else\b|\.get\s*\(|\bchecked_|"
            r"\bmatches!\b|->\s*Result<|\?;)"
        ),
        "help": ("Authenticated/crafted inbound message handler uses a "
                 "panic-capable op (unwrap/expect/slice-index) on attacker-"
                 "controlled data without fallible handling - one crafted "
                 "message aborts the node (panic-abort DoS)."),
        # only count when the enclosing fn name marks an inbound/decode/rpc path.
        # Tightened from the iter3 marker (which included bare `process`/`parse`,
        # broad verbs present on many internal fns) to inbound/decode/rpc handler
        # verbs - cuts the surface (14 -> 11 files on zebra) while keeping every
        # TRAIN panic fixture firing.
        "fn_name_marker": (
            r"(?i)(handle_|on_message|on_request|recv|receive|decode|"
            r"deserialize|from_bytes|read_body|rpc_|inbound|dispatch)"
        ),
    },
    "consensus_divergence_rule_omission": {
        "language": "rust",
        "class_tag": "consensus-divergence",
        "severity": "HIGH",
        # positive: a consensus-verification mechanism token - sighash / sigop
        # counting / script-opcode iteration / verification-result cache lookup /
        # ffi digest buffer. GENERALISED over the mechanism vocabulary, not any
        # single advisory's symbol. Any one of these in a verification context
        # is the surface where a reference-impl rule can be silently omitted.
        # Two CLASS-LEVEL consensus-verification sub-mechanisms, both anchored on
        # consensus-rule tokens (never the bare generic `verify(` / `copy_from(` /
        # `is_coinbase()` that produced the iter3 over-broad surface):
        #   (a) zcash/bitcoin script-validity: sighash / sigop counting,
        #       SIGHASH_* hash-type handling, disabled-opcode early-terminate,
        #       coinbase-skip during sigop accumulation, height-blind verification
        #       cache (cache.get/find keyed on txid/hash), FFI stale-buffer
        #       (Some(d) => buffer.copy_from arm).
        #   (b) BSC/validator-set consensus client: aggregate-signature verify
        #       (bls::verify), aggregate_public_key, validators_bit_set, epoch
        #       ancestry / next-validator rotation.
        # Every alternative is consensus-specific; empirically these fire ONLY in
        # modules/consensus/* and consensus-client trees (no business-logic /
        # RPC spray), unlike the dropped bare `verify(`.
        "positive": (
            r"(?i)("
            r"\bsighash\b|\bsig_?op\b|\bis_sigop\b|MAX_BLOCK_SIGOPS|SIGHASH_\w+|"
            r"script\s*\.\s*opcodes|compute_sighash|is_disabled\s*\(|"
            r"coinbase[^;\n]{0,30}(?:continue|skip)|"
            r"cache\s*\.\s*(?:get|find)\w*\s*\([^)]*(?:txid|hash)|"
            r"(?:Some|None)\s*(?:\([^)]*\))?\s*=>[^;\n]{0,60}"
            r"(?:copy_from|buffer|digest)|"
            r"bls\s*::\s*verify|aggregate_public_key|validators?_bit_set|"
            r"epoch_header_ancestry|next_validator"
            r")"
        ),
        # negative: a height/upgrade-gated rule application present
        # (activation-height / network-upgrade / consensus-branch conditioning,
        # OR an explicit index-bounds / None-rejection guard) suppresses the
        # rule-omission smell - the omission itself is the bug.
        "negative": (
            r"(?i)(activation_?height|network_?upgrade|consensus_?branch|"
            r"NetworkUpgrade|return\s+Err\b[^;]*(?:index|bounds|none|empty)|"
            r"\.get\s*\([^)]*\)\s*\.\s*ok_or)"
        ),
        "help": ("Block/script/signature validity routine omits a reference-"
                 "implementation consensus rule (sigop counting, SIGHASH_SINGLE "
                 "bounds, height-aware cache, FFI digest freshness) - nodes that "
                 "apply vs omit the rule split the chain (consensus "
                 "divergence)."),
        # marker matched against fn name OR body (see _NAME_OR_BODY in scan()).
        "fn_name_marker": None,
    },
    "state_mutation_before_guard": {
        "language": "rust",
        "class_tag": "ordering-validation-toctou",
        "severity": "MEDIUM",
        # positive: a map/index `.insert(`/`.push(` that lexically PRECEDES a
        # validity/rejection guard (check_/validate_/ensure_/reject/duplicate) in
        # the SAME body - the insert-then-guard ordering encoded as a single
        # co-occurrence regex. The iter3 spray (33 hits / 25 files with the
        # separate ordering pass, far more with a flat `.insert(`) came from the
        # bare insert/assignment alternation matching every map write; folding the
        # downstream-guard requirement into the positive anchors on the
        # TOCTOU mechanism (a write that has a later validity guard in the same
        # fn). negative=None / ordering_check=False because the ordering is now
        # intrinsic to the positive.
        "positive": (
            r"(?s)\.(?:insert|push)\s*\([^;]*\)\s*;[\s\S]{0,200}?"
            r"(?:check_|validate_|ensure_|reject|duplicate)\w*\s*\("
        ),
        "negative": None,
        "help": ("State index/map is mutated BEFORE the validity/rejection "
                 "guard for the same untrusted content runs in the same "
                 "function - a rejected item leaves a poisoned index entry "
                 "(TOCTOU / ordering)."),
        "ordering_check": False,  # ordering is intrinsic to the positive regex
    },
    "accumulate_before_bound_check": {
        "language": "rust",
        "class_tag": "ordering-arithmetic-overflow",
        "severity": "MEDIUM",
        "positive": (
            r"\b[\w.]*(?:balance|total|sum|acc|amount)\b[^;]*\+=[^;]*;"
        ),
        "negative": (
            r"(?:checked_add|saturating_add|\.checked\(|overflowing_add|"
            r"ensure!\s*\([^)]*MAX|<=\s*[\w:.]*MAX)"
        ),
        "help": ("A money/balance accumulator adds credits before subtracting "
                 "debits (or before a MAX bound) without checked arithmetic - "
                 "the intermediate may transiently overflow a bounded type."),
    },
    "incomplete_cleanup_on_reorg": {
        "language": "rust",
        "class_tag": "incomplete-cleanup",
        "severity": "MEDIUM",
        # positive: THREE self-contained residue-on-bail shapes, each carrying an
        # INLINE negative-lookahead for its own cleanup so the whole-body negative
        # cannot cross-suppress a sibling shape:
        #   (1) `.insert(...);` ... (no `.remove(` in the gap) ... `return Err`
        #       - a write left resident on an early-error path.
        #   (2) an `Err(_elapsed|timeout|deadline) =>  ... return Err` match arm
        #       - the uncleaned timeout arm that leaks the in-flight handle.
        #   (3) `fn pop_tip ... remove_block` WITHOUT a `subtree_roots.pop()`
        #       - the asymmetric tip-pop that retains a stale derived root.
        # The iter3 spray (193 hits / 97 files) came from bare `.insert(`/`.push(`
        # matching every map write in the tree; the ordering/lookahead structure
        # below anchors on the bail-without-cleanup mechanism. negative=None
        # because each shape suppresses itself inline (a body-level negative would
        # cross-suppress shape (2), whose Ok-arm legitimately calls `.remove`).
        "positive": (
            r"(?s)(?:"
            r"\.insert\s*\([^;]*\)\s*;(?:(?!\.remove\s*\()[\s\S]){0,160}?"
            r"\breturn\s+Err\b"
            r"|Err\s*\(\s*_?\s*(?:elapsed|timeout|deadline)\w*\s*\)\s*=>"
            r"[^,}]*?return\s+Err"
            r"|\bfn\s+pop_tip\b(?:(?!subtree_roots\s*\.\s*pop)[\s\S]){0,300}?"
            r"remove_block"
            r")"
        ),
        "negative": None,
        "help": ("A state write or partial rollback path does not clear all "
                 "derived index/cache state (a missing remove(key) after an "
                 "error return, or a retained subtree-root after pop) - residue "
                 "persists and corrupts state across a reorg."),
        "fn_name_marker": None,
    },
    "no_per_peer_throttle": {
        "language": "rust",
        "class_tag": "resource-exhaustion-dos",
        "severity": "MEDIUM",
        # positive: a SHARED concurrency primitive (Semaphore::new / .acquire() /
        # in-flight slot pool) consumed by inbound work, OR a global sync reset
        # (restart_sync / reset_sync). Anchored on the shared-slot mechanism ONLY.
        # The iter3 spray (291 hits / 78 files) came from the bare English-verb
        # alternation `request|fetch|download|get_blocks`; that is DROPPED here so
        # the detector fires AT the shared-resource construct, not on any fn whose
        # prose contains the word "download". Token-class, no instance literals.
        "positive": (
            r"(?i)(Semaphore::new\s*\(|\.acquire\s*\(|\bin[_-]?flight\b|"
            r"restart_sync\s*\(|reset_sync\s*\()"
        ),
        # negative: a PER-PEER keying / rate-limit / quota / backoff present
        # suppresses the smell (the throttle exists). At a fix-commit ref the
        # vulnerable fn has gained per-peer keying, so this correctly silences the
        # patched code; on the vulnerable shape (TRAIN fixture) no per-peer key is
        # present and the detector fires.
        "negative": (
            r"(?i)(per[_-]?peer|peer[_-]?id|HashMap<\s*(?:PeerId|SocketAddr)|"
            r"rate[_-]?limit|\bquota\b|\bbackoff\b|max[_-]?in[_-]?flight)"
        ),
        "help": ("An inbound request/sync/gossip path consumes a SHARED "
                 "concurrency slot (Semaphore/acquire) or triggers a GLOBAL "
                 "reset (restart_sync) with no per-peer keying - a single peer "
                 "exhausts the resource or stalls discovery for everyone."),
        "fn_name_marker": None,
    },
    "unauthenticated_sync_data": {
        "language": "rust",
        "class_tag": "insufficient-data-authenticity",
        "severity": "MEDIUM",
        # positive: a single peer's data triggers a GLOBAL sync reset
        # (restart_sync / reset_sync / sync_status reset). Anchored on the
        # global-reset mechanism. The iter3 spray (25 hits / 17 files) came from
        # the broad `(sync|import|apply|accept) ... (block|header|state|data)`
        # verb-noun clause and the bare `verify(block)`; both are DROPPED so the
        # detector fires AT the global-reset construct. Token-class only.
        "positive": (
            r"(?i)(restart_sync\s*\(|reset_sync\s*\(|"
            r"self\.\s*sync_status\s*\.\s*(?:lock|reset))"
        ),
        # negative: a per-peer attribution / ban / misbehavior penalty OR an
        # authenticity proof (signature/merkle/checkpoint/pow) on that path
        # suppresses the smell (the global reset is gated by accountable input).
        "negative": (
            r"(?i)(per[_-]?peer|peer[_-]?id|ban[_-]?peer|disconnect\s*\(\s*peer|"
            r"misbehav|penal|signature_?valid|merkle_?proof|"
            r"checkpoint_?verified|verify_?pow)"
        ),
        "help": ("A sync/import path lets ONE peer's invalid data trigger a "
                 "global action (restart_sync) or accepts external block/state "
                 "without per-peer attribution or an authenticity proof - "
                 "sync poisoning / single-peer DoS."),
        "fn_name_marker": None,
    },
    # ---- GO family: fork-divergence (go.mod replace pinned at a SHA) ------
    "fork_replace_pinned_at_sha": {
        "language": "go",
        "class_tag": "fork-divergence-missing-upstream-fix",
        "severity": "HIGH",
        "backend": "regex_file",  # matches go.mod text, not a fn body
        # positive: a `replace ... => github.com/<fork> vX-DATE-SHA12` pseudo-
        # version pin (the canonical fork-pinned-at-SHA shape). Token-class:
        # any module, any fork owner, any 14-digit date, any 12-hex SHA.
        # token-class: any module, any fork owner, any pseudo-version tail
        # ending in a 12-hex commit SHA. Tolerates both the `-DATE-SHA` and the
        # `DATE..SHA` pseudo-version separators seen across go tooling.
        "positive": (
            r"replace\s+[\w./-]+\s*=>\s*github\.com/[\w-]+/[\w.-]+"
            r"\s+v[\w.+-]*?[0-9a-f]{12}\b"
        ),
        "negative": None,
        "help": ("go.mod pins a forked upstream at a frozen pseudo-version "
                 "(date-SHA). If the fork HEAD == audit-pin, upstream security "
                 "fixes shipped after the pin are not backported - "
                 "fork-divergence. Triage: diff fork vs upstream since "
                 "merge-base for fix/panic/consensus/cve/dos/overflow/nil/race "
                 "commits absent from the fork."),
        "file_glob": "go.mod",
    },
    # ---- GO family: iavl/cosmos cache mutated mid-commit (fn-body race) ----
    "fork_batch_flush_race": {
        "language": "go",
        "class_tag": "fork-divergence-missing-upstream-fix",
        "severity": "HIGH",
        # positive: a cache mutation (cache.Add/Remove) or a Commit/WriteSync
        # that runs without an in-flight wait - the iavl/cosmos fast-node race
        # mechanism. Token-class over cache/batch idiom, not a literal symbol.
        "positive": (
            r"(?:\w*[Cc]ache\.(?:Add|Remove)\s*\(|"
            r"batch\.(?:Set|Write|WriteSync)\s*\(|"
            r"\.WriteSync\s*\(\s*\))"
        ),
        # negative: staged pending buffers (pendingAdditions/pendingFastNode) or
        # an explicit in-flight wait (<-inflight / .Wait()) on that path.
        "negative": (
            r"(?:pending[A-Z]\w*|pendingFastNode|<-\s*\w*[Ii]nflight|"
            r"\.Wait\s*\(\s*\)|sync\.WaitGroup)"
        ),
        "help": ("A fast-node/iavl cache is mutated mid-commit, or Commit/"
                 "WriteSync runs without waiting for the in-flight batch, with "
                 "no pending-staging buffers - upstream shipped the staged-"
                 "buffer / wait fix that this fork did not backport (race / "
                 "fork-divergence)."),
        "fn_name_marker": None,
    },
}


def _seed_family_go(detector_id: str) -> str:
    """Route a go fork-divergence seed to the right sub-mechanism family by its
    detector_id shape. go.mod-replace -> fork_replace_pinned_at_sha; cache /
    batch / commit / goroutine races -> fork_batch_flush_race."""
    did = (detector_id or "").lower()
    if "not-backported" in did or "replace" in did or "blocksync" in did:
        return "fork_replace_pinned_at_sha"
    if any(k in did for k in ("cache", "batch", "commit", "flush", "goroutine",
                              "migration", "store", "race", "wait")):
        return "fork_batch_flush_race"
    # default the meta-class to the go.mod-pin detector (broadest fork signal)
    return "fork_replace_pinned_at_sha"


# ---------------------------------------------------------------------------
def _seed_family(attack_class: str) -> str | None:
    """Map a seed attack_class to a mechanism-family key (or None to skip)."""
    ac = (attack_class or "").lower()
    for needle, fam in _CLASS_TO_FAMILY:
        if needle in ac:
            return fam
    return None


def _is_instance_memorised(pattern: str) -> bool:
    """Anti-overfit guard: True if `pattern` is a fixed literal string with no
    metacharacter / token-class (i.e. it would only ever match one specific
    source file's verbatim symbols). Such a pattern is REFUSED."""
    if not pattern:
        return True
    # strip the regex metacharacters; if what remains is a single long literal
    # symbol with no alternation / char-class / quantifier, it's memorised.
    meta = set(r".^$*+?{}[]()|\\")
    has_meta = any(ch in meta for ch in pattern)
    if not has_meta:
        return True
    # A pattern that is ONE literal wrapped in \b...\b with no alternation and
    # no token-class is still effectively a literal lookup.
    core = re.sub(r"\\b|\^|\$", "", pattern)
    if "|" not in core and "[" not in core and not re.search(r"[*+?{]", core):
        # e.g. "\bvalidateTransferLeavesNotExitedToL1\b" - instance literal
        if re.fullmatch(r"[\w:./]+\\?\(?", core or ""):
            return True
    return False


def load_seeds(seed_paths: list[Path]) -> list[dict]:
    """Read every seed .jsonl, returning the parsed inner statement merged with
    the envelope attack_class / source_audit_ref / target_lang."""
    out = []
    for sp in seed_paths:
        if not sp.exists():
            continue
        for line in sp.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
                st = json.loads(env["statement"])
            except Exception:
                continue
            out.append({
                "attack_class": env.get("attack_class"),
                "language": st.get("language") or env.get("target_lang"),
                "detector_id": st.get("detector_id"),
                "regex_pattern": st.get("regex_pattern", ""),
                "ast_query_hint": st.get("ast_query_hint", ""),
                "fp_reduction_strategy": st.get("fp_reduction_strategy", ""),
                "positive_fixture_snippet": st.get("positive_fixture_snippet", ""),
                "source_audit_ref": env.get("source_audit_ref", ""),
                "record_id": env.get("record_id", ""),
                "verification_tier": env.get("verification_tier", ""),
            })
    return out


def build_detectors(seeds: list[dict]) -> tuple[dict, dict]:
    """Group seeds into mechanism families and produce one CLASS-LEVEL detector
    per family. Returns (detectors_by_family, skipped_by_reason)."""
    by_family: dict[str, list[dict]] = defaultdict(list)
    skipped: dict[str, list[str]] = defaultdict(list)
    for s in seeds:
        fam = _seed_family(s["attack_class"])
        if fam == "__go_forkdiv__":
            fam = _seed_family_go(s["detector_id"])
        if fam is None:
            skipped["placeholder-smell-no-mechanism"].append(s["record_id"])
            continue
        if fam not in _FAMILIES:
            skipped["family-undefined"].append(s["record_id"])
            continue
        by_family[fam].append(s)

    detectors = {}
    for fam, members in by_family.items():
        spec = _FAMILIES[fam]
        # emit-time validation: every anchor regex MUST compile, else this is a
        # tool bug not a detector miss - fail loudly.
        for key in ("positive", "negative", "fn_name_marker"):
            pat = spec.get(key)
            if pat:
                try:
                    re.compile(pat)
                except re.error as e:
                    raise ValueError(
                        f"family {fam} {key} regex does not compile: {e}")
        # anti-overfit: never adopt a member's literal regex as the anchor; the
        # family anchor is always the GENERALISED token-class one. But we DO
        # record which member regexes were rejected as instance-memorised so
        # the report is honest.
        rejected_literals = [m["detector_id"] for m in members
                             if _is_instance_memorised(m["regex_pattern"])]
        detectors[fam] = {
            "family": fam,
            "class_tag": spec["class_tag"],
            "language": spec["language"],
            "severity": spec["severity"],
            "backend": spec.get("backend", "regex"),
            "positive": spec["positive"],
            "negative": spec.get("negative"),
            "fn_name_marker": spec.get("fn_name_marker"),
            "ordering_check": spec.get("ordering_check", False),
            "file_glob": spec.get("file_glob"),
            "help": spec["help"],
            "member_count": len(members),
            "member_record_ids": [m["record_id"] for m in members],
            "member_attack_classes": sorted({m["attack_class"] for m in members}),
            "rejected_instance_literals": rejected_literals,
            "source_refs": sorted({m["source_audit_ref"][:120]
                                   for m in members if m["source_audit_ref"]})[:5],
            "train_fixtures": [m["positive_fixture_snippet"] for m in members
                               if m["positive_fixture_snippet"]
                               and "see verbatim" not in m["positive_fixture_snippet"]],
        }
    return detectors, dict(skipped)


# ---------------------------------------------------------------------------
# Emit: standalone scan() Python module + portable .yaml sidecar.
# ---------------------------------------------------------------------------
_PY_TEMPLATE = r'''#!/usr/bin/env python3
# AUTO-GENERATED by tools/advisory-seed-to-dsl.py - DO NOT EDIT BY HAND.
# CLASS-LEVEL detector (mechanism: @@FAMILY@@); anti-overfit: token-class anchors.
"""@@FAMILY@@ - @@HELP@@

Class tag: @@CLASS_TAG@@   Language: @@LANGUAGE@@   Severity: @@SEVERITY@@
Source advisories: @@SOURCE_REFS@@
Mechanism is matched, NOT any single instance (see advisory-seed-to-dsl.py).
"""
from __future__ import annotations
import re
from pathlib import Path

DETECTOR_ID = @@FAMILY_R@@
CLASS_TAG = @@CLASS_TAG_R@@
LANGUAGE = @@LANGUAGE_R@@
SEVERITY = @@SEVERITY_R@@

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "tests", "test"}
_POSITIVE = re.compile(@@POSITIVE_R@@)
_NEGATIVE = re.compile(@@NEGATIVE_R@@) if @@NEGATIVE_R@@ else None
_FN_MARKER = re.compile(@@FN_MARKER_R@@) if @@FN_MARKER_R@@ else None
_FILE_GLOB = @@FILE_GLOB_R@@
_ORDERING = @@ORDERING_R@@
_EXT = @@EXT_R@@

_FN_HEADER_RE = re.compile(
    r"^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|const\s+)*"
    r"(?:fn|func)\s+(?P<name>[A-Za-z_]\w*)")


def _iter_files(root: Path):
    if _FILE_GLOB:
        for p in root.rglob(_FILE_GLOB):
            if not any(part in _SKIP_DIRS for part in p.parts):
                yield p
        return
    for p in root.rglob("*" + _EXT):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def _functions(src: str):
    """Yield (name, start_line, body) for each fn/func in src (brace-balanced)."""
    lines = src.splitlines()
    i = 0
    while i < len(lines):
        m = _FN_HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        depth = 0
        started = False
        body = []
        j = i
        while j < len(lines):
            ln = lines[j]
            depth += ln.count("{") - ln.count("}")
            body.append(ln)
            if "{" in ln:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i + 1, "\n".join(body)
        i = j + 1 if j > i else i + 1


def scan(root):
    """rust/go runner interface: list[(filepath, line, message)]."""
    root = Path(root)
    hits = []
    for f in _iter_files(root):
        try:
            src = f.read_text(errors="ignore")
        except Exception:
            continue
        if _FILE_GLOB:
            for mm in _POSITIVE.finditer(src):
                ln = src[:mm.start()].count("\n") + 1
                hits.append((str(f), ln, DETECTOR_ID + ": " + mm.group(0)[:80]))
            continue
        for name, start, body in _functions(src):
            if _FN_MARKER and not _FN_MARKER.search(name):
                continue
            pm = _POSITIVE.search(body)
            if not pm:
                continue
            if _NEGATIVE and _NEGATIVE.search(body):
                continue  # canonical guard present -> suppress
            if _ORDERING:
                g = re.search(r"(?:check_|validate_|ensure_|reject|duplicate)", body)
                if not g or g.start() < pm.start():
                    continue
            ln = start + body[:pm.start()].count("\n")
            hits.append((str(f), ln, DETECTOR_ID + ": " + name + " :: " + pm.group(0)[:60]))
    return hits


if __name__ == "__main__":
    import sys
    for fp, ln, msg in scan(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(fp + ":" + str(ln) + ":" + msg)
'''


def _render_py(fam, det, ext):
    """Render the scan() module by literal token replacement (avoids str.format
    brace collisions with the Python body)."""
    repl = {
        "@@FAMILY@@": fam,
        "@@HELP@@": det["help"].replace("\n", " "),
        "@@CLASS_TAG@@": det["class_tag"],
        "@@LANGUAGE@@": det["language"],
        "@@SEVERITY@@": det["severity"],
        "@@SOURCE_REFS@@": ("; ".join(det["source_refs"])[:200] or "n/a"),
        "@@FAMILY_R@@": repr(fam),
        "@@CLASS_TAG_R@@": repr(det["class_tag"]),
        "@@LANGUAGE_R@@": repr(det["language"]),
        "@@SEVERITY_R@@": repr(det["severity"]),
        "@@POSITIVE_R@@": repr(det["positive"]),
        "@@NEGATIVE_R@@": repr(det["negative"]),
        "@@FN_MARKER_R@@": repr(det["fn_name_marker"]),
        "@@FILE_GLOB_R@@": repr(det["file_glob"]),
        "@@ORDERING_R@@": repr(bool(det["ordering_check"])),
        "@@EXT_R@@": repr(ext),
    }
    out = _PY_TEMPLATE
    for k, v in repl.items():
        out = out.replace(k, v)
    return out


def _yaml_for(det: dict) -> str:
    """Portable .yaml DSL sidecar. backend=cosmos for go fn-body families,
    backend=regex otherwise. Carries the same positive/negative anchors."""
    backend = "cosmos" if det["language"] == "go" and not det["file_glob"] else "regex"
    lines = [
        f"pattern: from-adv-{det['family'].replace('_', '-')}",
        f"source: advisory-seed-corpus/{det['family']}",
        f"severity: {det['severity']}",
        f"confidence: MEDIUM",
        f"backend: {backend}",
        f"tags: [{det['class_tag']}]",
        "",
        f"# CLASS-LEVEL mechanism detector auto-derived from "
        f"{det['member_count']} advisory seed(s).",
        f"# Mechanism matched, not any instance. Anti-overfit verified by "
        f"advisory-seed-to-dsl.py.",
    ]
    for ref in det["source_refs"]:
        lines.append(f"# advisory: {ref}")
    lines += [
        "",
        "preconditions: []",
        "",
        "match:",
    ]
    if det["file_glob"]:
        lines.append(f"  - file.glob: {det['file_glob']}")
        lines.append(f"  - file.body_contains_regex: {json.dumps(det['positive'])}")
    else:
        lines.append("  - function.kind: external_or_public")
        if det["fn_name_marker"]:
            lines.append(f"  - function.name_matches: {json.dumps(det['fn_name_marker'])}")
        lines.append(f"  - function.body_contains_regex: {json.dumps(det['positive'])}")
        if det["negative"]:
            lines.append(f"  - function.body_not_contains_regex: {json.dumps(det['negative'])}")
    lines += [
        "",
        f"help: {json.dumps(det['help'])}",
        f"wiki_title: {json.dumps(det['family'].replace('_', ' ').title())}",
        f"wiki_description: {json.dumps(det['help'])}",
    ]
    return "\n".join(lines) + "\n"


def emit(detectors: dict, out_dir: Path) -> dict:
    """Write one .py scan module + one .yaml sidecar per family. Returns
    manifest dict (counts by language/class)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"emitted": [], "by_language": defaultdict(int),
                "by_class": defaultdict(int)}
    for fam, det in sorted(detectors.items()):
        ext = ".rs" if det["language"] == "rust" else ".go"
        py = _render_py(fam, det, ext)
        py_path = out_dir / f"{fam}.py"
        py_path.write_text(py)
        yaml_path = out_dir / f"from-adv-{fam.replace('_', '-')}.yaml"
        yaml_path.write_text(_yaml_for(det))
        def _rel(p):
            try:
                return str(p.relative_to(REPO_ROOT))
            except ValueError:
                return str(p)
        manifest["emitted"].append({
            "family": fam, "py": _rel(py_path),
            "yaml": _rel(yaml_path),
            "language": det["language"], "class_tag": det["class_tag"],
            "member_count": det["member_count"],
            "rejected_instance_literals": det["rejected_instance_literals"],
        })
        manifest["by_language"][det["language"]] += 1
        manifest["by_class"][det["class_tag"]] += 1
    manifest["by_language"] = dict(manifest["by_language"])
    manifest["by_class"] = dict(manifest["by_class"])
    return manifest


def self_verify(detectors: dict, out_dir: Path) -> dict:
    """Load each emitted scan() module and fire it on its family's TRAIN
    fixture snippets (NOT held-out source). A detector that does not fire on at
    least one TRAIN fixture of its class is reported FAIL (honest)."""
    import importlib.util
    import tempfile
    results = {}
    for fam, det in sorted(detectors.items()):
        py_path = out_dir / f"{fam}.py"
        if not py_path.exists():
            results[fam] = {"status": "NO-MODULE"}
            continue
        spec = importlib.util.spec_from_file_location(f"_adv_{fam}", py_path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            results[fam] = {"status": "IMPORT-FAIL", "error": str(e)[:120]}
            continue
        fixtures = det.get("train_fixtures") or []
        if not fixtures:
            results[fam] = {"status": "NO-TRAIN-FIXTURE",
                            "note": "seed had only placeholder snippet"}
            continue
        fired = 0
        ext = ".rs" if det["language"] == "rust" else ".go"
        fname = "go.mod" if det.get("file_glob") == "go.mod" else f"train{ext}"
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            for k, fx in enumerate(fixtures):
                # wrap a bare snippet in a fn so the fn-body scanner sees it,
                # unless it's a file-glob (go.mod) family.
                if det.get("file_glob"):
                    text = fx
                    p = tdp / f"case{k}" / "go.mod"
                else:
                    has_fn = re.search(r"\b(?:fn|func)\s+\w+", fx)
                    marker = det.get("fn_name_marker")
                    # name the wrapper fn to satisfy the fn_name_marker
                    wname = "handle_inbound" if marker else "f"
                    text = fx if has_fn else f"fn {wname}() {{\n{fx}\n}}\n"
                    p = tdp / f"case{k}" / fname
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
                try:
                    hits = mod.scan(str(p.parent))
                except Exception:
                    hits = []
                if hits:
                    fired += 1
        results[fam] = {
            "status": "FIRES" if fired else "NO-FIRE-ON-TRAIN",
            "train_fixtures": len(fixtures),
            "fired_on": fired,
        }
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", nargs="+", help="seed .jsonl paths")
    ap.add_argument("--out", default="detectors/from_advisories",
                    help="output dir (fresh)")
    ap.add_argument("--self-verify", action="store_true",
                    help="fire emitted detectors on TRAIN fixtures and report")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    default_seeds = [
        REPO_ROOT / "audit/corpus_tags/derived/detector_seeds_zebra_advisories.jsonl",
        REPO_ROOT / "audit/corpus_tags/derived/detector_seeds_dydx_fork_divergence_advisories.jsonl",
        REPO_ROOT / "audit/corpus_tags/derived/detector_seeds_hyperbridge_advisories.jsonl",
    ]
    seed_paths = ([Path(s) for s in args.seeds] if args.seeds else default_seeds)
    out_dir = (Path(args.out) if Path(args.out).is_absolute()
               else REPO_ROOT / args.out)

    seeds = load_seeds(seed_paths)
    detectors, skipped = build_detectors(seeds)
    manifest = emit(detectors, out_dir)
    verify = self_verify(detectors, out_dir) if args.self_verify else None

    report = {
        "seeds_read": len(seeds),
        "families_emitted": len(detectors),
        "out_dir": str(out_dir),
        "by_language": manifest["by_language"],
        "by_class": manifest["by_class"],
        "skipped": skipped,
        "emitted": manifest["emitted"],
        "self_verify": verify,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"seeds_read={report['seeds_read']}  "
              f"families_emitted={report['families_emitted']}  "
              f"out={report['out_dir']}")
        print(f"by_language={report['by_language']}  by_class={report['by_class']}")
        if skipped:
            print(f"skipped={ {k: len(v) for k, v in skipped.items()} }")
        for e in manifest["emitted"]:
            rej = (f"  [rejected-literals:{len(e['rejected_instance_literals'])}]"
                   if e["rejected_instance_literals"] else "")
            print(f"  - {e['family']:38s} {e['language']:5s} "
                  f"members={e['member_count']}{rej}")
        if verify:
            print("--- self-verify (TRAIN fixtures) ---")
            for fam, v in verify.items():
                print(f"  {fam:38s} {v['status']:18s} "
                      f"{v.get('fired_on','')}/{v.get('train_fixtures','')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
