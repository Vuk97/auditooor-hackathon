#!/usr/bin/env python3
# <!-- r36-rebuttal: single-owner lane terminal-iter1-A; orchestrator commits; only this tool + its test + the generated corpus jsonl + schema are touched -->
"""fetchable-vuln-corpus-build.py - reproducibly build the held-out MEASUREMENT
corpus (reference/fetchable_vuln_corpus.jsonl) that auditor-backtest.py and
capability-metric-publisher.py read.

Problem this answers
--------------------
PR3a wired FETCHABLE-ONLY admission + split discipline into auditor-backtest.py,
and capability-metric-publisher.py defaults to reading
`reference/fetchable_vuln_corpus.jsonl`. But that file was NEVER populated, so
PR11 measured 0 scorable cases - the whole measurement loop produced
"0 scorable" not "X% recall". This builder fills the gap HONESTLY: it emits one
case per CONFIRMED, source-backed, ON-DISK-FETCHABLE vulnerability the team
already found, mapped to a real file:line in a checked-out repo at a known SHA.

A case is admitted ONLY when its cited file actually resolves inside a real git
checkout. That is the fetchability guarantee the backtest relies on: the
detection layer is handed live, re-readable source, so a MISS is a real
capability miss and a CAUGHT is a real catch.

Two sources (both produce identical case schema)
------------------------------------------------
  (i)  TRUSTED corpus records (via tools/lib/trusted_corpus_resolver.py) -
       ACTIVE-tier only (trust_state=='active'). Prose / fabricated / advisory /
       quarantined rows are NEVER admitted (this is the 0/40-confound fix). A
       trusted row is admitted only when it carries repo/prefix_ref + vuln_class
       + file_line AND a local checkout for that repo/ref is present so the
       source is genuinely fetchable. When the trusted index is absent (PR1 not
       yet run) this source contributes zero cases - it does NOT fall back to the
       raw, unfiltered corpus (that would re-introduce the confound).
  (ii) CONFIRMED on-disk findings under <audits-root>/<ws>/submissions/{filed,
       paste_ready} - real findings whose draft cites a file:line that resolves
       in the workspace's checked-out source tree at the recorded HEAD SHA.
       KILLED / DROP / NEGATIVE / FP / concession / *-CANDIDATE folders are
       excluded (those are not confirmed positives).

Case schema (one JSON object per line)
--------------------------------------
    {
      "case_id":    "<ws>--<slug>",            # stable
      "id":         "<ws>--<slug>",            # alias auditor-backtest reads
      "repo":       "owner/name",              # from the checkout origin url
      "repo_url":   "https://github.com/owner/name(.git)",
      "prefix_ref": "<full-sha>",              # the checked-out HEAD (audit pin)
      "vuln_class": "reentrancy",              # normalized attack/vuln class
      "language":   "solidity|rust|go|move|cairo|...",
      "file_line":  "rel/path/File.sol:142",   # resolves under the checkout
      "split":      "TRAIN|HELD_OUT",          # class-disjoint deterministic
      "source_tier":"onchain-confirmed-finding|trusted-active-corpus",
      "fetch_status":"immutable_ready",        # auditor-backtest fetchable status
      "short_desc": "<one-line>",
      "local_checkout": "/abs/path/to/checkout"  # so backtest reads it offline
    }

ANTI-OVERFIT split - TWO reproducible modes (--split-mode)
----------------------------------------------------------
None of the confirmed findings were used to author the DSL detectors (they are
net-new audit findings, not detector-authoring fixtures), so any of them is a
legitimate held-out target. Two split modes answer two DIFFERENT capability
questions; both are deterministic and reproducible (same input -> same split):

  (A) class-disjoint  (default; measures NOVEL-VECTOR / unseen-class capability)
      Partition by vuln_class and assign WHOLE classes to HELD_OUT vs TRAIN by a
      deterministic hash of the class name. A held-out class shares NO case with
      any TRAIN class, so its recall is a CLASS-LEVEL number: "can a detector
      built without ever seeing class X catch class X". A class never appears in
      both splits.

        held_out  <=>  (sha256('<seed>:'+vuln_class) mod 100) < HELD_OUT_PCT

  (B) instance-holdout (measures GENERALIZATION within a known class)
      Train and held-out SHARE classes but hold out DIFFERENT INSTANCES. Within
      each vuln_class the cases are partitioned ~(100-pct)/pct TRAIN/HELD_OUT by
      a deterministic hash of the per-INSTANCE case_id. A class with >=2 cases
      can therefore contribute to BOTH splits, making it measurable whether a
      CLASS-LEVEL detector built on TRAIN instances of a class generalizes to
      UNSEEN instances of the SAME class. Singleton classes (one case) fall
      wholly into TRAIN under instance-holdout so a single instance is never the
      only held-out probe for its class.

        held_out  <=>  (sha256('<seed>:'+case_id) mod 100) < HELD_OUT_PCT
                       AND the class has >=2 cases AND >=1 case stays in TRAIN

Both modes write split values TRAIN / HELD_OUT (the values every consumer
already normalizes), plus a per-case `split_mode` field naming which rule drew
the split. The header records the active mode + rule text.

Set --held-out-pct to tune the holdout fraction; --seed salts the hash so a
different but still valid partition can be drawn.

ANTI-OVERFIT (HARD RULE): detectors are authored on TRAIN + the advisory corpus
+ general bug-class knowledge ONLY, and graded on HELD_OUT. A detector whose
pattern is a verbatim slice of a held-out file's literal strings is instance-
memorization (cheating), not class-level detection. The held-out source files
must NOT be read when authoring detectors.

HONESTY
-------
- Only cases whose source actually resolves on disk are emitted. If that yields
  a small corpus, the real (small) count is reported - no padding with
  prose/fabricated rows.
- A low held-out recall when the backtest runs later is the TRUTH and is
  required to be reported as-is. This builder does not touch recall; it only
  assembles fetchable cases.

Usage
-----
    # canonical class-disjoint corpus (novel-vector / unseen-class recall)
    python3 tools/fetchable-vuln-corpus-build.py \
        [--audits-root /Users/wolf/audits] \
        [--workspaces morpho-midnight,hyperbridge,near,dydx,zebra,aztec,...] \
        [--out reference/fetchable_vuln_corpus.jsonl] \
        [--split-mode class-disjoint] [--held-out-pct 50] [--seed 0] \
        [--json] [--dry-run]

    # instance-holdout corpus (generalization to unseen instances of a class)
    python3 tools/fetchable-vuln-corpus-build.py \
        --split-mode instance-holdout --held-out-pct 30 \
        --out reference/fetchable_vuln_corpus.instance_holdout.jsonl

Writes the jsonl + a sibling `.header.json` describing the split rule + counts.
Exits 0 (measurement builder). --json prints the build summary to stdout.

RELATED TOOLS:
  * tools/auditor-backtest.py - CONSUMES this corpus (per-case CAUGHT/MISSED/NA).
    This builder PRODUCES the corpus; it never grades. DISJOINT file.
  * tools/capability-metric-publisher.py - CONSUMES this corpus across splits
    and computes held-out recall. PRODUCES nothing here.
  * tools/lib/trusted_corpus_resolver.py - source (i) read path (active tier).
  * tools/trusted-corpus-index-build.py (PR1, future) - builds the trusted index
    source (i) prefers; until it exists, source (i) contributes zero and all
    cases come from source (ii) on-disk findings.

Gap filled: no existing tool ASSEMBLED a fetchable, source-resolved, split-
tagged measurement corpus from confirmed on-disk findings + the active trusted
corpus. The catch-rate self-test builds fixture pairs, not external known-vuln
cases; the resolver picks a corpus path but does not project cases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDITS_ROOT = Path(os.environ.get("AUDITOOOR_AUDITS_ROOT", "/Users/wolf/audits"))
DEFAULT_WORKSPACES = [
    "morpho-midnight", "hyperbridge", "near", "dydx", "zebra", "aztec", "base-azul",
    "centrifuge-v3", "mezo", "reserve-governor", "revert-stableswap-hooks",
    "spark", "snowbridge", "nuva", "thegraph",
]
DEFAULT_OUT = REPO_ROOT / "reference" / "fetchable_vuln_corpus.jsonl"
SCHEMA = "auditooor.fetchable_vuln_corpus.v1"

sys.path.insert(0, str(REPO_ROOT / "tools" / "lib"))
try:
    import trusted_corpus_resolver as _tcr  # noqa: E402
except Exception:  # pragma: no cover - defensive
    _tcr = None

# Confirmed-positive status dirs. KILLED/superseded/oos are excluded by dir;
# DROP/NEGATIVE/FP/CANDIDATE/concession excluded by slug substring below.
CONFIRMED_STATUS_DIRS = ("filed", "paste_ready", "staging")
_NEG_SLUG_MARKERS = ("KILLED", "DROP", "NEGATIVE", "-FP", "CANDIDATE",
                     "concession", "-OOS", "DISPROVED", "AMENDMENT")

# language by file extension
_EXT_LANG = {
    ".sol": "solidity", ".vy": "vyper", ".rs": "rust", ".go": "go",
    ".move": "move", ".cairo": "cairo", ".ts": "typescript", ".py": "python",
    ".nr": "noir",
}

# full-path file:line ref inside a draft (must contain a '/' so it is a real
# relative path, not a bare filename we cannot resolve)
_FULLPATH_REF_RE = re.compile(
    r"`?([A-Za-z0-9_][A-Za-z0-9_./\-]*?/[A-Za-z0-9_./\-]+\."
    r"(?:sol|vy|rs|go|move|cairo|ts|py|nr)):(\d+)"
)
# structured header fields that, when present, carry the canonical site
_PRIMARY_FIELD_RE = re.compile(
    r"^\s*-?\s*(?:source-proof|Affected component|impacted_surface|"
    r"impacted-surface|Location|File)\s*:",
    re.IGNORECASE,
)
_ATTACK_FIELD_RE = re.compile(
    r"^\s*-?\s*(?:attack_class|Attack class|attack-class|vuln_class)\s*:\s*"
    r"`?([A-Za-z0-9_./\- ]+?)`?(?:\s*[(\[].*)?\s*$",
    re.IGNORECASE,
)
# keyword -> canonical class, applied to the title + selected_impact prose when
# no clean attack_class field exists. Ordered: first match wins.
_IMPACT_KEYWORDS = [
    ("reentrancy", ("reentran", "callback re-enter", "reenter")),
    ("signature-replay", ("replay", "domain separation", "cross-extrinsic",
                          "signature.*reuse", "missing.*domain")),
    ("integer-truncation", ("truncat", "low_u128", "u256-to-u128",
                            "downcast", "overflow", "underflow")),
    ("access-control", ("access control", "unauthorized", "onlyowner",
                        "privilege", "missing.*auth", "permission")),
    ("oracle-manipulation", ("oracle", "price manip", "twap", "stale price")),
    ("fund-theft", ("stealing or loss of funds", "direct.*loss", "drain",
                    "cross-user loss", "theft", "loss of funds")),
    ("fund-freeze", ("permanently frozen", "permanently freeze", "funds.*frozen",
                     "never receive", "non-payable", "freeze")),
    ("dos-resource-exhaustion", ("denial of service", "resource-exhaustion",
                                 "resource exhaustion", "slot leak", "saturate",
                                 "unbounded", "exhaust", "ddos", "ndos",
                                 " dos ", "cwe-770", "cwe-941")),
    ("decode-mismatch", ("decode-mismatch", "type confusion", "rlp", "mpt branch")),
    ("validator-set-injection", ("validator-set", "validator set injection",
                                 "consensus", "ancestry")),
    ("business-logic", ("attacks on logic", "business description",
                        "insecure-business-logic", "incorrect behavior",
                        "logic where behavior")),
]
_SEVERITY_FIELD_RE = re.compile(
    r"^\s*-?\s*Severity(?:\s*Selector)?\s*:\s*`?([A-Za-z]+)", re.IGNORECASE
)


# --------------------------------------------------------------------------
# git checkout discovery
# --------------------------------------------------------------------------
def _git(cmd, cwd):
    try:
        return subprocess.run(
            ["git", "-C", str(cwd), *cmd],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip()
    except Exception:
        return ""


def _origin_to_owner_name(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    u = url.removesuffix(".git")
    u = u.replace("git@github.com:", "").replace("https://github.com/", "")
    u = u.replace("http://github.com/", "").replace("ssh://git@github.com/", "")
    parts = [p for p in u.split("/") if p]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return u


def discover_checkouts(ws_dir: Path) -> list:
    """Return [{root, repo, repo_url, ref}] for every git checkout under
    <ws>/src, <ws>/repos, <ws>/external (depth<=2)."""
    out = []
    for sub in ("src", "repos", "external"):
        base = ws_dir / sub
        if not base.is_dir():
            continue
        # the base itself may be a checkout, or contain them one level down
        candidates = [base] + [p for p in base.iterdir() if p.is_dir()]
        for cand in candidates:
            if not (cand / ".git").exists():
                continue
            url = _git(["config", "--get", "remote.origin.url"], cand)
            ref = _git(["rev-parse", "HEAD"], cand)
            if not ref:
                continue
            out.append({
                "root": cand,
                "repo": _origin_to_owner_name(url),
                "repo_url": url,
                "ref": ref,
            })
    return out


def resolve_in_checkouts(rel_path: str, checkouts: list):
    """Find rel_path inside any checkout. Returns (checkout, resolved_rel) or
    (None, None). Tries the path as-given relative to each checkout root, then
    a basename-suffix search so a workspace-relative path like
    `src/zebrad/.../downloads.rs` still resolves when the checkout root is
    `<ws>/src`."""
    rel_path = rel_path.lstrip("./")
    for ck in checkouts:
        root = ck["root"]
        direct = root / rel_path
        if direct.is_file():
            return ck, str(direct.relative_to(root))
        # suffix match: try trimming leading components until it resolves
        parts = rel_path.split("/")
        for i in range(len(parts)):
            cand = root / "/".join(parts[i:])
            if cand.is_file():
                return ck, str(cand.relative_to(root))
    return None, None


# --------------------------------------------------------------------------
# finding extraction
# --------------------------------------------------------------------------
# canonical-class synonym map so the class-disjoint split treats equivalent
# classes as ONE class (a held-out class must share no case with TRAIN).
_CLASS_SYNONYMS = {
    "theft": "fund-theft",
    "loss-of-funds": "fund-theft",
    "stealing-or-loss-of-funds": "fund-theft",
    "freeze": "fund-freeze",
    "frozen-funds": "fund-freeze",
    "permanent-freeze": "fund-freeze",
    "dos": "dos-resource-exhaustion",
    "denial-of-service": "dos-resource-exhaustion",
    "resource-exhaustion": "dos-resource-exhaustion",
    "decoder-correctness": "decode-mismatch",
    "decode-correctness": "decode-mismatch",
    "type-confusion": "decode-mismatch",
    "insecure-business-logic": "business-logic",
    "logic": "business-logic",
    "integer-overflow": "arithmetic",
    "integer-underflow": "arithmetic",
    "off-by-one": "arithmetic",
    "truncation": "integer-truncation",
    "replay": "signature-replay",
    "signature-reuse": "signature-replay",
}


def normalize_vuln_class(raw: str) -> str:
    s = (raw or "").strip().lower()
    # take the first token group before any " / " or "(" detail
    s = re.split(r"\s*[/(]", s)[0].strip()
    s = s.replace("_", "-").replace(" ", "-")
    s = re.sub(r"-+", "-", s).strip("-")
    return _CLASS_SYNONYMS.get(s, s)


def _candidate_refs(text: str) -> list:
    """Ordered, de-duplicated list of (rel_path, line) full-path refs.

    Primary refs (those on a structured `source-proof:`/`Affected component:`/
    `impacted_surface:` header field line) come first - those are the
    author-declared canonical bug site. When no structured field is present, the
    bug site is the one cited MOST OFTEN (a finding repeats its bug site across
    Summary/Details/PoC), tie-broken by EARLIEST appearance so a sibling/contrast
    citation (the "the correct path does X" reference, usually cited once, late)
    does not outrank the repeatedly-cited bug site."""
    primary = []
    freq = {}
    first_seen = {}
    for lineno, line in enumerate(text.splitlines()):
        is_primary = bool(_PRIMARY_FIELD_RE.match(line))
        for m in _FULLPATH_REF_RE.finditer(line):
            key = (m.group(1), int(m.group(2)))
            if is_primary and key not in primary:
                primary.append(key)
            freq[key] = freq.get(key, 0) + 1
            first_seen.setdefault(key, lineno)
    ordered = list(primary)
    for key in sorted(freq, key=lambda k: (-freq[k], first_seen[k], k[0], k[1])):
        if key not in ordered:
            ordered.append(key)
    return ordered


def _extract_field(text: str, regex) -> str:
    for line in text.splitlines():
        m = regex.match(line)
        if m:
            try:
                return m.group(1).strip()
            except IndexError:
                return ""
    return ""


def classify_by_keywords(text: str, slug: str) -> str:
    """Best-effort canonical class from the draft's title + selected_impact
    prose + slug, used only when no clean attack_class field is present."""
    title = ""
    impact = ""
    for line in text.splitlines():
        t = line.strip()
        if not title and t.startswith("# "):
            title = t[2:]
        m = re.match(r"^\s*-?\s*selected_impact\s*:\s*(.+)", t, re.IGNORECASE)
        if m and not impact:
            impact = m.group(1)
    blob = f"{title} {impact} {slug}".lower()
    for cls, kws in _IMPACT_KEYWORDS:
        for kw in kws:
            if re.search(kw, blob):
                return cls
    return ""


def is_confirmed_positive(status_dir: str, slug: str) -> bool:
    if status_dir not in CONFIRMED_STATUS_DIRS:
        return False
    su = slug.upper()
    return not any(mk.upper() in su for mk in _NEG_SLUG_MARKERS)


# flat-layout tracker/non-finding stems to skip (pre-R41 workspaces store
# `<status>/<slug>.md` directly; trackers/responses are not findings).
_FLAT_SKIP_STEMS = ("README", "SUBMISSIONS", "TO_FILE", "INDEX", "TRACKER")
_FLAT_SKIP_SUBSTR = ("triager_comment", "triager-response", "_response_",
                     "-HOLD", "HOLD-", "dispute", "amendment",
                     # research / triage / consolidated notes are NOT confirmed
                     # findings (often carry FALSE-POSITIVE / No-Finds verdicts)
                     ".notes", "-consolidated", "-triage", "no-find", "notes")


def find_finding_drafts(ws_dir: Path) -> list:
    """[(status_dir, slug, md_path)] for confirmed findings under submissions/,
    handling BOTH the canonical per-finding-folder layout (R41:
    `<status>/<slug>/<slug>.md`) AND the older flat layout
    (`<status>/<slug>.md`, e.g. dydx)."""
    out = []
    subs = ws_dir / "submissions"
    if not subs.is_dir():
        return out
    for status in CONFIRMED_STATUS_DIRS:
        sdir = subs / status
        if not sdir.is_dir():
            continue
        for entry in sorted(sdir.iterdir()):
            if entry.is_dir():
                md = entry / f"{entry.name}.md"
                if md.is_file():
                    out.append((status, entry.name, md))
            elif entry.is_file() and entry.suffix == ".md":
                stem = entry.stem
                su = stem.upper()
                if any(su == sk or su.startswith(sk) for sk in _FLAT_SKIP_STEMS):
                    continue
                if any(sub.lower() in stem.lower() for sub in _FLAT_SKIP_SUBSTR):
                    continue
                out.append((status, stem, entry))
    return out


def build_finding_case(ws: str, slug: str, md_path: Path, checkouts: list):
    """Project one confirmed finding into a case dict, or None if not fetchable."""
    text = md_path.read_text(errors="replace")
    # positive-evidence gate: a confirmed finding draft carries at least one of
    # the finding-shape signals. Research / triage / "No-Finds" notes do not.
    low = text.lower()
    has_finding_shape = any(s in low for s in (
        "selected_impact", "severity tier", "severity:", "attack_class",
        "attack class", "impacted_surface", "source-proof", "## poc",
    ))
    if not has_finding_shape:
        return None, "no-finding-shape-signal"
    # drop drafts whose dominant verdict is a negative (false positive / no-find)
    neg_hits = low.count("false positive") + low.count("no-find") + low.count("no finds")
    if neg_hits >= 2 and "verdict" in low:
        return None, "research-note-negative-verdict"
    refs = _candidate_refs(text)
    if not refs:
        return None, "no-fullpath-ref"
    chosen = None
    for rel_path, line in refs:
        ck, resolved = resolve_in_checkouts(rel_path, checkouts)
        if ck is not None:
            chosen = (ck, resolved, line)
            break
    if chosen is None:
        return None, "no-ref-resolves-in-checkout"
    ck, resolved_rel, line = chosen
    ext = Path(resolved_rel).suffix.lower()
    lang = _EXT_LANG.get(ext, "unknown")
    vuln_class = normalize_vuln_class(_extract_field(text, _ATTACK_FIELD_RE))
    if not vuln_class or vuln_class in ("logic", "insecure-business-logic"):
        # fall back to keyword classification over title + selected_impact prose
        kw = classify_by_keywords(text, slug)
        if kw:
            vuln_class = normalize_vuln_class(kw)
    if not vuln_class:
        vuln_class = "business-logic"
    severity = (_extract_field(text, _SEVERITY_FIELD_RE) or "").lower()
    # one-line desc = first non-empty H1 or first prose sentence
    short = ""
    for line_t in text.splitlines():
        t = line_t.strip()
        if t.startswith("# "):
            short = t[2:].strip()
            break
    short = (short or slug).replace("`", "")[:200]
    case_id = f"{ws}--{slug}"
    return {
        "schema": SCHEMA,
        "case_id": case_id,
        "id": case_id,
        "repo": ck["repo"],
        "repo_url": ck["repo_url"],
        "prefix_ref": ck["ref"],
        "vuln_class": vuln_class,
        "language": lang,
        "file_line": f"{resolved_rel}:{line}",
        "source_tier": "onchain-confirmed-finding",
        "fetch_status": "immutable_ready",
        "severity_hint": severity,
        "short_desc": short,
        "local_checkout": str(ck["root"]),
        "workspace": ws,
    }, "ok"


# --------------------------------------------------------------------------
# trusted active-corpus source (i)
# --------------------------------------------------------------------------
def load_trusted_active_cases(checkouts_by_repo: dict) -> tuple:
    """Return (cases, note). Reads the ACTIVE trusted index only. A row is
    admitted only when trust_state=='active' AND it carries repo/prefix_ref +
    vuln_class + file_line AND a local checkout for that repo exists so source
    is fetchable. When the trusted index is absent -> ([], reason)."""
    if _tcr is None:
        return [], "trusted_corpus_resolver-unavailable"
    if not _tcr.trusted_index_available(REPO_ROOT):
        return [], "trusted-index-absent-source-i-contributes-zero"
    res = _tcr.resolve_active_corpus(repo_root_path=REPO_ROOT)
    idx = Path(res.primary_path)
    if not idx.is_file():
        return [], "trusted-index-path-missing"
    cases = []
    for raw in idx.read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        if (row.get("trust_state") or "").strip().lower() != "active":
            continue
        repo = row.get("target_repo") or row.get("repo") or ""
        ref = row.get("prefix_ref") or row.get("vulnerable_ref_full_sha") or ""
        fl = row.get("file_line") or ""
        vc = row.get("attack_class") or row.get("bug_class") or row.get("vuln_class") or ""
        if not (repo and ref and fl and vc):
            continue
        ck = checkouts_by_repo.get(_origin_to_owner_name(repo))
        if ck is None:
            continue  # not fetchable on disk -> drop honestly
        # verify the cited file resolves
        rel, _, _ln = fl.partition(":")
        _ckhit, resolved = resolve_in_checkouts(rel, [ck])
        if resolved is None:
            continue
        line = fl.rpartition(":")[2]
        ext = Path(resolved).suffix.lower()
        cid = f"trusted--{row.get('record_id', 'rec')}"
        cases.append({
            "schema": SCHEMA,
            "case_id": cid,
            "id": cid,
            "repo": ck["repo"],
            "repo_url": ck["repo_url"],
            "prefix_ref": ck["ref"],
            "vuln_class": normalize_vuln_class(vc),
            "language": _EXT_LANG.get(ext, "unknown"),
            "file_line": f"{resolved}:{line}" if line.isdigit() else resolved,
            "source_tier": "trusted-active-corpus",
            "fetch_status": "immutable_ready",
            "severity_hint": "",
            "short_desc": (row.get("record_id") or cid)[:200],
            "local_checkout": str(ck["root"]),
            "workspace": "",
        })
    return cases, f"trusted-active-admitted-{len(cases)}"


# --------------------------------------------------------------------------
# split assignment - two deterministic modes
# --------------------------------------------------------------------------
SPLIT_MODES = ("class-disjoint", "instance-holdout")


def _bucket(key: str, seed: int) -> int:
    h = hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()
    return int(h[:8], 16) % 100


def assign_split(vuln_class: str, held_out_pct: int, seed: int) -> str:
    """(A) class-disjoint: whole vuln_class -> HELD_OUT or TRAIN by class hash.

    Kept as the module-level entry the tests + class-disjoint mode call. A
    class never spans both splits.
    """
    return "HELD_OUT" if _bucket(vuln_class, seed) < held_out_pct else "TRAIN"


def assign_splits_class_disjoint(cases: list, held_out_pct: int, seed: int):
    for c in cases:
        c["split"] = assign_split(c["vuln_class"], held_out_pct, seed)
        c["split_mode"] = "class-disjoint"


def assign_splits_instance_holdout(cases: list, held_out_pct: int, seed: int):
    """(B) instance-holdout: within each class, hold out DIFFERENT INSTANCES by
    per-case_id hash so a class with >=2 cases lands in BOTH splits.

    Two invariants enforced deterministically:
      - a singleton class (one case) is wholly TRAIN (a lone instance is never
        the only held-out probe for its class);
      - a multi-case class always keeps >=1 case in TRAIN (so TRAIN has a
        same-class instance to author the class-level detector from) and, when
        the per-instance hash would have held out NONE, forces the lowest-hash
        instance into HELD_OUT so the class is genuinely measurable on unseen
        instances.
    """
    by_class: dict = {}
    for c in cases:
        by_class.setdefault(c["vuln_class"], []).append(c)
    for vc, group in by_class.items():
        for c in group:
            c["split_mode"] = "instance-holdout"
        if len(group) < 2:
            for c in group:
                c["split"] = "TRAIN"
            continue
        # deterministic per-instance assignment
        ranked = sorted(group, key=lambda c: (_bucket(c["case_id"], seed),
                                              c["case_id"]))
        for c in ranked:
            c["split"] = ("HELD_OUT"
                          if _bucket(c["case_id"], seed) < held_out_pct
                          else "TRAIN")
        held = [c for c in ranked if c["split"] == "HELD_OUT"]
        train = [c for c in ranked if c["split"] == "TRAIN"]
        # guarantee both sides non-empty for a multi-case class
        if not held:
            ranked[0]["split"] = "HELD_OUT"          # lowest-hash -> held out
        elif not train:
            ranked[-1]["split"] = "TRAIN"            # highest-hash -> train


# --------------------------------------------------------------------------
# main build
# --------------------------------------------------------------------------
def build_corpus(audits_root: Path, workspaces: list, held_out_pct: int,
                 seed: int, split_mode: str = "class-disjoint") -> tuple:
    if split_mode not in SPLIT_MODES:
        raise ValueError(f"split_mode must be one of {SPLIT_MODES}, got {split_mode!r}")
    cases = []
    skipped = []
    checkouts_by_repo = {}
    for ws in workspaces:
        ws_dir = audits_root / ws
        if not ws_dir.is_dir():
            skipped.append({"ws": ws, "reason": "workspace-dir-absent"})
            continue
        checkouts = discover_checkouts(ws_dir)
        for ck in checkouts:
            if ck["repo"]:
                checkouts_by_repo.setdefault(ck["repo"], ck)
        if not checkouts:
            skipped.append({"ws": ws, "reason": "no-git-checkout"})
            continue
        for status, slug, md in find_finding_drafts(ws_dir):
            if not is_confirmed_positive(status, slug):
                skipped.append({"ws": ws, "slug": slug,
                                "reason": "not-confirmed-positive"})
                continue
            case, why = build_finding_case(ws, slug, md, checkouts)
            if case is None:
                skipped.append({"ws": ws, "slug": slug, "reason": why})
                continue
            cases.append(case)

    # source (i): trusted active corpus
    trusted_cases, trusted_note = load_trusted_active_cases(checkouts_by_repo)
    cases.extend(trusted_cases)

    # dedupe by (repo, file_line) keeping the first (a root cause filed in
    # multiple statuses should appear once)
    seen = set()
    deduped = []
    for c in cases:
        key = (c["repo"], c["file_line"])
        if key in seen:
            skipped.append({"slug": c["case_id"], "reason": "dupe-repo-file_line"})
            continue
        seen.add(key)
        deduped.append(c)
    cases = deduped

    # assign split per the chosen mode
    if split_mode == "instance-holdout":
        assign_splits_instance_holdout(cases, held_out_pct, seed)
    else:
        assign_splits_class_disjoint(cases, held_out_pct, seed)

    if split_mode == "instance-holdout":
        split_rule = (
            "instance-holdout deterministic: within each vuln_class, held_out "
            f"<=> (sha256('{seed}:'+case_id) mod 100) < {held_out_pct}. Train and "
            "held-out SHARE classes but hold out DIFFERENT INSTANCES; a class "
            "with >=2 cases lands in BOTH splits (>=1 case forced to each side), "
            "so held-out recall measures GENERALIZATION to UNSEEN instances of a "
            "KNOWN class. Singleton classes fall wholly into TRAIN. None of these "
            "findings were used to author the DSL detectors."
        )
    else:
        split_rule = (
            "class-disjoint deterministic: held_out <=> "
            f"(sha256('{seed}:'+vuln_class) mod 100) < {held_out_pct}. "
            "Whole vuln_classes are assigned to HELD_OUT or TRAIN; a held-out "
            "class shares NO case with any TRAIN class, so the held-out recall "
            "is a class-level generalization number, not instance-level. None "
            "of these findings were used to author the DSL detectors."
        )

    # per-class both-sides count (meaningful for instance-holdout)
    per_class_splits: dict = {}
    for c in cases:
        per_class_splits.setdefault(c["vuln_class"], set()).add(c["split"])
    classes_in_both = sorted(
        k for k, v in per_class_splits.items() if {"TRAIN", "HELD_OUT"} <= v
    )

    header = {
        "schema": "auditooor.fetchable_vuln_corpus_header.v1",
        "split_mode": split_mode,
        "split_modes_available": list(SPLIT_MODES),
        "split_rule": split_rule,
        "split_rule_class_disjoint": (
            "class-disjoint: whole vuln_class -> HELD_OUT/TRAIN by class hash; "
            "measures novel-vector / unseen-class capability; a class never "
            "spans both splits."
        ),
        "split_rule_instance_holdout": (
            "instance-holdout: per-case_id hash within each class; classes with "
            ">=2 cases land in both splits; measures class-level detector "
            "generalization to unseen instances of the same class."
        ),
        "classes_in_both_splits": classes_in_both,
        "classes_in_both_splits_count": len(classes_in_both),
        "held_out_pct": held_out_pct,
        "seed": seed,
        "audits_root": str(audits_root),
        "workspaces": workspaces,
        "trusted_source_note": trusted_note,
        "anti_overfit_rule": (
            "detectors authored on TRAIN + advisory corpus + general bug-class "
            "knowledge ONLY, graded on HELD_OUT; held-out source files must NOT "
            "be read at authoring time; a verbatim slice of a held-out file is "
            "instance-memorization (cheating), not class-level detection."
        ),
        "fetchability_guarantee": (
            "every emitted case's file_line resolves inside a real git checkout "
            "at the recorded prefix_ref; non-resolving citations are dropped."
        ),
    }
    return cases, header, skipped


def summarize(cases: list) -> dict:
    by_split, by_lang, by_class, by_tier = {}, {}, {}, {}
    for c in cases:
        by_split[c["split"]] = by_split.get(c["split"], 0) + 1
        by_lang[c["language"]] = by_lang.get(c["language"], 0) + 1
        by_class[c["vuln_class"]] = by_class.get(c["vuln_class"], 0) + 1
        by_tier[c["source_tier"]] = by_tier.get(c["source_tier"], 0) + 1
    return {
        "total": len(cases),
        "by_split": dict(sorted(by_split.items())),
        "by_language": dict(sorted(by_lang.items(), key=lambda kv: -kv[1])),
        "by_vuln_class": dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
        "by_source_tier": dict(sorted(by_tier.items())),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audits-root", default=str(DEFAULT_AUDITS_ROOT))
    ap.add_argument("--workspaces", default=",".join(DEFAULT_WORKSPACES))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--held-out-pct", type=int, default=50)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--split-mode", choices=list(SPLIT_MODES),
                    default="class-disjoint",
                    help="class-disjoint (default; novel-vector/unseen-class "
                         "capability) or instance-holdout (generalization to "
                         "unseen instances of a known class).")
    ap.add_argument("--dry-run", action="store_true",
                    help="do not write the jsonl; just print the summary")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    workspaces = [w.strip() for w in args.workspaces.split(",") if w.strip()]
    cases, header, skipped = build_corpus(
        Path(args.audits_root), workspaces, args.held_out_pct, args.seed,
        split_mode=args.split_mode,
    )
    summary = summarize(cases)
    summary["split_mode"] = args.split_mode
    summary["classes_in_both_splits"] = header["classes_in_both_splits"]
    summary["classes_in_both_splits_count"] = header["classes_in_both_splits_count"]

    out_path = Path(args.out)
    if not args.dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"# {SCHEMA} - built by tools/fetchable-vuln-corpus-build.py"]
        lines.append(f"# split_mode={header['split_mode']}")
        lines.append("# " + header["split_rule"])
        for c in cases:
            lines.append(json.dumps(c, sort_keys=True))
        out_path.write_text("\n".join(lines) + "\n")
        (out_path.with_suffix(".header.json")).write_text(
            json.dumps({"header": header, "summary": summary,
                        "skipped_sample": skipped[:50],
                        "skipped_total": len(skipped)}, indent=2) + "\n"
        )

    report = {
        "schema": "auditooor.fetchable_vuln_corpus_build.v1",
        "out": str(out_path),
        "header": header,
        "summary": summary,
        "skipped_total": len(skipped),
        "dry_run": args.dry_run,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"fetchable-vuln-corpus: {summary['total']} cases -> {out_path}")
        print(f"  split_mode:     {summary['split_mode']}")
        print(f"  by_split:       {summary['by_split']}")
        print(f"  by_language:    {summary['by_language']}")
        print(f"  by_source_tier: {summary['by_source_tier']}")
        print(f"  by_vuln_class:  {summary['by_vuln_class']}")
        print(f"  classes_in_both_splits ({summary['classes_in_both_splits_count']}): "
              f"{summary['classes_in_both_splits']}")
        print(f"  skipped:        {len(skipped)} (see .header.json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
