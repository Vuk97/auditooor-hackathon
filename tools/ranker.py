#!/usr/bin/env python3
"""ranker — per-function hacker-mindset attack-class ranker (Phase-A MVP).

Implements scorers S1 + S4 from BIG_PLAN_2026-05-11 sub-report 06 §4. S2
(bug-family heatmap join) and S3 (cross-repo pattern transfer) are deferred
to Phase B per the design's "Phase-A weights: w1=0.7 w4=0.3, MVP skips
w2/w3".

Usage:
    python3 tools/ranker.py \
        --target-repo dydxprotocol/v4-chain \
        --file-path protocol/x/affiliates/keeper/msg_server.go \
        --function-signature 'func (k msgServer) RegisterAffiliate(...)' \
        [--audit-pin-sha SHA] [--top-n 5] [--min-confidence 0.4] [--json]

Output (YAML by default; JSON with --json):

    target: {repo, file_path, function_signature, shape_hash, shape_hash_fine}
    ranked_attack_classes:
      - attack_class: admin-bypass
        score: 3.42
        confidence: 0.91
        rank: 1
        evidence:
          - {verdict_id: ..., contribution: 1.20, scorer: S1}
          - {rule_id: RULE_D8, contribution: 1.50, scorer: S4}
    context_pack_id: ...
    context_pack_hash: ...
    generated_at_utc: ...

Stdlib-only. The ranker module is importable from the MCP server.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
SIG_EXTRACTS_DIR = REPO_ROOT / "audit" / "sig_extracts"
RANKER_RULES = REPO_ROOT / "audit" / "ranker_rules.yaml"
RANKER_WEIGHTS = REPO_ROOT / "audit" / "ranker_weights.yaml"
RANKER_WEIGHTS_PER_FAMILY = REPO_ROOT / "audit" / "ranker_weights_per_family.yaml"
SIBLING_FAMILIES = REPO_ROOT / "audit" / "sibling_repo_families.yaml"
BUG_CLASS_TO_AC_MAP = REPO_ROOT / "audit" / "bug_class_to_attack_classes_map.yaml"
CROSS_LANG_DETECTOR_MAP = REPO_ROOT / "reference" / "cross_lang_detector_map.yaml"
# Wave-14: attack-class negative-evidence subtraction. Caps confidence when
# none of the listed required primitives appear in calls_made (file-level
# shape-hash collapse FP fix). Audit anchor: x/accountplus/ante/ante.go
# scoring 0.91 fee-redirect with zero bankKeeper.SendCoins calls.
ATTACK_CLASS_PRIMITIVES = REPO_ROOT / "reference" / "attack_class_required_primitives.yaml"
CROSS_LANG_SYNONYMS_MAP = REPO_ROOT / "reference" / "cross_lang_bug_class_synonyms.yaml"
MCP_SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
PREDICTIONS_LOG = REPO_ROOT / "audit" / "ranker_predictions_log.jsonl"
import os  # for RANKER_PREDICTION_LOG_DISABLED env-var bypass


# --------------------------------------------------------------------------- #
# Wave-8: module-level tag/rule cache                                          #
#                                                                              #
# Each loader keeps (cached_value, mtime_at_load). On every call the          #
# directory / file mtime is compared; if unchanged the cache is returned       #
# directly (zero disk reads). If changed the data is reloaded and the cache   #
# updated.                                                                     #
#                                                                              #
# Set RANKER_CACHE_DISABLED=1 to bypass all caches (useful for tests that     #
# write temporary YAML files and need fresh reads).                            #
# --------------------------------------------------------------------------- #

_TAG_CACHE: "Optional[List[Any]]" = None          # noqa: F821 – forward ref ok at module level
_TAG_CACHE_MTIME: float = 0.0
_TAG_CACHE_DIR: "Optional[Path]" = None

_RULES_CACHE: "Optional[List[Any]]" = None        # noqa: F821
_RULES_CACHE_MTIME: float = 0.0
_RULES_CACHE_PATH: "Optional[Path]" = None

_BUG_CLASS_MAP_CACHE: "Optional[Dict[str, Any]]" = None  # noqa: F821
_BUG_CLASS_MAP_CACHE_MTIME: float = 0.0
_BUG_CLASS_MAP_CACHE_PATH: "Optional[Path]" = None

_CROSS_LANG_MAP_CACHE: "Optional[Dict[str, Any]]" = None  # noqa: F821
_CROSS_LANG_MAP_CACHE_MTIME: float = 0.0
_CROSS_LANG_MAP_CACHE_PATH: "Optional[Path]" = None

_CROSS_LANG_SYNONYMS_CACHE: "Optional[Dict[str, str]]" = None  # noqa: F821 — inverted: specific->canonical
_CROSS_LANG_SYNONYMS_CACHE_MTIME: float = 0.0
_CROSS_LANG_SYNONYMS_CACHE_PATH: "Optional[Path]" = None

# Wave-8: sig-extracts JSONL index cache.
# Maps repo_slug -> {file_path -> [record_dict, ...]}
# Avoids re-reading and re-parsing the ~14,500-line JSONL on every rank() call.
_SIG_EXTRACTS_CACHE: "Dict[str, Dict[str, List[Dict[str, Any]]]]" = {}  # noqa: F821
_SIG_EXTRACTS_CACHE_MTIME: "Dict[str, float]" = {}  # repo_slug -> mtime

# Wave-8: tags_dir mtime throttle.
# _tags_dir_mtime() globs+stats all *.yaml files, which is expensive when
# called on every cache-check in a hot loop.  We cache the computed mtime
# with a short recheck interval (default: 1.0s).  Within the TTL window, the
# previously computed mtime is returned directly without any filesystem ops.
_TAGS_DIR_MTIME_CACHE: "Dict[str, float]" = {}          # str(tags_dir) -> cached mtime
_TAGS_DIR_MTIME_CHECKED_AT: "Dict[str, float]" = {}     # str(tags_dir) -> time.monotonic() of last check
_TAGS_DIR_MTIME_TTL: float = 1.0                        # seconds


def _tags_dir_mtime(tags_dir: "Path") -> float:  # noqa: F821
    """Return max mtime across all *.yaml files in tags_dir, or 0.0 if empty.

    Result is cached for _TAGS_DIR_MTIME_TTL seconds to avoid repeated
    glob+stat on every cache-check in a hot rank() loop.
    """
    import time as _time
    key = str(tags_dir)
    now = _time.monotonic()
    if (
        key in _TAGS_DIR_MTIME_CACHE
        and (now - _TAGS_DIR_MTIME_CHECKED_AT.get(key, 0.0)) < _TAGS_DIR_MTIME_TTL
    ):
        return _TAGS_DIR_MTIME_CACHE[key]
    try:
        mtime = max(
            (p.stat().st_mtime for p in tags_dir.glob("*.yaml")),
            default=0.0,
        )
    except Exception:
        mtime = 0.0
    _TAGS_DIR_MTIME_CACHE[key] = mtime
    _TAGS_DIR_MTIME_CHECKED_AT[key] = now
    return mtime


def _file_mtime(path: "Path") -> float:  # noqa: F821
    """Return mtime of a single file, or 0.0 on error."""
    try:
        return path.stat().st_mtime
    except Exception:
        return 0.0


# --------------------------------------------------------------------------- #
# Helpers: load shape-hash module (its path has hyphens)                      #
# --------------------------------------------------------------------------- #

def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_SHAPE_HASH_MOD = None


def shape_hash_module():
    global _SHAPE_HASH_MOD
    if _SHAPE_HASH_MOD is None:
        _SHAPE_HASH_MOD = _load_module(
            "_ranker_shape_hash", REPO_ROOT / "tools" / "shape-hash.py"
        )
    return _SHAPE_HASH_MOD


# --------------------------------------------------------------------------- #
# Minimal YAML loader (subset: enough for ranker_rules.yaml + tag files)      #
# --------------------------------------------------------------------------- #
# The existing tools/verdict-tag-schema.py also ships a minimal YAML loader;
# we re-implement here for ranker independence (avoid load-order surprises).

_RX_BLANK = re.compile(r"^\s*(?:#.*)?$")


def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v


def _parse_scalar(s: str) -> Any:
    s = s.strip()
    if not s:
        return ""
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if s in ("null", "None", "~"):
        return None
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return _strip_quotes(s)
    # numeric?
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return s


def _parse_flow_list(s: str) -> List[Any]:
    """Parse a `[a, b, c]` flow list."""
    s = s.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return [s]
    inner = s[1:-1].strip()
    if not inner:
        return []
    parts: List[str] = []
    depth = 0
    buf: List[str] = []
    for ch in inner:
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return [_parse_scalar(p) for p in parts]


def yaml_load(text: str) -> Dict[str, Any]:
    """Very minimal YAML loader supporting:
      - top-level keys + nested mappings (indent-based)
      - block lists with `- key: value` and `- value` items
      - flow lists `[a, b]`
      - scalars (strings, ints, floats, bool, null)
    Not designed for general YAML; sufficient for ranker_rules.yaml + verdict tags.
    """
    lines = text.splitlines()
    pos = 0

    def _parse_block(indent: int) -> Any:
        nonlocal pos
        # Determine whether the block is a mapping or list by peeking
        result_map: Dict[str, Any] = {}
        result_list: List[Any] = []
        is_list = False
        first = True
        while pos < len(lines):
            line = lines[pos]
            if _RX_BLANK.match(line):
                pos += 1
                continue
            cur_indent = len(line) - len(line.lstrip(" "))
            if cur_indent < indent:
                break
            if cur_indent > indent:
                # belongs to a deeper block we didn't kick off — skip safely
                pos += 1
                continue
            stripped = line.strip()
            if stripped.startswith("- "):
                is_list = True
                first = False
                item_body = stripped[2:]
                if ":" in item_body and not item_body.startswith(("[", "{")):
                    # dict item, possibly multi-line
                    k, _, v = item_body.partition(":")
                    k = k.strip()
                    v = v.strip()
                    pos += 1
                    if v == "":
                        sub = _parse_block(indent + 2)
                        result_list.append({k: sub})
                    elif v.startswith("[") and v.endswith("]"):
                        result_list.append({k: _parse_flow_list(v)})
                    else:
                        item_dict = {k: _parse_scalar(v)}
                        # check for sibling keys at indent+2
                        while pos < len(lines):
                            nx = lines[pos]
                            if _RX_BLANK.match(nx):
                                pos += 1
                                continue
                            nx_indent = len(nx) - len(nx.lstrip(" "))
                            if nx_indent < indent + 2:
                                break
                            nx_stripped = nx.strip()
                            if nx_stripped.startswith("- "):
                                break
                            if ":" in nx_stripped:
                                kk, _, vv = nx_stripped.partition(":")
                                kk = kk.strip()
                                vv = vv.strip()
                                if vv == "":
                                    pos += 1
                                    item_dict[kk] = _parse_block(nx_indent + 2)
                                elif vv.startswith("[") and vv.endswith("]"):
                                    item_dict[kk] = _parse_flow_list(vv)
                                    pos += 1
                                else:
                                    item_dict[kk] = _parse_scalar(vv)
                                    pos += 1
                            else:
                                pos += 1
                        result_list.append(item_dict)
                else:
                    result_list.append(_parse_scalar(item_body))
                    pos += 1
            else:
                first = False
                if ":" in stripped:
                    k, _, v = stripped.partition(":")
                    k = k.strip()
                    v = v.strip()
                    pos += 1
                    if v == "":
                        sub = _parse_block(indent + 2)
                        result_map[k] = sub
                    elif v.startswith("[") and v.endswith("]"):
                        result_map[k] = _parse_flow_list(v)
                    elif v == "|" or v == ">":
                        # block scalar — slurp deeper indented lines
                        buf: List[str] = []
                        while pos < len(lines):
                            nx = lines[pos]
                            nx_indent = len(nx) - len(nx.lstrip(" "))
                            if nx.strip() == "" or nx_indent > indent:
                                buf.append(nx[indent + 2 :] if nx_indent >= indent + 2 else nx.strip())
                                pos += 1
                            else:
                                break
                        result_map[k] = "\n".join(buf).strip()
                    else:
                        result_map[k] = _parse_scalar(v)
                else:
                    pos += 1
        return result_list if is_list else result_map

    return _parse_block(0)


# --------------------------------------------------------------------------- #
# Tag loading                                                                 #
# --------------------------------------------------------------------------- #

@dataclass
class TagRecord:
    verdict_id: str
    target_repo: str
    audit_pin_sha: str
    language: str
    verdict_class: str
    bug_class: Optional[str]
    attack_classes_to_try: List[str]
    triager_outcome: Optional[str]
    drop_reason: Optional[str]
    sites: List[Dict[str, Any]]
    raw: Dict[str, Any]


def _load_tags_uncached(tags_dir: Path) -> List[TagRecord]:
    """Actual disk-reading implementation of load_tags (no cache)."""
    out: List[TagRecord] = []
    for tag_file in sorted(tags_dir.glob("*.yaml")):
        try:
            data = yaml_load(tag_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        rec = TagRecord(
            verdict_id=str(data.get("verdict_id", tag_file.stem)),
            target_repo=str(data.get("target_repo", "")),
            audit_pin_sha=str(data.get("audit_pin_sha", "")),
            language=str(data.get("language", "")),
            verdict_class=str(data.get("verdict_class", "")),
            bug_class=data.get("bug_class"),
            attack_classes_to_try=data.get("attack_classes_to_try") or [],
            triager_outcome=data.get("triager_outcome"),
            drop_reason=data.get("drop_reason"),
            sites=data.get("sites") or [],
            raw=data,
        )
        out.append(rec)
    return out


def load_tags(tags_dir: Path = TAGS_DIR) -> List[TagRecord]:
    """Load corpus tag records, using a module-level mtime cache.

    Cache is keyed by tags_dir path + directory mtime (max across all *.yaml
    files). Cache miss reloads from disk. Set RANKER_CACHE_DISABLED=1 to force
    disk reads every call (useful for tests that mutate the YAML files).
    """
    global _TAG_CACHE, _TAG_CACHE_MTIME, _TAG_CACHE_DIR
    if os.environ.get("RANKER_CACHE_DISABLED") == "1":
        return _load_tags_uncached(tags_dir)
    current_mtime = _tags_dir_mtime(tags_dir)
    if _TAG_CACHE is None or _TAG_CACHE_DIR != tags_dir or current_mtime > _TAG_CACHE_MTIME:
        _TAG_CACHE = _load_tags_uncached(tags_dir)
        _TAG_CACHE_MTIME = current_mtime
        _TAG_CACHE_DIR = tags_dir
    return _TAG_CACHE


# --------------------------------------------------------------------------- #
# Rule loading                                                                #
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    rule_id: str
    description: str
    provenance: str
    conditions: Dict[str, Any]
    contributes: Dict[str, float]


def _load_rules_uncached(rules_path: Path) -> List[Rule]:
    """Actual disk-reading implementation of load_rules (no cache)."""
    out: List[Rule] = []
    if not rules_path.exists():
        return out
    data = yaml_load(rules_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return out
    for rule_id, body in data.items():
        if not isinstance(body, dict):
            continue
        conds = body.get("conditions") or {}
        contribs_raw = body.get("contributes") or {}
        contribs: Dict[str, float] = {}
        for k, v in contribs_raw.items():
            try:
                contribs[k] = float(v)
            except (ValueError, TypeError):
                continue
        out.append(Rule(
            rule_id=str(rule_id),
            description=str(body.get("description", "")),
            provenance=str(body.get("provenance", "")),
            conditions=conds if isinstance(conds, dict) else {},
            contributes=contribs,
        ))
    return out


def load_rules(rules_path: Path = RANKER_RULES) -> List[Rule]:
    """Load ranker rules from YAML, using a module-level mtime cache.

    Cache miss (file changed or first call) reloads from disk. Set
    RANKER_CACHE_DISABLED=1 to bypass (for tests).
    """
    global _RULES_CACHE, _RULES_CACHE_MTIME, _RULES_CACHE_PATH
    if os.environ.get("RANKER_CACHE_DISABLED") == "1":
        return _load_rules_uncached(rules_path)
    current_mtime = _file_mtime(rules_path)
    if _RULES_CACHE is None or _RULES_CACHE_PATH != rules_path or current_mtime > _RULES_CACHE_MTIME:
        _RULES_CACHE = _load_rules_uncached(rules_path)
        _RULES_CACHE_MTIME = current_mtime
        _RULES_CACHE_PATH = rules_path
    return _RULES_CACHE


# --------------------------------------------------------------------------- #
# Function signature lookup (target side)                                     #
# --------------------------------------------------------------------------- #

def _load_sig_extracts_index(repo_slug: str) -> Dict[str, List[Dict[str, Any]]]:
    """Build a file_path -> [record, ...] index by reading the JSONL once.

    Called on cache miss. Returns empty dict if the JSONL doesn't exist.
    """
    jsonl = SIG_EXTRACTS_DIR / f"{repo_slug}.jsonl"
    index: Dict[str, List[Dict[str, Any]]] = {}
    if not jsonl.exists():
        return index
    with jsonl.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            fp = rec.get("file_path", "")
            if fp not in index:
                index[fp] = []
            index[fp].append(rec)
    return index


def _get_sig_extracts_index(repo_slug: str) -> Dict[str, List[Dict[str, Any]]]:
    """Return (and cache) the file_path index for repo_slug's JSONL.

    Uses module-level _SIG_EXTRACTS_CACHE keyed by repo_slug, with mtime-based
    invalidation. RANKER_CACHE_DISABLED=1 forces a fresh build every call.
    """
    jsonl = SIG_EXTRACTS_DIR / f"{repo_slug}.jsonl"
    if os.environ.get("RANKER_CACHE_DISABLED") == "1":
        return _load_sig_extracts_index(repo_slug)
    current_mtime = _file_mtime(jsonl)
    if (
        repo_slug not in _SIG_EXTRACTS_CACHE
        or current_mtime > _SIG_EXTRACTS_CACHE_MTIME.get(repo_slug, 0.0)
    ):
        _SIG_EXTRACTS_CACHE[repo_slug] = _load_sig_extracts_index(repo_slug)
        _SIG_EXTRACTS_CACHE_MTIME[repo_slug] = current_mtime
    return _SIG_EXTRACTS_CACHE[repo_slug]


def find_target_function(
    file_path: str,
    function_signature: Optional[str],
    repo_slug: str = "dydx-v4-chain",
) -> Optional[Dict[str, Any]]:
    """Look up a function record in the sig-extract JSONL for ``repo_slug``.

    Match priority:
      1. Exact file_path + function_signature substring (function_name)
      2. Exact file_path + first record in file
      3. Returns None

    Wave-8: uses module-level _SIG_EXTRACTS_CACHE index (file_path -> records)
    built once from the full JSONL. Avoids re-reading ~14,500 lines on every
    rank() call (dominant bottleneck after Wave-8 YAML caches landed).
    """
    index = _get_sig_extracts_index(repo_slug)
    candidates_in_file = index.get(file_path, [])
    if not candidates_in_file:
        return None
    name_filter: Optional[str] = None
    if function_signature:
        m = re.search(r"\b([A-Z][A-Za-z0-9_]*)\s*\(", function_signature)
        if m:
            name_filter = m.group(1)
    if name_filter:
        for rec in candidates_in_file:
            if rec.get("function_name") == name_filter:
                return rec
    return candidates_in_file[0]


# --------------------------------------------------------------------------- #
# Scorers                                                                     #
# --------------------------------------------------------------------------- #

OUTCOME_WEIGHTS = {
    "ACCEPTED": 1.0,
    "AMENDED_UP": 1.2,
    "AMENDED_DOWN": 0.6,
    "REJECTED_OOS": 0.1,
    "REJECTED_DUPE": 0.5,
    "PENDING": 0.4,
    "WITHDRAWN": 0.2,
}

# DROP-reason → outcome-like weight (Tier-6 anchor: b/c are still-live)
DROP_REASON_WEIGHTS = {
    "a-fix-stuck-no-residual": 0.1,
    "b-reverted": 0.8,
    "c-symptom-not-root": 0.6,
    "not-reachable": 0.2,
    "oos": 0.1,
    "benign-refactor": 0.1,
    "no-rubric-match": 0.3,
    "duplicate": 0.4,
    "fixed-post-pin": 0.1,
    "n/a": 0.4,
}


def outcome_weight(tag: TagRecord) -> float:
    if tag.triager_outcome and tag.triager_outcome in OUTCOME_WEIGHTS:
        return OUTCOME_WEIGHTS[tag.triager_outcome]
    if tag.verdict_class == "DROP" and tag.drop_reason:
        return DROP_REASON_WEIGHTS.get(tag.drop_reason, 0.3)
    if tag.verdict_class in ("FILED", "CONFIRMED"):
        return 0.8
    if tag.verdict_class in ("CANDIDATE", "NEAR-MISS", "HOLD"):
        return 0.5
    return 0.4


def recency_weight(tag: TagRecord, target_audit_pin_sha: Optional[str]) -> float:
    if target_audit_pin_sha and tag.audit_pin_sha:
        if (
            tag.audit_pin_sha.startswith(target_audit_pin_sha[:7])
            or target_audit_pin_sha.startswith(tag.audit_pin_sha[:7])
        ):
            return 1.0
        # Same target_repo but different audit-pin: medium recency
        return 0.7
    return 0.5


def shape_similarity(
    target_hash: str, target_hash_fine: str,
    site_hash: Optional[str], site_hash_fine: Optional[str],
    site_receiver_family: Optional[str], target_receiver_family: Optional[str],
) -> float:
    if not site_hash and not site_hash_fine:
        # No shape on the verdict side. Family-only similarity is the partial.
        if (
            site_receiver_family
            and target_receiver_family
            and site_receiver_family == target_receiver_family
        ):
            return 0.4
        return 0.0
    if site_hash and target_hash and site_hash == target_hash:
        return 1.0
    if site_hash_fine and target_hash_fine and site_hash_fine == target_hash_fine:
        return 0.7
    if (
        site_receiver_family
        and target_receiver_family
        and site_receiver_family == target_receiver_family
    ):
        return 0.4
    return 0.0


def _classify_recency(
    tag: TagRecord,
    target_repo: str,
    audit_pin_sha: Optional[str],
) -> str:
    """Classify a verdict's recency relative to the target as one of:
    'same_engagement', 'old_pin', or 'cross_engagement'.

    Classification rules:
      - same_engagement : tag.target_repo == target_repo AND tag.audit_pin_sha
        prefix-matches audit_pin_sha (or both are absent/unset).
      - old_pin         : tag.target_repo == target_repo but different (or
        missing) audit_pin_sha.
      - cross_engagement: tag.target_repo != target_repo.
    """
    if tag.target_repo and target_repo and tag.target_repo != target_repo:
        return "cross_engagement"
    # Same repo -- distinguish same-pin vs old-pin.
    if audit_pin_sha and tag.audit_pin_sha:
        if (
            tag.audit_pin_sha.startswith(audit_pin_sha[:7])
            or audit_pin_sha.startswith(tag.audit_pin_sha[:7])
        ):
            return "same_engagement"
        return "old_pin"
    # One or both pins missing -- treat as same_engagement if repos match.
    return "same_engagement"


def score_s1(
    target_record: Dict[str, Any],
    target_hash: str,
    target_hash_fine: str,
    tags: List[TagRecord],
    audit_pin_sha: Optional[str],
    target_repo: Optional[str] = None,
    recency_triple: Optional[Dict[str, float]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Return per-attack-class evidence trails.

    Wave-8: accepts ``recency_triple`` (a dict with keys
    ``same_engagement``, ``old_pin``, ``cross_engagement``) to apply
    per-family recency weights. Falls back to the legacy
    ``recency_weight()`` function when ``recency_triple`` is ``None``
    (backward-compat).
    """
    sh = shape_hash_module()
    target_family = sh.receiver_family(target_record.get("receiver_type"))

    out: Dict[str, List[Dict[str, Any]]] = {}
    for tag in tags:
        if not tag.attack_classes_to_try:
            continue
        # Skip same-target self-matches IF the verdict cites the same file_path
        # (avoids self-confirmation in the spike).
        ow = outcome_weight(tag)
        if recency_triple is not None and target_repo is not None:
            recency_class = _classify_recency(tag, target_repo, audit_pin_sha)
            rw = recency_triple[recency_class]
        else:
            recency_class = None
            rw = recency_weight(tag, audit_pin_sha)
        max_site_sim = 0.0
        site_chosen: Optional[Dict[str, Any]] = None
        for site in tag.sites or []:
            site_hash = site.get("shape_hash")
            site_fine = site.get("shape_hash_fine")
            site_recv = site.get("receiver_type")
            site_family = sh.receiver_family(site_recv) if site_recv else None
            sim = shape_similarity(
                target_hash, target_hash_fine,
                site_hash, site_fine,
                site_family, target_family,
            )
            if sim > max_site_sim:
                max_site_sim = sim
                site_chosen = site
        if max_site_sim <= 0.0:
            continue
        contribution = ow * max_site_sim * rw
        for ac in tag.attack_classes_to_try:
            ev = {
                "verdict_id": tag.verdict_id,
                "contribution": round(contribution, 4),
                "outcome_weight": ow,
                "shape_similarity": max_site_sim,
                "recency_weight": rw,
                "scorer": "S1",
                "site_file_path": (site_chosen or {}).get("file_path"),
            }
            if recency_class is not None:
                ev["recency_class"] = recency_class
            out.setdefault(ac, []).append(ev)
    return out


def _condition_matches(
    rec: Dict[str, Any],
    conditions: Dict[str, Any],
) -> bool:
    sh = shape_hash_module()
    lang = (conditions.get("lang") or "").lower()
    if lang and (rec.get("language") or "").lower() != lang:
        return False
    if "receiver_family" in conditions:
        if sh.receiver_family(rec.get("receiver_type")) != conditions["receiver_family"]:
            return False
    flags = sh.compute_flag_vector(rec.get("visibility"), rec.get("guards_detected"))
    for flag_key in sh.GUARD_FLAG_KEYS:
        cond_key = f"has_{flag_key}" if flag_key != "exported" else "has_exported"
        # Also accept bare "has_exported" rare; canonical via flag_key
        for k_variant in (f"has_{flag_key}", flag_key):
            if k_variant in conditions:
                want = int(conditions[k_variant])
                if flags[flag_key] != want:
                    return False
    if "visibility" in conditions:
        if rec.get("visibility") != conditions["visibility"]:
            return False
    if "name_match" in conditions:
        if not re.match(conditions["name_match"], rec.get("function_name") or ""):
            return False
    if "name_not_match" in conditions:
        if re.match(conditions["name_not_match"], rec.get("function_name") or ""):
            return False
    if "guard_in" in conditions:
        guards = set(rec.get("guards_detected") or [])
        if not (set(conditions["guard_in"]) & guards):
            return False
    if "guard_not_in" in conditions:
        guards = set(rec.get("guards_detected") or [])
        if set(conditions["guard_not_in"]) & guards:
            return False
    if "call_match" in conditions:
        calls = rec.get("calls_made") or []
        pat = conditions["call_match"]
        if not any(re.search(pat, c) for c in calls):
            return False
    if "call_not_match" in conditions:
        calls = rec.get("calls_made") or []
        pat = conditions["call_not_match"]
        if any(re.search(pat, c) for c in calls):
            return False
    return True


def score_s4(
    target_record: Dict[str, Any],
    rules: List[Rule],
) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for rule in rules:
        if not _condition_matches(target_record, rule.conditions):
            continue
        for ac, contrib in rule.contributes.items():
            out.setdefault(ac, []).append({
                "rule_id": rule.rule_id,
                "contribution": round(float(contrib), 4),
                "scorer": "S4",
                "provenance": rule.provenance,
            })
    return out


# --------------------------------------------------------------------------- #
# Phase-B: weights, sibling families, bug-class -> attack-class mapping        #
# --------------------------------------------------------------------------- #

_DEFAULT_WEIGHTS: Dict[str, Any] = {
    "weights": {"w1": 0.45, "w2": 0.20, "w3": 0.20, "w4": 0.15},
    "recency_weights": {
        "same_engagement": 0.85,
        "old_pin": 0.6,
        "cross_engagement": 0.4,
    },
    "shape_similarity": {"exact": 1.0, "fine_exact": 0.7, "partial": 0.4},
    "confidence": {"threshold": 0.4, "sigmoid_center": 0.5},
}


def load_weights(path: Path = RANKER_WEIGHTS) -> Dict[str, Any]:
    """Load audit/ranker_weights.yaml. Falls back to in-source defaults if
    the file is missing or unparsable; never raises.

    Wave-12: also surfaces ``language_overrides`` (per-language w1..w6
    blocks) under key ``language_overrides``. Empty dict if absent.
    """
    out = json.loads(json.dumps(_DEFAULT_WEIGHTS))  # deep copy
    out.setdefault("language_overrides", {})
    if not path.exists():
        return out
    try:
        data = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    for key in ("weights", "recency_weights", "shape_similarity", "confidence"):
        block = data.get(key)
        if isinstance(block, dict):
            for k, v in block.items():
                try:
                    out[key][k] = float(v)
                except (ValueError, TypeError):
                    continue
    # Wave-12: language_overrides — parse each language's w1..w6 floats.
    lang_block = data.get("language_overrides")
    if isinstance(lang_block, dict):
        parsed_lang: Dict[str, Dict[str, float]] = {}
        for lang_name, body in lang_block.items():
            if not isinstance(body, dict):
                continue
            wmap: Dict[str, float] = {}
            for k in ("w1", "w2", "w3", "w4", "w5", "w6"):
                v = body.get(k)
                if v is None:
                    continue
                try:
                    wmap[k] = float(v)
                except (ValueError, TypeError):
                    continue
            if wmap:
                parsed_lang[str(lang_name).lower()] = wmap
        out["language_overrides"] = parsed_lang
    return out


def resolve_language_weights(
    language: Optional[str],
    weights_cfg: Dict[str, Any],
) -> Tuple[Dict[str, float], Optional[str]]:
    """Wave-12: select per-language w1..w6 from ``weights_cfg``.

    Resolution:
      1. If ``language`` is non-empty and a matching key exists in
         ``weights_cfg["language_overrides"]``, return that block merged
         on top of the global ``weights:`` block.
      2. Otherwise return the global ``weights:`` block (defaults).

    Returns ``(weights_dict, language_id_or_None)``. ``language_id_or_None``
    is the lowercased language key that supplied the override (or ``None``
    if fallthrough to global defaults).

    The merge preserves any w1..w6 keys the language block omits — they
    fall through to the global block. This means a language override only
    needs to list the weights it wants to change. Total weight-sum is
    NOT renormalized; callers expect blocks to be intentionally crafted.
    """
    # Build a baseline from the global weights block, with hard defaults.
    base: Dict[str, float] = {
        "w1": 0.40, "w2": 0.15, "w3": 0.15,
        "w4": 0.10, "w5": 0.05, "w6": 0.15,
    }
    gw = (weights_cfg or {}).get("weights", {}) or {}
    for k in base:
        if k in gw:
            try:
                base[k] = float(gw[k])
            except (ValueError, TypeError):
                pass
    if not language:
        return base, None
    lang_key = str(language).lower()
    lang_map = (weights_cfg or {}).get("language_overrides", {}) or {}
    overrides = lang_map.get(lang_key)
    if not isinstance(overrides, dict) or not overrides:
        return base, None
    for k in base:
        if k in overrides:
            try:
                base[k] = float(overrides[k])
            except (ValueError, TypeError):
                pass
    return base, lang_key


def load_sibling_families(path: Path = SIBLING_FAMILIES) -> Dict[str, List[str]]:
    """Return {family_name: [repo, ...]}. Empty dict if missing."""
    if not path.exists():
        return {}
    try:
        data = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    fams = data.get("families") if isinstance(data, dict) else None
    if not isinstance(fams, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for fam, repos in fams.items():
        if isinstance(repos, list):
            out[str(fam)] = [str(r) for r in repos]
    return out


# --------------------------------------------------------------------------- #
# Wave-14: attack-class required-primitive filter                             #
# --------------------------------------------------------------------------- #


def load_attack_class_primitives(
    path: Path = ATTACK_CLASS_PRIMITIVES,
) -> Dict[str, Any]:
    """Load reference/attack_class_required_primitives.yaml.

    Returns ``{"enabled": bool, "default_cap": float, "by_class": {ac: {
    "regexes": [compiled_pat, ...], "cap": float}}, "fund_flow_path_allowlist":
    [compiled_pat, ...]}``. Returns an empty config (``enabled=False``) when
    the file is missing OR unparsable so legacy callers never break.
    """
    out: Dict[str, Any] = {
        "enabled": False,
        "default_cap": 0.30,
        "by_class": {},
        "fund_flow_path_allowlist": [],
        "fund_flow_allowlist_attack_classes": {
            "fee-redirect",
            "blocked-addr-bypass",
            "blocked-addr-rewards-redirect",
        },
    }
    if not path.exists():
        return out
    try:
        data = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    policy = data.get("policy") if isinstance(data.get("policy"), dict) else {}
    out["enabled"] = bool(policy.get("enabled", True))
    try:
        out["default_cap"] = float(
            policy.get("default_max_no_primitive_confidence", 0.30)
        )
    except (TypeError, ValueError):
        out["default_cap"] = 0.30
    allowlist_raw = policy.get("fund_flow_path_allowlist") or []
    if isinstance(allowlist_raw, list):
        compiled_allowlist = []
        for pat in allowlist_raw:
            try:
                compiled_allowlist.append(re.compile(str(pat)))
            except re.error:
                continue
        out["fund_flow_path_allowlist"] = compiled_allowlist
    allowlist_classes_raw = policy.get("fund_flow_allowlist_attack_classes") or []
    if isinstance(allowlist_classes_raw, list):
        out["fund_flow_allowlist_attack_classes"] = {
            str(item) for item in allowlist_classes_raw if str(item).strip()
        }
    rows = data.get("attack_classes") or []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        ac = row.get("attack_class")
        prims = row.get("required_primitives_any") or []
        if not ac or not isinstance(prims, list):
            continue
        compiled = []
        for p in prims:
            try:
                compiled.append(re.compile(str(p)))
            except re.error:
                continue
        try:
            cap = float(row.get("max_no_primitive_confidence", out["default_cap"]))
        except (TypeError, ValueError):
            cap = out["default_cap"]
        out["by_class"][str(ac)] = {"regexes": compiled, "cap": cap}
    return out


def _record_haystack(target_record: Optional[Dict[str, Any]]) -> str:
    """Build a regex-match haystack from a target record. We union
    ``calls_made``, ``function_signature``, ``guards_detected`` and the
    function body when available (via line-joining of calls). The primitive
    filter is intentionally a NEGATIVE-evidence subtraction; false-positive
    matches against the haystack cost nothing while false-negatives would
    cap a legitimate high-confidence hit, so we lean inclusive."""
    if not target_record:
        return ""
    parts: List[str] = []
    calls = target_record.get("calls_made") or []
    if isinstance(calls, list):
        parts.extend(str(c) for c in calls)
    guards = target_record.get("guards_detected") or []
    if isinstance(guards, list):
        parts.extend(str(g) for g in guards)
    sig = target_record.get("function_signature") or ""
    if sig:
        parts.append(str(sig))
    name = target_record.get("function_name") or ""
    if name:
        parts.append(str(name))
    return "\n".join(parts)


def apply_attack_class_primitive_filter(
    rows: List[Dict[str, Any]],
    target_record: Optional[Dict[str, Any]],
    primitives_cfg: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Wave-14: cap confidence on rows whose attack class requires a
    primitive that is absent from the target record's haystack.

    Mutates ``rows`` in place AND returns it (idempotent: a row that
    already shows ``primitive_filter_applied=true`` is skipped).

    The filter is conservative:
      - Only attack classes listed in
        ``reference/attack_class_required_primitives.yaml`` are filtered.
      - A row is capped ONLY when zero required-primitive regexes match
        the haystack.
      - When the target's file_path matches the YAML's
        ``fund_flow_path_allowlist`` and the row is an omission-style
        fund-flow class, the cap can be skipped. This protects positives
        like cantina-192 RegisterAffiliate without turning every keeper
        function into an admin/module-account candidate.
      - When capped, ``confidence`` is set to ``min(confidence, cap)``
        and ``score`` is NOT touched (gradient signal stays usable for
        ``tools/ranker-learn.py``).
      - Adds ``primitive_filter_applied``, ``primitive_filter_cap``,
        ``primitive_filter_prior_confidence``, ``primitive_filter_reason``
        to capped rows for observability.
    """
    if primitives_cfg is None:
        primitives_cfg = load_attack_class_primitives()
    if not primitives_cfg.get("enabled"):
        return rows
    by_class = primitives_cfg.get("by_class") or {}
    if not by_class:
        return rows
    fp = (target_record or {}).get("file_path") or ""
    haystack = _record_haystack(target_record)
    allowlist_path_match = False
    for pat in primitives_cfg.get("fund_flow_path_allowlist") or []:
        try:
            if pat.search(fp):
                allowlist_path_match = True
                break
        except Exception:
            continue
    omission_allowlist_classes = set(
        primitives_cfg.get("fund_flow_allowlist_attack_classes")
        or {"fee-redirect", "blocked-addr-bypass", "blocked-addr-rewards-redirect"}
    )
    omission_context = re.search(
        r"(affiliate|reward|fee|blocked|recipient|distribution)",
        f"{haystack}\n{fp}",
        re.IGNORECASE,
    )
    for row in rows:
        if row.get("primitive_filter_applied"):
            continue
        ac = row.get("attack_class")
        cfg = by_class.get(ac)
        if not cfg:
            continue
        regexes = cfg.get("regexes") or []
        if not regexes:
            continue
        if allowlist_path_match and ac in omission_allowlist_classes and omission_context:
            continue
        matched_any = False
        for pat in regexes:
            try:
                if pat.search(haystack):
                    matched_any = True
                    break
            except Exception:
                continue
        if matched_any:
            continue
        cap = float(cfg.get("cap", primitives_cfg.get("default_cap", 0.30)))
        old_conf = float(row.get("confidence", 0.0))
        new_conf = min(old_conf, cap)
        if new_conf < old_conf:
            row["confidence"] = round(new_conf, 4)
        row["primitive_filter_applied"] = True
        row["primitive_filter_cap"] = round(cap, 4)
        row["primitive_filter_prior_confidence"] = round(old_conf, 4)
        row["primitive_filter_reason"] = (
            f"no required primitive matched for attack_class={ac}"
        )
    return rows


def apply_prior_only_filter(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Cap attack classes supported only by broad S2 heatmap priors.

    S2/S5 are useful as cross-engagement and cross-language context, but
    without a local scorer they are not per-function proof signals. Keeping
    context-only rows below the default function-mindset threshold prevents
    generic corpus classes from filling every Go function's top-N list.
    """
    context_scorers = {"S2", "S5"}
    for row in rows:
        evidence = row.get("evidence") or []
        if not evidence:
            continue
        scorers = {str(ev.get("scorer") or "") for ev in evidence if isinstance(ev, dict)}
        if not scorers or not scorers.issubset(context_scorers):
            continue
        old_conf = float(row.get("confidence", 0.0))
        cap = 0.35
        if old_conf > cap:
            row["confidence"] = cap
        row["prior_only_filter_applied"] = True
        row["prior_only_filter_cap"] = cap
        row["prior_only_filter_prior_confidence"] = round(old_conf, 4)
        row["prior_only_filter_reason"] = "context prior without per-function corroboration"
    return rows


def find_family(target_repo: str, families: Dict[str, List[str]]) -> List[str]:
    """Return the sibling list (excluding ``target_repo``) for the family
    containing it. Empty list if no family matches."""
    for repos in families.values():
        if target_repo in repos:
            return [r for r in repos if r != target_repo]
    return []


def find_family_id(target_repo: str, families: Dict[str, List[str]]) -> Optional[str]:
    """Return the family-id (e.g. ``cosmos-sdk-forks``) that contains
    ``target_repo``. ``None`` if no family lists it. Wave-7 helper for
    per-family weight overrides."""
    for fam_id, repos in families.items():
        if target_repo in repos:
            return fam_id
    return None


# --------------------------------------------------------------------------- #
# Wave-7: per-family weight overrides                                         #
# --------------------------------------------------------------------------- #

def load_weights_per_family(
    path: Path = RANKER_WEIGHTS_PER_FAMILY,
) -> Dict[str, Any]:
    """Load audit/ranker_weights_per_family.yaml. Returns a dict shaped::

        {
          "default": {"w1": ..., "w2": ..., "w3": ..., "w4": ...},
          "families": {<family-id>: {"w1": ..., ...}, ...},
          "recency_per_family": {
            "default": {"same_engagement": ..., "old_pin": ..., "cross_engagement": ...},
            <family-id>: {...},
          },
        }

    Missing file or parse error → returns ``{"default": {}, "families": {},
    "recency_per_family": {"default": {}}}`` (caller falls back to global
    ranker_weights.yaml via load_weights()). Never raises.
    """
    out: Dict[str, Any] = {
        "default": {},
        "families": {},
        "recency_per_family": {"default": {}},
    }
    if not path.exists():
        return out
    try:
        raw = path.read_text(encoding="utf-8")
        # Strip inline comments (`key: value  # note`) so the mini-YAML
        # loader sees pure scalars. Don't touch block scalars (provenance).
        scrubbed_lines: List[str] = []
        in_block_scalar = False
        block_indent = 0
        for ln in raw.splitlines():
            stripped = ln.strip()
            if in_block_scalar:
                cur_indent = len(ln) - len(ln.lstrip(" "))
                if stripped == "" or cur_indent > block_indent:
                    scrubbed_lines.append(ln)
                    continue
                in_block_scalar = False
            if stripped.endswith(": |") or stripped.endswith(": >"):
                in_block_scalar = True
                block_indent = len(ln) - len(ln.lstrip(" "))
                scrubbed_lines.append(ln)
                continue
            # Strip inline `#` comment (only when not inside quotes — the
            # weights file has no quoted strings with `#`, so a naive split
            # is safe).
            if "#" in ln and not stripped.startswith("#"):
                # Preserve leading indentation + content up to comment
                head, _sep, _tail = ln.partition("#")
                scrubbed_lines.append(head.rstrip())
            else:
                scrubbed_lines.append(ln)
        data = yaml_load("\n".join(scrubbed_lines))
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    default_block = data.get("default")
    if isinstance(default_block, dict):
        for k in ("w1", "w2", "w3", "w4"):
            v = default_block.get(k)
            if v is not None:
                try:
                    out["default"][k] = float(v)
                except (ValueError, TypeError):
                    continue
    families_block = data.get("families")
    if isinstance(families_block, dict):
        for fam_id, body in families_block.items():
            if not isinstance(body, dict):
                continue
            fam_w: Dict[str, float] = {}
            for k in ("w1", "w2", "w3", "w4"):
                v = body.get(k)
                if v is not None:
                    try:
                        fam_w[k] = float(v)
                    except (ValueError, TypeError):
                        continue
            if fam_w:
                out["families"][str(fam_id)] = fam_w
    recency_block = data.get("recency_per_family")
    if isinstance(recency_block, dict):
        for fam_id, body in recency_block.items():
            if not isinstance(body, dict):
                continue
            recency: Dict[str, float] = {}
            for k in ("same_engagement", "old_pin", "cross_engagement"):
                v = body.get(k)
                if v is not None:
                    try:
                        recency[k] = float(v)
                    except (ValueError, TypeError):
                        continue
            if recency:
                out["recency_per_family"][str(fam_id)] = recency
    return out


def resolve_effective_weights(
    target_repo: str,
    weights_global: Dict[str, Any],
    per_family: Dict[str, Any],
    families: Dict[str, List[str]],
) -> Tuple[Dict[str, float], Optional[str]]:
    """Compute the effective w1..w4 for ``target_repo``.

    Resolution order (highest to lowest priority):
      1. ``per_family["families"][<family-id>]`` if target_repo resolves
         to a known family with overrides.
      2. ``per_family["default"]`` if present.
      3. ``weights_global["weights"]`` (audit/ranker_weights.yaml).
      4. Hard-coded sane defaults (0.45 / 0.20 / 0.20 / 0.15).

    Returns ``(weights_dict, family_id_or_None)``. ``family_id_or_None`` is
    the family-id that supplied the override (or ``None`` if fallthrough
    to default / global).
    """
    base = {"w1": 0.45, "w2": 0.20, "w3": 0.20, "w4": 0.15}
    # Layer 3: global from ranker_weights.yaml
    gw = (weights_global or {}).get("weights", {}) or {}
    for k in base:
        if k in gw:
            try:
                base[k] = float(gw[k])
            except (ValueError, TypeError):
                pass
    # Layer 2: per-family default
    pf_default = (per_family or {}).get("default", {}) or {}
    for k in base:
        if k in pf_default:
            base[k] = pf_default[k]
    # Layer 1: per-family override
    fam_id = find_family_id(target_repo, families) if families else None
    if fam_id:
        fam_overrides = (per_family or {}).get("families", {}).get(fam_id)
        if isinstance(fam_overrides, dict):
            for k in base:
                if k in fam_overrides:
                    base[k] = fam_overrides[k]
            return base, fam_id
    return base, None


def resolve_effective_recency(
    target_repo: str,
    per_family: Dict[str, Any],
    families: Dict[str, List[str]],
) -> Dict[str, float]:
    """Compute the effective recency triple for ``target_repo``. Falls back
    to per-family default block, then to a hard-coded baseline."""
    base = {"same_engagement": 0.85, "old_pin": 0.6, "cross_engagement": 0.4}
    rpf = (per_family or {}).get("recency_per_family", {}) or {}
    rpf_default = rpf.get("default", {}) or {}
    for k in base:
        if k in rpf_default:
            base[k] = rpf_default[k]
    fam_id = find_family_id(target_repo, families) if families else None
    if fam_id and isinstance(rpf.get(fam_id), dict):
        for k in base:
            if k in rpf[fam_id]:
                base[k] = rpf[fam_id][k]
    return base


def _load_bug_class_to_ac_map_uncached(path: Path) -> Dict[str, Any]:
    """Actual disk-reading implementation of load_bug_class_to_ac_map (no cache)."""
    out: Dict[str, Any] = {"mappings": {}, "heatmap_family_bridges": {}}
    if not path.exists():
        return out
    try:
        data = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return out
    if isinstance(data, dict):
        m = data.get("mappings")
        if isinstance(m, dict):
            out["mappings"] = {
                str(k): list(v) for k, v in m.items() if isinstance(v, list)
            }
        b = data.get("heatmap_family_bridges")
        if isinstance(b, dict):
            out["heatmap_family_bridges"] = {
                str(k): list(v) for k, v in b.items() if isinstance(v, list)
            }
    return out


def load_bug_class_to_ac_map(
    path: Path = BUG_CLASS_TO_AC_MAP,
) -> Dict[str, Any]:
    """Return {"mappings": {bug_class: [attack_class,...]},
                "heatmap_family_bridges": {heatmap_family: [bug_class,...]}}.
    Empty dicts if file missing. Uses module-level mtime cache; set
    RANKER_CACHE_DISABLED=1 to bypass.
    """
    global _BUG_CLASS_MAP_CACHE, _BUG_CLASS_MAP_CACHE_MTIME, _BUG_CLASS_MAP_CACHE_PATH
    if os.environ.get("RANKER_CACHE_DISABLED") == "1":
        return _load_bug_class_to_ac_map_uncached(path)
    current_mtime = _file_mtime(path)
    if (
        _BUG_CLASS_MAP_CACHE is None
        or _BUG_CLASS_MAP_CACHE_PATH != path
        or current_mtime > _BUG_CLASS_MAP_CACHE_MTIME
    ):
        _BUG_CLASS_MAP_CACHE = _load_bug_class_to_ac_map_uncached(path)
        _BUG_CLASS_MAP_CACHE_MTIME = current_mtime
        _BUG_CLASS_MAP_CACHE_PATH = path
    return _BUG_CLASS_MAP_CACHE


# --------------------------------------------------------------------------- #
# Phase-B scorer S2: bug-family heatmap join                                  #
# --------------------------------------------------------------------------- #

_SEV_WEIGHT = {
    "CRITICAL": 1.0, "CRIT": 1.0,
    "HIGH": 0.7,
    "MED": 0.3, "MEDIUM": 0.3,
    "LOW": 0.1,
    "INFO": 0.05, "INFORMATIONAL": 0.05,
}


def _call_mcp_bug_family_heatmap(
    workspace_path: str,
    mcp_path: Path = MCP_SERVER_PATH,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Subprocess-call the vault MCP server's vault_bug_family_heatmap
    callable. Returns (heatmap[], focus_engagement) or ([], None) on failure.
    """
    import subprocess
    if not mcp_path.exists():
        return [], None
    try:
        r = subprocess.run(
            [
                sys.executable, str(mcp_path),
                "--call", "vault_bug_family_heatmap",
                "--args", json.dumps({"workspace_path": workspace_path}),
            ],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return [], None
    txt = r.stdout or ""
    i = txt.find("{")
    if i < 0:
        return [], None
    try:
        d = json.loads(txt[i:])
    except Exception:
        return [], None
    hm = d.get("heatmap")
    focus = d.get("focus_engagement")
    return (hm if isinstance(hm, list) else []), (str(focus) if focus else None)


def _local_bug_family_aggregate(
    target_repo: str,
    tags: List[TagRecord],
) -> List[Dict[str, Any]]:
    """Fallback: aggregate bug_class counts from the in-tree corpus_tags
    when the MCP callable is unavailable.

    Emits rows shaped like ``{"bug_class": ..., "count": int,
    "top_severity": str, "engagement": str}``.

    Same-repo tags are EXCLUDED — S1 already covers them via shape-similarity.
    S2's contribution is cross-engagement transfer only, otherwise we
    double-count the same evidence and inflate confidence.
    """
    from collections import defaultdict
    counts: Dict[str, int] = defaultdict(int)
    sevs: Dict[str, str] = {}
    engagements: Dict[str, str] = {}
    sev_rank = {"CRIT": 4, "CRITICAL": 4, "HIGH": 3, "MED": 2, "MEDIUM": 2, "LOW": 1, "INFO": 0, "INFORMATIONAL": 0, "": 0}
    for t in tags:
        if not t.bug_class:
            continue
        if t.target_repo == target_repo:
            continue  # S1 owns same-repo evidence
        counts[t.bug_class] += 1
        sev = (t.raw.get("severity_claimed") or "").upper() or "MED"
        if sev_rank.get(sev, 0) > sev_rank.get(sevs.get(t.bug_class, ""), 0):
            sevs[t.bug_class] = sev
        if t.bug_class not in engagements:
            engagements[t.bug_class] = t.target_repo
    return [
        {
            "bug_class": bc,
            "count": c,
            "top_severity": sevs.get(bc, "MED"),
            "engagement": engagements.get(bc, ""),
        }
        for bc, c in counts.items()
    ]


def score_s2(
    target_repo: str,
    bug_class_to_ac_map: Dict[str, Any],
    tags: List[TagRecord],
    workspace_path: Optional[str] = None,
    mcp_path: Path = MCP_SERVER_PATH,
) -> Dict[str, List[Dict[str, Any]]]:
    """Bug-family heatmap join.

    Calls vault_bug_family_heatmap; falls back to in-tree corpus_tags
    aggregation if MCP empty.

    The heatmap callable emits rows keyed by ``bug_family`` strings drawn
    from ``reference/recurring_bug_families.md``. We translate those to
    fine-grained ``bug_class`` keys via the YAML's ``heatmap_family_bridges``
    table, then look up the attack-class set in ``mappings``.

    Fallback rows are keyed by ``bug_class`` directly (no bridge needed).
    """
    from collections import defaultdict

    rows: List[Dict[str, Any]] = []
    focus_engagement: Optional[str] = None
    if workspace_path:
        rows, focus_engagement = _call_mcp_bug_family_heatmap(workspace_path, mcp_path)
    used_fallback = False
    if not rows:
        rows = _local_bug_family_aggregate(target_repo, tags)
        used_fallback = True

    mappings = bug_class_to_ac_map.get("mappings", {})
    bridges = bug_class_to_ac_map.get("heatmap_family_bridges", {})

    scores: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        # row may be in 'bug_family' (MCP) or 'bug_class' (fallback) form
        family_key = row.get("bug_family") or row.get("bug_class") or ""
        if not family_key:
            continue
        count = int(row.get("count") or 1)
        sev = str(row.get("top_severity") or row.get("severity") or "MED").upper()
        sev_w = _SEV_WEIGHT.get(sev, 0.3)
        engagement = row.get("engagement") or row.get("workspace") or ""

        # Skip same-engagement rows: S1 already covers same-corpus signal.
        # S2's job is cross-engagement transfer.
        if focus_engagement and engagement and engagement == focus_engagement:
            continue

        # Resolve bug-class candidates:
        if family_key in mappings:
            bcs = [family_key]
        else:
            bcs = list(bridges.get(family_key, []))
        if not bcs:
            continue

        for bc in bcs:
            acs = mappings.get(bc) or []
            if not acs:
                continue
            # S2 contributions are cross-engagement priors. Per-row magnitude
            # is intentionally log-capped: high-frequency generic classes
            # such as "access-control" can have thousands of corpus hits and
            # must not drown per-function S1/S3/S4 evidence.
            scaler = 0.10 if not used_fallback else 0.07  # base per-row magnitude
            frequency_signal = min(math.log1p(max(count, 1)), 5.0)
            contribution = frequency_signal * sev_w * scaler
            for ac in acs:
                scores[ac].append({
                    "scorer": "S2",
                    "bug_family": family_key,
                    "bug_class": bc,
                    "engagement": engagement,
                    "count": count,
                    "severity": sev,
                    "contribution": round(contribution, 4),
                    "source": "vault_bug_family_heatmap" if not used_fallback else "corpus_tags_fallback",
                })
    return dict(scores)


# --------------------------------------------------------------------------- #
# Phase-B scorer S3: cross-repo pattern transfer                              #
# --------------------------------------------------------------------------- #

def score_s3(
    target_repo: str,
    target_hash: str,
    target_hash_fine: str,
    target_receiver_family: Optional[str],
    sibling_families: Dict[str, List[str]],
    tags: List[TagRecord],
    recency_triple: Optional[Dict[str, float]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Cross-repo pattern transfer.

    Wave-8: uses ``recency_triple["cross_engagement"]`` as the sibling-repo
    discount factor when ``recency_triple`` is provided (per-family recency
    wiring). Falls back to the legacy hardcoded 0.5 discount when
    ``recency_triple`` is ``None`` (backward-compat).

    A pattern from a sibling repo (same family) contributes its
    outcome-weight x shape-similarity x cross_engagement_weight. The
    cross_engagement weight reflects that sibling-repo evidence is
    presumptive but cross-engagement (lower confidence than a direct
    same-corpus match in S1).
    """
    from collections import defaultdict
    sh = shape_hash_module()

    siblings = find_family(target_repo, sibling_families)
    if not siblings:
        return {}

    # Determine the cross-engagement discount to apply to all sibling hits.
    cross_discount: float = (
        recency_triple["cross_engagement"]
        if recency_triple is not None
        else 0.5
    )

    scores: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for tag in tags:
        if tag.target_repo == target_repo:
            continue  # same-repo handled by S1
        if tag.target_repo not in siblings:
            continue
        if not tag.attack_classes_to_try:
            continue
        ow = outcome_weight(tag)
        max_site_sim = 0.0
        site_chosen: Optional[Dict[str, Any]] = None
        for site in tag.sites or []:
            site_hash = site.get("shape_hash")
            site_fine = site.get("shape_hash_fine")
            site_recv = site.get("receiver_type")
            site_family = sh.receiver_family(site_recv) if site_recv else None
            sim = shape_similarity(
                target_hash, target_hash_fine,
                site_hash, site_fine,
                site_family, target_receiver_family,
            )
            if sim > max_site_sim:
                max_site_sim = sim
                site_chosen = site
        if max_site_sim <= 0.0:
            continue
        contribution = cross_discount * ow * max_site_sim
        for ac in tag.attack_classes_to_try:
            scores[ac].append({
                "scorer": "S3",
                "verdict_id": tag.verdict_id,
                "sibling_repo": tag.target_repo,
                "contribution": round(contribution, 4),
                "outcome_weight": ow,
                "shape_similarity": max_site_sim,
                "discount": cross_discount,
                "site_file_path": (site_chosen or {}).get("file_path"),
            })
    return dict(scores)


# --------------------------------------------------------------------------- #
# Wave-7 scorer S5: cross-language transfer                                   #
# --------------------------------------------------------------------------- #

def _load_cross_lang_map_uncached(path: Path) -> Dict[str, Any]:
    """Actual disk-reading implementation of load_cross_lang_map (no cache)."""
    if not path.exists():
        return {}
    try:
        data = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def load_cross_lang_map(
    path: Path = CROSS_LANG_DETECTOR_MAP,
) -> Dict[str, Any]:
    """Load reference/cross_lang_detector_map.yaml, using a module-level mtime
    cache. Returns ``{}`` if the file is missing or unparsable. Never raises.
    Set RANKER_CACHE_DISABLED=1 to bypass cache.
    """
    global _CROSS_LANG_MAP_CACHE, _CROSS_LANG_MAP_CACHE_MTIME, _CROSS_LANG_MAP_CACHE_PATH
    if os.environ.get("RANKER_CACHE_DISABLED") == "1":
        return _load_cross_lang_map_uncached(path)
    current_mtime = _file_mtime(path)
    if (
        _CROSS_LANG_MAP_CACHE is None
        or _CROSS_LANG_MAP_CACHE_PATH != path
        or current_mtime > _CROSS_LANG_MAP_CACHE_MTIME
    ):
        _CROSS_LANG_MAP_CACHE = _load_cross_lang_map_uncached(path)
        _CROSS_LANG_MAP_CACHE_MTIME = current_mtime
        _CROSS_LANG_MAP_CACHE_PATH = path
    return _CROSS_LANG_MAP_CACHE


# Backward-compat alias used in some internal helpers / specs.
_load_cross_lang_map = load_cross_lang_map


# --------------------------------------------------------------------------- #
# Wave-8 S5 synonym loader                                                     #
# --------------------------------------------------------------------------- #

def _build_synonym_index(raw: Dict[str, Any]) -> Dict[str, str]:
    """Invert the canonical_synonyms block: specific_string -> canonical.

    Returns an empty dict if the YAML is malformed.
    """
    index: Dict[str, str] = {}
    block = raw.get("canonical_synonyms") if isinstance(raw, dict) else None
    if not isinstance(block, dict):
        return index
    for canonical, synonyms in block.items():
        if not isinstance(synonyms, list):
            continue
        for synonym in synonyms:
            s = str(synonym).strip()
            if s:
                index[s] = str(canonical)
    return index


def load_cross_lang_synonyms(
    path: Path = CROSS_LANG_SYNONYMS_MAP,
) -> Dict[str, str]:
    """Load reference/cross_lang_bug_class_synonyms.yaml and return an
    inverted index: ``{specific_bug_class: canonical_bug_class}``.

    Uses a module-level mtime cache (same pattern as load_cross_lang_map).
    Returns ``{}`` if the file is missing or unparsable. Never raises.
    Set RANKER_CACHE_DISABLED=1 to bypass cache.
    """
    global _CROSS_LANG_SYNONYMS_CACHE, _CROSS_LANG_SYNONYMS_CACHE_MTIME, _CROSS_LANG_SYNONYMS_CACHE_PATH
    if os.environ.get("RANKER_CACHE_DISABLED") == "1":
        raw = {}
        if path.exists():
            try:
                raw = yaml_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                pass
        return _build_synonym_index(raw)
    current_mtime = _file_mtime(path)
    if (
        _CROSS_LANG_SYNONYMS_CACHE is None
        or _CROSS_LANG_SYNONYMS_CACHE_PATH != path
        or current_mtime > _CROSS_LANG_SYNONYMS_CACHE_MTIME
    ):
        raw: Dict[str, Any] = {}
        if path.exists():
            try:
                raw = yaml_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                pass
        _CROSS_LANG_SYNONYMS_CACHE = _build_synonym_index(raw)
        _CROSS_LANG_SYNONYMS_CACHE_MTIME = current_mtime
        _CROSS_LANG_SYNONYMS_CACHE_PATH = path
    return _CROSS_LANG_SYNONYMS_CACHE


def _shape_similarity_for_s5(
    target_hash: str,
    target_hash_fine: str,
    site_hash: str,
    site_fine: str,
) -> float:
    """Hash-only shape similarity (no receiver family for cross-lang; the
    family hierarchy is language-specific and not comparable Go<->Rust)."""
    if not (site_hash or site_fine):
        # No hash on the verdict site: weak partial credit so the
        # empirical-anchor bonus path can still inflate the contribution.
        return 0.2
    if site_hash and target_hash and site_hash == target_hash:
        return 1.0
    if site_fine and target_hash_fine and site_fine == target_hash_fine:
        return 0.7
    # No exact match — fall back to a weak partial so cross-lang bug-class
    # alignment alone still nudges the score.
    return 0.2


def score_s5_cross_lang_transfer(
    target_language: str,
    target_shape: str,
    target_shape_fine: str,
    tags: Optional[List[TagRecord]] = None,
    cross_lang_map: Optional[Dict[str, Any]] = None,
    synonyms: Optional[Dict[str, str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Transfer signal across languages via cross_lang_detector_map.yaml.

    Algorithm (BIG_PLAN Wave-7):

      For each (bug_class -> language map) entry that lists the target
      language, scan the corpus for verdicts in a sibling language whose
      ``bug_class`` matches the entry's canonical class. For each match,
      contribute::

          0.4 * outcome_weight * shape_similarity

      to every attack_class the matched verdict cites. The 0.4 factor is
      a *cross-language* discount (vs 0.5 for cross-repo same-language in
      S3) reflecting weaker confidence-of-evidence.

    Additionally: if the cross-lang-map entry has an ``empirical_anchor``
    field (citing a filed verdict by id) AND we discover the corpus
    contains a sibling-language verdict whose bug_class matches the
    entry, add a flat +0.3 bonus to every distinct attack_class the
    matched verdict cites. This rewards entries that already have a
    real-world filed instance.

    Wave-8 extension -- synonym matching:
      If ``synonyms`` is provided (an inverted index built from
      ``cross_lang_bug_class_synonyms.yaml``), a verdict whose ``bug_class``
      does not exactly equal the canonical class is also considered a match
      if ``synonyms.get(verdict.bug_class) == canonical_class``. The synonym-
      matched verdict carries a small additional discount (0.9x) relative to
      an exact match. When a tag also carries a ``cross_lang_canonical_bug_classes``
      list (added by the Wave-8 re-tagging pass), any canonical that appears in
      that list is also treated as a direct match (no additional discount; the
      tag owner already asserted the mapping).

    Notes on backward compat:
      - If ``cross_lang_detector_map.yaml`` is missing or empty -> returns ``{}``.
      - If ``target_language`` is empty or not listed in any mapping -> ``{}``.
      - Tags from the same language as the target are skipped (S1/S2/S3 own
        those signals; S5 must not double-count).
      - ``synonyms`` defaults to ``None``; if not supplied,
        load_cross_lang_synonyms() is called automatically so the Wave-8
        synonym map is always active without caller changes.
    """
    from collections import defaultdict

    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if not target_language:
        return {}

    target_language = target_language.lower()
    if cross_lang_map is None:
        cross_lang_map = load_cross_lang_map()
    mappings_block = cross_lang_map.get("mappings") if isinstance(cross_lang_map, dict) else None
    if not isinstance(mappings_block, list):
        return {}
    if tags is None:
        tags = load_tags()
    # Wave-8: load synonym index if not supplied by caller.
    if synonyms is None:
        synonyms = load_cross_lang_synonyms()

    # Index tags by bug_class for fast lookup (exact canonical class).
    tags_by_bug_class: Dict[str, List[TagRecord]] = defaultdict(list)
    # Wave-8: also index by cross_lang_canonical_bug_classes entries (additive field).
    tags_by_canonical: Dict[str, List[TagRecord]] = defaultdict(list)
    for t in tags:
        if t.bug_class:
            tags_by_bug_class[str(t.bug_class)].append(t)
        # cross_lang_canonical_bug_classes is a free-form list field; access via
        # the raw data dict since TagRecord does not have a typed slot for it.
        raw_data = t.raw if hasattr(t, "raw") else {}
        for canon in raw_data.get("cross_lang_canonical_bug_classes") or []:
            tags_by_canonical[str(canon)].append(t)

    def _iter_sibling_verdicts(bug_class: str, sibling_lang: str):
        """Yield (verdict, match_kind) for sibling-language verdicts that map
        to *bug_class* via exact, synonym, or cross_lang_canonical match.
        Deduplicates by verdict_id within this call."""
        seen: set = set()
        # 1. Exact canonical match.
        for verdict in tags_by_bug_class.get(bug_class, []):
            if (verdict.language or "").lower() == sibling_lang:
                if verdict.verdict_id not in seen:
                    seen.add(verdict.verdict_id)
                    yield verdict, "exact"
        # 2. Synonym match: verdict.bug_class resolves to bug_class via synonyms.
        for specific_bc, canonical in (synonyms or {}).items():
            if canonical != bug_class:
                continue
            for verdict in tags_by_bug_class.get(specific_bc, []):
                if (verdict.language or "").lower() == sibling_lang:
                    if verdict.verdict_id not in seen:
                        seen.add(verdict.verdict_id)
                        yield verdict, "synonym"
        # 3. cross_lang_canonical_bug_classes field match (additive re-tag).
        for verdict in tags_by_canonical.get(bug_class, []):
            if (verdict.language or "").lower() == sibling_lang:
                if verdict.verdict_id not in seen:
                    seen.add(verdict.verdict_id)
                    yield verdict, "canonical_field"

    for entry in mappings_block:
        if not isinstance(entry, dict):
            continue
        bug_class = entry.get("bug_class")
        if not bug_class:
            continue
        # Only run for entries where the target language has at least one
        # known same-language detector. If the map declares "no go detector
        # for this class" we treat it as cross-lang-transferable.
        same_lang_detectors = entry.get(target_language)
        if same_lang_detectors is None:
            # target language not represented in this entry at all -> skip
            continue
        # Iterate sibling languages.
        # Wave-8 note: canonical_field verdicts (tags that explicitly declare
        # cross_lang_canonical_bug_classes) are checked for ALL sibling langs,
        # even when the cross_lang_detector_map entry lists no detector for that
        # sibling lang (e.g. `rust: []`). The tag's assertion overrides the map.
        matched_verdicts: List[TagRecord] = []
        seen_all_verdict_ids: set = set()
        for sibling_lang in ("go", "rust", "solidity", "python", "ts"):
            if sibling_lang == target_language:
                continue
            # canonical_field verdicts bypass the sibling_detectors guard.
            canonical_field_verdicts = [
                v for v in tags_by_canonical.get(bug_class, [])
                if (v.language or "").lower() == sibling_lang
                   and v.verdict_id not in seen_all_verdict_ids
            ]
            sibling_detectors = entry.get(sibling_lang)
            if not sibling_detectors and not canonical_field_verdicts:
                continue
            verdict_iter = _iter_sibling_verdicts(bug_class, sibling_lang) if sibling_detectors else (
                (v, "canonical_field") for v in canonical_field_verdicts
            )
            for verdict, match_kind in verdict_iter:
                if verdict.verdict_id in seen_all_verdict_ids:
                    continue
                seen_all_verdict_ids.add(verdict.verdict_id)
                matched_verdicts.append(verdict)
                ow = outcome_weight(verdict)
                # Synonym matches get a small additional discount (0.9x).
                synonym_factor = 0.9 if match_kind == "synonym" else 1.0
                # Per-site shape similarity (hash-only; receiver family
                # is not cross-language comparable).
                max_sim = 0.0
                site_chosen: Optional[Dict[str, Any]] = None
                for site in verdict.sites or []:
                    sim = _shape_similarity_for_s5(
                        target_shape, target_shape_fine,
                        str(site.get("shape_hash") or ""),
                        str(site.get("shape_hash_fine") or ""),
                    )
                    if sim > max_sim:
                        max_sim = sim
                        site_chosen = site
                if max_sim <= 0.0:
                    continue
                contribution = 0.4 * synonym_factor * ow * max_sim
                for ac in verdict.attack_classes_to_try or []:
                    out[ac].append({
                        "scorer": "S5",
                        "verdict_id": verdict.verdict_id,
                        "sibling_language": sibling_lang,
                        "target_language": target_language,
                        "bug_class": bug_class,
                        "match_kind": match_kind,
                        "contribution": round(contribution, 4),
                        "outcome_weight": ow,
                        "shape_similarity": max_sim,
                        "discount": round(0.4 * synonym_factor, 4),
                        "site_file_path": (site_chosen or {}).get("file_path"),
                    })

        # Empirical-anchor bonus: +0.3 per distinct attack-class touched
        # by a matched sibling-language verdict, if the entry cites an
        # empirical anchor (a real filed instance of the class).
        anchor = entry.get("empirical_anchor")
        if anchor and matched_verdicts:
            seen_acs: set = set()
            for v in matched_verdicts:
                for ac in v.attack_classes_to_try or []:
                    if ac in seen_acs:
                        continue
                    seen_acs.add(ac)
                    out[ac].append({
                        "scorer": "S5",
                        "subkind": "empirical_anchor_bonus",
                        "bug_class": bug_class,
                        "empirical_anchor": anchor,
                        "contribution": 0.3,
                    })

    return dict(out)


def sigmoid(x: float) -> float:
    if x < -50:
        return 0.0
    if x > 50:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


# --------------------------------------------------------------------------- #
# S6 — Mechanical detector grounding (Wave-9 Track B).                        #
#                                                                             #
# Reads workspace-local engage_report.md (parsed into a struct by             #
# tools/engage-report-parser.py) and lifts attack-class scores when a         #
# detector fired on the same file + within ±30 lines of the function body.   #
# Severity-weighted (HIGH=0.7, MEDIUM=0.4, LOW=0.15) so HIGH evidence         #
# dominates LOW noise.                                                        #
# --------------------------------------------------------------------------- #

DETECTOR_TO_AC_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"

S6_LINE_FUZZ = 30
S6_SEVERITY_WEIGHTS = {"HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}
S6_PER_HIT_FACTOR = 0.8


def load_detector_to_attack_classes_map(
    path: Path = DETECTOR_TO_AC_MAP,
) -> Dict[str, List[str]]:
    """Load detector_cluster_name -> list[attack_class] mapping."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return {}
    raw = data.get("mappings") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        # support flat dict form (detector -> [acs]) for forward compat
        raw = {
            k: v for k, v in (data or {}).items()
            if isinstance(v, list)
        }
    out: Dict[str, List[str]] = {}
    for det, acs in raw.items():
        if isinstance(acs, list):
            out[str(det)] = [str(a) for a in acs if a]
    return out


def _s6_file_matches(target_file: str, hit_file_path: str) -> bool:
    """Suffix-match: target may be ws-relative or absolute; hit is absolute.

    A target ``src/Vault.sol`` matches a hit at
    ``/Users/wolf/audits/ws/src/Vault.sol`` (suffix) and vice versa.
    Empty strings never match.
    """
    if not target_file or not hit_file_path:
        return False
    if target_file == hit_file_path:
        return True
    return hit_file_path.endswith("/" + target_file) or target_file.endswith(
        "/" + hit_file_path
    )


def score_s6_detector_grounding(
    target_file: str,
    target_line_range: Tuple[int, int],
    workspace_engage_report: Optional[Dict[str, Any]],
    detector_to_attack_classes_map: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Return {attack_class: [evidence_entry, ...]} from engage_report hits.

    Algorithm:
      For each cluster in workspace_engage_report["clusters"]:
        - Map cluster_name -> list[attack_class] via detector_to_attack_classes_map
        - For each hit in cluster["hits"]:
            - If hit.file_path suffix-matches target_file AND
              hit.line is within target_line_range expanded by ±S6_LINE_FUZZ:
                - contribution = S6_PER_HIT_FACTOR * sev_weight[severity]
                - emit evidence row for every mapped attack class

    Returns empty dict if report is None or has no parse_ok hits.
    """
    from collections import defaultdict

    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if not workspace_engage_report:
        return {}
    if not workspace_engage_report.get("parse_ok") and "clusters" not in workspace_engage_report:
        return {}
    clusters = workspace_engage_report.get("clusters") or []
    if not clusters:
        return {}
    if detector_to_attack_classes_map is None:
        detector_to_attack_classes_map = load_detector_to_attack_classes_map()
    if not detector_to_attack_classes_map:
        return {}

    line_lo, line_hi = target_line_range or (0, 0)
    fuzz_lo = max(0, line_lo - S6_LINE_FUZZ)
    fuzz_hi = line_hi + S6_LINE_FUZZ

    for cluster in clusters:
        cluster_name = cluster.get("cluster_name") or ""
        acs = detector_to_attack_classes_map.get(cluster_name)
        if not acs:
            continue
        for hit in cluster.get("hits", []) or []:
            hf = hit.get("file_path") or ""
            if not _s6_file_matches(target_file, hf):
                continue
            hline = int(hit.get("line") or 0)
            if hline == 0:
                continue
            # Within fuzz window if function range is set, else any line counts.
            if line_lo or line_hi:
                if hline < fuzz_lo or hline > fuzz_hi:
                    continue
            sev = (hit.get("severity") or "LOW").upper()
            sev_weight = S6_SEVERITY_WEIGHTS.get(sev, S6_SEVERITY_WEIGHTS["LOW"])
            contribution = round(S6_PER_HIT_FACTOR * sev_weight, 4)
            for ac in acs:
                out[ac].append({
                    "scorer": "S6",
                    "detector_cluster": cluster_name,
                    "detector_id": hit.get("detector_id") or cluster_name,
                    "severity": sev,
                    "file_path": hf,
                    "line": hline,
                    "contribution": contribution,
                })
    return dict(out)


def combine_scores(
    s1: Dict[str, List[Dict[str, Any]]],
    s4: Dict[str, List[Dict[str, Any]]],
    s2: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    s3: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    s5: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    s6: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    w1: float = 0.30,
    w2: float = 0.20,
    w3: float = 0.20,
    w4: float = 0.10,
    w5: float = 0.05,
    w6: float = 0.15,
    threshold: float = 0.0,
    sigmoid_steepness: float = 3.0,
    convergence_bonus: float = 0.15,
    language: Optional[str] = None,
    weights_cfg: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Combine S1/S2/S3/S4/S5 evidence per-attack-class.

    Score = w1*S1 + w2*S2 + w3*S3 + w4*S4 + w5*S5
            + convergence_bonus * (#scorers_with_nonzero_evidence - 1)

    Confidence = sigmoid(sigmoid_steepness * (score - threshold))

    The convergence bonus rewards multi-scorer alignment: when an attack
    class shows up in 2+ independent scorers (e.g., S1 same-corpus shape
    match + S2 cross-engagement bug-family prior), the bonus reflects the
    "two independent signals agree" likelihood lift. Phase-B per BIG_PLAN
    sub-report 06 §4.4. S5 (cross-language transfer) added Wave-7.

    Wave-12: when ``language`` is provided and ``weights_cfg`` carries a
    matching ``language_overrides[<lang>]`` block, the per-language w1..w5
    weights REPLACE the explicit w1..w5 keyword args. Callers can opt out
    by passing ``language=None`` (default — preserves backward-compat).
    The w6 slot in the per-language block is read but ignored here (no
    S6 scorer wired into HEAD yet; Wave-9 ships S6 as a separate parallel
    commit and will pick up w6 from the same language block).

    Backward-compat: callers that pass only S1/S4 (Phase-A style) or
    S1/S2/S3/S4 (Phase-B style) still work — S5 defaults to ``{}`` and its
    weight is applied to 0.
    """
    # Wave-12: language-aware weight selection. When the caller supplies
    # both a language and a weights_cfg dict, prefer the per-language
    # block. Otherwise fall through to the explicit w1..w5 args.
    if language and isinstance(weights_cfg, dict):
        lang_weights, lang_resolved = resolve_language_weights(language, weights_cfg)
        if lang_resolved is not None:
            w1 = float(lang_weights.get("w1", w1))
            w2 = float(lang_weights.get("w2", w2))
            w3 = float(lang_weights.get("w3", w3))
            w4 = float(lang_weights.get("w4", w4))
            w5 = float(lang_weights.get("w5", w5))
            w6 = float(lang_weights.get("w6", w6))
    s2 = s2 or {}
    s3 = s3 or {}
    s5 = s5 or {}
    s6 = s6 or {}
    all_acs = (
        set(s1.keys())
        | set(s2.keys())
        | set(s3.keys())
        | set(s4.keys())
        | set(s5.keys())
        | set(s6.keys())
    )
    rows: List[Dict[str, Any]] = []
    for ac in all_acs:
        s1_total = sum(e["contribution"] for e in s1.get(ac, []))
        s2_total = sum(e["contribution"] for e in s2.get(ac, []))
        s3_total = sum(e["contribution"] for e in s3.get(ac, []))
        s4_total = sum(e["contribution"] for e in s4.get(ac, []))
        s5_total = sum(e["contribution"] for e in s5.get(ac, []))
        s6_total = sum(e["contribution"] for e in s6.get(ac, []))
        scorer_hits = sum(
            1 for t in (s1_total, s2_total, s3_total, s4_total, s5_total, s6_total) if t > 0.0
        )
        bonus = max(0, scorer_hits - 1) * convergence_bonus
        score = (
            w1 * s1_total
            + w2 * s2_total
            + w3 * s3_total
            + w4 * s4_total
            + w5 * s5_total
            + w6 * s6_total
            + bonus
        )
        evidence: List[Dict[str, Any]] = []
        evidence.extend(sorted(s1.get(ac, []), key=lambda e: -e["contribution"]))
        evidence.extend(sorted(s2.get(ac, []), key=lambda e: -e["contribution"]))
        evidence.extend(sorted(s3.get(ac, []), key=lambda e: -e["contribution"]))
        evidence.extend(sorted(s4.get(ac, []), key=lambda e: -e["contribution"]))
        evidence.extend(sorted(s5.get(ac, []), key=lambda e: -e["contribution"]))
        evidence.extend(sorted(s6.get(ac, []), key=lambda e: -e["contribution"]))
        conf = sigmoid(sigmoid_steepness * (score - threshold))
        rows.append({
            "attack_class": ac,
            "score": round(score, 4),
            "confidence": round(conf, 4),
            "scorer_hits": scorer_hits,
            "convergence_bonus": round(bonus, 4),
            "evidence": evidence,
        })
    rows.sort(key=lambda r: -r["score"])
    return rows


# --------------------------------------------------------------------------- #
# Top-level rank function (importable)                                        #
# --------------------------------------------------------------------------- #

@dataclass
class RankResult:
    target: Dict[str, Any]
    ranked_attack_classes: List[Dict[str, Any]]
    context_pack_id: str
    context_pack_hash: str
    generated_at_utc: str
    inputs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "auditooor.ranker_result.v1",
            "target": self.target,
            "ranked_attack_classes": self.ranked_attack_classes,
            "context_pack_id": self.context_pack_id,
            "context_pack_hash": self.context_pack_hash,
            "generated_at_utc": self.generated_at_utc,
            "inputs": self.inputs,
        }


def _repo_slug_for(target_repo: str) -> str:
    # dydxprotocol/v4-chain → dydx-v4-chain
    parts = (target_repo or "").split("/")
    if len(parts) == 2:
        owner, name = parts
        # heuristic: drop common owner prefix "protocol"
        if owner == "dydxprotocol":
            return f"dydx-{name}"
        return f"{owner}-{name}"
    return (target_repo or "unknown").replace("/", "-")


def _split_top_level_commas(blob: str) -> List[str]:
    parts: List[str] = []
    start = 0
    depth = 0
    for idx, ch in enumerate(blob):
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(blob[start:idx].strip())
            start = idx + 1
    tail = blob[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _extract_paren_block(text: str, start: int) -> Tuple[str, int]:
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:idx], idx
    return "", start


def _synthesize_target_record(file_path: str, function_signature: Optional[str]) -> Dict[str, Any]:
    sig = (function_signature or "").strip()
    rest = re.sub(r"^func\s+", "", sig).strip()
    receiver_type: Optional[str] = None
    if rest.startswith("("):
        receiver_blob, end = _extract_paren_block(rest, 0)
        receiver_parts = receiver_blob.split()
        if receiver_parts:
            receiver_type = receiver_parts[-1]
        rest = rest[end + 1:].strip()

    name_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rest)
    function_name = name_match.group(1) if name_match else ""
    rest = rest[name_match.end():].strip() if name_match else rest
    params: List[Dict[str, str]] = []
    return_types: List[str] = []
    if rest.startswith("("):
        param_blob, end = _extract_paren_block(rest, 0)
        rest_after = rest[end + 1:].strip()
        for part in _split_top_level_commas(param_blob):
            toks = part.rsplit(None, 1)
            if len(toks) == 2:
                names, typ = toks
                for name in [n.strip() for n in names.split(",") if n.strip()]:
                    params.append({"name": name, "type": typ})
            elif part:
                params.append({"name": "", "type": part})
        if rest_after.startswith("("):
            ret_blob, _ = _extract_paren_block(rest_after, 0)
            return_types = [p.strip().split()[-1] for p in _split_top_level_commas(ret_blob) if p.strip()]
        elif rest_after:
            return_types = [rest_after.split()[0]]

    return {
        "file_path": file_path,
        "language": "go",
        "function_signature": sig,
        "function_name": function_name,
        "params": params,
        "return_types": return_types,
        "guards_detected": ["error-return"] if "error" in return_types else [],
        "visibility": "exported" if function_name[:1].isupper() else "private",
        "receiver_type": receiver_type,
    }


def _weights_sha8(weights_path: Path = RANKER_WEIGHTS) -> str:
    """Return first 8 chars of sha256(weights_yaml_bytes). Empty file → 8x0."""
    try:
        raw = weights_path.read_bytes()
    except Exception:
        return "00000000"
    return hashlib.sha256(raw).hexdigest()[:8]


def _scorer_contrib_map(
    scorer: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, float]:
    """Compress a scorer's per-AC evidence list into AC→total-contribution."""
    out: Dict[str, float] = {}
    for ac, ev_list in (scorer or {}).items():
        out[ac] = round(sum(e.get("contribution", 0.0) for e in ev_list), 4)
    return out


def _append_prediction_log(
    target_repo: str,
    file_path: str,
    function_signature: str,
    shape_hash: str,
    predicted_top_5: List[str],
    s1: Dict[str, List[Dict[str, Any]]],
    s2: Dict[str, List[Dict[str, Any]]],
    s3: Dict[str, List[Dict[str, Any]]],
    s4: Dict[str, List[Dict[str, Any]]],
    weights_used_sha8: str,
    s5: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    log_path: Path = PREDICTIONS_LOG,
) -> None:
    """Append a single prediction row to audit/ranker_predictions_log.jsonl.

    Used by tools/ranker-learn.py to compute gradient signal: did the
    realized triager-confirmed attack_class match a row in predicted_top_5?
    """
    row = {
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_repo": target_repo,
        "file_path": file_path,
        "function_signature": function_signature,
        "shape_hash": shape_hash,
        "predicted_top_5": predicted_top_5,
        "scores_by_scorer": {
            "S1": _scorer_contrib_map(s1),
            "S2": _scorer_contrib_map(s2),
            "S3": _scorer_contrib_map(s3),
            "S4": _scorer_contrib_map(s4),
            "S5": _scorer_contrib_map(s5 or {}),
        },
        "weights_used_sha8": weights_used_sha8,
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def rank(
    target_repo: str,
    file_path: str,
    function_signature: Optional[str] = None,
    audit_pin_sha: Optional[str] = None,
    top_n: int = 5,
    min_confidence: float = 0.4,
    w1: Optional[float] = None,
    w2: Optional[float] = None,
    w3: Optional[float] = None,
    w4: Optional[float] = None,
    w5: Optional[float] = None,
    w6: Optional[float] = None,
    workspace_path: Optional[str] = None,
    tags_dir: Path = TAGS_DIR,
    rules_path: Path = RANKER_RULES,
    weights_path: Path = RANKER_WEIGHTS,
    sibling_families_path: Path = SIBLING_FAMILIES,
    bug_class_map_path: Path = BUG_CLASS_TO_AC_MAP,
    cross_lang_map_path: Path = CROSS_LANG_DETECTOR_MAP,
    detector_to_ac_map_path: Path = DETECTOR_TO_AC_MAP,
    mcp_path: Path = MCP_SERVER_PATH,
    enable_s2: bool = True,
    enable_s3: bool = True,
    enable_s5: bool = True,
    enable_s6: bool = True,
    workspace_engage_report: Optional[Dict[str, Any]] = None,
    target_line_start: int = 0,
    target_line_end: int = 0,
) -> RankResult:
    sh = shape_hash_module()
    repo_slug = _repo_slug_for(target_repo)
    target_record = find_target_function(file_path, function_signature, repo_slug=repo_slug)
    if target_record is None:
        # synthesize a minimal record from inputs
        target_record = _synthesize_target_record(file_path, function_signature)
    target_hash = sh.compute_shape_hash(
        language=target_record.get("language", "go"),
        params=target_record.get("params"),
        return_types=target_record.get("return_types"),
        visibility=target_record.get("visibility"),
        guards_detected=target_record.get("guards_detected"),
        receiver_type=target_record.get("receiver_type"),
        fine=False,
    )
    target_hash_fine = sh.compute_shape_hash(
        language=target_record.get("language", "go"),
        params=target_record.get("params"),
        return_types=target_record.get("return_types"),
        visibility=target_record.get("visibility"),
        guards_detected=target_record.get("guards_detected"),
        receiver_type=target_record.get("receiver_type"),
        fine=True,
        body_features=target_record.get("body_features"),
    )

    tags = load_tags(tags_dir)
    rules = load_rules(rules_path)

    weights_cfg = load_weights(weights_path)
    cfg_weights = weights_cfg.get("weights", {})
    # Wave-7: per-family override. Falls back to global weights when family
    # is unknown or per-family yaml is missing. Explicit CLI w1..w4 win.
    per_family_cfg = load_weights_per_family()
    families_for_weights = load_sibling_families(sibling_families_path)
    fam_weights, resolved_family_id = resolve_effective_weights(
        target_repo=target_repo,
        weights_global=weights_cfg,
        per_family=per_family_cfg,
        families=families_for_weights,
    )
    eff_w1 = float(w1) if w1 is not None else fam_weights["w1"]
    eff_w2 = float(w2) if w2 is not None else fam_weights["w2"]
    eff_w3 = float(w3) if w3 is not None else fam_weights["w3"]
    eff_w4 = float(w4) if w4 is not None else fam_weights["w4"]
    # Wave-7: S5 weight. Read from global yaml; per-family override not
    # yet wired (S5 is the cross-language scorer; per-family tuning lands
    # in a follow-up).
    eff_w5 = (
        float(w5) if w5 is not None
        else float(cfg_weights.get("w5", 0.05))
    )
    # Wave-9 Track B: S6 weight resolution.
    eff_w6 = (
        float(w6) if w6 is not None
        else float(cfg_weights.get("w6", 0.15))
    )
    # Wave-12: per-language overrides. Resolution priority (highest first):
    #   1. Explicit CLI w1..w5 args (already applied above).
    #   2. Per-family override (already applied via resolve_effective_weights).
    #   3. Per-language override (Wave-12 — this block).
    #   4. Global ranker_weights.yaml defaults.
    # Language overrides apply only to slots NOT already overridden by an
    # explicit caller-arg OR by the family layer. Semantic: "language" is a
    # corpus-shape default; "family" is a topic-specific override of that
    # default; explicit args are the operator's last word.
    target_language = str(target_record.get("language", "") or "").lower()
    lang_weights, resolved_language = resolve_language_weights(
        target_language, weights_cfg
    )
    if resolved_language is not None:
        if w1 is None and resolved_family_id is None:
            eff_w1 = float(lang_weights.get("w1", eff_w1))
        if w2 is None and resolved_family_id is None:
            eff_w2 = float(lang_weights.get("w2", eff_w2))
        if w3 is None and resolved_family_id is None:
            eff_w3 = float(lang_weights.get("w3", eff_w3))
        if w4 is None and resolved_family_id is None:
            eff_w4 = float(lang_weights.get("w4", eff_w4))
        # w5 is not in the per-family schema; language override applies
        # whenever the caller didn't pass an explicit value.
        if w5 is None:
            eff_w5 = float(lang_weights.get("w5", eff_w5))
        # Wave-9 Track B: w6 same treatment as w5.
        if w6 is None:
            eff_w6 = float(lang_weights.get("w6", eff_w6))

    target_receiver_family = sh.receiver_family(target_record.get("receiver_type"))

    # Wave-8: resolve per-family recency triple and thread into S1 + S3.
    recency_triple = resolve_effective_recency(
        target_repo=target_repo,
        per_family=per_family_cfg,
        families=families_for_weights,
    )

    s1 = score_s1(
        target_record, target_hash, target_hash_fine, tags, audit_pin_sha,
        target_repo=target_repo,
        recency_triple=recency_triple,
    )
    s4 = score_s4(target_record, rules)
    s2: Dict[str, List[Dict[str, Any]]] = {}
    s3: Dict[str, List[Dict[str, Any]]] = {}
    s5: Dict[str, List[Dict[str, Any]]] = {}
    if enable_s2:
        bc_map = load_bug_class_to_ac_map(bug_class_map_path)
        s2 = score_s2(
            target_repo=target_repo,
            bug_class_to_ac_map=bc_map,
            tags=tags,
            workspace_path=workspace_path,
            mcp_path=mcp_path,
        )
    if enable_s3:
        families = load_sibling_families(sibling_families_path)
        s3 = score_s3(
            target_repo=target_repo,
            target_hash=target_hash,
            target_hash_fine=target_hash_fine,
            target_receiver_family=target_receiver_family,
            sibling_families=families,
            tags=tags,
            recency_triple=recency_triple,
        )
    if enable_s5:
        cross_lang_map = load_cross_lang_map(cross_lang_map_path)
        s5 = score_s5_cross_lang_transfer(
            target_language=str(target_record.get("language", "")).lower(),
            target_shape=target_hash,
            target_shape_fine=target_hash_fine,
            tags=tags,
            cross_lang_map=cross_lang_map,
        )
    # Wave-9 Track B: S6 mechanical detector grounding.
    s6: Dict[str, List[Dict[str, Any]]] = {}
    s6_enabled = False
    if enable_s6 and workspace_engage_report:
        s6 = score_s6_detector_grounding(
            target_file=file_path,
            target_line_range=(int(target_line_start or 0), int(target_line_end or 0)),
            workspace_engage_report=workspace_engage_report,
            detector_to_attack_classes_map=load_detector_to_attack_classes_map(
                detector_to_ac_map_path
            ),
        )
        s6_enabled = True
    else:
        # No engage_report — w6 forced to 0 so S6 contributes nothing.
        eff_w6 = 0.0

    conf_cfg = weights_cfg.get("confidence", {})
    sigmoid_center = float(conf_cfg.get("sigmoid_center", 0.0))
    sigmoid_steepness = float(conf_cfg.get("sigmoid_steepness", 3.0))
    convergence_bonus = float(conf_cfg.get("convergence_bonus", 0.15))
    combined = combine_scores(
        s1, s4, s2=s2, s3=s3, s5=s5, s6=s6,
        w1=eff_w1, w2=eff_w2, w3=eff_w3, w4=eff_w4, w5=eff_w5, w6=eff_w6,
        threshold=sigmoid_center,
        sigmoid_steepness=sigmoid_steepness,
        convergence_bonus=convergence_bonus,
    )
    # Wave-14: attack-class required-primitive filter. Caps confidence on
    # classes (fee-redirect / blocked-addr-bypass / admin-bypass / ...)
    # when the target function has zero matching primitives in its
    # calls_made + signature haystack. Audit anchor:
    # audit/postmortems/wave14-ranker-file-level-fp-2026-05-11.md.
    combined = apply_attack_class_primitive_filter(combined, target_record)
    combined = apply_prior_only_filter(combined)
    # Re-sort after capping so high-confidence-pre-cap rows do not
    # crowd out genuine primitives-matched rows at the top.
    combined.sort(key=lambda r: (-float(r.get("confidence", 0.0)), -float(r.get("score", 0.0))))
    filtered = [c for c in combined if c["confidence"] >= min_confidence]
    if top_n and top_n > 0:
        filtered = filtered[:top_n]
    for i, row in enumerate(filtered, 1):
        row["rank"] = i

    target_payload = {
        "repo": target_repo,
        "file_path": file_path,
        "function_signature": function_signature or target_record.get("function_signature", ""),
        "function_name": target_record.get("function_name"),
        "receiver_type": target_record.get("receiver_type"),
        "receiver_family": sh.receiver_family(target_record.get("receiver_type")),
        "params": target_record.get("params") or [],
        "return_types": target_record.get("return_types") or [],
        "language": target_record.get("language", "go"),
        "shape_hash": target_hash,
        "shape_hash_fine": target_hash_fine,
        "guards_detected": target_record.get("guards_detected") or [],
    }
    canonical = json.dumps({
        "target": target_payload,
        "rules_count": len(rules),
        "tags_count": len(tags),
        # Wave-12: include resolved language in cache key so two otherwise-
        # identical targets that happen to have different `language` fields
        # cannot collide on the same context_pack_hash.
        "resolved_language": resolved_language or "",
    }, sort_keys=True)
    h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    # Phase E: append prediction-log row for the continuous learning loop.
    # Disabled via RANKER_PREDICTION_LOG_DISABLED=1 (used by tests + benches).
    try:
        if os.environ.get("RANKER_PREDICTION_LOG_DISABLED") != "1":
            _append_prediction_log(
                target_repo=target_repo,
                file_path=file_path,
                function_signature=function_signature or target_record.get("function_signature", ""),
                shape_hash=target_hash,
                predicted_top_5=[r["attack_class"] for r in filtered[:5]],
                s1=s1, s2=s2, s3=s3, s4=s4, s5=s5,
                weights_used_sha8=_weights_sha8(weights_path),
            )
    except Exception:
        # Disk-write failures must never break ranking. Swallow silently.
        pass
    return RankResult(
        target=target_payload,
        ranked_attack_classes=filtered,
        context_pack_id=f"auditooor.ranker_result.v1:{h[:16]}",
        context_pack_hash=h,
        generated_at_utc=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        inputs={
            "target_repo": target_repo,
            "file_path": file_path,
            "function_signature": function_signature,
            "audit_pin_sha": audit_pin_sha,
            "top_n": top_n,
            "min_confidence": min_confidence,
            "w1": eff_w1,
            "w2": eff_w2,
            "w3": eff_w3,
            "w4": eff_w4,
            "w5": eff_w5,
            "w6": eff_w6,
            "workspace_path": workspace_path,
            "s2_enabled": enable_s2,
            "s3_enabled": enable_s3,
            "s5_enabled": enable_s5,
            "s6_enabled": s6_enabled,
            "family_id": resolved_family_id,
            "weights_source": (
                "per_family_override" if resolved_family_id else
                ("per_language_override" if resolved_language else
                 "global_or_per_family_default")
            ),
            "language_id": resolved_language,
            "recency_triple": recency_triple,
        },
    )


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

def _emit_yaml(d: Any, indent: int = 0) -> str:
    """Minimal YAML emitter."""
    sp = "  " * indent
    if isinstance(d, dict):
        out: List[str] = []
        for k, v in d.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{sp}{k}:")
                out.append(_emit_yaml(v, indent + 1))
            else:
                out.append(f"{sp}{k}: {_emit_scalar(v)}")
        return "\n".join(out)
    if isinstance(d, list):
        out_l: List[str] = []
        for item in d:
            if isinstance(item, (dict, list)):
                first = True
                for line in _emit_yaml(item, indent + 1).splitlines():
                    if first:
                        out_l.append(f"{sp}- {line.lstrip()}")
                        first = False
                    else:
                        out_l.append(f"{sp}  {line.lstrip()}" if line.startswith("  ") else f"{sp}  {line}")
                if first:
                    out_l.append(f"{sp}- {{}}")
            else:
                out_l.append(f"{sp}- {_emit_scalar(item)}")
        return "\n".join(out_l)
    return f"{sp}{_emit_scalar(d)}"


def _emit_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if any(ch in s for ch in ":#[]{},") or s == "":
        return json.dumps(s)
    return s


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target-repo", required=True)
    ap.add_argument("--file-path", required=True)
    ap.add_argument("--function-signature", default=None)
    ap.add_argument("--audit-pin-sha", default=None)
    ap.add_argument("--top-n", type=int, default=5)
    ap.add_argument("--min-confidence", type=float, default=0.4)
    ap.add_argument("--w1", type=float, default=None)
    ap.add_argument("--w2", type=float, default=None)
    ap.add_argument("--w3", type=float, default=None)
    ap.add_argument("--w4", type=float, default=None)
    ap.add_argument("--workspace-path", default=None)
    ap.add_argument("--disable-s2", action="store_true")
    ap.add_argument("--disable-s3", action="store_true")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of YAML.")
    args = ap.parse_args(argv)
    result = rank(
        target_repo=args.target_repo,
        file_path=args.file_path,
        function_signature=args.function_signature,
        audit_pin_sha=args.audit_pin_sha,
        top_n=args.top_n,
        min_confidence=args.min_confidence,
        w1=args.w1,
        w2=args.w2,
        w3=args.w3,
        w4=args.w4,
        workspace_path=args.workspace_path,
        enable_s2=not args.disable_s2,
        enable_s3=not args.disable_s3,
    )
    d = result.to_dict()
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        print(_emit_yaml(d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
