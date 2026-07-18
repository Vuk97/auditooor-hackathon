#!/usr/bin/env python3
"""verdict-tag-extractor — Walk ``~/audits/*/agent_outputs/**`` (and
``submissions/{paste_ready,staging,superseded}``) emitting partial YAML
verdict tags conforming to ``auditooor.verdict_tag.v1``.

Per the design (sub-report 06 §1.1 + §"Tagging pipeline"), this is the
regex-layer extractor — it populates *mandatory* fields and as many of the
shallow optional fields as can be reliably regexed. Semantic fields like
``bug_class`` and ``attack_classes_to_try`` are left blank for the LLM /
manual layer.

CLI:
    python3 tools/verdict-tag-extractor.py
        [--workspace <path>]        # default: walk all ~/audits/*
        [--out-dir audit/corpus_tags/tags]
        [--include-glob '**/*verdict*.md']
        [--dry-run]
        [--reindex]                 # rebuild secondary indexes only
        [--verbose]

Emits a summary line:
    verdicts_scanned=N tags_emitted=M coverage_mandatory_fields=P% \
      by_language={go:X,rust:Y,solidity:Z,...} \
      by_class={DROP:..,FILED:..,...}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
EXTRACTOR_VERSION = "0.1.0"
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"

AUDITS_ROOT = Path(os.environ.get("AUDITOOOR_AUDITS_ROOT", str(Path.home() / "audits")))


# ----------------------------- regex bank ----------------------------------

# audit-pin SHA: either 7-40 hex chars after `audit-pin`, `audit_pin_sha:`,
# or in commit references after `@`.
RX_PIN_SHA = re.compile(
    r"(?:audit[- _]?pin[^a-z0-9]+)([0-9a-f]{7,40})",
    re.IGNORECASE,
)
RX_PIN_SHA_ALT = re.compile(r"(?:audit-pin|audit_pin_sha)[^`]*?`?([0-9a-f]{7,40})`?", re.IGNORECASE)

# target_repo: owner/name with hint markers
RX_REPO_LINE = re.compile(
    r"(?:target[- _]repo|target|repo)\s*[:=]\s*`?([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)`?",
    re.IGNORECASE,
)
RX_REPO_INLINE = re.compile(r"`([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)`")
RX_REPO_GH = re.compile(r"github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)")

# file-line patterns: foo/bar.go:123, src/lib.rs:45-60
RX_FILE_LINE = re.compile(
    r"(?P<path>[A-Za-z0-9_./-]+\.(?:go|rs|sol|py|sql|ts|tsx|js|mjs|move|circom))(?::(?P<lstart>\d+)(?:-(?P<lend>\d+))?)?"
)

# Cantina-NNN, immunefi-NNNNN parity precedents
RX_CANTINA = re.compile(r"cantina[- ](\d{2,5})", re.IGNORECASE)
RX_IMMUNEFI = re.compile(r"immunefi[- _]?(\d{4,6})", re.IGNORECASE)

# severity verbatim
RX_SEVERITY = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)\b")

# verdict_class markers (case-insensitive; first match wins in priority order)
VERDICT_CLASS_PRIORITY = [
    ("FILED", re.compile(r"\bFILED\b|## ?Filed at cantina|^FILED:?", re.IGNORECASE | re.MULTILINE)),
    ("AMENDED", re.compile(r"\bAMENDED[_ -]?(?:UP|DOWN|CLUSTER)?\b|AMENDED[- ]cluster", re.IGNORECASE)),
    ("CONFIRMED", re.compile(r"\bCONFIRMED\b|verdict[: ]+confirmed", re.IGNORECASE)),
    ("DUPE", re.compile(r"\bduplicate\b|closed[- ]dupe|dupe-of", re.IGNORECASE)),
    ("CANDIDATE", re.compile(r"\bCANDIDATE\b|candidate[- ]finding|paste-?ready[- ]?candidate", re.IGNORECASE)),
    ("HOLD", re.compile(r"\bHOLD\b|^HOLD:|hold[- ]pending", re.IGNORECASE | re.MULTILINE)),
    ("NEAR-MISS", re.compile(r"\bNEAR[- ]MISS\b|near[- ]miss", re.IGNORECASE)),
    ("NEGATIVE", re.compile(r"\bNEGATIVE\b|negative verdict|verdict[: ]+negative", re.IGNORECASE)),
    ("DROP", re.compile(r"\bDROP\b|verdict[: ]+drop|^DROP:|## DROP|^drop-", re.IGNORECASE | re.MULTILINE)),
]

# extension -> language
LANG_BY_EXT = {
    ".go": "go",
    ".rs": "rust",
    ".sol": "solidity",
    ".py": "python",
    ".sql": "sql",
    ".ts": "ts",
    ".tsx": "ts",
    ".js": "js",
    ".mjs": "js",
    ".move": "move",
    ".circom": "circom",
}

# Drop-reason regex
RX_DROP_REASON = [
    ("c-symptom-not-root", re.compile(r"symptom[- ]not[- ]root|root[- ]cause[- ]elsewhere", re.IGNORECASE)),
    ("b-reverted", re.compile(r"\breverted\b|revert-of|tier[- ]?6[- ]?b\b", re.IGNORECASE)),
    ("a-fix-stuck-no-residual", re.compile(r"fix[- ]stuck|no[- ]residual", re.IGNORECASE)),
    ("not-reachable", re.compile(r"not[- ]reachable|unreachable[- ]path|reachability[- ]blocked", re.IGNORECASE)),
    ("oos", re.compile(r"\boos\b|out[- ]of[- ]scope", re.IGNORECASE)),
    ("benign-refactor", re.compile(r"benign[- ]refactor", re.IGNORECASE)),
    ("no-rubric-match", re.compile(r"no rubric (?:verbatim )?match|rubric-verbatim-or-drop", re.IGNORECASE)),
    ("duplicate", re.compile(r"\bduplicate\b|dupe-of", re.IGNORECASE)),
    ("fixed-post-pin", re.compile(r"fixed[- ]post[- ]pin|post-pin fix", re.IGNORECASE)),
]

# Filing platform hints
RX_PLATFORM = [
    ("cantina", re.compile(r"\bcantina[- /]|cantina\.xyz", re.IGNORECASE)),
    ("immunefi", re.compile(r"\bimmunefi\b|immunefi\.com", re.IGNORECASE)),
    ("sherlock", re.compile(r"\bsherlock\b", re.IGNORECASE)),
    ("code4rena", re.compile(r"\bcode4rena\b|c4rena", re.IGNORECASE)),
]


# ----------------------------- helpers -------------------------------------


def slugify_verdict_id(verdict_id: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", verdict_id)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:200]


def detect_target_repo(text: str, default_hint: Optional[str] = None) -> Optional[str]:
    """Detect canonical owner/repo. Filters out:
    - filesystem-looking paths (`patterns/...`, `submissions/...`, `test/...`)
    - branch / version names (`release/v0.50.x`)
    - file paths (anything ending in a code-file extension or with > 1 slash)
    - dotted internal paths (`.auditooor/...`)
    """
    def _ok(cand: str) -> bool:
        if not cand or "/" not in cand:
            return False
        if cand.count("/") != 1:
            return False  # multi-slash = file path
        if cand.startswith(".") or cand.startswith("test/") or cand.startswith("agent_outputs/"):
            return False
        if cand.startswith("submissions/") or cand.startswith("patterns/"):
            return False
        if cand.startswith("release/") or cand.startswith("x/") or cand.startswith("docs/"):
            return False
        if cand.startswith("subaccounts/") or cand.startswith("base/"):
            return False
        # exclude file extensions
        if re.search(r"\.(go|rs|sol|py|md|json|yaml|yml|toml|ts|js|tsx|jsx|move|circom|sql)$", cand, re.IGNORECASE):
            return False
        owner, _, repo = cand.partition("/")
        if not re.match(r"^[A-Za-z][A-Za-z0-9._-]+$", owner):
            return False
        if not re.match(r"^[A-Za-z][A-Za-z0-9._-]+$", repo):
            return False
        return True

    m = RX_REPO_LINE.search(text)
    if m and _ok(m.group(1)):
        return m.group(1)
    m = RX_REPO_GH.search(text)
    if m and _ok(m.group(1)):
        return m.group(1)
    # Inline backtick repos — pick first ok candidate
    for m in RX_REPO_INLINE.finditer(text):
        cand = m.group(1)
        if _ok(cand):
            return cand
    return default_hint


def detect_audit_pin_sha(text: str) -> Optional[str]:
    m = RX_PIN_SHA_ALT.search(text)
    if m:
        return m.group(1).lower()
    m = RX_PIN_SHA.search(text)
    if m:
        return m.group(1).lower()
    # Fallback — first 40-hex SHA in body
    m = re.search(r"`([0-9a-f]{40})`", text)
    if m:
        return m.group(1).lower()
    return None


def detect_verdict_class(text: str, filename: str) -> str:
    # Filename hints first
    fn = filename.upper()
    if "FILED_" in fn or "FILED-" in fn:
        return "FILED"
    if "AMENDED" in fn:
        return "AMENDED"
    if "DUPE" in fn or "DUPLICATE" in fn:
        return "DUPE"
    if "SUPERSEDED" in fn:
        return "DUPE"
    for cls, rx in VERDICT_CLASS_PRIORITY:
        if rx.search(text):
            return cls
    return "DROP"  # safest default for unmarked verdicts in hunt-iter dirs


def detect_sites(text: str, max_sites: int = 12) -> List[Dict[str, Any]]:
    seen: Dict[Tuple[str, Optional[int]], Dict[str, Any]] = {}
    for m in RX_FILE_LINE.finditer(text):
        path = m.group("path")
        # filter common non-source noise
        if "/" not in path and "." in path and path.count(".") == 1:
            # bare "foo.go" without dir — likely test fixture mention; keep but de-prioritize
            pass
        if path.startswith("./"):
            path = path[2:]
        lstart_s = m.group("lstart")
        lend_s = m.group("lend")
        lstart = int(lstart_s) if lstart_s else None
        lend = int(lend_s) if lend_s else None
        key = (path, lstart)
        if key in seen:
            if lend and not seen[key].get("line_end"):
                seen[key]["line_end"] = lend
            continue
        site: Dict[str, Any] = {"file_path": path}
        if lstart is not None:
            site["line_start"] = lstart
        if lend is not None:
            site["line_end"] = lend
        seen[key] = site
        if len(seen) >= max_sites:
            break
    return list(seen.values())


def detect_language(sites: List[Dict[str, Any]], text: str) -> str:
    counts: Dict[str, int] = {}
    for s in sites:
        ext = Path(s["file_path"]).suffix.lower()
        lang = LANG_BY_EXT.get(ext)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        # textual hints
        low = text.lower()
        if "func " in low and "package " in low:
            return "go"
        if "fn " in low and ("impl " in low or "pub " in low):
            return "rust"
        if "pragma solidity" in low or "function " in low and "address" in low:
            return "solidity"
        return "unknown"
    if len(counts) > 1:
        # mixed if no single language dominates
        top, top_n = max(counts.items(), key=lambda kv: kv[1])
        rest = sum(v for k, v in counts.items() if k != top)
        if top_n >= 2 * rest:
            return top
        return "mixed"
    return next(iter(counts.keys()))


def detect_parity_precedents(text: str) -> List[str]:
    out = set()
    for m in RX_CANTINA.finditer(text):
        out.add(f"cantina-{m.group(1)}")
    for m in RX_IMMUNEFI.finditer(text):
        out.add(f"immunefi-{m.group(1)}")
    return sorted(out)


def detect_severity(text: str, filename: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (severity_claimed, severity_final).

    Heuristics: severity_claimed = first severity word in body; severity_final
    = severity in filename suffix (e.g. ``-CRITICAL.md``).
    """
    fn = filename.upper()
    final = None
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        if fn.endswith(f"-{s}.MD") or fn.endswith(f"_{s}.MD"):
            final = s
            break
    m = RX_SEVERITY.search(text)
    claimed = m.group(1).upper() if m else None
    return claimed, final


def detect_drop_reason(text: str, verdict_class: str) -> Optional[str]:
    if verdict_class not in ("DROP", "NEGATIVE", "DUPE"):
        return None
    for reason, rx in RX_DROP_REASON:
        if rx.search(text):
            return reason
    return "n/a"


def detect_platform(text: str, path: Path) -> Optional[str]:
    s = str(path).lower()
    if "cantina" in s:
        return "cantina"
    if "immunefi" in s:
        return "immunefi"
    for plat, rx in RX_PLATFORM:
        if rx.search(text):
            return plat
    return None


def detect_filing_id(text: str, filename: str) -> Optional[str]:
    m = re.search(r"cantina[- ](\d{2,5})", filename, re.IGNORECASE)
    if m:
        return f"cantina-{m.group(1)}"
    m = re.search(r"#(\d{4,6})", text)
    if m:
        return f"immunefi-{m.group(1)}"
    return None


def detect_evidence_class(text: str) -> Optional[str]:
    low = text.lower()
    if "--- pass:" in low or "^ok\t" in low or "tests pass" in low:
        return "runtime-pass"
    if "harness" in low and ("test" in low or "regtest" in low):
        return "source+harness"
    if "source-only" in low or "source proof" in low:
        return "source-proof"
    if "cluster impact" in low or "cluster-impact" in low:
        return "cluster-impact"
    return None


def detect_runtime_pass_line(text: str) -> Optional[str]:
    m = re.search(r"--- PASS:[^\n]+", text)
    if m:
        return m.group(0).strip()[:200]
    return None


def detect_poc_path(text: str) -> Optional[str]:
    # heuristic: line containing 'PoC' and a path
    for line in text.splitlines():
        ll = line.lower()
        if "poc" not in ll:
            continue
        m = RX_FILE_LINE.search(line)
        if m:
            return m.group("path")
    return None


# ----------------------------- core ---------------------------------------


def workspace_for_path(p: Path) -> str:
    # ~/audits/<workspace>/agent_outputs/.../foo.md  →  <workspace>
    try:
        rel = p.relative_to(AUDITS_ROOT)
    except ValueError:
        return "unknown"
    parts = rel.parts
    if parts:
        return parts[0]
    return "unknown"


def verdict_id_for(path: Path) -> str:
    """workspace-relative verdict id.

    Strips the workspace dir AND a leading ``agent_outputs/`` / ``submissions/``
    so the id reads as e.g. ``dydx-hunt-iter-1/DYDX-FOO-verdict.md`` per the
    sub-report 06 §1.1 example.
    """
    try:
        rel = path.relative_to(AUDITS_ROOT)
        parts = list(rel.parts)
        # strip the workspace name from the start
        parts = parts[1:]
        # strip leading agent_outputs / submissions bucket
        if parts and parts[0] in ("agent_outputs", "submissions", "mining_rounds"):
            parts = parts[1:]
        return "/".join(parts)
    except ValueError:
        return path.name


def known_workspace_repo_hint(workspace: str) -> Optional[str]:
    return {
        "dydx": "dydxprotocol/v4-chain",
        "spark": "buildonspark/spark",
        "base-azul": "base-org/azul",
        "centrifuge-v3": "centrifuge/protocol-v3",
        "morpho": "morpho-org/morpho-blue",
        "reserve-governor": "reserve-protocol/protocol",
        "snowbridge": "Snowfork/snowbridge",
        "k2": "k2-network/k2",
        "kiln-v1": "kilnfi/kiln",
        "monetrix": "monetrix/monetrix",
        "thegraph": "graphprotocol/contracts",
        "polymarket": "Polymarket/ctf",
        "revert-stableswap-hooks": "Revert-Finance/v4-stableswap",
    }.get(workspace)


def discover_verdicts(workspace: Optional[str], include_glob: Optional[str]) -> Iterable[Path]:
    """Yield candidate .md paths to tag."""
    if workspace:
        roots = [AUDITS_ROOT / workspace]
    else:
        if not AUDITS_ROOT.is_dir():
            return []
        roots = [p for p in AUDITS_ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")]

    glob_pat = include_glob or "**/*.md"
    out: List[Path] = []
    for root in roots:
        if not root.exists():
            continue
        # canonical buckets
        sub_paths = [
            root / "agent_outputs",
            root / "submissions",
            root / "mining_rounds",
        ]
        for sp in sub_paths:
            if not sp.exists():
                continue
            for p in sp.rglob("*.md"):
                # filter to verdict-ish files when no glob narrowing
                low = p.name.lower()
                if include_glob is None:
                    # explicit blocklist — these are status indexes, not findings
                    blocked = (
                        "submissions.md",
                        "submission_readiness_matrix.md",
                        "submission_readiness.md",
                        "audit_completion_status.md",
                        "base_draft_status.md",
                        "deployment_reality_check.md",
                        "submit_now_decision.md",
                        "low_priority_disposition.md",
                        "to_file.md",
                        "submission_reverify_2026-04-25.md",
                        "candidate-triage.md",
                        "candidate_board_audit_20260503.md",
                        "swival_medium_candidates_need_harness.md",
                    )
                    if low in blocked:
                        continue
                    if (
                        "verdict" in low
                        or "filed_" in low
                        or "amended" in low
                        or "candidate" in low
                        or low.startswith("hunt-")
                        or "-immunefi-submission" in low
                        or low.startswith("filed")
                        or low.endswith("-critical.md")
                        or low.endswith("-high.md")
                        or low.endswith("-medium.md")
                    ):
                        out.append(p)
                else:
                    out.append(p)
    return out


def build_tag(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    workspace = workspace_for_path(path)
    repo_hint = known_workspace_repo_hint(workspace)
    target_repo = detect_target_repo(text, repo_hint) or (repo_hint or "unknown/unknown")
    pin_sha = detect_audit_pin_sha(text) or "0000000"
    sites = detect_sites(text)
    language = detect_language(sites, text)
    vclass = detect_verdict_class(text, path.name)
    parity = detect_parity_precedents(text)
    sev_claimed, sev_final = detect_severity(text, path.name)
    drop_reason = detect_drop_reason(text, vclass)
    platform = detect_platform(text, path)
    filing_id = detect_filing_id(text, path.name)
    evidence_class = detect_evidence_class(text)
    runtime_pass = detect_runtime_pass_line(text)
    poc_path = detect_poc_path(text)

    tag: Dict[str, Any] = {
        "verdict_id": verdict_id_for(path),
        "target_repo": target_repo,
        "audit_pin_sha": pin_sha,
        "language": language,
        "verdict_class": vclass,
        "extraction_provenance": "regex",
        "extractor_version": EXTRACTOR_VERSION,
        "extracted_at_utc": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if sites:
        tag["sites"] = sites
    if parity:
        tag["parity_precedents"] = parity
    if sev_claimed:
        tag["severity_claimed"] = sev_claimed
    if sev_final:
        tag["severity_final"] = sev_final
    if drop_reason:
        tag["drop_reason"] = drop_reason
    if platform:
        tag["platform"] = platform
    if filing_id:
        tag["filing_id"] = filing_id
    if evidence_class:
        tag["evidence_class"] = evidence_class
    if runtime_pass:
        tag["runtime_pass_line"] = runtime_pass
    if poc_path:
        tag["poc_path"] = poc_path
    return tag


# --------------------------- YAML emitter ---------------------------------


def emit_yaml(tag: Dict[str, Any]) -> str:
    """Tiny YAML emitter — keeps output stable & dep-free."""
    lines: List[str] = []
    order = [
        "verdict_id",
        "target_repo",
        "audit_pin_sha",
        "language",
        "verdict_class",
        "extraction_provenance",
        "extractor_version",
        "extracted_at_utc",
        "platform",
        "filing_id",
        "severity_claimed",
        "severity_final",
        "triager_outcome",
        "evidence_class",
        "poc_path",
        "runtime_pass_line",
        "drop_reason",
        "bug_class",
        "attack_classes_to_try",
        "parity_precedents",
        "killed_by_rubrics",
        "detector_seeds_emitted",
        "upstream_refs",
        "sites",
        "notes",
    ]
    seen_keys = set()
    force_quote_keys = {"audit_pin_sha", "filing_id", "extractor_version"}
    for k in order:
        if k not in tag:
            continue
        seen_keys.add(k)
        v = tag[k]
        if k in force_quote_keys and isinstance(v, str):
            lines.append(f'{k}: "{v}"')
        else:
            lines.extend(_emit_kv(k, v))
    # any extras
    for k, v in tag.items():
        if k in seen_keys:
            continue
        lines.extend(_emit_kv(k, v))
    return "\n".join(lines) + "\n"


def _emit_kv(k: str, v: Any) -> List[str]:
    if v is None:
        return [f"{k}: null"]
    if isinstance(v, bool):
        return [f"{k}: {'true' if v else 'false'}"]
    if isinstance(v, (int, float)):
        return [f"{k}: {v}"]
    if isinstance(v, str):
        return [f"{k}: {_yaml_scalar(v)}"]
    if isinstance(v, list):
        if not v:
            return [f"{k}: []"]
        if all(isinstance(x, str) for x in v):
            return [f"{k}: [{', '.join(_yaml_scalar(x) for x in v)}]"]
        # list of dicts
        out = [f"{k}:"]
        for it in v:
            if isinstance(it, dict):
                first = True
                for ik, iv in it.items():
                    prefix = "  - " if first else "    "
                    if isinstance(iv, str):
                        out.append(f"{prefix}{ik}: {_yaml_scalar(iv)}")
                    elif isinstance(iv, (int, float)):
                        out.append(f"{prefix}{ik}: {iv}")
                    elif isinstance(iv, list) and all(isinstance(x, str) for x in iv):
                        out.append(f"{prefix}{ik}: [{', '.join(_yaml_scalar(x) for x in iv)}]")
                    else:
                        out.append(f"{prefix}{ik}: {iv}")
                    first = False
            else:
                out.append(f"  - {_yaml_scalar(str(it))}")
        return out
    if isinstance(v, dict):
        out = [f"{k}:"]
        for ik, iv in v.items():
            if isinstance(iv, str):
                out.append(f"  {ik}: {_yaml_scalar(iv)}")
            else:
                out.append(f"  {ik}: {iv}")
        return out
    return [f"{k}: {v}"]


def _yaml_scalar(s: str) -> str:
    needs_quote = (
        any(c in s for c in [":", "#", "{", "}", "[", "]", ",", "&", "*", "!", "|", ">", "'", '"', "%", "@", "`"])
        or s.strip() != s
        or s == ""
        or s.lower() in ("true", "false", "null", "yes", "no", "on", "off")
    )
    # Permit plain unquoted for simple alphanum/hyphen/slash/dot
    if not needs_quote and re.match(r"^[A-Za-z0-9_./+\-=]+$", s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------- indexes --------------------------------------


def rebuild_indexes(tag_dir: Path, index_dir: Path) -> Dict[str, int]:
    index_dir.mkdir(parents=True, exist_ok=True)
    by_repo: Dict[str, List[Dict[str, Any]]] = {}
    by_lang: Dict[str, List[Dict[str, Any]]] = {}
    by_attack: Dict[str, List[Dict[str, Any]]] = {}
    by_bug: Dict[str, List[Dict[str, Any]]] = {}
    n_tags = 0

    sys.path.insert(0, str(REPO_ROOT / "tools"))
    try:
        from importlib import import_module
        mod = import_module("verdict-tag-schema".replace("-", "_"))  # would fail; use direct import below
    except Exception:
        # direct re-implement: we just call _load_yaml from this module
        pass

    # local YAML loader to avoid re-implementing
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_vts", str(REPO_ROOT / "tools" / "verdict-tag-schema.py")
    )
    vts = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(vts)
    load_yaml = vts._load_yaml  # type: ignore[attr-defined]

    for yp in sorted(tag_dir.glob("*.yaml")):
        try:
            doc = load_yaml(yp)
        except Exception as e:
            print(f"index: skip {yp.name}: {e}", file=sys.stderr)
            continue
        if not isinstance(doc, dict):
            continue
        n_tags += 1
        rec = {"verdict_id": doc.get("verdict_id"), "tag_file": yp.name}
        repo = doc.get("target_repo") or "unknown"
        by_repo.setdefault(repo, []).append(rec)
        lang = doc.get("language") or "unknown"
        by_lang.setdefault(lang, []).append(rec)
        for ac in (doc.get("attack_classes_to_try") or []):
            by_attack.setdefault(str(ac), []).append(rec)
        if doc.get("bug_class"):
            by_bug.setdefault(str(doc["bug_class"]), []).append(rec)

    def write_index(name: str, m: Dict[str, List[Dict[str, Any]]]) -> int:
        outp = index_dir / name
        with outp.open("w", encoding="utf-8") as fh:
            for k in sorted(m.keys()):
                for rec in m[k]:
                    row = {"key": k, **rec}
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
        return sum(len(v) for v in m.values())

    counts = {
        "by_target_repo.jsonl": write_index("by_target_repo.jsonl", by_repo),
        "by_language.jsonl": write_index("by_language.jsonl", by_lang),
        "by_attack_class.jsonl": write_index("by_attack_class.jsonl", by_attack),
        "by_bug_class.jsonl": write_index("by_bug_class.jsonl", by_bug),
    }
    counts["tags_indexed"] = n_tags
    return counts


# --------------------------- main -----------------------------------------


def _load_yaml_via_schema_tool(path: Path) -> Any:
    """Load YAML using the loader from tools/verdict-tag-schema.py."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_vts", str(REPO_ROOT / "tools" / "verdict-tag-schema.py")
    )
    vts = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(vts)
    return vts._load_yaml(path)  # type: ignore[attr-defined]


def _apply_seed(seed_path: Path, out_dir: Path, index_dir: Path) -> int:
    """Apply a hand-fill enrichment YAML to existing tag files.

    The seed YAML format is a top-level mapping of
    ``<tag_filename>.yaml -> {bug_class, attack_classes_to_try, ...}``.
    Each matching tag file is loaded, merged with the seed entry, marked
    extraction_provenance=hybrid, and re-emitted.
    """
    seed = _load_yaml_via_schema_tool(seed_path)
    if not isinstance(seed, dict):
        print(f"seed file root must be a mapping, got {type(seed).__name__}", file=sys.stderr)
        return 2
    applied = 0
    missing = 0
    for tag_filename, enrichment in seed.items():
        tag_path = out_dir / tag_filename
        if not tag_path.exists():
            print(f"missing tag file: {tag_path}", file=sys.stderr)
            missing += 1
            continue
        if not isinstance(enrichment, dict):
            continue
        doc = _load_yaml_via_schema_tool(tag_path)
        if not isinstance(doc, dict):
            continue
        # Merge — seed values take precedence
        for k, v in enrichment.items():
            doc[k] = v
        doc["extraction_provenance"] = "hybrid"
        doc["extracted_at_utc"] = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        tag_path.write_text(emit_yaml(doc), encoding="utf-8")
        applied += 1
    print(f"seed_applied={applied} missing={missing}")
    counts = rebuild_indexes(out_dir, index_dir)
    print(f"index_counts={counts}")
    return 0


MANDATORY_FIELDS = (
    "verdict_id",
    "target_repo",
    "audit_pin_sha",
    "language",
    "verdict_class",
    "extraction_provenance",
    "extractor_version",
    "extracted_at_utc",
)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", help="Restrict to one ~/audits/<ws>/")
    p.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    p.add_argument("--include-glob", help="Glob narrower than default; e.g. '**/*verdict*.md'")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--reindex", action="store_true", help="Only rebuild index/* from existing tags/")
    p.add_argument("--apply-seed", help="Apply hand-fill YAML enrichment to existing tags. See seed_manual_enrichment_*.yaml format.")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--limit", type=int, default=0, help="Cap number of tags emitted (debug).")
    args = p.parse_args(argv)

    out_dir = Path(args.out_dir)
    index_dir = out_dir.parent / "index"

    if args.reindex:
        counts = rebuild_indexes(out_dir, index_dir)
        print(json.dumps(counts, sort_keys=True))
        return 0

    if args.apply_seed:
        return _apply_seed(Path(args.apply_seed), out_dir, index_dir)

    out_dir.mkdir(parents=True, exist_ok=True)

    scanned = 0
    emitted = 0
    by_lang: Dict[str, int] = {}
    by_class: Dict[str, int] = {}
    coverage_hits = 0
    coverage_total = 0

    for path in discover_verdicts(args.workspace, args.include_glob):
        scanned += 1
        try:
            tag = build_tag(path)
        except Exception as e:
            if args.verbose:
                print(f"skip {path}: {e}", file=sys.stderr)
            continue
        emitted += 1
        by_lang[tag["language"]] = by_lang.get(tag["language"], 0) + 1
        by_class[tag["verdict_class"]] = by_class.get(tag["verdict_class"], 0) + 1
        for f in MANDATORY_FIELDS:
            coverage_total += 1
            if tag.get(f):
                coverage_hits += 1
        if args.dry_run:
            if args.verbose:
                print(f"would emit: {tag['verdict_id']}")
            continue
        slug = slugify_verdict_id(tag["verdict_id"])
        outp = out_dir / f"{slug}.yaml"
        outp.write_text(emit_yaml(tag), encoding="utf-8")
        if args.limit and emitted >= args.limit:
            break

    coverage_pct = (100.0 * coverage_hits / coverage_total) if coverage_total else 0.0
    print(
        f"verdicts_scanned={scanned} tags_emitted={emitted} "
        f"coverage_mandatory_fields={coverage_pct:.1f}% "
        f"by_language={by_lang} "
        f"by_class={by_class}"
    )
    if not args.dry_run:
        counts = rebuild_indexes(out_dir, index_dir)
        print(f"index_counts={counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
