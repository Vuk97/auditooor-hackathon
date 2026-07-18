#!/usr/bin/env python3
"""per-fn-mimo-batch-gen.py - enriched MIMO batch generator from ranked per-fn questions.

r36-rebuttal: registered lane per-fn-mimo-upgrade-2026-05-27.

Replaces the generic mimo-harness-batch-gen.py (which fires 2007 questions
against the workspace context blob with no fn:line anchor). This consumes
ranked per-fn questions from per-fn-question-ranker.py and emits an enriched
batch where each task prompt contains:

  1. Function anchor: file:line + signature + body excerpt
  2. Workspace docs (compact): SCOPE/SEVERITY/BUG_BOUNTY OOS catalog
  3. Top-3 matched chain templates from global_chain_templates.jsonl
  4. Top-5 exploit predicates from exploit_predicates_promoted.jsonl
  5. Workspace anti-pattern catalog excerpts
  6. KDE warnings (auto-skip-similar)
  7. STRICT JSON output schema + R76 hallucination rule (must grep)

Per-task prompt budget ~6-8K chars (down from 14K generic blob, but now
function-anchored). MIMO cost-per-task drops, YES-rate predicted to rise.

USAGE:
  python3 tools/per-fn-mimo-batch-gen.py \
    --ranked-questions ranked.jsonl --workspace ~/audits/<ws> \
    --output batch.jsonl
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.per_fn_mimo_batch.v1"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent

# FORK-DELTA HAND-OFF: for a fork-target unit, the per-fn brief carries a
# fork_delta_status so a hunt agent knows whether the function's file is
# Sei-modified/added (in-scope) vs unmodified-upstream (OOS). The materialize
# step writes <ws>/.auditooor/fork_modified/<local_name>.json; we read it once.
try:
    from tools.lib.fork_modified import (  # type: ignore
        fork_modified_keep_set,
        load_fork_modified_artifact,
    )
except Exception:  # pragma: no cover - direct-script fallback
    try:
        sys.path.insert(0, str(AUDITOOOR_ROOT / "tools" / "lib"))
        from fork_modified import (  # type: ignore
            fork_modified_keep_set,
            load_fork_modified_artifact,
        )
    except Exception:
        fork_modified_keep_set = None  # type: ignore
        load_fork_modified_artifact = None  # type: ignore


def load_fork_delta_index(ws: Path) -> dict[str, set | None]:
    """{local_name: keep_set_or_None} from every materialized fork_modified
    artifact under <ws>/.auditooor/fork_modified/. None keep-set = upstream
    unresolved (all units treated in-scope). Empty dict = not a fork / no
    artifacts."""
    out: dict[str, set | None] = {}
    if load_fork_modified_artifact is None or fork_modified_keep_set is None:
        return out
    d = ws / ".auditooor" / "fork_modified"
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        art = load_fork_modified_artifact(ws, p.stem)
        if art is not None:
            out[p.stem] = fork_modified_keep_set(art)
    return out


def fork_delta_status_for(file_path: str, fork_delta_idx: dict[str, set | None]) -> dict | None:
    """Return a fork_delta_status dict for a task whose function lives in
    ``file_path`` when that file is under a resolved fork tree, else None (the
    unit is not a fork-target unit). Shape:
      {local_name, sei_modified: yes|no|unresolved,
       repo_relative_path, diff_pointer}
    ``sei_modified='no'`` means UNMODIFIED-UPSTREAM (OOS - should already have
    been dropped upstream, but the agent is told explicitly)."""
    if not fork_delta_idx or not file_path:
        return None
    fp = str(file_path)
    for name, keep in fork_delta_idx.items():
        prefix = f"src/{name}/"
        seg = f"/src/{name}/"
        if fp.startswith(prefix):
            rel = fp[len(prefix):]
        elif seg in fp:
            rel = fp.split(seg, 1)[1]
        else:
            continue
        if keep is None:
            sei_modified = "unresolved"
        else:
            sei_modified = "yes" if rel in keep else "no"
        return {
            "local_name": name,
            "sei_modified": sei_modified,
            "repo_relative_path": rel,
            "diff_pointer": f".auditooor/fork_modified/{name}.json",
        }
    return None

# C1 - exploit-anchor corpus -> prompt (default-OFF env AUDITOOOR_EXPLOIT_ANCHOR_PROMPT=1).
# REUSE the shared helper (which reuses reverse-correlator.load_anchors + its ranker);
# do NOT rebuild a ranker here. render_exploit_anchor_block returns '' when the env is
# OFF / corpus missing / nothing clears the similarity threshold -> prompt unchanged.
try:
    from tools.lib import exploit_anchor_prompt as _exploit_anchor  # type: ignore
except Exception:  # pragma: no cover - direct-script fallback
    try:
        sys.path.insert(0, str(AUDITOOOR_ROOT / "tools" / "lib"))
        import exploit_anchor_prompt as _exploit_anchor  # type: ignore
    except Exception:
        _exploit_anchor = None  # type: ignore

# Static OOS-pattern templates per workspace; if BUG_BOUNTY.md exists,
# the operator-published OOS catalog is loaded instead.
DEFAULT_OOS_NOTE = (
    "Workspace OOS catalog: if your candidate finding matches a BUG_BOUNTY.md "
    "numbered OOS row, set applies_to_target='no' with dupe_check pointing at "
    "the OOS row ID."
)


_PATH_LINE_RE = re.compile(r"^(?P<path>.*?):(?P<line>\d+)(?::\d+)?$")


def _split_path_line(raw: str) -> tuple[str, int | None]:
    """Split a 'path:line' or 'path:line:col' anchor into (path, line).

    A bare path (or a path whose ':' is not followed by digits, e.g. a Windows
    drive letter 'C:\\x') is returned intact with line=None. The per-fn question
    corpus stores the authoritative line as a ':N' suffix on the 'file' field for
    ~all Solidity units and a fraction of Go units; treating the whole string as a
    filesystem path (the historical bug) both broke source resolution AND forced
    read_file_excerpt to fall back to name-matching. Language-agnostic."""
    raw = (raw or "").strip()
    if not raw:
        return ("", None)
    m = _PATH_LINE_RE.match(raw)
    if m and m.group("path"):
        try:
            return (m.group("path"), int(m.group("line")))
        except (TypeError, ValueError):
            return (raw, None)
    return (raw, None)


def _debase_fn_name(fn_name: str) -> str:
    """Reduce a possibly-qualified, possibly-signatured function identifier to the
    bare name used at its definition site. 'Type.method(a,b)' -> 'method';
    'pkg::fn' -> 'fn'; 'Recv.Foo' -> 'Foo'; 'foo(uint256)' -> 'foo'. Generic across
    Solidity/Go/Rust/Python identifiers."""
    s = (fn_name or "").strip()
    if not s or s == "?":
        return ""
    s = s.split("(", 1)[0].strip()          # drop a signature suffix
    for sep in ("::", "."):                  # drop a Type./pkg:: qualifier
        if sep in s:
            s = s.split(sep)[-1].strip()
    return s


def read_file_excerpt(file_path: str, fn_name: str, max_lines: int = 30,
                      known_line: int | None = None) -> tuple[str, int, int]:
    """Read a function's body excerpt with surrounding context. Returns (excerpt, start_line, end_line).

    Resolution order: (1) an authoritative `known_line` from the enumerator (the
    per-fn corpus already knows the definition line for many units); (2) a
    definition-site name match that is Go-receiver-aware and qualifier/signature
    tolerant. The historical regex `(func|function|...)\\s+NAME` silently failed on
    every Go METHOD (`func (s *StateDB) SubRefund(` - the receiver sits between the
    keyword and the name) and on every qualified/signatured NAME, emitting
    "excerpt unavailable" for ~75% of a Go/fork residual (SEI 2026-07-04)."""
    if not file_path:
        return ("", 0, 0)
    # Defensive: tolerate a 'path:line' anchor even if the caller did not split it.
    stripped_path, suffix_line = _split_path_line(file_path)
    if suffix_line is not None and known_line is None and not Path(file_path).is_file():
        file_path, known_line = stripped_path, suffix_line
    p = Path(file_path)
    if not p.is_file():
        return ("", 0, 0)
    try:
        text = p.read_text(encoding="utf-8", errors="replace").split("\n")
    except Exception:
        return ("", 0, 0)
    n = len(text)
    # (1) authoritative line from the enumerator - language-agnostic, no matching.
    if known_line and 0 < known_line <= n:
        start = known_line - 1
        end = min(n, start + max_lines)
        return ("\n".join(text[start:end]), start + 1, end)
    # (2) definition-site match: keyword, then (optionally) a Go receiver
    # `(...)` or Rust generics before the bare NAME, then an opener `( { <`.
    base = _debase_fn_name(fn_name)
    if not base:
        return ("", 0, 0)
    fn_re = re.compile(
        r"(?:function|fn|def|func)\b[^\n{]*?\b" + re.escape(base) + r"\s*[(<{]")
    for i, line in enumerate(text):
        if fn_re.search(line):
            start = max(0, i)
            end = min(n, start + max_lines)
            return ("\n".join(text[start:end]), start + 1, end)
    return ("", 0, 0)


def compact_workspace_docs(ws: Path, max_chars: int = 3000) -> str:
    """Compact SCOPE.md + SEVERITY.md + BUG_BOUNTY.md to ~3K chars total."""
    parts = []
    for name in ("SCOPE.md", "SEVERITY.md", "BUG_BOUNTY.md"):
        f = ws / name
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # Take first 1K chars from each
        parts.append(f"=== {name} (first 1000 chars) ===\n" + text[:1000])
    out = "\n\n".join(parts)
    return out[:max_chars]


def load_global_chain_templates_indexed() -> dict[str, list[dict]]:
    """global_chain_templates.jsonl grouped by attack_class."""
    out = collections.defaultdict(list)
    p = AUDITOOOR_ROOT / "audit/corpus_tags/derived/global_chain_templates.jsonl"
    if not p.is_file():
        return out
    try:
        with p.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                klass = (r.get("attack_class") or r.get("class") or "").lower()
                if klass:
                    out[klass].append(r)
    except Exception:
        pass
    return out


def load_exploit_predicates_indexed() -> dict[str, list[dict]]:
    """exploit_predicates_promoted.jsonl grouped by attack_class."""
    out = collections.defaultdict(list)
    p = AUDITOOOR_ROOT / "audit/corpus_tags/derived/exploit_predicates_promoted.jsonl"
    if not p.is_file():
        return out
    try:
        with p.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                klass = (r.get("attack_class") or r.get("class") or "").lower()
                if klass:
                    out[klass].append(r)
    except Exception:
        pass
    return out


def load_kde(workspace_name: str, limit: int = 20) -> list[str]:
    """Top-N KDE reasons for warn-injection."""
    kde_path = AUDITOOOR_ROOT / "reports" / "known_dead_ends.jsonl"
    out = []
    if not kde_path.is_file():
        return out
    with kde_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("workspace") != workspace_name and workspace_name != "any":
                continue
            reason = (r.get("kill_reason") or "")[:160]
            if reason:
                out.append(reason)
                if len(out) >= limit:
                    break
    return out


# ---------------------------------------------------------------------------
# A2 - COVERAGE-PLANE DRAIN (default-OFF env AUDITOOOR_PLANE_DRAIN=1)
#
# The ranked-question path never reads .auditooor/coverage_plane.jsonl, so the
# materialized not-enumerated (unit x impact-frame) cells were drained by
# nothing on this builder too. When AUDITOOOR_PLANE_DRAIN=1 AND the plane exists,
# APPEND one enriched hunt task per not-enumerated cell (source_of_truth=
# 'coverage_plane', impact=<frame>). Env-off / plane-absent -> no tasks appended,
# byte-identical to the legacy ranked-question output.
# ---------------------------------------------------------------------------
def _plane_drain_enabled() -> bool:
    """A2 gate: env AUDITOOOR_PLANE_DRAIN=1 (default OFF)."""
    return os.environ.get("AUDITOOOR_PLANE_DRAIN", "").strip().lower() in ("1", "true", "yes", "on")


def load_plane_not_enumerated(ws: Path) -> list[dict]:
    """Return the coverage_plane.jsonl rows whose status=='not-enumerated'. Empty
    when the plane is absent. Each returned dict carries file / function / frame /
    lang / unit as-is for downstream task construction."""
    plane = ws / ".auditooor" / "coverage_plane.jsonl"
    if not plane.is_file():
        return []
    out: list[dict] = []
    try:
        for line in plane.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                cell = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(cell, dict) and str(cell.get("status") or "").strip() == "not-enumerated":
                out.append(cell)
    except Exception:
        return []
    return out


def build_plane_drain_task(idx: int, cell: dict, ws: Path, ws_name: str,
                           compact_docs: str) -> dict:
    """Build one enriched MIMO task for a not-enumerated coverage_plane cell. Reuses
    read_file_excerpt for the fn body and the same STRICT-JSON output contract as
    build_enriched_task, but the ADVERSARY GOAL is the cell's impact FRAME."""
    rel, _cl_line = _split_path_line(str(cell.get("file") or cell.get("asset") or "").strip())
    fn = str(cell.get("function") or "").strip()
    for _lk in ("line", "start_line", "line_start"):
        _lv = cell.get(_lk)
        if isinstance(_lv, int) and _lv > 0:
            _cl_line = _lv
            break
    frame = str(cell.get("frame") or "").strip()
    file_path = _resolve_source_file(ws, rel) or rel
    excerpt, start_line, end_line = read_file_excerpt(file_path, fn, known_line=_cl_line)
    nl = chr(10)
    parts = [
        f"You are a security auditor for {ws_name} (coverage-plane drain: one impact frame).",
        "",
        f"ADVERSARY GOAL (this task hunts ONE impact frame deeply): drive the target "
        f"`{fn or '(file-level)'}` in {rel} to produce a **{frame or 'in-scope impact'}** outcome. "
        "A source-cited rule-out for THIS frame IS genuine coverage.",
        "",
        "TASK: read the SPECIFIC FUNCTION at the cited file:line and reason adversarially "
        "about whether the impact frame is reachable. Output STRICT JSON only - no prose around it.",
        "",
        "REQUIRED JSON KEYS (all required, even if null/'NA'):",
        "  applies_to_target: yes | no | maybe",
        "  confidence: low | medium | high",
        "  candidate_finding: string (one-sentence brief, ANCHOR TO THE FN)",
        "  file_line: 'path/to/file.sol:42' (must be the line in the excerpt)",
        "  code_excerpt: string (1-3 lines of actual code FROM THE EXCERPT BELOW)",
        "  severity_estimate: LOW | MEDIUM | HIGH | CRITICAL | NA",
        "  rubric_row_cited: string verbatim from SEVERITY.md",
        "  dupe_check: string (cross-ref filed / known_dead_ends / BUG_BOUNTY.md OOS row)",
        "  falsification_attempt: string (what specific source check would disprove this?)",
        "  notes: string",
        "",
        "HARD RULES (R76 hallucination guard - the operator's gate fails closed):",
        "  - code_excerpt MUST be a verbatim substring of the FUNCTION EXCERPT below.",
        "  - file_line MUST be a real line in the cited file (start_line .. end_line).",
        "  - If neither holds, set applies_to_target='no' and notes='unable-to-anchor'.",
        "",
        f"=== TARGET (coverage-plane cell: impact frame={frame or 'NA'}) ===",
        f"FILE: {file_path}",
        f"FN: {fn or '(file-level)'}",
        f"LINE RANGE: {start_line}..{end_line}",
        "",
        "FUNCTION EXCERPT:",
        "```",
        excerpt[:2000] if excerpt else "(excerpt unavailable - file or fn not found; set applies_to_target='no')",
        "```",
        "",
        "=== WORKSPACE DOCS (compact) ===",
        compact_docs,
        "",
        "=== END CONTEXT ===",
        "",
        DEFAULT_OOS_NOTE,
        "",
        "Apply the impact frame to the FUNCTION above. Return STRICT JSON only.",
    ]
    prompt = nl.join(parts)
    _frame = "" if os.environ.get("PER_IMPACT_FRAMES", "1") == "0" else frame
    return {
        "task_id": f"perfn_mimo_{ws_name}_plane_{idx:05d}",
        "task_type": "per_fn_workspace_hunt_v2",
        "workspace": ws_name,
        "workspace_path": str(ws),
        "source_question_id": "coverage-plane-not-enumerated",
        "source_of_truth": "coverage_plane",
        "impact": _frame,
        "function_anchor": {"file": file_path, "fn": fn, "start_line": start_line, "end_line": end_line},
        "rank": -1,
        "score": 0,
        "prompt": prompt,
        "max_tokens": 1500,
    }


def _norm_file_line(s: str) -> str:
    """Normalize a 'path/to/file.rs:42' surface to its BASENAME (lowercased) for
    loose indexing. We key on the basename so a guard gap recorded as a
    workspace-relative path (e.g. 'src/Vault.sol:1') still matches a target fn
    whose file is given as an absolute path (e.g. '/tmp/ws/src/Vault.sol')."""
    s = (s or "").strip()
    if not s:
        return ""
    s = re.sub(r":\d+(?::\d+)?$", "", s)
    # basename only - robust across absolute / ws-relative / src-stripped forms
    s = s.replace("\\", "/").rstrip("/")
    base = s.rsplit("/", 1)[-1]
    return base.lower()


def load_guard_negative_space_indexed(ws: Path) -> dict:
    """Load <ws>/.auditooor/negative_space_gaps.jsonl indexed by normalized file
    path. Schema (auditooor.negative_space_gap.v1): file_line, guard_id, kind,
    invariant_hint, gap_found(bool), disposition. Mirrors how exploit-queue.py
    reads negative_space: keep only rows that record a REAL gap (gap_found True,
    OR gap_found absent and disposition not a drop/ruled-out)."""
    out = collections.defaultdict(list)
    pth = ws / ".auditooor" / "negative_space_gaps.jsonl"
    if not pth.is_file():
        return out
    drop = {"drop", "dropped", "ruled-out", "ruled_out", "no-gap", "no_gap"}
    try:
        with pth.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(r, dict):
                    continue
                gap_found = r.get("gap_found")
                disposition = str(r.get("disposition") or "").strip().lower()
                if gap_found is True:
                    actionable = True
                elif gap_found is False:
                    actionable = False
                else:
                    actionable = disposition not in drop
                if not actionable:
                    continue
                key = _norm_file_line(str(r.get("file_line") or "").strip())
                if not key:
                    continue
                out[key].append(r)
    except Exception:
        pass
    return out


def load_sibling_asymmetries_indexed(ws: Path) -> dict:
    """Load <ws>/.auditooor/sibling_guard_asymmetries.jsonl indexed by the
    normalized file path of the UNDER-guarded sibling (path_b). Schema
    (auditooor.sibling_path_guard_diff.v1): pair, path_a{file,line,name},
    path_b{file,line,name}, guard_on_a_missing_on_b(list), shared_invariant_hint,
    verdict. Keep only verdict == 'asymmetry-candidate' rows."""
    out = collections.defaultdict(list)
    pth = ws / ".auditooor" / "sibling_guard_asymmetries.jsonl"
    if not pth.is_file():
        return out
    try:
        with pth.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(r, dict):
                    continue
                if str(r.get("verdict") or "").strip().lower() != "asymmetry-candidate":
                    continue
                path_b = r.get("path_b") if isinstance(r.get("path_b"), dict) else {}
                key = _norm_file_line(str(path_b.get("file") or "").strip())
                if not key:
                    continue
                out[key].append(r)
    except Exception:
        pass
    return out


# r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
def load_adversarial_hypotheses_indexed(ws: Path) -> dict:
    """Load <ws>/.auditooor/adversarial_hypothesis_top5.json and index the
    per-function adversarial differential hypotheses by normalized file path.
    The AHDH payload (schema auditooor.adversarial_hypothesis_differential.*,
    emitted by tools/adversarial-hypothesis-differential-hunter.py) nests a
    top-level `functions` list; each function record carries
    function.file_path + hypotheses[] (each hyp has attack_class,
    violated_invariant, manipulated_state, required_preconditions, source_ref
    'file:line'). We key each function by its normalized file basename so a
    target fn whose file is given absolute/ws-relative still matches. Returns
    {} when the silo artifact is absent."""
    out = collections.defaultdict(list)
    pth = ws / ".auditooor" / "adversarial_hypothesis_top5.json"
    if not pth.is_file():
        return out
    try:
        payload = json.loads(pth.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(payload, dict):
        return out
    fns = payload.get("functions")
    if not isinstance(fns, list):
        return out
    for rec in fns:
        if not isinstance(rec, dict):
            continue
        # file_path may live at the top of the record (AHDH _function_to_dict)
        # or under a nested `function` object (per-hypothesis function block).
        fpath = rec.get("file_path")
        if not fpath:
            fn_obj = rec.get("function") if isinstance(rec.get("function"), dict) else {}
            fpath = fn_obj.get("file_path")
        hyps = rec.get("hypotheses")
        if not isinstance(hyps, list) or not hyps:
            continue
        key = _norm_file_line(str(fpath or "").strip())
        if not key:
            continue
        out[key].append(rec)
    return out


# r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
def load_novel_vector_invariants_indexed(ws: Path) -> dict:
    """Load <ws>/.auditooor/novel_vector_invariants.json (schema
    auditooor.novel_vector_invariants.v1, emitted by audit-deep Step 13 via
    tools/novel-vector-invariant-miner.py) and index the per-target/per-function
    derived invariants by normalized source file path. The workspace-level JSON
    carries a `per_file` list of {file, lang, jsonl}; each `jsonl` holds the
    derived-invariant records (schema auditooor.novel_vector_invariant.v1 with
    target/function/statement/family/invariant_class/assertion_expr fields). We
    read each per-file jsonl and group the records under the normalized basename
    of its `file`. Returns {} when the silo artifact is absent."""
    out = collections.defaultdict(list)
    pth = ws / ".auditooor" / "novel_vector_invariants.json"
    if not pth.is_file():
        return out
    try:
        payload = json.loads(pth.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(payload, dict):
        return out
    per_file = payload.get("per_file")
    if not isinstance(per_file, list):
        return out
    for rec in per_file:
        if not isinstance(rec, dict):
            continue
        src = rec.get("file") or ""
        key = _norm_file_line(str(src).strip())
        if not key:
            continue
        jsonl = rec.get("jsonl")
        invs = []
        if isinstance(jsonl, str) and jsonl:
            jp = Path(jsonl)
            if jp.is_file():
                try:
                    for line in jp.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ir = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(ir, dict) and ir.get("statement"):
                            invs.append(ir)
                except Exception:
                    invs = []
        if invs:
            out[key].extend(invs)
    return out


# r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
def load_guard_probe_packets_indexed(ws: Path) -> dict:
    """Load <ws>/.auditooor/guard_probe_packets.jsonl indexed by the normalized
    file path of the guard (FIX 2). Schema (auditooor.guard_probe_packet.v1):
    guard_id, file_line, guard_line, invariant_hint, checks,
    invariant_context_incomplete. This is the deep-analysis silo emitted by
    tools/guard-context-extract.py - the per-guard 'what this guard does NOT
    check' context. Distinct from negative_space_gaps (verdict rows): the probe
    packet carries the guard CONDITION + a compact function window so the brief
    can surface the exact blind spot."""
    out = collections.defaultdict(list)
    pth = ws / ".auditooor" / "guard_probe_packets.jsonl"
    if not pth.is_file():
        return out
    try:
        with pth.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(r, dict):
                    continue
                key = _norm_file_line(str(r.get("file_line") or "").strip())
                if not key:
                    continue
                out[key].append(r)
    except Exception:
        pass
    return out


def load_math_spec_indexed(ws: Path) -> dict:
    """Load <ws>/math_invariants/math_spec.json and index per-contract math
    invariants by normalized file basename (FIX 1). math_spec is contract-keyed
    (schema_version 1.0, tool math-invariant-miner.py); we key each contract by
    its lowercased name so a target function whose file basename stem equals the
    contract name (the common Solidity one-contract-per-file convention) picks
    up its conservation laws / one-sided-mutation violations / fuzz candidates.
    Returns {} when the silo artifact is absent."""
    out = collections.defaultdict(list)
    pth = ws / "math_invariants" / "math_spec.json"
    if not pth.is_file():
        return out
    try:
        spec = json.loads(pth.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(spec, dict):
        return out
    contracts = spec.get("contracts")
    if not isinstance(contracts, dict):
        return out
    for cname, cdata in contracts.items():
        if not isinstance(cdata, dict):
            continue
        viols = cdata.get("violations") if isinstance(cdata.get("violations"), list) else []
        cands = cdata.get("candidates") if isinstance(cdata.get("candidates"), list) else []
        if not viols and not cands:
            continue
        rec = {"contract": str(cname), "violations": viols, "candidates": cands}
        out[str(cname).lower()].append(rec)
    return out


def build_math_spec_block(file_path: str, fn: str, math_idx: dict) -> str:
    """Build the MATH-INVARIANT context block for the contract matching the
    unit at file_path (matched by file basename stem == contract name, the
    one-contract-per-file convention). Returns '' when no math-spec context
    applies."""
    if not math_idx:
        return ""
    base = _norm_file_line(file_path)            # e.g. 'vault.sol'
    stem = base.rsplit(".", 1)[0] if "." in base else base   # 'vault'
    recs = math_idx.get(stem) or math_idx.get(base) or []
    if not recs:
        return ""
    nl = chr(10)
    parts = ["=== MATH-INVARIANT SPEC (conservation laws this contract must hold) ==="]
    for rec in recs[:2]:
        contract = str(rec.get("contract") or "?")[:60]
        viols = rec.get("violations") or []
        cands = rec.get("candidates") or []
        if viols:
            parts.append(f"  contract {contract} VIOLATIONS (one-sided mutation):")
            for v in viols[:4]:
                if isinstance(v, dict):
                    fnname = str(v.get("function") or v.get("fn") or "?")[:60]
                    law = str(v.get("law") or v.get("conservation_law") or v.get("hint") or "")[:160]
                    parts.append(f"    - {fnname} may break: {law}")
        if cands:
            parts.append(f"  contract {contract} invariants worth fuzzing:")
            for c in cands[:4]:
                if isinstance(c, dict):
                    txt = str(c.get("invariant") or c.get("description") or c.get("hint") or "")[:160]
                elif isinstance(c, str):
                    txt = c[:160]
                else:
                    txt = ""
                if txt:
                    parts.append(f"    - {txt}")
    parts.append("")
    return nl.join(parts)


# r36-rebuttal: lane orphan-queue-wiring-2026-06 registered in .auditooor/agent_pathspec.json
def load_economic_hypotheses_indexed(ws: Path) -> dict:
    """Load <ws>/.auditooor/economic_hypotheses.json (FIX 1; the economic
    attack-surface enumeration emitted by tools/economic-hypotheses.sh, wired
    into audit-deep Step 16) and index the per-file economic-hypothesis
    Summary tables by the lowercased file basename stem (one-contract-per-file
    convention). Each per-file markdown carries a '## Summary table' of
    Category / Hits / Key signal rows; we surface the categories with >=1 hit
    so the brief can anchor a candidate to a live economic surface instead of
    re-deriving it. Returns {} when the silo artifact is absent."""
    out = collections.defaultdict(list)
    pth = ws / ".auditooor" / "economic_hypotheses.json"
    if not pth.is_file():
        return out
    try:
        payload = json.loads(pth.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(payload, dict):
        return out
    per_file = payload.get("per_file")
    if not isinstance(per_file, list):
        return out
    for rec in per_file:
        if not isinstance(rec, dict):
            continue
        if not rec.get("markdown_written"):
            continue
        md_path = rec.get("markdown")
        src = rec.get("file") or ""
        if not isinstance(md_path, str) or not md_path:
            continue
        cats = _parse_economic_summary_categories(Path(md_path))
        if not cats:
            continue
        base = _norm_file_line(str(src))
        stem = base.rsplit(".", 1)[0] if "." in base else base
        out[stem].append({"file": str(src), "categories": cats})
    return out


def _parse_economic_summary_categories(md_path: Path) -> list:
    """Parse the '## Summary table' of an economic_hypotheses markdown and
    return the [Category, Hits] rows with a non-zero hit count. Best-effort;
    returns [] on any read/parse problem."""
    try:
        text = md_path.read_text(encoding="utf-8")
    except Exception:
        return []
    rows = []
    in_table = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("## Summary table"):
            in_table = True
            continue
        if in_table:
            if s.startswith("## ") and "Summary table" not in s:
                break
            if not s.startswith("|"):
                continue
            cells = [c.strip() for c in s.strip("|").split("|")]
            # Expected header: | # | Category | Hits | Key signal |
            if len(cells) < 3:
                continue
            cat, hits = cells[1], cells[2]
            if cat.lower() in {"category", ""} or set(cat) <= {"-", ":"}:
                continue
            try:
                n = int(re.sub(r"[^0-9]", "", hits) or "0")
            except Exception:
                n = 0
            if n > 0:
                rows.append((cat, n))
    return rows


def build_economic_hypotheses_block(file_path: str, econ_idx: dict) -> str:
    """Build the ECONOMIC-ATTACK-SURFACE block (FIX 1) for the contract at
    file_path, matched by file basename stem. Returns '' when no economic
    surface applies."""
    if not econ_idx:
        return ""
    base = _norm_file_line(file_path)
    stem = base.rsplit(".", 1)[0] if "." in base else base
    recs = econ_idx.get(stem) or econ_idx.get(base) or []
    if not recs:
        return ""
    nl = chr(10)
    parts = ["=== ECONOMIC ATTACK SURFACE (live economic hit categories for this contract) ==="]
    for rec in recs[:2]:
        cats = rec.get("categories") or []
        if not cats:
            continue
        rendered = ", ".join(f"{str(c)[:40]} ({int(n)} hit(s))" for c, n in cats[:8])
        parts.append(f"  - {rendered}")
    if len(parts) == 1:
        return ""
    parts.append("")
    return nl.join(parts)


def build_guard_probe_block(file_path: str, probe_idx: dict) -> str:
    """Build the GUARD-PROBE-PACKET block (FIX 2) for the unit at file_path,
    matched by normalized file path. Surfaces the per-guard 'what this guard
    does NOT check' context emitted by guard-context-extract.py. Returns ''
    when no probe packet applies to this unit."""
    if not probe_idx:
        return ""
    key = _norm_file_line(file_path)
    if not key:
        return ""
    rows = (probe_idx or {}).get(key, [])[:4]
    if not rows:
        return ""
    nl = chr(10)
    parts = ["=== GUARD PROBE PACKETS (per-guard blind spot - what each guard does NOT check) ==="]
    for r in rows:
        gid = str(r.get("guard_id") or r.get("file_line") or "?")[:80]
        fl = str(r.get("file_line") or "?")[:120]
        gline = str(r.get("guard_line") or "")[:160]
        hint = str(r.get("invariant_hint") or r.get("checks") or "")[:200]
        incomplete = bool(r.get("invariant_context_incomplete"))
        flag = " [context-incomplete: escalate to full read before certifying no-gap]" if incomplete else ""
        parts.append(f"  - guard '{gid}' @ {fl}{flag}")
        if gline:
            parts.append(f"    condition: {gline}")
        if hint:
            parts.append(f"    blind spot: {hint}")
    parts.append("")
    return nl.join(parts)


def build_guard_deficiency_block(file_path: str, negspace_idx: dict, asym_idx: dict) -> str:
    """Build the GUARD NEGATIVE-SPACE + SIBLING-PATH ASYMMETRY context block for
    the unit at file_path (matched by normalized file path). Returns '' when no
    guard-deficiency context applies to this unit."""
    key = _norm_file_line(file_path)
    if not key:
        return ""
    neg_rows = (negspace_idx or {}).get(key, [])[:4]
    asym_rows = (asym_idx or {}).get(key, [])[:3]
    if not neg_rows and not asym_rows:
        return ""
    nl = chr(10)
    parts = []
    if neg_rows:
        parts.append("=== GUARD NEGATIVE-SPACE (what these guards do NOT check) ===")
        for r in neg_rows:
            guard_id = str(r.get("guard_id") or r.get("file_line") or "?")[:80]
            kind = str(r.get("kind") or "guard")[:40]
            hint = str(r.get("invariant_hint") or "guard admits an input that violates its protected invariant")[:200]
            parts.append(f"  - {kind} guard '{guard_id}': {hint}")
        parts.append("")
    if asym_rows:
        parts.append("=== SIBLING-PATH ASYMMETRY (guard present on sibling, missing here) ===")
        for r in asym_rows:
            pair = str(r.get("pair") or "?")[:60]
            missing = r.get("guard_on_a_missing_on_b")
            missing_names = (", ".join(str(m) for m in missing)
                             if isinstance(missing, list) and missing else "unknown")[:160]
            path_a = r.get("path_a") if isinstance(r.get("path_a"), dict) else {}
            a_surface = ""
            if isinstance(path_a, dict):
                af = str(path_a.get("file") or "").strip()
                al = path_a.get("line")
                a_surface = f"{af}:{al}" if af and al is not None else af
            hint = str(r.get("shared_invariant_hint") or "")[:160]
            parts.append(
                f"  - pair '{pair}': this path is MISSING guard(s) [{missing_names}] "
                f"that its sibling {a_surface or '(sibling)'} enforces."
                + (f" Shared invariant: {hint}" if hint else "")
            )
        parts.append("")
    return nl.join(parts)


# r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
def build_adversarial_hypothesis_block(file_path: str, adv_idx: dict) -> str:
    """Build the ADVERSARIAL DIFFERENTIAL HYPOTHESES block for the unit at
    file_path (matched by normalized file path). Surfaces the top adversarial
    normal-vs-manipulated-path hypotheses emitted by
    adversarial-hypothesis-differential-hunter.py. Returns '' when no hypothesis
    applies to this unit."""
    if not adv_idx:
        return ""
    key = _norm_file_line(file_path)
    if not key:
        return ""
    fn_recs = (adv_idx or {}).get(key, [])
    if not fn_recs:
        return ""
    # Flatten hypotheses across the function record(s) matching this file, cap top ~3.
    rows = []
    for rec in fn_recs:
        hyps = rec.get("hypotheses") if isinstance(rec, dict) else None
        if isinstance(hyps, list):
            rows.extend(h for h in hyps if isinstance(h, dict))
    rows = rows[:3]
    if not rows:
        return ""
    nl = chr(10)
    parts = ["=== ADVERSARIAL DIFFERENTIAL HYPOTHESES (normal-vs-manipulated path) ==="]
    for h in rows:
        klass = str(h.get("attack_class") or "?")[:60]
        inv = str(h.get("violated_invariant") or "")[:200]
        manip = str(h.get("manipulated_state") or "")[:160]
        preconds = h.get("required_preconditions")
        pre_txt = ("; ".join(str(p) for p in preconds)
                   if isinstance(preconds, list) and preconds else "")[:200]
        ref = str(h.get("source_ref") or "")[:120]
        parts.append(f"  - [{klass}] violated invariant: {inv}" + (f" (@ {ref})" if ref else ""))
        if manip:
            parts.append(f"    manipulated state: {manip}")
        if pre_txt:
            parts.append(f"    preconditions: {pre_txt}")
    parts.append("")
    return nl.join(parts)


# r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
def build_novel_vector_block(file_path: str, nv_idx: dict) -> str:
    """Build the TARGET-SPECIFIC NOVEL INVARIANTS block for the unit at
    file_path (matched by normalized file path). Surfaces the target-specific
    derived invariants emitted by novel-vector-invariant-miner.py. Returns ''
    when no derived invariant applies to this unit."""
    if not nv_idx:
        return ""
    key = _norm_file_line(file_path)
    if not key:
        return ""
    rows = (nv_idx or {}).get(key, [])[:3]
    if not rows:
        return ""
    nl = chr(10)
    parts = ["=== TARGET-SPECIFIC NOVEL INVARIANTS (derived spec; counterexample = candidate finding) ==="]
    for r in rows:
        fn = str(r.get("function") or "?")[:60]
        stmt = str(r.get("statement") or "")[:220]
        fam = str(r.get("family") or r.get("invariant_class") or "")[:60]
        if not stmt:
            continue
        parts.append(f"  - {fn}" + (f" [{fam}]" if fam else "") + f": {stmt}")
    if len(parts) == 1:
        return ""
    parts.append("")
    return nl.join(parts)


_SRC_BASENAME_INDEX: dict[str, dict[str, list[str]]] = {}
_PRUNE_DIRS = {"node_modules", "out", "artifacts", "cache", ".git", "test",
               "tests", "mock", "mocks", "lib", "coverage", "broadcast", "typechain"}

def _build_basename_index(ws: Path) -> dict[str, list[str]]:
    """One-pass basename->paths index under ws (prunes node_modules/out/etc).
    Cached per workspace so the 285-task loop does not re-walk the tree."""
    key = str(ws)
    if key in _SRC_BASENAME_INDEX:
        return _SRC_BASENAME_INDEX[key]
    import os
    idx: dict[str, list[str]] = {}
    root = ws / "src"
    walk_root = str(root if root.is_dir() else ws)
    for dirpath, dirnames, filenames in os.walk(walk_root):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
        for fn in filenames:
            idx.setdefault(fn, []).append(os.path.join(dirpath, fn))
    _SRC_BASENAME_INDEX[key] = idx
    return idx

def _resolve_source_file(ws: Path, raw: str) -> str:
    """Resolve a source_path (possibly a bare basename) to the real in-scope file
    under the workspace. Prefers contracts/ or src/ subtrees. Generic, language-agnostic."""
    if not raw or raw == "?":
        return ""
    p = Path(raw)
    if p.is_absolute() and p.is_file():
        return str(p)
    cand = ws / raw
    if cand.is_file():
        return str(cand)
    matches = _build_basename_index(ws).get(p.name, [])
    if not matches:
        return ""
    matches = sorted(matches, key=lambda m: (0 if ("/contracts/" in m or "/src/" in m) else 1, len(m)))
    return matches[0]


# ---------------------------------------------------------------------------
# LANE 1 - EXPLOIT-QUEUE OBLIGATION FEED (LOGIC_ARSENAL_ROADMAP capability #1)
#
# Before this lane the per-fn hunt prompt read NEITHER exploit_queue.json NOR
# INVARIANT_LEDGER (0 grep hits in this builder). Every open exploit-queue
# obligation (a pre-hunt hypothesis the exploit-conversion loop left OPEN) and
# every authored economic invariant grounded at a file:line was invisible to the
# LLM hunting that exact function - so the agent re-derived the surface from
# scratch and auto-refuted, never carrying the standing obligation it was meant
# to discharge. These two loaders index both artifacts by (file,fn) and
# build_open_obligations_block injects an OPEN-OBLIGATIONS + AUTHORED-INVARIANTS
# section into build_enriched_task for the matching unit.
# ---------------------------------------------------------------------------
def _eq_open(row: dict) -> bool:
    """An exploit_queue row is an OPEN obligation iff its quality gate is 'open'
    (equivalently proof_status in {unproved, needs_harness}, never killed /
    closed_negative / disqualified / r76-quarantined). Mirrors how
    exploit-queue.py / the conversion gate treat quality_gate_status='open' as
    the not-yet-discharged surface."""
    qg = str(row.get("quality_gate_status") or "").strip().lower()
    # 'needs_source' is an UNDISCHARGED obligation, not a closed one: after the
    # corpus-fuel prefilter (exploit-queue.py) the surviving real-surface leads are
    # exactly quality_gate='needs_source' - and the per-fn hunt DOES have the source
    # for its own fn, so it can discharge them. Excluding them made Lane-1's
    # exploit-queue arm feed 0 units on nuva/axelar after the prefilter ran
    # (Lane1<->Lane2 tension, 2026-07-13). Treat it as open so the two compose.
    if qg in ("open", "needs_source"):
        return True
    if qg in ("disqualified", "closed_negative", "quarantined_r76_hallucination"):
        return False
    ps = str(row.get("proof_status") or "").strip().lower()
    return ps in ("unproved", "needs_harness", "needs_source")


# Sentinel base_fn used to key a FILE-LEVEL (not fn-precise) exploit-queue
# obligation - one recovered from source_refs / root_cause_hypothesis when the
# row's contract/function are unset. Chosen to never collide with a real
# base_fn token.
_FILE_OBL_FN = "\x00file"

# path.ext:line  (line optional) - the same file-ref shape load_invariant_ledger
# uses, extended so a path with no ':line' still matches.
_EQ_FILE_REF = re.compile(r"([\w./\-]+\.(?:go|sol|rs|move|vy|cairo))(?::\d+)?")


def _eq_file_from_refs(r: dict) -> str:
    """Recover the file BASENAME for an exploit-queue row whose contract/function
    are unset. Prefer source_refs[0], then scan root_cause_hypothesis / impact_path
    prose for a 'file.ext[:line]' reference. Returns '' when none is present (e.g.
    workspace-level advisory rows that name no file - axelar's Q-DUPE/Q-AC rows)."""
    refs = r.get("source_refs")
    cands = []
    if isinstance(refs, list):
        cands.extend(str(x) for x in refs if x)
    elif isinstance(refs, str):
        cands.append(refs)
    for key in ("root_cause_hypothesis", "impact_path"):
        v = r.get(key)
        if isinstance(v, str) and v:
            cands.append(v)
    for c in cands:
        m = _EQ_FILE_REF.search(c)
        if m:
            return _norm_file_line(m.group(1))
    return ""


def load_exploit_queue_obligations_indexed(ws: Path) -> dict:
    """Load <ws>/.auditooor/exploit_queue.json and index the OPEN obligations by
    normalized (basename(contract), base_fn(function)). Schema
    auditooor.exploit_queue.* nests the queue under key 'queue'; each row carries
    contract (file), function, title, attack_class, likely_severity,
    broken_invariant_ids, root_cause_hypothesis, impact_path. Returns a
    defaultdict keyed by 'basename::base_fn' (fn-precise) so a target fn matches
    only its own standing obligation; empty when the artifact is absent."""
    out = collections.defaultdict(list)
    pth = ws / ".auditooor" / "exploit_queue.json"
    if not pth.is_file():
        return out
    try:
        payload = json.loads(pth.read_text(encoding="utf-8"))
    except Exception:
        return out
    if isinstance(payload, dict):
        rows = payload.get("queue") or payload.get("entries") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    seen = set()
    for r in rows:
        if not isinstance(r, dict) or not _eq_open(r):
            continue
        contract = str(r.get("contract") or "").strip()
        fn = str(r.get("function") or "").strip()
        # Key on the FILE basename (from source_refs) - both consumers
        # (build_open_obligations_block + the lane-1 WARN) look up by
        # _norm_file_line(file_path), which carries the extension (e.g.
        # 'crosschainmanager.sol'), whereas _norm_file_line(contract) yields the
        # bare contract/type NAME ('crosschainmanager' / Go 'msgserver' for
        # msg_server.go) - an extension/name mismatch that made EVERY fn-precise
        # reasoner obligation MISS the per-fn brief. Fall back to the contract
        # name only when no file ref is recoverable (workspace-level advisory).
        base = _eq_file_from_refs(r) or _norm_file_line(contract)
        if base and fn:
            # fn-precise obligation
            # dedup identical obligations (same hypothesis emitted per-source-ref)
            dk = (base, _base_fn(fn), str(r.get("title") or ""),
                  tuple(r.get("broken_invariant_ids") or []))
            if dk in seen:
                continue
            seen.add(dk)
            out[f"{base}::{_base_fn(fn)}"].append(r)
            continue
        # FALLBACK (needs_source live schema): contract/function are None; the file
        # surface is carried in source_refs[0] (e.g.
        # 'src/.../CrossChainVault.sol:81') and/or the root_cause_hypothesis prose.
        # Recover the basename and index a FILE-LEVEL (fn=None) obligation under
        # 'basename::<_FILE_OBL_FN>'. Without this every needs_source row was
        # silently dropped ('not base or not fn'), so nuva's 10 CrossChainVault-
        # anchored admin-domain leads never reached any per-fn brief (2026-07-13).
        fb = _eq_file_from_refs(r)
        if not fb:
            continue
        dk = (fb, _FILE_OBL_FN, str(r.get("title") or ""),
              tuple(r.get("broken_invariant_ids") or []))
        if dk in seen:
            continue
        seen.add(dk)
        out[f"{fb}::{_FILE_OBL_FN}"].append(r)
    return out


def _iter_markdown_table_rows(text: str):
    """Yield the list-of-cell values for each data row of every GitHub-flavored
    markdown table in `text` (skips the header + the |---|---| separator)."""
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        # separator row (---|:--:| ...) -> skip
        if all(set(c) <= set("-: ") and c for c in cells):
            continue
        yield cells


def load_invariant_ledger_indexed(ws: Path) -> dict:
    """Parse <ws>/INVARIANT_LEDGER.md (human mirror of invariant_ledger.json) and
    index each authored invariant by the normalized basename of the file it is
    grounded at. The ledger is one or more markdown tables whose columns vary by
    workspace (nuva: id|subsystem|property|invariant|source anchor|status|...;
    axelar: #|ID|Invariant|Grounding file:line|Enforcing guard|Method|Verdict).
    We locate the grounding by scanning every cell for a real 'file.ext:line'
    reference, key by its basename, and keep the invariant id + statement +
    status so the per-fn brief can surface the standing invariant for that file.
    Empty when the ledger is absent."""
    out = collections.defaultdict(list)
    pth = ws / "INVARIANT_LEDGER.md"
    if not pth.is_file():
        return out
    try:
        text = pth.read_text(encoding="utf-8")
    except Exception:
        return out
    file_ref = re.compile(r"([\w./\-]+\.(?:go|sol|rs|move|vy|cairo)):(\d+)")
    id_re = re.compile(r"\bINV[-\w]+\b")
    seen = set()
    for cells in _iter_markdown_table_rows(text):
        joined = " ".join(cells)
        m = file_ref.search(joined)
        if not m:
            continue
        base = _norm_file_line(m.group(1))
        if not base:
            continue
        idm = id_re.search(joined)
        inv_id = idm.group(0) if idm else ""
        # statement = the widest non-id, non-status cell (the invariant prose)
        skip = {"", inv_id}
        cand = [c for c in cells if c and c not in skip and not file_ref.search(c)]
        statement = max(cand, key=len) if cand else ""
        status = ""
        for c in cells:
            cl = c.lower()
            if any(k in cl for k in ("executed", "hold", "killed", "clean",
                                     "counterexample", "blocked", "scaffold",
                                     "missing_harness")):
                status = c
        dk = (base, inv_id, statement[:80])
        if dk in seen:
            continue
        seen.add(dk)
        out[base].append({"id": inv_id, "statement": statement,
                          "status": status, "source": m.group(0)})
    return out


def build_open_obligations_block(file_path: str, fn: str,
                                  eq_obl_idx: dict, inv_ledger_idx: dict) -> str:
    """Build the OPEN-OBLIGATIONS + AUTHORED-INVARIANTS block for the unit at
    (file_path, fn). exploit-queue obligations match fn-precise (basename::fn);
    authored invariants match by file basename (the ledger anchors a file:line,
    not a fn). Returns '' when neither applies (prompt byte-identical to legacy)."""
    base = _norm_file_line(file_path)
    obls = []
    if eq_obl_idx and base:
        # fn-precise obligations (row carried an explicit contract+function)
        if fn and fn != "?":
            obls = list(eq_obl_idx.get(f"{base}::{_base_fn(fn)}") or [])
        # PLUS file-level obligations recovered from source_refs/root_cause when
        # the row named no function - every unit in this file inherits them.
        file_obls = eq_obl_idx.get(f"{base}::{_FILE_OBL_FN}") or []
        for r in file_obls:
            if r not in obls:
                obls.append(r)
        obls = obls[:4]
    invs = (inv_ledger_idx.get(base) if inv_ledger_idx and base else None) or []
    invs = invs[:4]
    if not obls and not invs:
        return ""
    nl = chr(10)
    parts = []
    if obls:
        parts.append("=== OPEN EXPLOIT-QUEUE OBLIGATIONS (standing hypotheses left OPEN for THIS function - discharge or refute each) ===")
        for r in obls:
            title = str(r.get("title") or "?")[:160]
            ac = str(r.get("attack_class") or "?")[:60]
            sev = str(r.get("likely_severity") or "?")[:16]
            bids = ", ".join(str(x) for x in (r.get("broken_invariant_ids") or []))[:120]
            rc = str(r.get("root_cause_hypothesis") or "")[:240]
            context = r.get("obligation_context")
            if not isinstance(context, dict):
                context = {}
            question = str(context.get("question") or r.get("question") or "")[:240]
            expected = str(context.get("expected_invariant") or r.get("expected_invariant") or "")[:240]
            kill = str(context.get("kill_condition") or r.get("kill_condition") or "")[:240]
            terminal = str(context.get("terminal_condition") or r.get("terminal_condition") or "")[:180]
            parts.append(f"  - [{sev}/{ac}] {title}")
            if bids:
                parts.append(f"    broken_invariant_ids: {bids}")
            if rc:
                parts.append(f"    root-cause hypothesis: {rc}")
            if question:
                parts.append(f"    proof question: {question}")
            if expected:
                parts.append(f"    expected invariant: {expected}")
            if kill:
                parts.append(f"    falsification control: {kill}")
            if terminal:
                parts.append(f"    terminal condition: {terminal}")
        parts.append("")
    if invs:
        parts.append("=== AUTHORED INVARIANTS (from INVARIANT_LEDGER.md - grounded at this file; a counterexample here IS the finding) ===")
        for iv in invs:
            iid = str(iv.get("id") or "?")[:40]
            st = str(iv.get("status") or "")[:40]
            src = str(iv.get("source") or "")[:120]
            stmt = str(iv.get("statement") or "")[:280]
            parts.append(f"  - {iid} [{st}] @ {src}")
            if stmt:
                parts.append(f"    invariant: {stmt}")
        parts.append("")
    return nl.join(parts)


def build_enriched_task(idx: int, q: dict, ws: Path, ws_name: str,
                         compact_docs: str, chain_idx: dict, predicate_idx: dict,
                         kde_warnings: list[str],
                         negspace_idx: dict | None = None,
                         asym_idx: dict | None = None,
                         probe_idx: dict | None = None,
                         math_idx: dict | None = None,
                         econ_idx: dict | None = None,
                         adv_idx: dict | None = None,
                         nv_idx: dict | None = None,
                         fork_delta_idx: dict | None = None,
                         eq_obl_idx: dict | None = None,
                         inv_ledger_idx: dict | None = None) -> dict:
    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered in .auditooor/agent_pathspec.json
    # r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
    """Build one enriched MIMO task prompt."""
    fn = q.get("function") or q.get("fn") or ""
    _unit = q.get("unit_id") or q.get("unit") or ""
    if not fn or fn == "?":
        # unit_id carries the function identity in one of two shapes: a qualified
        # 'File::fn' or a BARE function token (the per-fn-question-ranker emits the
        # bare form, e.g. unit_id='burn'). Recovering only the '::' form left every
        # bare-unit_id task with fn='?', which collapses _sidecar_slug to a per-FILE
        # path so all N functions of a file overwrite ONE sidecar - silently losing
        # per-function coverage credit (NUVA residual: 14 msg_server.go units -> 1
        # file). A bare unit_id IS the function name.
        _u = str(_unit).strip()
        if "::" in _u:
            fn = _u.split("::")[-1].strip()
        elif _u:
            fn = _u
    fn = fn or "?"
    # per_fn_hacker_questions stores the path under source_path (often a bare
    # basename), NOT "file"; resolve it to the real in-scope file so the excerpt
    # and anchor are populated (else every task is FILE=? / excerpt-unavailable).
    file_path, _known_line = _split_path_line(
        str(q.get("file") or q.get("source_path") or q.get("source") or "?"))
    for _lk in ("line", "start_line", "line_start", "def_line"):
        _lv = q.get(_lk)
        if isinstance(_lv, int) and _lv > 0:
            _known_line = _lv
            break
    _resolved = _resolve_source_file(ws, file_path)
    if _resolved:
        file_path = _resolved
    fn_class = q.get("question_class", "generic")
    question = q.get("question", "")
    anchor_inv = q.get("anchor_invariant", "")
    rank = q.get("rank", -1)
    score = q.get("score", 0)

    # Read fn excerpt
    excerpt, start_line, end_line = read_file_excerpt(file_path, fn, known_line=_known_line)

    # Matched chains
    chains = chain_idx.get(fn_class, [])[:3]
    chain_block = ""
    if chains:
        chain_block = "\n".join(
            f"  - chain_id={c.get('chain_id', '?')} steps={(c.get('steps_summary') or c.get('steps') or '?')[:120]}"
            for c in chains
        )

    # Matched predicates
    predicates = predicate_idx.get(fn_class, [])[:5]
    pred_block = ""
    if predicates:
        pred_block = "\n".join(
            f"  - {(p.get('predicate') or p.get('description') or '?')[:140]}"
            for p in predicates
        )

    kde_block = ""
    if kde_warnings:
        kde_block = "\n".join(f"  - {k}" for k in kde_warnings[:8])

    guard_def_block = build_guard_deficiency_block(file_path, negspace_idx, asym_idx)
    # r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
    math_spec_block = build_math_spec_block(file_path, fn, math_idx or {})
    guard_probe_block = build_guard_probe_block(file_path, probe_idx or {})
    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered in .auditooor/agent_pathspec.json
    econ_hyp_block = build_economic_hypotheses_block(file_path, econ_idx or {})
    # r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
    adv_hyp_block = build_adversarial_hypothesis_block(file_path, adv_idx or {})
    novel_vec_block = build_novel_vector_block(file_path, nv_idx or {})
    # LANE 1: exploit-queue open obligations + authored invariants for THIS unit
    open_obl_block = build_open_obligations_block(
        file_path, fn, eq_obl_idx or {}, inv_ledger_idx or {})

    nl = chr(10)
    parts = [
        f"You are a security auditor for {ws_name} (function-anchored hunt).",
        "",
        "TASK: Apply the hypothesis to the SPECIFIC FUNCTION at the cited file:line.",
        "Output STRICT JSON only - no prose around it.",
        "",
        "REQUIRED JSON KEYS (all required, even if null/'NA'):",
        "  applies_to_target: yes | no | maybe",
        "  confidence: low | medium | high",
        "  candidate_finding: string (one-sentence brief, ANCHOR TO THE FN)",
        "  file_line: 'path/to/file.sol:42' (must be the line in the excerpt)",
        "  code_excerpt: string (paste 1-3 lines of the actual vulnerable code FROM THE EXCERPT BELOW)",
        "  severity_estimate: LOW | MEDIUM | HIGH | CRITICAL | NA",
        "  rubric_row_cited: string verbatim from SEVERITY.md",
        "  dupe_check: string (cross-ref filed / known_dead_ends / BUG_BOUNTY.md OOS row)",
        "  falsification_attempt: string (what specific source check would disprove this?)",
        "  novel_angle_score: integer 1-5",
        "  chain_with: list of chain_id matches from MATCHED CHAINS below (or [])",
        "  notes: string",
        "",
        "HARD RULES (R76 hallucination guard - the operator's gate fails closed):",
        "  - code_excerpt MUST be a verbatim substring of the FUNCTION EXCERPT below.",
        "  - file_line MUST be a real line in the cited file (start_line .. end_line).",
        "  - If neither holds, set applies_to_target='no' and notes='unable-to-anchor'.",
        "  - DO NOT synthesize 'conceptual' / 'typical' / 'pattern' code; refuse and emit no.",
        "  - If dupe_check matches BUG_BOUNTY.md OOS or known_dead_ends, set applies_to_target='no'.",
        "",
        f"=== TARGET FUNCTION (rank #{rank}, score={score:.2f}, class={fn_class}) ===",
        f"FILE: {file_path}",
        f"FN: {fn}",
        f"LINE RANGE: {start_line}..{end_line}",
        f"ANCHOR INVARIANT: {anchor_inv}",
        "",
        "FUNCTION EXCERPT:",
        "```",
        excerpt[:2000] if excerpt else "(excerpt unavailable - file or fn not found; set applies_to_target='no')",
        "```",
        "",
        "=== HYPOTHESIS TO TEST ===",
        question,
        "",
    ]
    # LANE 1: surface the standing exploit-queue obligations + authored invariants
    # FIRST (before the corpus silos) - these are the not-yet-discharged
    # hypotheses the pipeline already staked out for this exact function.
    if open_obl_block:
        parts.extend([
            open_obl_block,
            "Use the OPEN OBLIGATIONS / AUTHORED INVARIANTS above: the function "
            "under test carries a standing, not-yet-discharged hypothesis. Either "
            "produce the counterexample that discharges it (anchor candidate_finding "
            "to the named broken_invariant_ids / invariant id) or refute it with a "
            "source-cited falsification_attempt - do NOT ignore it.",
            "",
        ])
    # r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
    if math_spec_block:
        parts.extend([
            math_spec_block,
            "Use the math-invariant spec above: if a one-sided-mutation VIOLATION "
            "or a fuzz-candidate invariant for this contract can be broken by the "
            "function under test, anchor your candidate_finding to that exact "
            "conservation-law gap (cite the contract + function).",
            "",
        ])
    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered in .auditooor/agent_pathspec.json
    if econ_hyp_block:
        parts.extend([
            econ_hyp_block,
            "Use the economic attack surface above: if the function under test "
            "reaches one of the listed economic hit categories (oracle read, "
            "flashloan callback, rate/rounding math, LP-share math, "
            "liquidation, slippage/deadline, fee-on-transfer), anchor your "
            "candidate_finding to that exact economic gap.",
            "",
        ])
    if guard_probe_block:
        parts.extend([
            guard_probe_block,
            "Use the guard-probe packets above: each lists what a guard does NOT "
            "check. If the function under test reaches a state where a listed "
            "blind spot is exploitable, anchor your candidate_finding to that "
            "guard's gap (cite the guard_id + file:line).",
            "",
        ])
    if guard_def_block:
        parts.extend([
            guard_def_block,
            "Use the guard-deficiency context above: if a listed guard fails to "
            "check what its invariant requires, or a sibling enforces a guard this "
            "path omits, anchor your candidate_finding to that exact gap.",
            "",
        ])
    # r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
    if adv_hyp_block:
        parts.extend([
            adv_hyp_block,
            "Use the adversarial differential hypotheses above: if the function "
            "under test admits the manipulated path, anchor your candidate_finding "
            "to the violated_invariant (cite the attack_class + source_ref).",
            "",
        ])
    if novel_vec_block:
        parts.extend([
            novel_vec_block,
            "Use the target-specific novel invariants above: if the function under "
            "test can drive any listed invariant to a counterexample, anchor your "
            "candidate_finding to that exact spec violation.",
            "",
        ])
    if chain_block:
        parts.extend([
            "=== MATCHED COMPOUND-ATTACK CHAINS (cite chain_with if your finding completes one) ===",
            chain_block,
            "",
        ])
    if pred_block:
        parts.extend([
            "=== EXPLOIT PREDICATES (proven primitives this class composes from) ===",
            pred_block,
            "",
        ])
    if kde_block:
        parts.extend([
            "=== KNOWN DEAD-ENDS (skip if your finding overlaps) ===",
            kde_block,
            "",
        ])
    # C1: attach top-K historical exploit anchors most similar to this hunt context
    # (fn + hypothesis + class). Env-OFF / no-match -> '' (prompt byte-identical).
    if _exploit_anchor is not None:
        _anchor_block = _exploit_anchor.render_exploit_anchor_block(
            f"{fn} {question} {fn_class} {anchor_inv}", top_k=3, fmt="plain")
        if _anchor_block:
            parts.extend([_anchor_block, ""])
    # FORK-DELTA HAND-OFF: tell the agent whether this function's file is
    # Sei-modified (in-scope) or unmodified-upstream (OOS) for a fork target.
    fork_delta = fork_delta_status_for(str(file_path), fork_delta_idx or {})
    if fork_delta is not None:
        _sm = fork_delta["sei_modified"]
        if _sm == "yes":
            _fd_note = (
                f"FORK-DELTA: this file is SEI-MODIFIED vs upstream "
                f"({fork_delta['local_name']}@base). It IS in scope - hunt the "
                f"Sei delta. Diff pointer: {fork_delta['diff_pointer']} "
                f"(rel: {fork_delta['repo_relative_path']})."
            )
        elif _sm == "no":
            _fd_note = (
                f"FORK-DELTA: this file is UNMODIFIED-UPSTREAM vs "
                f"{fork_delta['local_name']}@base and is OUT OF SCOPE (inherited "
                f"upstream code). Only report a finding if the Sei fork's own "
                f"delta reaches it. Diff pointer: {fork_delta['diff_pointer']}."
            )
        else:
            _fd_note = (
                f"FORK-DELTA: upstream for {fork_delta['local_name']} was "
                f"UNRESOLVED at materialize time; scope is KEEP-ALL. Verify the "
                f"file is a real Sei modification before claiming impact."
            )
        parts.extend(["=== FORK DELTA ===", _fd_note, ""])
    parts.extend([
        "=== WORKSPACE DOCS (compact) ===",
        compact_docs,
        "",
        "=== END CONTEXT ===",
        "",
        DEFAULT_OOS_NOTE,
        "",
        "Apply hypothesis to the FUNCTION above. Return STRICT JSON only.",
    ])

    prompt = nl.join(parts)
    # (unit x FRAME) key - the CANONICAL scoped-hunt enablement of the coverage
    # substrate: tag each task with an `impact` FRAME so haiku-fanout-dispatcher's
    # _sidecar_slug (brick 1) writes a frame-DISTINCT sidecar (hunt__unit__I-<frame>)
    # instead of collapsing every hunt-angle of a function into ONE file (the
    # mono-focus/latest-wins collision that nearly buried the strata MIN_SHARES
    # freeze). Frame = the row's real impact_id when present (impact-methodology
    # rows), else the question_class (the distinct hunt angle). Default ON;
    # PER_IMPACT_FRAMES=0 restores the byte-identical legacy (frame-less) slug.
    _frame = str(q.get("impact_id") or q.get("impact") or fn_class or "")
    if os.environ.get("PER_IMPACT_FRAMES", "1") == "0":
        _frame = ""
    return {
        "task_id": f"perfn_mimo_{ws_name}_{idx:05d}",
        "task_type": "per_fn_workspace_hunt_v2",
        "workspace": ws_name,
        "workspace_path": str(ws),
        "source_question_id": q.get("anchor_invariant", "?") + ":" + fn_class,
        "impact": _frame,
        "function_anchor": {"file": file_path, "fn": fn, "start_line": start_line, "end_line": end_line},
        "fork_delta_status": fork_delta,
        "rank": rank,
        "score": score,
        "prompt": prompt,
        "max_tokens": 1500,
    }


def _base_fn(fn: str) -> str:
    """Normalize a function identity to its bare name (strip signature + qualifier)
    so a task fn and a sidecar fn compare equal across minor shape drift."""
    fn = (fn or "").split("(")[0]
    return fn.split("::")[-1].split(".")[-1]


def _terminal_disposition_keys(ws: Path) -> set:
    """(basename(file), base_fn, source_question_id) for GENUINE TERMINAL per-fn
    sidecars. A hunt task matching one of these has already been dispositioned at a
    terminal verdict (applies_to_target in {yes,no}) for that exact (unit, hypothesis)
    pair - re-dispatching it just burns an agent re-confirming a closed unit (Strata
    2026-07-07: 168/318 scoped tasks were terminal dupes; batch 0003 spent 130k tokens
    re-clearing 10 already-ruled-out views). ONLY status=='ok' sidecars with a real
    yes/no verdict count; halted / errored / 'maybe' / needs-source-verification stubs
    are NON-terminal and MUST stay huntable (never suppress an unhunted unit - the
    same-unit-under-a-NEW-hypothesis task also survives because the sqid differs)."""
    import glob as _glob
    import re as _re
    keys = set()
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    if not d.is_dir():
        return keys
    for p in _glob.glob(str(d / "*.json")):
        try:
            j = json.loads(Path(p).read_text(errors="ignore"))
        except (json.JSONDecodeError, ValueError, OSError):
            continue
        if not isinstance(j, dict) or j.get("status") != "ok" or j.get("error"):
            continue
        res = j.get("result")
        atv = None
        if isinstance(res, str):
            m = _re.search(r'"applies_to_target"\s*:\s*"(\w+)"', res)
            atv = m.group(1) if m else None
        elif isinstance(res, dict):
            atv = res.get("applies_to_target")
        if atv not in ("yes", "no"):
            continue
        anc = j.get("function_anchor")
        if isinstance(anc, dict):
            f, fn = anc.get("file", ""), anc.get("fn", "")
        elif isinstance(anc, str) and "::" in anc:
            f, fn = anc.split("::", 1)
        else:
            continue
        keys.add((os.path.basename(f or ""), _base_fn(fn), j.get("source_question_id")))
    return keys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--ranked-questions", required=True)
    p.add_argument("--workspace", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--max-tasks", type=int, default=200)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws = Path(args.workspace)
    ws_name = ws.name

    sys.stderr.write("[per-fn-batch] loading enrichment corpora...\n")
    compact_docs = compact_workspace_docs(ws)
    chain_idx = load_global_chain_templates_indexed()
    pred_idx = load_exploit_predicates_indexed()
    kde_warnings = load_kde(ws_name)
    negspace_idx = load_guard_negative_space_indexed(ws)
    asym_idx = load_sibling_asymmetries_indexed(ws)
    # r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
    probe_idx = load_guard_probe_packets_indexed(ws)
    math_idx = load_math_spec_indexed(ws)
    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered in .auditooor/agent_pathspec.json
    econ_idx = load_economic_hypotheses_indexed(ws)
    # r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
    adv_idx = load_adversarial_hypotheses_indexed(ws)
    nv_idx = load_novel_vector_invariants_indexed(ws)
    # FORK-DELTA: hand each fork-target unit a fork_delta_status (Sei-modified vs
    # unmodified-upstream) from the materialized fork_modified artifacts.
    fork_delta_idx = load_fork_delta_index(ws)
    # LANE 1: exploit-queue OPEN obligations + authored invariants, (file,fn)-indexed
    eq_obl_idx = load_exploit_queue_obligations_indexed(ws)
    inv_ledger_idx = load_invariant_ledger_indexed(ws)
    sys.stderr.write(
        f"[per-fn-batch] exploit_queue open-obligation units={len(eq_obl_idx)} "
        f"authored-invariant files={len(inv_ledger_idx)}\n")
    if fork_delta_idx:
        _scoped = sum(1 for v in fork_delta_idx.values() if v is not None)
        sys.stderr.write(
            f"[per-fn-batch] fork_delta forks={len(fork_delta_idx)} "
            f"(scoped={_scoped}); per-fn briefs carry fork_delta_status\n"
        )
    sys.stderr.write(f"[per-fn-batch] guard_probe_files={len(probe_idx)} "
                     f"math_contracts={len(math_idx)} econ_contracts={len(econ_idx)} "
                     f"adv_hyp_files={len(adv_idx)} novel_vec_files={len(nv_idx)}\n")
    sys.stderr.write(f"[per-fn-batch] compact_docs={len(compact_docs)} chars "
                     f"chain_classes={len(chain_idx)} pred_classes={len(pred_idx)} "
                     f"kde_warnings={len(kde_warnings)}\n")

    # Load ranked questions
    questions = []
    with open(args.ranked_questions) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                questions.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    questions = questions[:args.max_tasks]
    sys.stderr.write(f"[per-fn-batch] questions: {len(questions)}\n")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tasks_built = 0
    plane_drained = 0
    dropped_resolved = 0
    obligation_feed_misses = 0  # LANE 1 advisory enforce-hook counter
    # RESIDUAL DEDUP (default-ON; AUDITOOOR_HUNT_INCLUDE_RESOLVED=1 to force a full
    # re-hunt): drop tasks whose exact (unit, hypothesis) already has a GENUINE
    # terminal sidecar so the scoped hunt dispatches the coverage RESIDUAL, not the
    # already-closed surface (Strata 2026-07-07: without this, 168/318 scoped tasks
    # were terminal dupes and each burned a full agent re-confirming a ruled-out unit).
    _include_resolved = os.environ.get("AUDITOOOR_HUNT_INCLUDE_RESOLVED", "0") == "1"
    _skip_keys = set() if _include_resolved else _terminal_disposition_keys(ws)
    if _skip_keys:
        sys.stderr.write(f"[per-fn-batch] residual dedup: {len(_skip_keys)} terminal "
                         f"(unit,hypothesis) disposition(s) loaded from sidecars\n")
    with out_path.open("w") as fh:
        for i, q in enumerate(questions):
            # r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
            task = build_enriched_task(i, q, ws, ws_name, compact_docs,
                                        chain_idx, pred_idx, kde_warnings,
                                        negspace_idx, asym_idx,
                                        # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered
                                        probe_idx, math_idx, econ_idx,
                                        # r36-rebuttal: lane novelpanel-readback-2026-06 registered
                                        adv_idx, nv_idx,
                                        fork_delta_idx=fork_delta_idx,
                                        eq_obl_idx=eq_obl_idx,
                                        inv_ledger_idx=inv_ledger_idx)
            # LANE 1 enforce-hook (advisory this wave; next wave = fail-closed):
            # if this unit HAS an open exploit-queue obligation but the built
            # prompt lacks the OPEN-OBLIGATIONS block, warn.
            _a0 = task.get("function_anchor") or {}
            _obl_key = (f"{_norm_file_line(_a0.get('file', ''))}::"
                        f"{_base_fn(_a0.get('fn', ''))}")
            if eq_obl_idx.get(_obl_key) and \
                    "OPEN EXPLOIT-QUEUE OBLIGATIONS" not in task.get("prompt", ""):
                obligation_feed_misses += 1
                sys.stderr.write(
                    f"[per-fn-batch] WARN lane1: unit {_obl_key} has "
                    f"{len(eq_obl_idx[_obl_key])} open obligation(s) but prompt "
                    f"lacks the OPEN-OBLIGATIONS block (advisory; next wave fails closed)\n")
            if _skip_keys:
                _a = task.get("function_anchor") or {}
                _k = (os.path.basename(_a.get("file", "")), _base_fn(_a.get("fn", "")),
                      task.get("source_question_id"))
                if _k in _skip_keys:
                    dropped_resolved += 1
                    continue
            fh.write(json.dumps(task) + "\n")
            tasks_built += 1
        # A2 coverage-plane drain: default-OFF (AUDITOOOR_PLANE_DRAIN=1). APPEND one
        # enriched task per not-enumerated plane cell so the materialized cells that
        # NO ranked question covers still seed a hunt. Env-off / plane-absent -> no
        # append (byte-identical to the legacy ranked-question-only output).
        if _plane_drain_enabled():
            for j, cell in enumerate(load_plane_not_enumerated(ws)):
                task = build_plane_drain_task(j, cell, ws, ws_name, compact_docs)
                fh.write(json.dumps(task) + "\n")
                tasks_built += 1
                plane_drained += 1
    if plane_drained:
        sys.stderr.write(f"[per-fn-batch] A2 coverage-plane drain appended {plane_drained} "
                         f"not-enumerated cells (AUDITOOOR_PLANE_DRAIN=1)\n")

    avg_prompt_len = 0
    if tasks_built:
        with out_path.open() as fh:
            for line in fh:
                avg_prompt_len += len(json.loads(line)["prompt"])
        avg_prompt_len //= tasks_built

    sys.stderr.write(f"[per-fn-batch] wrote {tasks_built} enriched tasks to {out_path} "
                     f"(avg prompt {avg_prompt_len} chars)\n")
    if dropped_resolved:
        sys.stderr.write(f"[per-fn-batch] residual dedup: dropped {dropped_resolved} "
                         f"already-terminal (unit,hypothesis) task(s); dispatching the "
                         f"{tasks_built}-task RESIDUAL only "
                         f"(AUDITOOOR_HUNT_INCLUDE_RESOLVED=1 to re-hunt all)\n")

    summary = {
        "schema_version": SCHEMA,
        "tasks_built": tasks_built,
        "dropped_already_resolved": dropped_resolved,
        "obligation_feed_misses": obligation_feed_misses,
        "exploit_queue_open_units_indexed": len(eq_obl_idx),
        "authored_invariant_files_indexed": len(inv_ledger_idx),
        "avg_prompt_chars": avg_prompt_len,
        "compact_docs_chars": len(compact_docs),
        "chain_classes_indexed": len(chain_idx),
        "pred_classes_indexed": len(pred_idx),
        "kde_warnings_injected": len(kde_warnings),
        "output": str(out_path),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"tasks built: {tasks_built}")
        print(f"avg prompt size: {avg_prompt_len} chars (vs generic ~14K)")
        print(f"corpus enrichment: chains={len(chain_idx)} preds={len(pred_idx)} kde={len(kde_warnings)}")
        print(f"output: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
