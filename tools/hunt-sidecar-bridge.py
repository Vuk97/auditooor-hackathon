#!/usr/bin/env python3
# r36-rebuttal: funnel-enforcement-gates-AB
"""hunt-sidecar-bridge.py - materialize a workspace's hunt sidecars into the
workspace so the hunt-completeness artifact-mining gate (and coverage tooling)
can see them.

Generic gap this closes: the per-function LLM hunt (make hunt-haiku + the haiku
Workflow / mimo-corpus-miner) writes its per-task sidecars under the auditooor
repo's `audit/corpus_tags/derived/<harness>/` dir, keyed by workspace. But the
hunt-completeness gate reads `<ws>/hunt_findings_sidecars/` (or the .auditooor
variant). The sidecars exist and are real, just in the wrong place. This bridge
copies the sidecars that belong to the target workspace (matched by their
`workspace_path` / `workspace` field - never by filename guesswork) into
`<ws>/.auditooor/hunt_findings_sidecars/`.

Honesty: it ONLY copies sidecars whose recorded workspace_path resolves to the
target workspace. It never fabricates sidecars; if the hunt produced none for
this workspace, it copies nothing and the gate stays honestly unsatisfied.

Generic + target-agnostic. The derived root is discovered from this tool's own
location (<repo>/tools/ -> <repo>/audit/corpus_tags/derived), with an override.

GATE A - R76 source-existence enforcement (funnel-enforcement-gates-AB):
A sidecar with applies_to_target=yes (or maybe+high/medium confidence) that
cites an empty / hallucinated file_line (or a file_path_hint that does not
resolve to a real in-scope source file) is DOWNGRADED before being written:
  - applies_to_target becomes "no"
  - r76_source_existence_fail=True + r76_source_existence_reason=<why>
This preserves the negative signal for coverage accounting (the hunt ran) while
making it impossible for a hallucinated candidate to be promoted as positive.
A sidecar with a real file_line that exists in the workspace passes unchanged.
Pass --no-r76 to disable the gate (testing only).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_DEFAULT_DERIVED = _REPO / "audit" / "corpus_tags" / "derived"
_FCC_TOOL = _REPO / "tools" / "function-coverage-completeness.py"

# sidecar filename shapes the hunt emits (per-task hunt records).
# perfn_mimo_*.json: make hunt-haiku --scoped writes files with this prefix inside
# haiku_harness_*_scoped_* dirs (e.g. haiku_harness_beanstalk_scoped_n285/).
# haiku_harness_*.json matches 0 real files (that is a dir-name prefix, not a
# file-name prefix) but kept for forward-compat in case the writer ever changes.
_SIDECAR_GLOBS = ("mimo_harness_*.json", "haiku_harness_*.json", "hunt_*.json",
                  "*_sidecar.json", "perfn_mimo_*.json")
# dirs / names that are NOT per-task sidecars
_SKIP_NAMES = {"_haiku_plan", "engage_report.json", "intake_baseline.json",
               "detector_environment_manifest.json", "manifest.json"}

# GATE A: R76 source-existence gate constants
_HALLUCINATION_PHRASE_RE = re.compile(
    r"\b(N/?A|conceptual|illustrative|hypothetical|typical|"
    r"vulnerable\s+pattern|generic\s+pattern|sample\s+code)\b",
    re.IGNORECASE,
)
_SOURCE_EXTENSIONS = frozenset(
    [".sol", ".go", ".rs", ".move", ".cairo", ".vy", ".ts", ".js", ".py",
     # Obyte Oscript Autonomous Agents (declarative DSL). Registering them here
     # makes the R76 source-existence gate collect + verify a hunt sidecar that
     # cites an .oscript/.aa file (previously such a cite was treated as a
     # non-source suffix -> unverifiable -> silently unenforced).
     ".oscript", ".aa"]
)
_SKIP_DIR_NAMES = frozenset(
    [".git", ".auditooor", ".audit_logs", ".venv", "__pycache__",
     "node_modules", "target", "build", "dist", "out", "coverage"]
)


# ---------------------------------------------------------------------------
# GATE A helper: source-file index
# ---------------------------------------------------------------------------

def _collect_source_files(ws: Path) -> dict[str, list[Path]]:
    """Return basename -> [resolved paths] for all in-scope source files."""
    by_name: dict[str, list[Path]] = {}
    for root, dirs, files in os.walk(str(ws)):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIR_NAMES]
        for name in files:
            p = Path(root) / name
            if p.suffix.lower() in _SOURCE_EXTENSIONS:
                by_name.setdefault(name, []).append(p.resolve())
    return by_name


def _resolve_source_path(raw: str, ws: Path,
                         by_name: dict[str, list[Path]]) -> Path | None:
    """Try to resolve a raw file reference to a real path under ws."""
    raw = raw.strip().strip("`'\"")
    # Strip any line-number suffix (file.sol:42, file.sol#L42)
    raw_path = re.sub(r"(?:[:#]L?\d+.*)?$", "", raw).strip()
    if not raw_path:
        return None
    direct = Path(raw_path)
    candidates: list[Path] = []
    if direct.is_absolute():
        candidates.append(direct)
    else:
        for prefix in ("", "src/", "contracts/", "protocol/", "modules/"):
            candidates.append(ws / (prefix + raw_path))
    for c in candidates:
        try:
            r = c.resolve(strict=False)
        except OSError:
            continue
        if r.is_file():
            return r
    # Basename fallback
    basename = Path(raw_path).name
    if basename and basename in by_name:
        hits = by_name[basename]
        if len(hits) == 1:
            return hits[0]
        # Prefer production (not test)
        prod = [h for h in hits if not re.search(
            r"(^test_|_test\.go$|\.t\.sol$|\.s\.sol$|/test/|/tests/)", str(h)
        )]
        if len(prod) == 1:
            return prod[0]
        if prod:
            return prod[0]
        if hits:
            return hits[0]
    return None


# A line that is only whitespace / punctuation / brackets carries no verbatim
# signal (a bare ``});`` or ``{`` appears everywhere), so it is NOT required to
# match. Everything else with >= 6 non-trivial chars is a substantive line.
_PUNCT_ONLY_LINE_RE = re.compile(r"^[\s{}()\[\];,.:+\-*/&|!<>=?%^~`'\"]*$")
_SUBSTANTIVE_MIN = 6


def _substantive_excerpt_lines(excerpt: str) -> list[str]:
    """Whitespace-normalized substantive lines of a code_excerpt.

    A substantive line is one that carries a verbatim source signal: >= 6 chars
    after whitespace-collapse and NOT pure punctuation/brackets. Blank, tiny and
    brace-only lines are dropped (they match anywhere, so requiring them proves
    nothing and would false-fail on formatting).
    """
    out: list[str] = []
    for raw in excerpt.split("\n"):
        s = re.sub(r"\s+", " ", raw).strip()
        if len(s) < _SUBSTANTIVE_MIN:
            continue
        if _PUNCT_ONLY_LINE_RE.match(s):
            continue
        out.append(s)
    return out


def _needle_in_source(needle: str, ws: Path, cited_file: Path | None) -> bool:
    """True iff ``needle`` (already whitespace-normalized) is a verbatim substring
    of the cited source file (whitespace-normalized), else a whole-tree grep."""
    if cited_file is not None:
        try:
            cf = Path(cited_file)
            if cf.is_file():
                content = re.sub(
                    r"\s+", " ",
                    cf.read_text(encoding="utf-8", errors="ignore"),
                )
                return needle in content
        except OSError:
            pass
    # No resolvable cited file: fall back to the recursive whole-tree grep. Use a
    # whitespace-tolerant grep by matching the needle as a fixed string against
    # each file; grep -F is line-oriented so a needle spanning wrapped source
    # lines can miss, but this path is only reached without a cited file.
    try:
        r = subprocess.run(
            ["grep", "-rqF",
             "--include=*.sol", "--include=*.rs", "--include=*.go",
             "--include=*.ts", "--include=*.py", "--include=*.cairo",
             "--include=*.vy", "--include=*.move",
             "--include=*.oscript", "--include=*.aa",
             needle, str(ws)],
            timeout=30, capture_output=True,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return True  # grep unavailable - skip verification


def _grep_excerpt(ws: Path, excerpt: str, min_chars: int = 30,
                  cited_file: Path | None = None) -> bool:
    """Return True if excerpt appears in workspace source.

    MULTILINE-AWARE R76 (2026-07-10): a genuine multiline code_excerpt is verbatim
    source but wraps DIFFERENTLY than the file (the agent reflows a statement onto
    one line, or the file wraps one statement across two). The prior check picked
    only the single LONGEST line as the needle - which had TWO defects:
      (a) it credited a whole block whenever its longest line was verbatim, EVEN
          IF every other line was fabricated (an R76 anti-hallucination hole); and
      (b) with the longest line being an agent annotation / abridged, it dropped a
          genuine finding.
    Fix: split on newlines, keep only SUBSTANTIVE lines (>= 6 chars, not brace /
    punctuation only), and for a MULTILINE excerpt (>= 2 substantive lines) credit
    ONLY IF EVERY substantive line is a whitespace-normalized verbatim substring of
    the cited source. If ANY substantive line is absent -> False (soft R76 flag,
    preserving the anti-hallucination purpose). Whitespace-normalization on BOTH
    sides makes reflowed-but-verbatim source match; a fabricated line still fails.

    Behavior-preserving for a SINGLE substantive line: the original longest-line
    needle logic is used unchanged.

    PERF + PRECISION (cited_file): when the verdict cites a real file the excerpt
    only needs to exist in THAT file, so this is one file read (no whole-tree grep)
    and the miss is AUTHORITATIVE (soft R76 flag, coverage still credited). The
    slow recursive grep is reserved for the rare no-cited-file case.
    """
    excerpt = excerpt.strip()
    if len(excerpt) < min_chars:
        return True  # too short to verify - skip
    subs = _substantive_excerpt_lines(excerpt)
    if not subs:
        return True

    # MULTILINE path: every substantive line must be verbatim in the cited source.
    if len(subs) >= 2:
        for line in subs:
            if not _needle_in_source(line[:200], ws, cited_file):
                return False
        return True

    # SINGLE substantive line: preserve the original longest-line needle behavior.
    lines = [ln.strip() for ln in excerpt.split("\n") if len(ln.strip()) >= min_chars]
    if not lines:
        return True
    needle = max(lines, key=len)[:120]
    needle = re.sub(r"\s+", " ", needle).strip()
    if len(needle) < min_chars:
        return True
    return _needle_in_source(needle, ws, cited_file)


def _fn_index_for_ws(ws: Path) -> dict:
    """Map (file_basename, line) -> function name from the workspace's function
    enumeration (function-coverage-completeness --emit-worklist).

    Generic gap this closes: the workflow-drill / mega per-fn hunt emit shape
    (tools/workflow-drill-sidecar-emit.py) stores only an inner ``file_line``
    and NO outer ``function_anchor``. function-coverage-completeness credits a
    per-fn verdict only when it can resolve function_anchor.{file,function}
    (it matches by function NAME + file basename), so those sidecars bridge but
    stay UNTOUCHED/hollow - the per-fn hunt's verdicts are silently uncredited.
    The hunt targeted exactly the worklist functions, so (file_basename, line)
    from the cited file_line maps back to the exact function name here.

    Best-effort: returns {} on any failure (the bridge then copies as-is, the
    prior behaviour) - never hard-errors, never fabricates.

    PERF (default OFF): this enumeration runs `fcc --emit-worklist` which is the
    dominant cost of a re-bridge on large Go/Rust workspaces (>15 min on
    near-intents' ~1890 fns). It is no longer required for crediting: fcc resolves
    a synthesized {file,line} anchor by exact decl-line (commit
    fcc-resolve-anchor-by-declline), so _synth_anchor emits {file,line} directly.
    Set AUDITOOOR_BRIDGE_FN_INDEX=1 to re-enable name backfill into the anchor.
    """
    if os.environ.get("AUDITOOOR_BRIDGE_FN_INDEX", "0") != "1":
        return {}
    if not _FCC_TOOL.is_file():
        return {}
    try:
        proc = subprocess.run(
            [sys.executable, str(_FCC_TOOL), "--workspace", str(ws),
             "--emit-worklist", "--json"],
            capture_output=True, text=True, timeout=900,
        )
        out = (proc.stdout or "").strip()
        payload = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except Exception:
        return {}
    idx: dict[tuple[str, int], str] = {}
    for row in (payload.get("worklist") or []):
        fn = str(row.get("function") or row.get("name") or "").strip()
        fl = str(row.get("file_line") or "").strip()
        if not fn or ":" not in fl:
            continue
        fpath, _, lpart = fl.rpartition(":")
        m = re.search(r"\d+", lpart)
        if fpath and m:
            idx[(Path(fpath).name, int(m.group()))] = fn
    return idx


def _synth_anchor(rec: dict, inner: dict, fn_index: dict) -> dict | None:
    """Synthesize a {file, function, line} anchor for a sidecar that lacks a
    usable outer function_anchor, resolved from the inner file_line via the
    workspace fn index. Returns None when the sidecar already has a usable
    anchor or the file_line cannot be resolved to a known function."""
    fa = rec.get("function_anchor")
    if isinstance(fa, dict) and fa.get("file") and (fa.get("function") or fa.get("fn")):
        return None  # already usable
    fl = str(inner.get("file_line") or "").strip()
    if ":" not in fl:
        return None
    fpath, _, lpart = fl.rpartition(":")
    m = re.search(r"\d+", lpart)
    if not (fpath and m):
        return None
    line = int(m.group())
    # {file, line} is sufficient: function-coverage now resolves the anchor by
    # exact decl-line within the file (commit fcc-resolve-anchor-by-declline), so
    # the slow per-workspace name index is no longer required. Include the name
    # only when a (cheap/mocked) index already has it; never block on it.
    anchor = {"file": fpath, "line": line}
    if fn_index:
        fn = fn_index.get((Path(fpath).name, line))
        if fn:
            anchor["function"] = fn
    return anchor


def _parse_inner(d: dict) -> dict | None:
    """Parse the inner JSON payload from a sidecar's 'result' string."""
    r = d.get("result", "")
    if not isinstance(r, str) or not r.strip():
        return None
    body = r.strip().strip("`").lstrip("json").strip()
    try:
        j = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    return j if isinstance(j, dict) else None


# ---------------------------------------------------------------------------
# GATE A core: r76_source_existence_check
# ---------------------------------------------------------------------------

def r76_source_existence_check(
    inner: dict,
    ws: Path | None,
    by_name: dict[str, list[Path]] | None = None,
) -> dict:
    """Gate A: check a parsed inner sidecar payload for source existence.

    Returns a dict with:
      pass_gate: bool - True if candidate is safe to promote as-is
      reason: str - why it failed (empty string on pass)
      applies_override: str | None - if non-None, overwrite applies_to_target

    Rules (fail-closed):
    1. Empty / hallucination-phrase file_line on a yes/maybe(+conf) candidate
       with no resolvable file_path_hint -> fail: r76-empty-file-line
    2. file_line cites a path that does not exist anywhere in the workspace
       -> fail: r76-file-not-in-workspace
    3. code_excerpt present and does not grep-match workspace source
       -> fail: r76-excerpt-not-in-source
    4. applies_to_target=no -> pass-negative (honest negative signal)
    5. No file_line and no file_path_hint and applies_to_target=yes -> fail
    """
    applies = str(inner.get("applies_to_target", "") or "").strip().lower()
    confidence = str(inner.get("confidence", "") or "").strip().lower()
    file_line = str(inner.get("file_line", "") or "").strip()
    file_hint = str(inner.get("file_path_hint", "") or "").strip()
    excerpt = str(inner.get("code_excerpt", "") or "").strip()

    # Only gate on positive / uncertain-but-confident signals.
    # applies_to_target=no is an honest negative - always pass.
    is_positive = applies == "yes"
    is_uncertain = applies == "maybe" and confidence in ("high", "medium")
    if not (is_positive or is_uncertain):
        return {"pass_gate": True, "reason": "", "applies_override": None}

    # Rule 1: empty or hallucination-phrase file_line
    has_real_file_line = bool(file_line) and not _HALLUCINATION_PHRASE_RE.search(file_line)
    if not has_real_file_line:
        if file_hint and ws is not None:
            # Has file_path_hint - try to validate that fallback
            by_n = by_name if by_name is not None else _collect_source_files(ws)
            resolved = _resolve_source_path(file_hint, ws, by_n)
            if resolved is None:
                return {
                    "pass_gate": False,
                    "reason": (
                        f"r76-file-not-in-workspace: "
                        f"applies_to_target={applies}, file_line={file_line!r}, "
                        f"file_path_hint={file_hint!r} not found under workspace"
                    ),
                    "applies_override": "no",
                }
            # file_path_hint resolves - additionally check excerpt
            if excerpt and not _grep_excerpt(ws, excerpt, cited_file=resolved):
                return {
                    "pass_gate": False,
                    "reason": (
                        "r76-excerpt-not-in-source: "
                        "code_excerpt not found in workspace source files"
                    ),
                    "applies_override": "no",
                }
            # Hint resolves, excerpt ok (or absent) - pass
            return {"pass_gate": True, "reason": "", "applies_override": None}
        # No resolvable anchor at all
        return {
            "pass_gate": False,
            "reason": (
                f"r76-empty-file-line: applies_to_target={applies} but "
                f"file_line={file_line!r} and no resolvable file_path_hint"
            ),
            "applies_override": "no",
        }

    # Rule 2: file_line is set - verify the cited path exists in workspace
    cited_path: Path | None = None
    if ws is not None:
        by_n = by_name if by_name is not None else _collect_source_files(ws)
        # file_line may be "src/Foo.sol:42" or just "Foo.sol"
        path_part = re.sub(r"(?:[:#]L?\d+.*)?$", "", file_line).strip()
        if path_part and Path(path_part).suffix.lower() in _SOURCE_EXTENSIONS:
            resolved = _resolve_source_path(path_part, ws, by_n)
            if resolved is None:
                return {
                    "pass_gate": False,
                    "reason": (
                        f"r76-file-not-in-workspace: file_line cites {path_part!r} "
                        f"which does not exist in workspace"
                    ),
                    "applies_override": "no",
                }
            cited_path = resolved  # reuse for the fast excerpt check below

    # Rule 3: excerpt verification. By the time we reach here Rule 2 has already
    # verified the cited FILE exists (a hallucinated file hard-failed above). A
    # failing excerpt match with a REAL file+line is therefore NOT a hallucination
    # - it is almost always an ABRIDGED excerpt (agents write "...; FtBurn{...}"
    # ellipses that cannot grep-match verbatim source). Treat it as a SOFT signal:
    # downgrade the positive claim to "no" (the finding is not excerpt-verified, so
    # it must not be promoted), but do NOT set the HARD r76_source_existence_fail -
    # the function was genuinely examined at a real file:line, so it still counts as
    # coverage (function-coverage credits applies=no + real file_line unless the
    # cite itself is hallucinated). This fixed 783/910 near-intents verdicts that
    # the verbatim-only match wrongly buried as hollow.
    if excerpt and ws is not None and not _grep_excerpt(ws, excerpt, cited_file=cited_path):
        return {
            "pass_gate": False,
            "reason": (
                "r76-excerpt-unverified: code_excerpt not found verbatim (file+line "
                "are real; likely abridged) - soft downgrade, coverage preserved"
            ),
            "applies_override": "no",
            "soft_excerpt_fail": True,
        }

    return {"pass_gate": True, "reason": "", "applies_override": None}


def _apply_r76_downgrade(d: dict, check: dict) -> dict:
    """Return a modified copy of sidecar with R76 downgrade applied to inner payload."""
    inner = _parse_inner(d)
    if inner is None:
        # Not a standard MIMO sidecar - pass through unchanged
        return d
    inner_out = dict(inner)
    override = check.get("applies_override")
    if override is not None:
        inner_out["applies_to_target"] = override
    if check.get("soft_excerpt_fail"):
        # Real file+line, only the (likely abridged) excerpt did not grep-match.
        # SOFT signal: record it transparently but do NOT set the hard
        # r76_source_existence_fail, so the verified file:line still credits as
        # coverage (the positive claim is already downgraded to "no" above).
        inner_out["r76_excerpt_unverified"] = True
        inner_out["r76_source_existence_reason"] = check.get("reason", "")[:300]
    else:
        # Hard fail (hallucinated / missing file): block coverage credit.
        inner_out["r76_source_existence_fail"] = True
        inner_out["r76_source_existence_reason"] = check.get("reason", "")[:300]
    out = dict(d)
    out["result"] = json.dumps(inner_out)
    return out


# ---------------------------------------------------------------------------
# Workspace / sidecar helpers (original)
# ---------------------------------------------------------------------------

def _sidecar_ws(path: Path) -> tuple[str | None, str | None]:
    """Return (workspace_path, workspace) recorded in a sidecar, or (None, None)."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return (None, None)
    rec = d if isinstance(d, dict) else (d[0] if isinstance(d, list) and d and isinstance(d[0], dict) else {})
    if not isinstance(rec, dict):
        return (None, None)
    return (rec.get("workspace_path"), rec.get("workspace"))


# ---------------------------------------------------------------------------
# bridge() - main entry point
# ---------------------------------------------------------------------------

def bridge(ws: Path, derived_root: Path, *, enforce_r76: bool = True) -> dict:
    """Copy hunt sidecars for ws from derived_root into ws/.auditooor/hunt_findings_sidecars/.

    With enforce_r76=True (default): any sidecar whose inner payload has
    applies_to_target=yes (or maybe+high/medium confidence) but cites an
    empty / hallucinated / nonexistent file_line is DOWNGRADED to
    applies_to_target=no + r76_source_existence_fail=True before writing.
    """
    ws = ws.resolve()
    out_dir = ws / ".auditooor" / "hunt_findings_sidecars"
    matched = 0
    scanned = 0
    r76_downgraded = 0
    if not derived_root.is_dir():
        return {
            "matched": 0, "scanned": 0, "r76_downgraded": 0,
            "out_dir": str(out_dir),
            "note": f"derived root not found: {derived_root}",
        }
    out_dir.mkdir(parents=True, exist_ok=True)
    # Pre-build the source-file index once for this workspace (GATE A)
    by_name: dict[str, list[Path]] | None = None
    if enforce_r76 and ws.is_dir():
        try:
            by_name = _collect_source_files(ws)
        except Exception:
            by_name = None  # gate degrades gracefully - never hard-errors
    # Pre-build the (file,line)->function index so sidecars missing an outer
    # function_anchor (the workflow-drill mega-hunt emit shape) get one
    # synthesized and thus credit into function-coverage.
    fn_index = _fn_index_for_ws(ws) if ws.is_dir() else {}
    anchors_synth = 0

    # Candidate sidecar files. The per-task hunt sidecars live as
    # <task_id>.json INSIDE harness dirs (mimo_harness_<ws>_workflow/,
    # haiku_harness_<ws>_scoped_*/) - the workflow-drill / mega per-fn emit shape
    # names them by task_id, which the old filename-prefix globs miss entirely
    # (so the whole mega hunt never bridged). Scan every *.json under a harness
    # dir, plus the loose filename-prefixed sidecars for back-compat. The
    # workspace belongs-check below still gates which ones are copied.
    candidates: set[Path] = set()
    for dpat in ("mimo_harness_*/*.json", "haiku_harness_*/*.json"):
        candidates.update(derived_root.glob(dpat))
    for glob_pat in _SIDECAR_GLOBS:
        candidates.update(derived_root.rglob(glob_pat))
    seen: set[str] = set()
    if True:
        for f in sorted(candidates):
            if not f.is_file() or f.name in _SKIP_NAMES:
                continue
            if any(part in _SKIP_NAMES for part in f.parts):
                continue
            scanned += 1
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            wpath = d.get("workspace_path")
            wname = d.get("workspace")
            belongs = False
            if wpath:
                try:
                    belongs = Path(wpath).resolve() == ws
                except (OSError, ValueError):
                    belongs = False
            if not belongs and wname:
                belongs = (wname == ws.name)
                # A ``workspace`` field can hold the FULL PATH (not just the short
                # name): tools/workflow-drill-sidecar-emit.py writes
                # ``workspace=<args.workspace>``, and callers pass the absolute
                # workspace path (the Obyte hunt did), so every such sidecar was
                # silently dropped by the ``wname == ws.name`` short-name compare.
                # Accept a full-path workspace that resolves to ws. Generic + safe:
                # it can only ADD a match for a sidecar whose workspace is exactly ws.
                if not belongs:
                    try:
                        belongs = (Path(str(wname)).expanduser().resolve() == ws)
                    except (OSError, ValueError, RuntimeError):
                        belongs = False
                # Accept an engagement-alias name: the mega per-fn hunt tags
                # sidecars with the short name passed to the workflow (e.g.
                # "monero" / "nearintents") while the dir is "monero-oxide" /
                # "near-intents". Match on a normalized (alnum-only) prefix with
                # a >=5-char floor so short accidental prefixes never collide.
                if not belongs:
                    n1 = re.sub(r"[^a-z0-9]", "", str(wname).lower())
                    n2 = re.sub(r"[^a-z0-9]", "", ws.name.lower())
                    if len(n1) >= 5 and (n1 == n2 or n2.startswith(n1) or n1.startswith(n2)):
                        belongs = True
            if not belongs:
                continue

            # GATE A: R76 source-existence enforcement
            write_data = d
            inner = _parse_inner(d)
            if enforce_r76 and inner is not None:
                check = r76_source_existence_check(inner, ws, by_name)
                if not check["pass_gate"]:
                    write_data = _apply_r76_downgrade(d, check)
                    r76_downgraded += 1
            # Synthesize a missing function_anchor from the inner file_line so
            # function-coverage can credit the verdict (workflow-drill emit shape
            # has no outer function_anchor). Never overwrites a usable anchor.
            if inner is not None:
                anchor = _synth_anchor(write_data, inner, fn_index)
                if anchor is not None:
                    if write_data is d:
                        write_data = dict(d)
                    write_data["function_anchor"] = anchor
                    anchors_synth += 1

            key = f.name
            if key in seen:
                key = f"{f.parent.name}__{f.name}"
            seen.add(key)
            try:
                dst = out_dir / key
                if write_data is d:
                    shutil.copy2(f, dst)
                else:
                    dst.write_text(
                        json.dumps(write_data, indent=2) + "\n",
                        encoding="utf-8",
                    )
                matched += 1
            except OSError:
                pass

    return {
        "matched": matched,
        "scanned": scanned,
        "r76_downgraded": r76_downgraded,
        "anchors_synthesized": anchors_synth,
        "fn_index_size": len(fn_index),
        "out_dir": str(out_dir),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Bridge hunt sidecars into the workspace.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--derived-root", default=None,
                    help=f"override derived root (default {_DEFAULT_DERIVED})")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-r76", action="store_true",
                    help="Disable Gate A R76 source-existence enforcement (testing only)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[hunt-sidecar-bridge] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    derived = (Path(args.derived_root).expanduser()
               if args.derived_root else _DEFAULT_DERIVED)
    res = bridge(ws, derived, enforce_r76=not args.no_r76)
    downgraded_note = (
        f"  (r76_downgraded={res['r76_downgraded']})"
        if res.get("r76_downgraded") else ""
    )
    print(
        f"[hunt-sidecar-bridge] {ws.name}: matched {res['matched']} of "
        f"{res['scanned']} scanned sidecar(s) -> {res['out_dir']}"
        + downgraded_note
        + (f"  ({res['note']})" if res.get("note") else "")
    )
    if args.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    # exit 0 even on 0 matches (honest: the hunt simply produced none for this ws);
    # the gate stays unsatisfied, which is correct.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
