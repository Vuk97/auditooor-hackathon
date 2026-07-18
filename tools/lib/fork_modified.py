"""lib/fork_modified.py - importable core of the fork-modified-files-scope logic.

Extracted from tools/fork-modified-files-scope.py so the step-1 manifest emitter
(and any other in-process consumer) can compute the FORK-MODIFIED surface without
shelling out to the CLI. The CLI (tools/fork-modified-files-scope.py) re-exports
these names so its behavior is unchanged.

WHAT THIS COMPUTES: the Polygon-Labs (or any fork's) ACTUAL modification surface
vs its upstream. Most bounty programs that include a fork (bor/cosmos-sdk/cometbft,
etc.) put ONLY the fork's own modifications in scope - "unmodified upstream is OUT
OF SCOPE". A naive in-scope enumeration over the whole fork tree pulls in tens of
thousands of inherited-upstream functions that are OOS, drowning the hunt.

We compute the modified+added file set via a CONTENT-HASH TREE DIFF of the fork
checkout against a shallow clone of the upstream at a given ref (no merge-base
needed - robust to rebased/squashed fork history), then filter an
inscope_units.jsonl so that rows under the fork's local_name keep ONLY units whose
repo-relative file was modified/added by the fork. Rows for OTHER repos/langs pass
through untouched.

Completeness-safety: callers that cannot resolve the upstream pass
``modified_files=None`` to :func:`filter_manifest`, which keeps the FULL fork set -
an audit must never silently UNDER-scope.

Pure stdlib.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _normalized_content_hash(raw: bytes) -> str:
    """sha1 of WHITESPACE-NORMALIZED content.

    A fork file that differs from upstream ONLY in line endings (CRLF vs LF),
    trailing whitespace, or blank-line insertions is NOT a semantic Polygon
    modification - none of those change code (gofmt-irrelevant). Hashing raw
    bytes over-scopes such files as "modified" (e.g. bor rlp/decode.go, byte-
    different only in blank lines, was wrongly kept as in-scope). Normalize:
    decode, split on any line ending, rstrip each line, drop blank lines, rejoin.
    This CANNOT under-scope a real change: any added/edited/removed token alters
    a non-blank line and survives normalization.
    """
    text = raw.decode("utf-8", errors="replace")
    lines = [ln.rstrip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln != ""]
    return hashlib.sha1("\n".join(lines).encode("utf-8")).hexdigest()


# Default source-extension set: a BROAD multi-language source surface so a fork in
# ANY ecosystem (not just Go) gets a real content-diff instead of an empty set ->
# silent keep-all. Callers may pass a narrower set (e.g. from workspace-detected
# languages) to compute_modified_files(..., extensions=...).
DEFAULT_SOURCE_EXTENSIONS = frozenset({
    ".go", ".sol", ".rs", ".move", ".cairo", ".vy", ".huff", ".fe", ".nr",
    ".ts", ".js", ".py", ".c", ".cpp", ".h", ".rb", ".java", ".kt", ".scala", ".ml",
})

# Per-language test-file name patterns (fnmatch globs). A fork test file is never
# the in-scope modification surface, so skip them when skip_tests is set. Keyed by
# extension; the Go entry preserves the historical '_test.go' behavior exactly.
TEST_FILE_PATTERNS: dict[str, tuple[str, ...]] = {
    ".go": ("*_test.go",),
    ".sol": ("*.t.sol",),
    ".rs": ("*_test.rs",),
    ".ts": ("*.test.ts",),
    ".js": ("*.test.js",),
    ".py": ("test_*.py", "*_test.py"),
}

# Directory components that are never the in-scope surface (vendored / generated /
# test-data trees). Same set the Go-only path used, plus the JS-ecosystem dir.
_SKIP_DIR_PARTS = {".git", "vendor", "testdata", "third_party", "node_modules"}


def _is_test_file(name: str, suffix: str) -> bool:
    """True if filename matches the test-file pattern(s) for its extension."""
    import fnmatch

    for pat in TEST_FILE_PATTERNS.get(suffix, ()):  # noqa: SIM110 - readability
        if fnmatch.fnmatch(name, pat):
            return True
    return False


def _source_files(
    root: Path,
    *,
    extensions,
    skip_tests: bool,
    skip_vendor: bool = True,
) -> dict[str, str]:
    """Map repo-relative path -> whitespace-normalized content hash for source files.

    A file is included when its suffix is in ``extensions``. Skips vendored /
    generated / test-data trees (when ``skip_vendor``) and per-language test files
    (when ``skip_tests``) that are never the in-scope modification surface.
    """
    exts = {e if e.startswith(".") else "." + e for e in extensions}
    out: dict[str, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        suffix = p.suffix
        if suffix not in exts:
            continue
        rel = p.relative_to(root)
        if skip_vendor and (set(rel.parts) & _SKIP_DIR_PARTS):
            continue
        if skip_tests and _is_test_file(p.name, suffix):
            continue
        try:
            out[rel.as_posix()] = _normalized_content_hash(p.read_bytes())
        except OSError:
            continue
    return out


def _go_files(root: Path, *, skip_tests: bool) -> dict[str, str]:
    """Back-compat shim: Go-only file map (delegates to :func:`_source_files`).

    Retained because external callers / tests import this name directly. New code
    should call :func:`_source_files` with an explicit extension set.
    """
    return _source_files(root, extensions=(".go",), skip_tests=skip_tests)


def compute_modified_files(
    fork_dir: Path,
    upstream_dir: Path,
    *,
    extensions=None,
    skip_tests: bool = True,
) -> set[str]:
    """Fork-modified surface = files added in the fork OR whose content differs.

    ``extensions`` selects which source languages to diff. ``None`` (the default)
    uses :data:`DEFAULT_SOURCE_EXTENSIONS`, a broad multi-language set that includes
    ``.go`` - so the historical Go behavior is byte-for-byte preserved while a
    Solidity/Rust/Move/Cairo/Vyper/... fork now diffs its real source surface
    instead of returning the empty set (which would silently keep-all off-Go).
    """
    exts = DEFAULT_SOURCE_EXTENSIONS if extensions is None else extensions
    fork = _source_files(fork_dir, extensions=exts, skip_tests=skip_tests)
    up = _source_files(upstream_dir, extensions=exts, skip_tests=skip_tests)
    modified: set[str] = set()
    for rel, sha in fork.items():
        if rel not in up or up[rel] != sha:
            modified.add(rel)
    return modified


def filter_manifest(
    manifest_path: Path,
    out_path: Path,
    repo_local_name: str,
    modified_files: set[str] | None,
) -> dict:
    """Filter inscope_units rows for repo_local_name to modified_files.

    modified_files is None => keep all rows for the repo (upstream-unresolved).
    Rows for other repos/langs are always passed through unchanged.
    """
    repo_seg = f"/src/{repo_local_name}/"
    repo_prefix = f"src/{repo_local_name}/"
    kept_repo = dropped_repo = passthrough = 0
    out_lines: list[str] = []
    with manifest_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            try:
                row = json.loads(s)
            except json.JSONDecodeError:
                out_lines.append(s)
                passthrough += 1
                continue
            f = str(row.get("file") or row.get("path") or "")
            in_repo = repo_seg in f or f.startswith(repo_prefix)
            if not in_repo:
                out_lines.append(s)
                passthrough += 1
                continue
            if modified_files is None:
                out_lines.append(s)
                kept_repo += 1
                continue
            # derive repo-relative path
            if repo_seg in f:
                rel = f.split(repo_seg, 1)[1]
            else:
                rel = f[len(repo_prefix):]
            if rel in modified_files:
                out_lines.append(s)
                kept_repo += 1
            else:
                dropped_repo += 1
    out_path.write_text("\n".join(out_lines) + ("\n" if out_lines else ""), encoding="utf-8")
    return {
        "repo": repo_local_name,
        "kept_in_repo": kept_repo,
        "dropped_in_repo_oos_upstream": dropped_repo,
        "passthrough_other": passthrough,
    }


# ---------------------------------------------------------------------------
# UPSTREAM RESOLUTION (git-clone -> language-package-cache -> unresolved)
#
# For a FORK target the fork-modified surface is computed by diffing the fork
# checkout against upstream AT the base ref. The original path did a single
# `git clone --depth 1 --branch <ref>` from github.com. That FAILS silently on a
# SHALLOW fork clone whose upstream ref is not a local git object AND whenever
# github is unreachable, dropping the whole audit to completeness-safe keep-all
# (the SEI go-ethereum bug: the upstream v1.15.7 tree is available in the Go
# MODULE CACHE but never a local git object, so agents got inconsistent scope).
#
# resolve_upstream_dir() tries, in order:
#   (1) git clone --depth 1 --branch <ref>  (works when the ref is a real
#       upstream tag/branch and github is reachable);
#   (2) the LANGUAGE PACKAGE CACHE for the ecosystem - for a GO fork,
#       `go mod download <upstream_module>@<base_ref>` then diff the extracted
#       read-only module dir under $GOMODCACHE (github fetch NOT required when
#       the module is already downloaded / proxied). This is the shallow-clone
#       fallback that makes fork-delta deterministic on a fork whose upstream is
#       not a local git object;
#   (3) unresolved -> None + a loud WARN (caller keeps-all, never under-scopes).
# ---------------------------------------------------------------------------

# owner/repo -> the Go MODULE PATH used by go.mod. For github-hosted modules the
# module path is just `github.com/<owner>/<repo>`; a caller may override with an
# explicit module path (e.g. a /v2 major-version suffix) via go_module_path=.
def _go_module_path_for(upstream_repo: str) -> str:
    ur = (upstream_repo or "").strip().strip("/")
    if ur.startswith("github.com/"):
        return ur
    return f"github.com/{ur}"


def _gomodcache_dir() -> Path:
    """Resolve $GOMODCACHE (default $GOPATH/pkg/mod, default ~/go/pkg/mod).

    Uses `go env GOMODCACHE` when a go toolchain is on PATH; else falls back to
    the documented default so a materialize can still find an already-extracted
    module. Never raises."""
    env_val = os.environ.get("GOMODCACHE")
    if env_val:
        return Path(env_val).expanduser()
    try:
        rc = subprocess.run(
            ["go", "env", "GOMODCACHE"],
            capture_output=True, text=True, timeout=30,
            env=_go_env(),
        )
        if rc.returncode == 0 and rc.stdout.strip():
            return Path(rc.stdout.strip()).expanduser()
    except (OSError, subprocess.SubprocessError):
        pass
    gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
    return Path(gopath).expanduser() / "pkg" / "mod"


def _go_env(gotoolchain: str | None = None) -> dict:
    """Env for a go subprocess. Pins GOTOOLCHAIN when requested so the fork's
    declared toolchain (e.g. go1.25.8) is used even on a newer host go."""
    env = dict(os.environ)
    if gotoolchain:
        env["GOTOOLCHAIN"] = gotoolchain
    return env


def _go_mod_cache_module_dir(
    upstream_repo: str,
    base_ref: str,
    *,
    go_module_path: str | None = None,
    gotoolchain: str | None = None,
    download: bool = True,
) -> Path | None:
    """Return the read-only extracted module dir for <module>@<base_ref> in the
    Go module cache, running `go mod download` first when needed. None if the
    module cannot be resolved by this method (no go toolchain, download failed,
    dir absent).

    The extracted dir is ``$GOMODCACHE/<escaped-module>@<version>`` where the
    version is the base_ref (a semver tag like v1.15.7). We look for an existing
    extracted dir first (works fully offline when already downloaded), then try
    `go mod download` to populate it."""
    module = (go_module_path or _go_module_path_for(upstream_repo)).strip()
    ver = (base_ref or "").strip()
    if not module or not ver:
        return None
    cache = _gomodcache_dir()
    # Go escapes uppercase letters in module paths as '!<lower>'; upstream go-eth
    # style paths (github.com/ethereum/go-ethereum) are all-lowercase so the
    # direct join works. Handle the uppercase-escape defensively anyway.
    escaped = "".join(("!" + c.lower()) if c.isupper() else c for c in module)
    candidate = cache / f"{escaped}@{ver}"
    if candidate.is_dir():
        return candidate
    if not download:
        return None
    # Populate the cache. `go mod download` does not need a module context when
    # given an explicit module@version, but some go versions require GO111MODULE
    # + a working dir; run in a scratch temp dir with a throwaway go.mod.
    try:
        with tempfile.TemporaryDirectory(prefix="fork-gomod-") as td:
            gomod = Path(td) / "go.mod"
            gomod.write_text("module scratch\n\ngo 1.21\n", encoding="utf-8")
            rc = subprocess.run(
                ["go", "mod", "download", "-x", f"{module}@{ver}"],
                capture_output=True, text=True, timeout=1800,
                cwd=td,
                env=_go_env(gotoolchain),
            )
        if rc.returncode != 0:
            _eprint(
                f"[fork-modified] go mod download {module}@{ver} failed: "
                f"{(rc.stderr or rc.stdout).strip()[:240]}"
            )
            return None
    except (OSError, subprocess.SubprocessError) as exc:
        _eprint(f"[fork-modified] go mod download {module}@{ver} error: {exc}")
        return None
    if candidate.is_dir():
        return candidate
    # Re-resolve GOMODCACHE post-download in case go env changed nothing but the
    # dir now exists under a freshly-created cache root.
    cache2 = _gomodcache_dir()
    candidate2 = cache2 / f"{escaped}@{ver}"
    return candidate2 if candidate2.is_dir() else None


def _git_clone_upstream(upstream_repo: str, ref: str, dest: Path) -> bool:
    """Shallow clone ``owner/repo`` at ref into dest. True on success."""
    if not upstream_repo or not ref:
        return False
    url = f"https://github.com/{upstream_repo}.git"
    try:
        rc = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
            capture_output=True, text=True, timeout=900,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return rc.returncode == 0


def resolve_upstream_dir(
    upstream_repo: str,
    base_ref: str,
    *,
    lang: str = "go",
    clone_root: Path | None = None,
    go_module_path: str | None = None,
    gotoolchain: str | None = None,
    allow_download: bool = True,
) -> tuple[Path | None, str, "tempfile.TemporaryDirectory | None"]:
    """Resolve upstream <owner/repo>@<base_ref> to a local source dir to diff.

    Returns ``(upstream_dir_or_None, upstream_source, tmp_holder_or_None)`` where
    ``upstream_source`` is one of ``git-clone`` / ``go-mod-cache`` / ``unresolved``
    and ``tmp_holder`` (when non-None) MUST be kept alive by the caller until the
    diff is done, then cleaned up.

    Order: git clone (all langs), then - for a GO fork - the go module cache
    fallback (the shallow-clone-safe path), then unresolved (caller keeps-all).
    """
    if not upstream_repo or not base_ref:
        return None, "unresolved", None
    # AUDITOOOR_FORK_NO_GIT_CLONE=1 skips the git-clone step so the LANGUAGE
    # PACKAGE CACHE fallback is used directly (models a shallow fork clone whose
    # upstream ref is not a local git object AND/OR an offline/github-unreachable
    # host - the SEI go-ethereum scenario). Deterministic + no network needed.
    _skip_clone = os.environ.get("AUDITOOOR_FORK_NO_GIT_CLONE", "") not in ("", "0")
    tmp_holder: tempfile.TemporaryDirectory | None = None
    if not _skip_clone:
        # (1) git clone of the upstream ref.
        if clone_root is not None:
            clone_root.mkdir(parents=True, exist_ok=True)
            dest = clone_root / f"upstream_{Path(upstream_repo).name}_{base_ref}"
        else:
            tmp_holder = tempfile.TemporaryDirectory(prefix="fork-upstream-")
            dest = Path(tmp_holder.name) / "upstream"
        if dest.is_dir() and (dest / ".git").is_dir():
            return dest, "git-clone", tmp_holder
        if _git_clone_upstream(upstream_repo, base_ref, dest):
            return dest, "git-clone", tmp_holder
        # clone failed - discard its temp holder before the cache fallback.
        if tmp_holder is not None:
            tmp_holder.cleanup()
            tmp_holder = None
    # (2) language package cache fallback. Go: the module cache.
    if (lang or "").lower() == "go":
        mod_dir = _go_mod_cache_module_dir(
            upstream_repo, base_ref,
            go_module_path=go_module_path, gotoolchain=gotoolchain,
            download=allow_download,
        )
        if mod_dir is not None and mod_dir.is_dir():
            # module-cache dirs are read-only; no temp holder to clean.
            return mod_dir, "go-mod-cache", None
    # (3) unresolved.
    _eprint(
        f"[fork-modified] WARN upstream {upstream_repo}@{base_ref} UNRESOLVED "
        f"by git-clone AND {lang}-package-cache; caller KEEPS ALL its units "
        f"(completeness-safe, no under-scope)"
    )
    return None, "unresolved", None


def materialize_fork_modified(
    fork_dir: Path,
    upstream_repo: str,
    base_ref: str,
    *,
    lang: str = "go",
    extensions=None,
    skip_tests: bool = True,
    go_module_path: str | None = None,
    gotoolchain: str | None = None,
    clone_root: Path | None = None,
    allow_download: bool = True,
) -> dict:
    """Compute the DURABLE fork-delta artifact for a single fork.

    Returns a dict (the ``.auditooor/fork_modified/<local_name>.json`` payload):
      {schema, local_name, upstream_repo, base_ref, upstream_source,
       sei_modified_files[], sei_added_files[], modified_count, added_count,
       unmodified_upstream_count, verdict}

    ``verdict`` is ``scoped`` when upstream resolved (modified+added lists are
    authoritative) or ``upstream-unresolved`` when NO method resolved upstream
    (both lists empty + a keep-all signal for the caller). Completeness-safe:
    an unresolved upstream NEVER produces a drop-list.

    ``sei_added_files``  = source files present in the fork but NOT upstream.
    ``sei_modified_files`` = source files present in both but content-differing
                             (whitespace-normalized).
    """
    fork_dir = Path(fork_dir)
    local_name = fork_dir.name
    exts = DEFAULT_SOURCE_EXTENSIONS if extensions is None else extensions
    payload: dict = {
        "schema": "auditooor.fork_modified.v1",
        "local_name": local_name,
        "upstream_repo": upstream_repo,
        "base_ref": base_ref,
        "lang": lang,
        "upstream_source": "unresolved",
        "sei_modified_files": [],
        "sei_added_files": [],
        "modified_count": 0,
        "added_count": 0,
        "unmodified_upstream_count": None,
        "verdict": "upstream-unresolved",
    }
    if not fork_dir.is_dir():
        payload["verdict"] = "fork-dir-absent"
        return payload

    up_dir, up_source, tmp_holder = resolve_upstream_dir(
        upstream_repo, base_ref, lang=lang, clone_root=clone_root,
        go_module_path=go_module_path, gotoolchain=gotoolchain,
        allow_download=allow_download,
    )
    payload["upstream_source"] = up_source
    try:
        if up_dir is None:
            # unresolved: keep-all - no drop-list. Loud WARN already printed.
            return payload
        fork_map = _source_files(fork_dir, extensions=exts, skip_tests=skip_tests)
        up_map = _source_files(up_dir, extensions=exts, skip_tests=skip_tests)
        modified: list[str] = []
        added: list[str] = []
        for rel, sha in fork_map.items():
            if rel not in up_map:
                added.append(rel)
            elif up_map[rel] != sha:
                modified.append(rel)
        modified.sort()
        added.sort()
        # unmodified-upstream = fork files present+identical upstream (the OOS set)
        unmodified = sum(
            1 for rel, sha in fork_map.items()
            if rel in up_map and up_map[rel] == sha
        )
        payload.update({
            "upstream_source": up_source,
            "sei_modified_files": modified,
            "sei_added_files": added,
            "modified_count": len(modified),
            "added_count": len(added),
            "unmodified_upstream_count": unmodified,
            "verdict": "scoped",
        })
        return payload
    finally:
        if tmp_holder is not None:
            tmp_holder.cleanup()


def load_fork_modified_artifact(ws: Path, local_name: str) -> dict | None:
    """Read ``<ws>/.auditooor/fork_modified/<local_name>.json``. None if absent /
    unreadable / malformed."""
    p = Path(ws) / ".auditooor" / "fork_modified" / f"{local_name}.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def fork_modified_keep_set(artifact: dict | None) -> set[str] | None:
    """The IN-SCOPE (keep) repo-relative file set from a fork_modified artifact:
    modified UNION added. Returns None (keep-all) when the artifact is absent or
    its upstream was unresolved (verdict != scoped) - never under-scope."""
    if not isinstance(artifact, dict):
        return None
    if artifact.get("verdict") != "scoped":
        return None
    keep: set[str] = set()
    keep.update(str(f) for f in (artifact.get("sei_modified_files") or []))
    keep.update(str(f) for f in (artifact.get("sei_added_files") or []))
    return keep


def write_fork_modified_artifact(ws: Path, payload: dict) -> Path:
    """Write ``<ws>/.auditooor/fork_modified/<local_name>.json`` (stable JSON)."""
    local_name = str(payload.get("local_name") or "fork")
    out_dir = Path(ws) / ".auditooor" / "fork_modified"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{local_name}.json"
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out


__all__ = [
    "_eprint",
    "_normalized_content_hash",
    "_go_files",
    "_source_files",
    "_is_test_file",
    "DEFAULT_SOURCE_EXTENSIONS",
    "TEST_FILE_PATTERNS",
    "compute_modified_files",
    "filter_manifest",
    "resolve_upstream_dir",
    "materialize_fork_modified",
    "load_fork_modified_artifact",
    "fork_modified_keep_set",
    "write_fork_modified_artifact",
]
