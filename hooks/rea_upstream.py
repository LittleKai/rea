"""REA upstream update detector (SessionStart / PreInvocation hook) and safe 3-way sync engine.

Usage:
    D:/Dev/conda-envs/py312/python.exe hooks/rea_upstream.py session-start    # Claude Code / Codex hook
    D:/Dev/conda-envs/py312/python.exe hooks/rea_upstream.py pre-invocation   # Antigravity (AGY) hook
    D:/Dev/conda-envs/py312/python.exe hooks/rea_upstream.py check [--force]  # CLI check
    D:/Dev/conda-envs/py312/python.exe hooks/rea_upstream.py status           # Detailed JSON diff vs upstream/main
    D:/Dev/conda-envs/py312/python.exe hooks/rea_upstream.py sync             # Backup + FF upstream/main + 3-way merge AGENTS.md
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = ROOT / "_reference" / "cache"
CHECK_CACHE_FILE = CACHE_DIR / "upstream_check.json"
BACKUP_ROOT = CACHE_DIR / "setup-backup"
CHECK_TTL_SECONDS = 24 * 3600
UPSTREAM_URL = "https://github.com/morluto/rea"
REMOTE_BRANCH = "main"


def _upstream_remote() -> str:
    """Prefer the named `upstream` remote; fall back to UPSTREAM_URL if not configured."""
    res = subprocess.run(["git", "remote"], cwd=ROOT, capture_output=True, timeout=5, check=False)
    remotes = res.stdout.decode("utf-8", "replace").split()
    return "upstream" if "upstream" in remotes else UPSTREAM_URL


def _worktree_script(start: Path) -> Path | None:
    """Return hooks/rea_upstream.py of the checkout containing `start`, or None if it is this file."""
    for parent in (start, *start.parents):
        candidate = parent / "hooks" / "rea_upstream.py"
        if candidate.is_file():
            return None if candidate.resolve() == Path(__file__).resolve() else candidate
    return None


def _git(*args: str, cwd: Path = ROOT, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        err = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(args)}: {err}")
    return result


def _out(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", "replace").strip()


def _load_cache() -> dict:
    try:
        return json.loads(CHECK_CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(data: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CHECK_CACHE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError:
        pass


def _is_behind(remote_head: str) -> bool:
    if not remote_head:
        return False
    # 0 = remote_head is already in HEAD's ancestry (up to date); non-zero = new commits upstream.
    res = _git("merge-base", "--is-ancestor", remote_head, "HEAD", check=False, timeout=5)
    return res.returncode != 0


def check_upstream(force: bool = False, session_key: str = "") -> str | None:
    """Return a 1-line notice if upstream/main has newer commits than HEAD; fail-open on any error."""
    now = time.time()
    cache = _load_cache()
    try:
        remote_name = _upstream_remote()
        local_head = _out(_git("rev-parse", "HEAD", timeout=5))
        remote_head = str(cache.get("remote_head") or "")
        checked_at = float(cache.get("checked_at") or 0)
        if force or (now - checked_at > CHECK_TTL_SECONDS) or not remote_head:
            refs = _out(
                _git("ls-remote", remote_name, f"refs/heads/{REMOTE_BRANCH}", timeout=6)
            ).split()
            if refs:
                remote_head = refs[0]
            cache["checked_at"] = now
            cache["remote_head"] = remote_head
            cache["local_head"] = local_head
        if not remote_head or not _is_behind(remote_head):
            cache["local_head"] = local_head
            _save_cache(cache)
            return None
        if session_key:
            notified = cache.get("notified_sessions")
            if not isinstance(notified, list):
                notified = []
            tag = f"{session_key}:{remote_head[:12]}"
            if tag in notified:
                return None
            notified = (notified + [tag])[-50:]
            cache["notified_sessions"] = notified
        _save_cache(cache)
        return (
            f"[REA Upstream] Phát hiện bản mới trên upstream/{REMOTE_BRANCH} "
            f"(local `{local_head[:7]}` -> upstream `{remote_head[:7]}`). "
            "Hãy báo ngắn gọn cho người dùng và hỏi xem có muốn dùng skill `rea-upstream-sync` "
            "để cập nhật an toàn (bảo toàn AGENTS.md, CLAUDE.md, .claude/, _reference/) không."
        )
    except Exception:
        return None


def _backup_local_customizations() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = BACKUP_ROOT / stamp
    dest.mkdir(parents=True, exist_ok=True)
    for rel in (
        "AGENTS.md",
        "CLAUDE.md",
        ".claude",
        ".codex/hooks.json",
        ".agents/hooks.json",
        ".agents/skills/rea-upstream-sync",
        "hooks/rea_upstream.py",
    ):
        src = ROOT / rel
        if not src.exists():
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True)
        else:
            shutil.copy2(src, target)
    return dest


def _merge_three_way(ours: bytes, base: bytes, theirs: bytes) -> tuple[bytes, int]:
    """Run git merge-file on LF-normalized bytes; return (merged_bytes, conflict_count)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        paths = []
        for label, payload in (
            ("local-setup-v2", ours.replace(b"\r\n", b"\n")),
            ("upstream-old", base.replace(b"\r\n", b"\n")),
            ("upstream-new", theirs.replace(b"\r\n", b"\n")),
        ):
            p = tmp_path / label
            p.write_bytes(payload)
            paths.append(str(p))
        res = subprocess.run(
            [
                "git",
                "merge-file",
                "-p",
                "-L",
                "local-setup-v2",
                "-L",
                "upstream-old",
                "-L",
                "upstream-new",
                *paths,
            ],
            capture_output=True,
            check=False,
        )
    if res.returncode < 0 or res.returncode > 127:
        raise RuntimeError(res.stderr.decode("utf-8", "replace").strip())
    return res.stdout, res.returncode


def upstream_status() -> dict:
    remote_name = _upstream_remote()
    _git("fetch", "--quiet", remote_name, REMOTE_BRANCH, timeout=120)
    local_head = _out(_git("rev-parse", "HEAD"))
    remote_ref = f"{remote_name}/{REMOTE_BRANCH}" if remote_name == "upstream" else "FETCH_HEAD"
    remote_head = _out(_git("rev-parse", remote_ref))
    commits = [
        line
        for line in _out(_git("log", "--oneline", f"{local_head}..{remote_head}")).splitlines()
        if line.strip()
    ]
    changed_files = [
        line
        for line in _out(_git("diff", "--name-only", f"{local_head}...{remote_head}")).splitlines()
        if line.strip()
    ]
    return {
        "up_to_date": len(commits) == 0,
        "remote": remote_name,
        "local_head": local_head,
        "remote_head": remote_head,
        "commit_count": len(commits),
        "commits": commits[:50],
        "changed_files": changed_files,
        "agents_md_changed_upstream": "AGENTS.md" in changed_files,
        "needs_npm_ci": "package-lock.json" in changed_files or "package.json" in changed_files,
        "needs_build": any(
            f.startswith(("src/", "scripts/", "bridge/", ".agents/skills/reverse-engineer-anything/"))
            for f in changed_files
        ),
    }


def sync_upstream() -> dict:
    dirty_lines = [
        line
        for line in _out(_git("status", "--porcelain", "--untracked-files=no")).splitlines()
        if line.strip() and line.split(maxsplit=1)[-1].strip() != "AGENTS.md"
    ]
    if dirty_lines:
        raise RuntimeError(
            "Working tree có file tracked ngoài AGENTS.md đang sửa dở; hãy commit/stash trước khi sync:\n"
            + "\n".join(dirty_lines)
        )

    backup_dir = _backup_local_customizations()
    info = upstream_status()
    if info["up_to_date"]:
        _save_cache(
            {
                "checked_at": time.time(),
                "local_head": info["local_head"],
                "remote_head": info["remote_head"],
                "notified_sessions": [],
            }
        )
        return {**info, "status": "already_up_to_date", "backup_dir": str(backup_dir)}

    local_head = info["local_head"]
    remote_head = info["remote_head"]
    agents_path = ROOT / "AGENTS.md"
    ours_bytes = agents_path.read_bytes() if agents_path.is_file() else b""
    base_bytes = _git("show", f"{local_head}:AGENTS.md").stdout
    theirs_bytes = _git("show", f"{remote_head}:AGENTS.md").stdout

    # Restore tracked AGENTS.md to local_head so git merge --ff-only succeeds cleanly.
    _git("checkout", "HEAD", "--", "AGENTS.md")
    try:
        _git("merge", "--ff-only", remote_head, timeout=120)
    except Exception:
        agents_path.write_bytes(ours_bytes)
        raise

    conflicts = 0
    upstream_diff_file = None
    if base_bytes.replace(b"\r\n", b"\n") == theirs_bytes.replace(b"\r\n", b"\n"):
        # Upstream did not touch AGENTS.md -> restore local Setup v2 AGENTS.md directly.
        agents_path.write_bytes(ours_bytes)
    else:
        diff_bytes = _git("diff", local_head, remote_head, "--", "AGENTS.md").stdout
        diff_path = backup_dir / "upstream-AGENTS.diff"
        diff_path.write_bytes(diff_bytes)
        upstream_diff_file = str(diff_path)
        merged, conflicts = _merge_three_way(ours_bytes, base_bytes, theirs_bytes)
        agents_path.write_bytes(merged)

    _save_cache(
        {
            "checked_at": time.time(),
            "local_head": remote_head,
            "remote_head": remote_head,
            "notified_sessions": [],
        }
    )
    return {
        **info,
        "status": "synced_with_conflicts" if conflicts else "synced",
        "agents_md_conflicts": conflicts,
        "upstream_agents_diff": upstream_diff_file,
        "backup_dir": str(backup_dir),
    }


def main(argv: list[str]) -> int:
    mode = (argv[0].lower() if argv else "check")
    raw = b""
    if mode in {"session-start", "pre-invocation"}:
        try:
            if sys.stdin and not sys.stdin.isatty():
                raw = sys.stdin.buffer.read()
            else:
                raw = b"{}"
        except OSError:
            raw = b"{}"
        relay = _worktree_script(Path.cwd())
        if relay is not None:
            res = subprocess.run([sys.executable, str(relay), *argv], input=raw, capture_output=True, check=False)
            sys.stdout.buffer.write(res.stdout)
            sys.stderr.buffer.write(res.stderr)
            return res.returncode

    payload = {}
    if raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                payload = parsed
        except ValueError:
            payload = {}

    if mode == "session-start":
        session_id = str(payload.get("session_id") or "")
        msg = check_upstream(force=False, session_key=session_id)
        out = (
            {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": msg}}
            if msg
            else {}
        )
        print(json.dumps(out, ensure_ascii=False))
        return 0

    if mode == "pre-invocation":
        conv_id = str(payload.get("conversationId") or payload.get("session_id") or "agy-session")
        msg = check_upstream(force=False, session_key=conv_id)
        out = {"injectSteps": [{"ephemeralMessage": msg}]} if msg else {}
        print(json.dumps(out, ensure_ascii=False))
        return 0

    if mode == "check":
        force = "--force" in argv[1:]
        msg = check_upstream(force=force)
        if msg:
            print(msg)
        elif "--verbose" in argv[1:]:
            print("UP_TO_DATE")
        return 0

    if mode == "status":
        print(json.dumps(upstream_status(), indent=2, ensure_ascii=False))
        return 0

    if mode == "sync":
        result = sync_upstream()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    for _s in (sys.stdout, sys.stderr):
        if hasattr(_s, "reconfigure"):
            _s.reconfigure(encoding="utf-8")
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        if sys.argv[1:2] and sys.argv[1].lower() in {"session-start", "pre-invocation"}:
            # Fail-open in lifecycle hooks so network/git glitches never block an agent session.
            print("{}")
            raise SystemExit(0)
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
