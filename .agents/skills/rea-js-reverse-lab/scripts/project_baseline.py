#!/usr/bin/env python3
# Source: https://github.com/WhiteNightShadow/hello_js_reverse_skill@9fb8e001d68a5e0b83f12285950f667f219623a9 | License: CC0-1.0
"""Create and check portable project baselines without storing source or credentials."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

VERSION = "1.0.0"


def _is_within(path: Path, root: Path) -> bool:
    norm_path = Path(os.path.normcase(str(path.resolve())))
    norm_root = Path(os.path.normcase(str(root.resolve())))
    return norm_path.is_relative_to(norm_root)


def _relative_posix(path: Path, root: Path) -> str:
    norm_path = Path(os.path.normcase(str(path.resolve())))
    norm_root = Path(os.path.normcase(str(root.resolve())))
    rel_parts = norm_path.relative_to(norm_root).parts
    orig_parts = path.resolve().parts[-len(rel_parts) :] if rel_parts else ()
    return Path(*orig_parts).as_posix() if orig_parts else "."


def snapshot(root: Path, files: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in files:
        path = (root / name).resolve()
        if not _is_within(path, root):
            raise ValueError("baseline files must stay inside the project root")
        key = _relative_posix(path, root)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        result[key] = digest.hexdigest()
    return result


def current_skill_version() -> str:
    skill_md = Path(__file__).resolve().parents[1] / "SKILL.md"
    if not skill_md.exists():
        return VERSION
    text = skill_md.read_text(encoding="utf-8")
    match = re.search(r'^\s*(?:>\s*)?version:\s*"?([^"\r\n]+)"?', text, re.M)
    return match.group(1).strip() if match else VERSION


def parse_identities(items: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        name, separator, value = item.partition("=")
        if not separator or not name or not value:
            raise ValueError("--identity expects name=value")
        result[name] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Record SDK/signer/fixture hashes for upgrade reviews")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("action", choices=["create", "check"])
    parser.add_argument("--root", default=".")
    parser.add_argument("--manifest", default="project-manifest.json")
    parser.add_argument("--files", nargs="+")
    parser.add_argument("--skill-version", default=current_skill_version())
    parser.add_argument("--mcp-version", default="unknown")
    parser.add_argument("--browser-version", default="unknown")
    parser.add_argument(
        "--identity",
        action="append",
        default=[],
        help="name=value, for example sdk_public=1.2.3 or impl_revision=v2",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    manifest = (root / args.manifest).resolve()
    if not _is_within(manifest, root):
        raise ValueError("manifest must stay inside project root")

    if args.action == "create":
        if not args.files:
            parser.error("create requires --files")
        data: dict[str, object] = {
            "schema_version": 1,
            "versions": {
                "skill": args.skill_version,
                "mcp": args.mcp_version,
                "browser": args.browser_version,
            },
            "files": snapshot(root, args.files),
        }
        identities = parse_identities(args.identity)
        if identities:
            data["identities"] = identities
        files_map = data["files"]
        if isinstance(files_map, dict) and _relative_posix(manifest, root) in files_map:
            raise ValueError("manifest cannot hash itself")
        manifest.parent.mkdir(parents=True, exist_ok=True)
        with manifest.open("x", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
        print(
            json.dumps(
                {
                    "status": "created",
                    "manifest": str(manifest),
                    "files": len(files_map) if isinstance(files_map, dict) else 0,
                }
            )
        )
        return 0

    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("unsupported baseline schema")
    changed: list[str] = []
    missing: list[str] = []
    for name, expected in data["files"].items():
        try:
            if snapshot(root, [name])[name] != expected:
                changed.append(name)
        except FileNotFoundError:
            missing.append(name)
    print(
        json.dumps(
            {
                "status": "changed" if changed or missing else "unchanged",
                "changed": changed,
                "missing": missing,
                "versions": data.get("versions", {}),
                "identities": data.get("identities", {}),
            },
            ensure_ascii=False,
        )
    )
    return 1 if changed or missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
