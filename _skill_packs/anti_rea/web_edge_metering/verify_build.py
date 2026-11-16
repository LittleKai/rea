#!/usr/bin/env python3
"""Streaming production build artifact verifier (source maps, headers, renamed maps).

Source: https://github.com/dankezo/antiRea@bacba71ff082245913a8afed73bb374131d5e446
License: MIT (Copyright (c) 2026 dankezo)

Upgrades thankezo/antiRea scripts/verify-build.py:
- Streams ALL JS/CSS/MJS/CJS/HTML files in 1 MiB chunks with a 4096 B carry buffer so
  sourceMappingURL directives straddling chunk boundaries are caught regardless of size.
- Detects public .map, .map.gz, and .map.br files.
- Detects SourceMap: response header declarations in _headers files.
- Requires "version": 3 alongside "mappings" and "sources" for renamed .json source maps
  to eliminate false positives on ordinary JSON data/schema files.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

VERIFY_BUILD_SCHEMA = "anti-rea.verify-build/v1"
CHUNK_BYTES = 1024 * 1024
CARRY_BYTES = 4096
FULL_JSON_PARSE_LIMIT = 10 * 1024 * 1024
MAX_FILES = 50_000

MAP_FILENAME_SUFFIXES = (".map", ".map.gz", ".map.br")
SCANNABLE_TEXT_EXTENSIONS = frozenset({".js", ".mjs", ".cjs", ".css", ".html", ".htm"})
HEADERS_SOURCEMAP_RE = re.compile(r"(?im)^\s*sourcemap\s*:")
VERSION3_BYTES_RE = re.compile(rb'"version"\s*:\s*3\b')
SOURCEMAP_URL_BYTES_RE = re.compile(
    rb"(?://[#@]|/\*[#@])[ \t]{0,64}sourceMappingURL[ \t]{0,64}=[ \t]{0,64}([^\s*\"'<>]{1,2048})",
    re.I,
)


def _chunked_contains(path: Path, needles: list[bytes], *, case_insensitive: bool = False) -> set[bytes]:
    found: set[bytes] = set()
    targets = [n.lower() if case_insensitive else n for n in needles]
    carry = b""
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_BYTES)
            if not chunk:
                break
            buf = carry + chunk
            hay = buf.lower() if case_insensitive else buf
            for orig, needle in zip(needles, targets):
                if orig not in found and needle in hay:
                    found.add(orig)
            if len(found) == len(needles):
                break
            carry = buf[-CARRY_BYTES:]
    return found


def scan_file_for_sourcemap_refs(path: Path) -> tuple[list[str], list[str]]:
    """Stream `path` in 1 MiB chunks (+ 4096 B carry) and return (kinds, extracted_refs).

    `kinds` contains any of `'inline'` or `'external'`.
    `extracted_refs` contains up to 8 matched `sourceMappingURL=...` targets.
    """
    kinds: list[str] = []
    refs: list[str] = []
    carry = b""
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_BYTES)
            eof = len(chunk) == 0
            buf = carry if eof else (carry + chunk)
            if not buf:
                break
            for m in SOURCEMAP_URL_BYTES_RE.finditer(buf):
                if not eof and m.end() == len(buf):
                    continue
                raw_target = m.group(1)
                target_str = raw_target.decode("utf-8", errors="replace").strip()
                kind = "inline" if target_str.lower().startswith("data:") else "external"
                if kind not in kinds:
                    kinds.append(kind)
                if target_str and target_str not in refs and len(refs) < 8:
                    refs.append(target_str)
            if eof:
                break
            carry = buf[-CARRY_BYTES:]
    return kinds, refs


def _is_renamed_sourcemap_json(path: Path, size: int) -> bool:
    if size <= FULL_JSON_PARSE_LIMIT:
        try:
            obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return False
        if not isinstance(obj, dict):
            return False
        return (
            obj.get("version") == 3
            and isinstance(obj.get("mappings"), str)
            and isinstance(obj.get("sources"), list)
        )
    # Streaming check for >10 MiB JSON files: require "mappings", "sources", and "version": 3
    hits = _chunked_contains(path, [b'"mappings"', b'"sources"', b'"version"'], case_insensitive=False)
    if len(hits) < 3:
        return False
    carry = b""
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_BYTES)
            if not chunk:
                break
            buf = carry + chunk
            if VERSION3_BYTES_RE.search(buf):
                return True
            carry = buf[-CARRY_BYTES:]
    return False


def _finding(path: str, severity: str, signal: str, rule: str) -> dict[str, str]:
    return {"path": path, "severity": severity, "signal": signal, "rule": rule}


def verify_build_directory(root: Path) -> dict[str, Any]:
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Deployment asset directory not found: {root}")

    results: list[dict[str, str]] = []
    count = 0
    capped = False

    for f in sorted(root.rglob("*")):
        try:
            if f.is_symlink() or not f.is_file():
                continue
            size = f.stat().st_size
        except OSError:
            continue
        count += 1
        if count > MAX_FILES:
            capped = True
            break

        rel = f.relative_to(root).as_posix()
        name_lower = f.name.lower()
        suffix_lower = f.suffix.lower()

        if name_lower.endswith(MAP_FILENAME_SUFFIXES):
            sig = "compressed-source-map" if name_lower.endswith((".map.gz", ".map.br")) else "public-source-map"
            results.append(_finding(rel, "high", sig, "no-sourcemap-file"))
        elif name_lower == "_headers":
            if size <= FULL_JSON_PARSE_LIMIT:
                text = f.read_text(encoding="utf-8", errors="replace")
                matched = HEADERS_SOURCEMAP_RE.search(text) is not None
            else:
                matched = bool(_chunked_contains(f, [b"sourcemap:"], case_insensitive=True))
            if matched:
                results.append(_finding(rel, "high", "sourcemap-response-header", "no-sourcemap-header"))
        elif suffix_lower == ".json":
            if _is_renamed_sourcemap_json(f, size):
                results.append(_finding(rel, "high", "renamed-source-map", "no-renamed-sourcemap"))
        elif suffix_lower in SCANNABLE_TEXT_EXTENSIONS:
            kinds, _refs = scan_file_for_sourcemap_refs(f)
            for kind in kinds:
                if kind == "inline":
                    results.append(_finding(rel, "high", "inline-source-map", "no-inline-sourcemap"))
                else:
                    results.append(_finding(rel, "high", "external-source-map", "no-external-sourcemap-ref"))

    if capped:
        results.append(_finding(".", "high", "coverage-incomplete", "scan-file-cap-exceeded"))

    return {
        "schema": VERIFY_BUILD_SCHEMA,
        "build_dir": str(root.resolve()),
        "scanned_files": count,
        "capped": capped,
        "finding_count": len(results),
        "findings": [
            {
                "code": f"VB-{item['rule'].upper()}",
                "severity": item["severity"],
                "tier": "Tier 1 / Tier 2",
                "path": item["path"],
                "signal": item["signal"],
                "rule": item["rule"],
                "title": f"{item['signal']} detected in {item['path']}",
                "evidence": f"{item['path']} ({item['rule']})",
                "remediation": "Strip sourceMappingURL directives, remove *.map/*.map.gz/*.map.br and renamed map JSONs, and omit SourceMap headers in public deployments.",
            }
            for item in results
        ],
    }


def _cli_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify production build artifacts for source-map leaks.")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = verify_build_directory(args.directory)
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1
    sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if args.strict and report["finding_count"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
