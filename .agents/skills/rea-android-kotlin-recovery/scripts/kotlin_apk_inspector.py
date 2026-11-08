#!/usr/bin/env python3
# Source: https://github.com/SimoneAvogadro/android-reverse-engineering-skill@0c7cf89830993df7dfc178498f69952262808bea | License: Apache-2.0
"""Inspect Android APK/XAPK containers, recover R8/ProGuard Kotlin class names, and extract API endpoints.

Subcommands:
  fingerprint     Identify frameworks, ABIs, DEX count, and Kotlin metadata in an APK/XAPK
  recover-kotlin  Recover original Kotlin FQNs from @Metadata and @DebugMetadata in JADX output
  lookup          Query recovered Kotlin mappings or grep JADX sources with deobfuscated FQN labels
  find-api        Scan JADX sources for Retrofit, OkHttp, Ktor, and hardcoded HTTP/WS URLs
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

VERSION = "1.0.0"

PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", re.M)
CLASS_DECL_RE = re.compile(
    r"^\s*(?:public\s+|protected\s+|private\s+|final\s+|abstract\s+|static\s+)*"
    r"(?:class|interface|enum)\s+([A-Za-z0-9_$]+)",
    re.M,
)
DEBUG_META_RE = re.compile(
    r'@DebugMetadata\s*\([^)]*?\bc\s*=\s*"([^"]+)"[^)]*?\bf\s*=\s*"([^"]*)"',
    re.S,
)
METADATA_BLOCK_RE = re.compile(r"@Metadata\s*\((.*?)\)\s*(?:@|\bpublic\b|\b final\b|\bclass\b|\binterface\b|\benum\b)", re.S)
D2_FIRST_DESC_RE = re.compile(r'\bd2\s*=\s*\{\s*"L([^";]+);"')

RETROFIT_RE = re.compile(r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\([^)]*\)|\.baseUrl\s*\([^)]*\)')
OKHTTP_RE = re.compile(r"\b(?:Request\.Builder|HttpUrl\.parse|addHeader|addInterceptor|CertificatePinner|okhttp3)\b")
KTOR_RE = re.compile(r"\b(?:io\.ktor|HttpClient)\b")
URL_RE = re.compile(r'\b(?:https?|wss?)://[^\s"\'<>)+]+')


def _inspect_zip_entries(zf: zipfile.ZipFile) -> tuple[list[str], int, bool]:
    names = zf.namelist()
    dex_names = [n for n in names if re.match(r"^(?:.*/)?classes\d*\.dex$", n)]
    has_kotlin = any(n.startswith("kotlin/") or n.endswith(".kotlin_builtins") for n in names)
    for dex_name in dex_names:
        try:
            data = zf.read(dex_name)
            if b"Lkotlin/Metadata;" in data or b"Lkotlin/coroutines/jvm/internal/DebugMetadata;" in data:
                has_kotlin = True
                break
        except Exception:
            continue
    return names, len(dex_names), has_kotlin


def cmd_fingerprint(args: argparse.Namespace) -> int:
    apk_path = Path(args.apk_path).resolve()
    if not apk_path.exists():
        print(f"error: file not found: {apk_path}", file=sys.stderr)
        return 2

    all_entries: list[str] = []
    split_apks: list[str] = []
    dex_count = 0
    has_kotlin = False

    with zipfile.ZipFile(apk_path, "r") as outer:
        outer_names, outer_dex, outer_kt = _inspect_zip_entries(outer)
        all_entries.extend(outer_names)
        dex_count += outer_dex
        has_kotlin = has_kotlin or outer_kt

        for name in outer_names:
            if name.lower().endswith(".apk"):
                split_apks.append(name)
                try:
                    nested_bytes = outer.read(name)
                    with zipfile.ZipFile(io.BytesIO(nested_bytes), "r") as inner:
                        in_names, in_dex, in_kt = _inspect_zip_entries(inner)
                        all_entries.extend(in_names)
                        dex_count += in_dex
                        has_kotlin = has_kotlin or in_kt
                except Exception:
                    continue

    abis = sorted(
        {
            parts[1]
            for entry in all_entries
            if (parts := entry.split("/")) and len(parts) >= 3 and parts[0] == "lib" and parts[-1].endswith(".so")
        }
    )

    frameworks: list[str] = []
    if any("libflutter.so" in e or "flutter_assets/" in e for e in all_entries):
        frameworks.append("flutter")
    if any("libreactnativejni.so" in e or "libhermes.so" in e or "index.android.bundle" in e for e in all_entries):
        frameworks.append("react_native")
    if any("libil2cpp.so" in e or "libunity.so" in e for e in all_entries):
        frameworks.append("unity")
    if any("libmonodroid.so" in e or "assemblies/" in e for e in all_entries):
        frameworks.append("xamarin")
    if any("assets/www/cordova.js" in e or "capacitor.config.json" in e for e in all_entries):
        frameworks.append("cordova_capacitor")
    if has_kotlin:
        frameworks.append("kotlin")
    if not frameworks:
        frameworks.append("native_android")

    container_type = "xapk_or_bundle" if split_apks or apk_path.suffix.lower() in (".xapk", ".apks", ".aab") else "apk"
    result = {
        "path": str(apk_path),
        "container_type": container_type,
        "primary_framework": frameworks[0],
        "frameworks_detected": frameworks,
        "abis": abis,
        "split_apks": split_apks,
        "has_kotlin_metadata": has_kotlin,
        "dex_count": dex_count,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Path: {result['path']}")
        print(f"Container: {result['container_type']} (DEX count: {dex_count})")
        print(f"Frameworks: {', '.join(frameworks)}")
        print(f"ABIs: {', '.join(abis) if abis else 'none'}")
        print(f"Kotlin metadata: {has_kotlin}")
    return 0


def _extract_obf_fqn(text: str, java_file: Path, sources_dir: Path) -> str:
    pkg_match = PACKAGE_RE.search(text)
    cls_match = CLASS_DECL_RE.search(text)
    if pkg_match and cls_match:
        return f"{pkg_match.group(1)}.{cls_match.group(1)}"
    try:
        rel = java_file.relative_to(sources_dir).with_suffix("")
        parts = list(rel.parts)
        if parts and parts[0] == "sources":
            parts = parts[1:]
        return ".".join(parts)
    except ValueError:
        return java_file.stem


def cmd_recover_kotlin(args: argparse.Namespace) -> int:
    sources_dir = Path(args.sources_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    if not sources_dir.exists():
        print(f"error: sources directory not found: {sources_dir}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str, str]] = []
    mapping_dict: dict[str, str] = {}
    pkg_counter: Counter[str] = Counter()

    for java_file in sorted(sources_dir.rglob("*.java")):
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if "@Metadata" not in text and "@DebugMetadata" not in text:
            continue

        obf_fqn = _extract_obf_fqn(text, java_file, sources_dir)
        real_fqn: str | None = None

        for m_block in METADATA_BLOCK_RE.finditer(text):
            d2_m = D2_FIRST_DESC_RE.search(m_block.group(1))
            if d2_m:
                candidate = d2_m.group(1).replace("/", ".").strip()
                if candidate and "." in candidate:
                    real_fqn = candidate
                    break

        if not real_fqn:
            dbg_m = DEBUG_META_RE.search(text)
            if dbg_m:
                candidate = dbg_m.group(1).replace("/", ".").strip()
                if candidate:
                    real_fqn = candidate

        if real_fqn:
            rel_path = java_file.relative_to(sources_dir).as_posix()
            rows.append((obf_fqn, real_fqn, rel_path))
            mapping_dict[obf_fqn] = real_fqn
            pkg = real_fqn.rsplit(".", 1)[0] if "." in real_fqn else "(default)"
            pkg_counter[pkg] += 1

    tsv_path = out_dir / "mapping.tsv"
    json_path = out_dir / "mapping.json"
    pkgs_path = out_dir / "packages.txt"

    tsv_lines = ["obf_fqn\treal_fqn\tfile"] + [f"{o}\t{r}\t{f}" for o, r, f in rows]
    tsv_path.write_text("\n".join(tsv_lines) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps(mapping_dict, ensure_ascii=False, indent=2), encoding="utf-8")
    pkg_lines = [f"{count:5d}  {pkg}" for pkg, count in pkg_counter.most_common()]
    pkgs_path.write_text("\n".join(pkg_lines) + ("\n" if pkg_lines else ""), encoding="utf-8")

    summary = {
        "recovered_classes": len(rows),
        "unique_real_fqns": len(set(mapping_dict.values())),
        "packages_count": len(pkg_counter),
        "mapping_tsv": str(tsv_path),
        "mapping_json": str(json_path),
        "packages_txt": str(pkgs_path),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def _load_tsv_rows(mapping_dir: Path) -> list[tuple[str, str, str]]:
    tsv_path = mapping_dir / "mapping.tsv"
    if not tsv_path.exists():
        return []
    rows: list[tuple[str, str, str]] = []
    for idx, line in enumerate(tsv_path.read_text(encoding="utf-8").splitlines()):
        if idx == 0 and line.startswith("obf_fqn\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            rows.append((parts[0], parts[1], parts[2]))
    return rows


def cmd_lookup(args: argparse.Namespace) -> int:
    mapping_dir = Path(args.mapping_dir).resolve()
    rows = _load_tsv_rows(mapping_dir)
    if not rows:
        print(f"error: no mapping.tsv rows found in {mapping_dir}", file=sys.stderr)
        return 2

    if args.obf:
        matches = [r for r in rows if r[0] == args.obf]
    elif args.pkg:
        prefix = args.pkg.rstrip(".")
        matches = [r for r in rows if r[1].startswith(prefix + ".") or r[1] == prefix]
    elif args.grep:
        if not args.sources:
            print("error: --grep requires --sources <sources_dir>", file=sys.stderr)
            return 2
        sources_dir = Path(args.sources).resolve()
        file_to_entry = {r[2]: (r[0], r[1]) for r in rows}
        regex = re.compile(args.grep)
        hit_count = 0
        for java_file in sorted(sources_dir.rglob("*.java")):
            rel = java_file.relative_to(sources_dir).as_posix()
            obf_fqn, real_fqn = file_to_entry.get(rel, (rel, "unmapped"))
            try:
                lines = java_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            for line_no, line in enumerate(lines, start=1):
                if regex.search(line):
                    print(f"[{real_fqn} ({obf_fqn})] {rel}:{line_no}: {line.strip()}")
                    hit_count += 1
        return 0 if hit_count > 0 else 1
    elif args.query:
        q = args.query.lower()
        matches = [r for r in rows if q in r[0].lower() or q in r[1].lower() or q in r[2].lower()]
    else:
        matches = rows[:50]

    for obf_fqn, real_fqn, rel_file in matches:
        print(f"{obf_fqn}\t->\t{real_fqn}\t({rel_file})")
    return 0 if matches else 1


def cmd_find_api(args: argparse.Namespace) -> int:
    sources_dir = Path(args.sources_dir).resolve()
    if not sources_dir.exists():
        print(f"error: sources directory not found: {sources_dir}", file=sys.stderr)
        return 2

    scan_all = args.all or not (args.retrofit or args.okhttp or args.ktor or args.urls)
    findings: dict[str, list[dict[str, object]]] = {
        "retrofit": [],
        "okhttp": [],
        "ktor": [],
        "urls": [],
    }

    for src_file in sorted(list(sources_dir.rglob("*.java")) + list(sources_dir.rglob("*.kt"))):
        rel = src_file.relative_to(sources_dir).as_posix()
        try:
            lines = src_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if (scan_all or args.retrofit) and RETROFIT_RE.search(stripped):
                findings["retrofit"].append({"file": rel, "line": line_no, "snippet": stripped})
            if (scan_all or args.okhttp) and OKHTTP_RE.search(stripped):
                findings["okhttp"].append({"file": rel, "line": line_no, "snippet": stripped})
            if (scan_all or args.ktor) and KTOR_RE.search(stripped):
                findings["ktor"].append({"file": rel, "line": line_no, "snippet": stripped})
            if (scan_all or args.urls) and URL_RE.search(stripped):
                for m in URL_RE.finditer(stripped):
                    findings["urls"].append({"file": rel, "line": line_no, "url": m.group(0)})

    if args.json:
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        for category, items in findings.items():
            print(f"=== {category.upper()} ({len(items)}) ===")
            for item in items[:50]:
                print(f"  {item['file']}:{item['line']} -> {item.get('url') or item.get('snippet')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_fp = sub.add_parser("fingerprint", help="Fingerprint an APK or XAPK archive")
    p_fp.add_argument("apk_path")
    p_fp.add_argument("--json", action="store_true")
    p_fp.set_defaults(run=cmd_fingerprint)

    p_rec = sub.add_parser("recover-kotlin", help="Recover Kotlin class names from JADX sources")
    p_rec.add_argument("sources_dir")
    p_rec.add_argument("out_dir")
    p_rec.set_defaults(run=cmd_recover_kotlin)

    p_lk = sub.add_parser("lookup", help="Query recovered Kotlin class mappings")
    p_lk.add_argument("mapping_dir")
    p_lk.add_argument("query", nargs="?")
    p_lk.add_argument("-o", "--obf", help="exact obfuscated FQN")
    p_lk.add_argument("-p", "--pkg", help="original package prefix")
    p_lk.add_argument("--grep", help="regex to search across JADX Java sources")
    p_lk.add_argument("--sources", help="JADX sources root for --grep")
    p_lk.set_defaults(run=cmd_lookup)

    p_api = sub.add_parser("find-api", help="Extract Retrofit, OkHttp, Ktor, and URL endpoints")
    p_api.add_argument("sources_dir")
    p_api.add_argument("--retrofit", action="store_true")
    p_api.add_argument("--okhttp", action="store_true")
    p_api.add_argument("--ktor", action="store_true")
    p_api.add_argument("--urls", action="store_true")
    p_api.add_argument("--all", action="store_true")
    p_api.add_argument("--json", action="store_true")
    p_api.set_defaults(run=cmd_find_api)

    args = parser.parse_args()
    return int(args.run(args))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
