#!/usr/bin/env python3
"""Unified Anti-REA orchestrator and source-exposure auditor (anti-rea v2.0.0).

Orchestrates both built-in Web/GLSL/Sec-Fetch audits (`audit-dir`, `check-url`)
and dormant capability packs under `_skill_packs/anti_rea/` (`packs`, `lint-gates`,
`verify-build`, `scan-score`, `gen-config`, `harden-py`, `inspect-apk`) so agent
startup context stays at a single active SKILL.md frontmatter.

Zero external dependencies. Compatible with locked Conda Python 3.10 / 3.12.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def _preparse_packs_dir(argv: list[str]) -> Path | None:
    for idx, tok in enumerate(argv):
        if tok == "--":
            break
        if tok == "--packs-dir" and idx + 1 < len(argv):
            return Path(argv[idx + 1])
        if tok.startswith("--packs-dir="):
            val = tok.split("=", 1)[1]
            if val:
                return Path(val)
    env_dir = os.environ.get("ANTI_REA_PACKS_DIR")
    return Path(env_dir) if env_dir else None


def _resolve_packs_dir_candidate(raw_dir: Path) -> Path:
    resolved = raw_dir.resolve()
    if (resolved / "pack_registry.json").is_file():
        return resolved
    if (resolved / "anti_rea" / "pack_registry.json").is_file():
        return resolved / "anti_rea"
    if (resolved / "_skill_packs" / "anti_rea" / "pack_registry.json").is_file():
        return resolved / "_skill_packs" / "anti_rea"
    return resolved


def _discover_repo_root(explicit_packs_dir: Path | None = None) -> Path:
    if explicit_packs_dir is not None:
        cand_dir = _resolve_packs_dir_candidate(explicit_packs_dir)
        if (
            cand_dir.name == "anti_rea"
            and cand_dir.parent.name == "_skill_packs"
            and (cand_dir / "pack_registry.json").is_file()
        ):
            return cand_dir.parents[1]
    here = Path(__file__).resolve()
    for base in (*here.parents, Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if (base / "_skill_packs" / "anti_rea" / "pack_registry.json").is_file():
            return base
    return here.parents[4]


_EARLY_PACKS_DIR = _preparse_packs_dir(sys.argv[1:])
_DEFAULT_REPO_ROOT = _discover_repo_root(_EARLY_PACKS_DIR)
if str(_DEFAULT_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEFAULT_REPO_ROOT))

try:
    import _skill_packs.anti_rea as _anti_rea_pkg  # noqa: E402
except ModuleNotFoundError:
    if _EARLY_PACKS_DIR is None:
        raise
    import types

    _EARLY_PACKS_BOOT = _resolve_packs_dir_candidate(_EARLY_PACKS_DIR)
    _sp_root = sys.modules.get("_skill_packs")
    if _sp_root is None:
        _sp_root = types.ModuleType("_skill_packs")
        _sp_root.__path__ = [str(_EARLY_PACKS_BOOT.parent)]
        sys.modules["_skill_packs"] = _sp_root
    _anti_rea_pkg = types.ModuleType("_skill_packs.anti_rea")
    _anti_rea_pkg.__path__ = [str(_EARLY_PACKS_BOOT)]
    setattr(_sp_root, "anti_rea", _anti_rea_pkg)
    sys.modules["_skill_packs.anti_rea"] = _anti_rea_pkg

if _EARLY_PACKS_DIR is not None:
    _EARLY_PACKS_RESOLVED = _resolve_packs_dir_candidate(_EARLY_PACKS_DIR)
    if _EARLY_PACKS_RESOLVED.is_dir() and str(_EARLY_PACKS_RESOLVED) not in _anti_rea_pkg.__path__:
        _anti_rea_pkg.__path__.insert(0, str(_EARLY_PACKS_RESOLVED))

from _skill_packs.anti_rea.apk_exposure_inspector.inspect_apk import admit_and_inspect_apk  # noqa: E402
from _skill_packs.anti_rea.bla_counter_rea.packaging_gates import run_packaging_gates  # noqa: E402
from _skill_packs.anti_rea.static_hardener_configs.antirea_core import (  # noqa: E402
    configs as antirea_configs,
    platforms as antirea_platforms,
    report as antirea_report,
)
from _skill_packs.anti_rea.static_hardener_configs.antirea_core.analyzers import (  # noqa: E402
    scan_tree as antirea_scan_tree,
)
from _skill_packs.anti_rea.static_hardener_configs.antirea_core.hardeners import (  # noqa: E402
    harden_tree as antirea_harden_tree,
)
from _skill_packs.anti_rea.web_edge_metering.verify_build import (  # noqa: E402
    scan_file_for_sourcemap_refs,
    verify_build_directory,
)

SKILL_VERSION = "2.0.0"
MAX_LIVE_REQUESTS = 8
MAX_INMEMORY_BUNDLE_BYTES = 8 * 1024 * 1024

STANDARD_WINDOW_PASSTHROUGH = frozenset(
    {
        "location",
        "document",
        "navigator",
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "crypto",
        "performance",
        "console",
        "history",
        "parent",
        "top",
        "frames",
        "self",
        "window",
        "globalThis",
        "devicePixelRatio",
        "innerWidth",
        "innerHeight",
        "outerWidth",
        "outerHeight",
        "MeshoptDecoder",
        "Mediabunny",
    }
)

DEFAULT_COMMERCIAL_PROBES = (
    "isPro",
    "isProActive",
    "proActive",
    "isProUnlocked",
    "checkProFeatureAccess",
    "shouldWatermarkExport",
    "licenseToken",
    "singleExportCredits",
)

GLSL_DECL_RE = re.compile(
    r"\b(?:uniform|varying|in|out)\s+(?:highp\s+|mediump\s+|lowp\s+)?"
    r"(?:vec[234]|ivec[234]|uvec[234]|mat[234]|float|int|sampler2D\w*|samplerCube\w*)\s+[A-Za-z_]\w*"
)
INTERNAL_PATH_RE = re.compile(
    r"(?:design-mcp/[A-Za-z0-9._/-]+|[A-Za-z]:\\[Uu]sers\\[^\"'\s]+|/Users/[^\"'\s]+|/home/[^\"'\s]+)"
)
IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{1,63}$")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file_stream(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_finding(
    code: str,
    severity: str,
    title: str,
    evidence: str,
    remediation: str,
    tier: str,
) -> dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "tier": tier,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
    }


def _decode_lumi_like_xor_table(js_text: str) -> dict[str, Any] | None:
    """Detect Base64 string tables paired with simple index-seeded XOR decoders."""
    m = re.search(r'=\s*(\[\s*"[A-Za-z0-9+/=]{2,}"(?:\s*,\s*"[A-Za-z0-9+/=]*"){15,}\s*\])', js_text)
    if not m:
        return None
    try:
        entries: list[str] = json.loads(m.group(1))
    except ValueError:
        return None

    ident_hits = 0
    shader_hits = 0
    sample_idents: list[str] = []
    for idx, b64 in enumerate(entries):
        try:
            raw = base64.b64decode(b64)
        except ValueError:
            continue
        key = ((idx + 1) * 0x45D9F3B) & 0xFF or 0x5A
        dec_bytes = bytes(b ^ ((key + ((i * 17) & 0xFF)) & 0xFF) for i, b in enumerate(raw))
        try:
            dec = dec_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "#version" in dec or "gl_Position" in dec or "void main" in dec:
            shader_hits += 1
        elif IDENT_RE.match(dec):
            ident_hits += 1
            if len(sample_idents) < 16:
                sample_idents.append(dec)

    return {
        "total_entries": len(entries),
        "identifier_entries": ident_hits,
        "shader_entries": shader_hits,
        "sample_identifiers": sample_idents,
    }


def _audit_source_glsl_templates(source_dir: Path) -> dict[str, Any]:
    encoded_like = 0
    skipped_interpolation: list[str] = []
    skipped_marker: list[str] = []
    for js_file in sorted(source_dir.rglob("*.js")):
        if "node_modules" in js_file.parts or "vendor" in js_file.parts:
            continue
        text = js_file.read_text(encoding="utf-8", errors="replace")
        rel = js_file.relative_to(source_dir).as_posix()
        for m in re.finditer(r"`((?:\\.|[^`\\])*)`", text, re.S):
            body = m.group(1)
            is_glsl = any(
                k in body
                for k in (
                    "#version 300 es",
                    "gl_Position",
                    "vFragColor",
                    "precision highp float",
                    "layout(location=",
                    "evalStageMaterial(",
                    "evalCrowdVertex(",
                )
            )
            if not is_glsl:
                continue
            if "${" in body:
                skipped_interpolation.append(f"{rel} ({len(body)} chars)")
            elif not any(k in body for k in ("#version", "gl_Position", "uBeamAperture10", "vFragColor")):
                skipped_marker.append(f"{rel} ({len(body)} chars)")
            else:
                encoded_like += 1
    return {
        "encoded_candidates": encoded_like,
        "skipped_due_to_interpolation": skipped_interpolation,
        "skipped_due_to_missing_marker": skipped_marker,
    }


def audit_directory(
    build_dir: Path,
    source_dir: Path | None = None,
    probe_symbols: list[str] | None = None,
) -> dict[str, Any]:
    if not build_dir.is_dir():
        raise FileNotFoundError(f"Build/public directory not found: {build_dir}")

    findings: list[dict[str, str]] = []
    ext_stats: dict[str, dict[str, int]] = {}
    total_files = 0
    total_bytes = 0

    map_files: list[str] = []
    sidecar_files: list[str] = []
    internal_path_leaks: list[str] = []
    sidecar_hash_leaks: list[str] = []
    raw_source_dirs: set[str] = set()
    js_bundles: list[Path] = []
    wrapped_glb_headers: list[str] = []
    raw_glb_files: list[str] = []
    kotlin_metadata_leaks: list[str] = []

    for root_str, _, files in os.walk(build_dir):
        root_path = Path(root_str)
        for fname in sorted(files):
            fpath = root_path / fname
            if fpath.is_symlink():
                continue
            rel = fpath.relative_to(build_dir).as_posix()
            sz = fpath.stat().st_size
            total_files += 1
            total_bytes += sz

            ext = (
                ".asset.json"
                if fname.endswith(".asset.json")
                else (".pack.js" if fname.endswith(".pack.js") else (fpath.suffix.lower() or "<none>"))
            )
            bucket = ext_stats.setdefault(ext, {"files": 0, "bytes": 0})
            bucket["files"] += 1
            bucket["bytes"] += sz

            if fname.endswith(".map"):
                map_files.append(rel)
            if fname.endswith(".asset.json") or fname in (".env", ".env.local", ".env.production", "tsconfig.json"):
                sidecar_files.append(rel)
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                for pm in INTERNAL_PATH_RE.findall(txt):
                    if len(internal_path_leaks) < 12:
                        internal_path_leaks.append(f"{rel}: {pm}")
                if '"glb_sha256"' in txt or '"source_sha256"' in txt:
                    if len(sidecar_hash_leaks) < 12:
                        sidecar_hash_leaks.append(rel)

            if rel.startswith(("src/", "js/core/", "js/modules/")):
                raw_source_dirs.add(rel.split("/")[0] + "/" + rel.split("/")[1])

            if fpath.suffix.lower() in (".js", ".mjs") and not fname.endswith(".pack.js"):
                js_bundles.append(fpath)

            if fpath.suffix.lower() == ".glb":
                head = fpath.read_bytes()[:12]
                if head[:4] == b"glTF":
                    raw_glb_files.append(rel)
                elif len(head) == 12:
                    wrapped_glb_headers.append(f"{rel} (magic={head[:6].decode('ascii', 'replace')})")

            if fpath.suffix.lower() in (".dex", ".java", ".kt"):
                raw_b = fpath.read_bytes()
                if b"Lkotlin/Metadata;" in raw_b or b"@Metadata" in raw_b or b"DebugMetadata" in raw_b:
                    if len(kotlin_metadata_leaks) < 10:
                        kotlin_metadata_leaks.append(rel)

    if map_files:
        findings.append(
            _make_finding(
                "F-SOURCEMAP-FILE",
                "high",
                "Source map (.map) files shipped in public build directory",
                f"{len(map_files)} file(s): {', '.join(map_files[:5])}",
                "Disable production source maps (sourcemap: false / hidden) and strip *.map before publishing.",
                "Tier 2",
            )
        )

    # Integrate streaming build verifier checks (.map.gz/.map.br, _headers SourceMap:, renamed .json maps)
    vb_report = verify_build_directory(build_dir)
    compressed_maps = [f["path"] for f in vb_report["findings"] if f["signal"] == "compressed-source-map"]
    header_maps = [f["path"] for f in vb_report["findings"] if f["signal"] == "sourcemap-response-header"]
    renamed_maps = [f["path"] for f in vb_report["findings"] if f["signal"] == "renamed-source-map"]

    if compressed_maps:
        findings.append(
            _make_finding(
                "F-COMPRESSED-SOURCEMAP",
                "high",
                "Compressed source map (.map.gz / .map.br) shipped in public build directory",
                f"{len(compressed_maps)} file(s): {', '.join(compressed_maps[:5])}",
                "Remove pre-compressed *.map.gz and *.map.br artifacts from public deployments.",
                "Tier 2",
            )
        )
    if header_maps:
        findings.append(
            _make_finding(
                "F-HEADERS-SOURCEMAP",
                "high",
                "Deployment _headers file advertises SourceMap response header",
                f"Detected in: {', '.join(header_maps[:5])}",
                "Remove public SourceMap: headers from CDN/Pages _headers configuration.",
                "Tier 1 / Tier 2",
            )
        )
    if renamed_maps:
        findings.append(
            _make_finding(
                "F-RENAMED-SOURCEMAP",
                "high",
                "Source map v3 payload shipped under renamed .json extension",
                f"{len(renamed_maps)} file(s): {', '.join(renamed_maps[:5])}",
                "Strip renamed source-map JSON files (version 3 + sources + mappings) from public output.",
                "Tier 2",
            )
        )

    if sidecar_files:
        detail = f"{len(sidecar_files)} sidecar/config file(s) (e.g. {', '.join(sidecar_files[:5])})"
        if internal_path_leaks:
            detail += f"; internal paths leaked: {', '.join(internal_path_leaks[:3])}"
        if sidecar_hash_leaks:
            detail += f"; raw asset SHA-256 exposed in {len(sidecar_hash_leaks)}+ file(s)"
        findings.append(
            _make_finding(
                "F-SIDECAR-METADATA",
                "medium" if not internal_path_leaks else "high",
                "Internal sidecar manifests or config files exposed in public output",
                detail,
                "Exclude *.asset.json, .env*, and build configs in sync/deploy scripts; keep only required OSS NOTICE/LICENSE files.",
                "Tier 2",
            )
        )

    if raw_source_dirs and any("min.js" in p.name for p in js_bundles):
        findings.append(
            _make_finding(
                "F-RAW-SOURCE-TREE",
                "high",
                "Unbundled source directories coexist alongside minified bundle",
                f"Directories present: {', '.join(sorted(raw_source_dirs))}",
                "Remove raw source directories from public output after bundling.",
                "Tier 2",
            )
        )

    probes = list(dict.fromkeys([*DEFAULT_COMMERCIAL_PROBES, *(probe_symbols or [])]))
    bundle_metrics: list[dict[str, Any]] = []

    for bpath in js_bundles:
        rel = bpath.relative_to(build_dir).as_posix()
        if "vendor/" in rel or bpath.name == "meshopt-decoder.js" or bpath.name == "demo-video.js":
            continue
        file_bytes = bpath.stat().st_size
        # Streaming 1 MiB + 4096 B carry-buffer scan runs on ALL bundles regardless of size
        smap_kinds, smap_refs = scan_file_for_sourcemap_refs(bpath)

        bounded_large = file_bytes > MAX_INMEMORY_BUNDLE_BYTES
        bounded_notice: str | None = None
        if bounded_large:
            bounded_notice = (
                f"In-memory regex heuristics bounded at {MAX_INMEMORY_BUNDLE_BYTES} bytes; "
                "streaming sourceMappingURL carry-buffer scan completed across full file."
            )
            glsl_decls: list[str] = []
            xor_info = None
            bind_vault_getters = 0
            matched_probes: list[str] = []
            allows_local_domain = False
            failopen_watermark = False
            inline_xorshift = False
            passthrough_leaks: list[str] = []
            bundle_sha256 = _sha256_file_stream(bpath)
        else:
            text = bpath.read_text(encoding="utf-8", errors="replace")
            bundle_sha256 = _sha256_bytes(text.encode("utf-8"))
            glsl_decls = GLSL_DECL_RE.findall(text)
            xor_info = _decode_lumi_like_xor_table(text)
            bind_vault_getters = len(re.findall(r"\(\)=>typeof\s+[A-Za-z_$][\w$]*!==['\"]undefined['\"]", text))
            matched_probes = [sym for sym in probes if re.search(rf"\b{re.escape(sym)}\b", text)]

            allows_local_domain = bool(
                re.search(r"(?:===\s*['\"]file:['\"]|['\"]file:['\"]\s*===)", text)
                and re.search(r"['\"]localhost['\"]", text)
                and "Unauthorized domain" in text
            )
            failopen_watermark = bool(
                re.search(r"if\s*\(\s*![A-Za-z_$][\w$]*\s*\)\s*return!1|if\s*\(\s*!hasToken\s*\)\s*return\s+false", text)
            )
            inline_xorshift = bool(re.search(r"<<\s*13[\s\S]{0,40}>>>\s*17[\s\S]{0,40}<<\s*5", text))

            passthrough_leaks = []
            for sm in re.finditer(r"new Set\(\[((?:\"[^\"]+\"|\'[^\']+\')(?:,(?:\"[^\"]+\"|\'[^\']+\'))*)\]\)", text):
                try:
                    raw_list = json.loads("[" + sm.group(1).replace("'", '"') + "]")
                except ValueError:
                    continue
                if "window" in raw_list and "document" in raw_list:
                    for k in raw_list:
                        if k not in STANDARD_WINDOW_PASSTHROUGH:
                            passthrough_leaks.append(k)

        metric_entry: dict[str, Any] = {
            "path": rel,
            "bytes": file_bytes,
            "sha256": bundle_sha256,
            "sourcemap_refs": smap_refs,
            "sourcemap_kinds": smap_kinds,
            "bounded_large_bundle": bounded_large,
            "bounded_large_bundle_notice": bounded_notice,
            "plaintext_glsl_declarations": len(glsl_decls),
            "sample_glsl_declarations": glsl_decls[:10],
            "bind_vault_getter_count": bind_vault_getters,
            "xor_table": xor_info,
            "matched_probe_symbols": matched_probes,
            "allows_local_or_file_domain": allows_local_domain,
            "failopen_offline_watermark": failopen_watermark,
            "inline_xorshift_asset_unwrapper": inline_xorshift,
            "custom_window_passthrough_keys": passthrough_leaks,
        }
        bundle_metrics.append(metric_entry)

        if smap_refs or smap_kinds:
            findings.append(
                _make_finding(
                    "F-SOURCEMAP-COMMENT",
                    "high",
                    f"sourceMappingURL directive present in {rel}",
                    f"References: {', '.join(smap_refs[:3]) or ', '.join(smap_kinds)}",
                    "Strip sourceMappingURL comments and omit source maps from public web artifacts.",
                    "Tier 2",
                )
            )

        if xor_info and xor_info["identifier_entries"] >= 20:
            findings.append(
                _make_finding(
                    "F-VAULT-SYMBOL-TABLE",
                    "high",
                    f"Self-documenting Core symbol table embedded in {rel}",
                    (
                        f"{xor_info['identifier_entries']}/{xor_info['total_entries']} string-table entries are plain "
                        f"identifiers (sample: {', '.join(xor_info['sample_identifiers'][:8])})"
                    ),
                    "Replace string-keyed __bindVault lookups with build-time randomized integer slot indices (__vaultSlot[id]) so zero core symbol names ship.",
                    "Tier 2",
                )
            )

        if glsl_decls:
            findings.append(
                _make_finding(
                    "F-GLSL-PLAINTEXT",
                    "medium",
                    f"Plaintext GLSL shader declarations survived encoding in {rel}",
                    f"{len(glsl_decls)} declaration(s), e.g. {', '.join(glsl_decls[:6])}",
                    "Encode template literal static quasis around ${...} expressions and match all GLSL helper blocks (precision/uniform/in/out), with a fail-closed build test.",
                    "Tier 2",
                )
            )

        if len(matched_probes) >= 3:
            findings.append(
                _make_finding(
                    "F-UNMANGLED-COMMERCIAL-PROPS",
                    "medium",
                    f"Unmangled commercial/gating property names in {rel}",
                    f"Matched {len(matched_probes)}/{len(probes)} probes: {', '.join(matched_probes[:10])}",
                    "Enable controlled mangleProps for internal module suffixes and commercial helpers while keeping explicit reserveProps for file/IPC schemas; move PRO exports to Backend.",
                    "Tier 2 / Tier 3",
                )
            )

        if allows_local_domain:
            findings.append(
                _make_finding(
                    "F-PERMISSIVE-DOMAIN-LOCK",
                    "high",
                    f"Production domain lock in {rel} allows offline file:// or localhost execution",
                    "Domain guard permits protocol 'file:' and/or hostname 'localhost' / '127.0.0.1'",
                    "Gate local/file origins behind an explicit --allow-local dev flag; restrict production builds strictly to owned domains and require window.top !== window.self when embedded.",
                    "Tier 2",
                )
            )

        if failopen_watermark:
            findings.append(
                _make_finding(
                    "F-FAILOPEN-WATERMARK",
                    "high",
                    f"Watermark / commercial check fails open when auth token is absent in {rel}",
                    "Detected `!token` -> `return false` branch in watermark predicate",
                    "Make production web builds fail-closed (`return !isProUnlocked()`) and move authoritative unwatermarked export generation to Backend.",
                    "Tier 2 / Tier 3",
                )
            )

        if inline_xorshift and wrapped_glb_headers:
            findings.append(
                _make_finding(
                    "F-INLINE-ASSET-SEED",
                    "medium",
                    "3D/binary assets use keyless PRNG wrapper with inline header seed",
                    f"{len(wrapped_glb_headers)} wrapped GLB(s) paired with inline xorshift32 unwrapper in {rel}",
                    "Encrypt premium assets at build time with WebCrypto AES-256-GCM using session-bound keys issued by authenticated Backend endpoints or short-lived presigned URLs.",
                    "Tier 4",
                )
            )

        if passthrough_leaks:
            findings.append(
                _make_finding(
                    "F-WINDOW-PASSTHROUGH",
                    "low",
                    f"Custom application globals exposed on real window via Proxy passthrough in {rel}",
                    f"Passthrough keys: {', '.join(passthrough_leaks)}",
                    "Remove custom pack/API globals from window passthrough and register lazy asset chunks through randomized per-build closures.",
                    "Tier 2",
                )
            )

    inspected_bundle_paths = {m["path"] for m in bundle_metrics}
    for vb_item in vb_report["findings"]:
        sig = vb_item.get("signal")
        vb_path = vb_item.get("path", "")
        if sig in ("inline-source-map", "external-source-map") and vb_path not in inspected_bundle_paths:
            findings.append(
                _make_finding(
                    "F-SOURCEMAP-COMMENT",
                    "high",
                    f"sourceMappingURL directive present in {vb_path}",
                    f"Signal: {sig}",
                    "Strip sourceMappingURL comments and omit source maps from public web artifacts.",
                    "Tier 2",
                )
            )
        elif sig == "coverage-incomplete":
            findings.append(
                _make_finding(
                    "F-SCAN-FILE-CAP",
                    "high",
                    "Build source-map scan hit the maximum file ceiling before completing",
                    vb_item.get("evidence", "scan-file-cap-exceeded"),
                    "Scope the audit directory to the shipped web output instead of unpruned workspace trees.",
                    "Tier 2",
                )
            )

    if kotlin_metadata_leaks:
        findings.append(
            _make_finding(
                "F-KOTLIN-METADATA",
                "medium",
                "Kotlin @Metadata / @DebugMetadata annotations retained in mobile/JVM artifact",
                f"Detected in: {', '.join(kotlin_metadata_leaks[:5])}",
                "Enable R8 fullMode and strip @kotlin.Metadata / @DebugMetadata on non-reflection internal classes to block automated symbol recovery.",
                "Tier 2",
            )
        )

    pkg_json = build_dir / "package.json"
    if pkg_json.is_file():
        pkg_txt = pkg_json.read_text(encoding="utf-8", errors="replace")
        if '"electron"' in pkg_txt and "EnableNodeCliInspectArguments" not in pkg_txt:
            findings.append(
                _make_finding(
                    "F-ELECTRON-FUSES",
                    "high",
                    "Electron package configuration lacks explicit @electron/fuses hardening",
                    "package.json references electron without EnableNodeCliInspectArguments / EnableEmbeddedAsarIntegrityValidation configuration",
                    "Flip Electron fuses at package time: disable EnableNodeCliInspectArguments & EnableNodeOptionsEnvironmentVariable, enable EnableEmbeddedAsarIntegrityValidation & OnlyLoadAppFromAsar.",
                    "Tier 1 / Tier 2",
                )
            )

    source_glsl = _audit_source_glsl_templates(source_dir) if source_dir and source_dir.is_dir() else None

    return {
        "schema": "anti-rea.audit-dir/v2",
        "skill_version": SKILL_VERSION,
        "build_dir": str(build_dir.resolve()),
        "total_files": total_files,
        "total_bytes": total_bytes,
        "extensions": ext_stats,
        "bundles": bundle_metrics,
        "source_glsl_audit": source_glsl,
        "finding_count": len(findings),
        "findings": findings,
    }


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        orig = urllib.parse.urlparse(req.full_url)
        dest_url = urllib.parse.urljoin(req.full_url, newurl)
        dest = urllib.parse.urlparse(dest_url)
        if dest.scheme not in ("http", "https") or (dest.scheme, dest.netloc.lower()) != (
            orig.scheme,
            orig.netloc.lower(),
        ):
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, dest_url)


_HTTP_OPENER = urllib.request.build_opener(
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
    _SameOriginRedirectHandler(),
)


def _passive_get(url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0 (anti-rea-audit/2.0)", **headers})
    try:
        with _HTTP_OPENER.open(req, timeout=timeout) as resp:
            body = resp.read(256 * 1024)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": url,
                "final_url": resp.url,
                "status": resp.status,
                "sampled_bytes": len(body),
                "body_sha256_prefix": _sha256_bytes(body)[:16],
                "headers": hdrs,
                "body_head": body[:512].decode("utf-8", errors="replace"),
            }
    except urllib.error.HTTPError as exc:
        hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return {
            "url": url,
            "final_url": url,
            "status": exc.code,
            "sampled_bytes": 0,
            "body_sha256_prefix": None,
            "headers": hdrs,
            "body_head": "",
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "url": url,
            "final_url": url,
            "status": 0,
            "error": str(exc),
            "sampled_bytes": 0,
            "body_sha256_prefix": None,
            "headers": {},
            "body_head": "",
        }


def _resolve_same_origin_asset_url(origin_scheme: str, origin_netloc: str, rel: str) -> str:
    cleaned = rel.strip()
    split_rel = urllib.parse.urlsplit(cleaned)
    if not cleaned or split_rel.scheme or split_rel.netloc or cleaned.startswith("//"):
        raise ValueError(f"Asset path must be a relative same-origin path: {rel}")
    origin = f"{origin_scheme}://{origin_netloc}"
    target_url = urllib.parse.urljoin(origin + "/", cleaned.lstrip("/"))
    t_parsed = urllib.parse.urlparse(target_url)
    if (t_parsed.scheme, t_parsed.netloc.lower()) != (origin_scheme, origin_netloc.lower()):
        raise ValueError(f"Asset path resolves outside target origin: {rel}")
    return target_url


def check_live_url(
    page_url: str,
    asset_paths: list[str] | None = None,
    allow_live: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    if not allow_live:
        raise PermissionError(
            "Live URL checks are disabled by default. Pass --allow-live only for user-owned/authorized deployments."
        )
    parsed = urllib.parse.urlparse(page_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid HTTP(S) URL: {page_url}")

    validated_assets = [
        (rel, _resolve_same_origin_asset_url(parsed.scheme, parsed.netloc, rel))
        for rel in (asset_paths or [])
    ]

    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings: list[dict[str, str]] = []
    checks: list[dict[str, Any]] = []

    main_res = _passive_get(page_url, {}, timeout)
    checks.append({"label": "page_plain_get", **main_res})

    robots_res = _passive_get(f"{origin}/robots.txt", {}, timeout)
    checks.append({"label": "robots_txt", **robots_res})
    if robots_res["status"] == 200 and parsed.path and parsed.path != "/":
        top_seg = "/" + parsed.path.strip("/").split("/")[0]
        if f"Disallow: {parsed.path}" not in robots_res["body_head"] and f"Disallow: {top_seg}" not in robots_res["body_head"]:
            findings.append(
                _make_finding(
                    "F-ROBOTS-MISSING",
                    "low",
                    f"robots.txt does not explicitly Disallow {parsed.path}",
                    f"Checked {origin}/robots.txt against {parsed.path}",
                    "Add Disallow rules and X-Robots-Tag: noindex, noarchive, nosnippet for private studio/app routes (note: robots.txt is advisory, pair with Edge auth).",
                    "Tier 1",
                )
            )

    if main_res["status"] > 0:
        csp = main_res["headers"].get("content-security-policy", "")
        xfo = main_res["headers"].get("x-frame-options", "")
        if "frame-ancestors" not in csp.lower() and not xfo:
            findings.append(
                _make_finding(
                    "F-CSP-FRAME-ANCESTORS",
                    "low",
                    "Entry page lacks Content-Security-Policy frame-ancestors or X-Frame-Options",
                    f"{page_url} returned neither frame-ancestors nor x-frame-options",
                    "Set `Content-Security-Policy: frame-ancestors 'self'` on studio/app routes.",
                    "Tier 1",
                )
            )

    budget_left = MAX_LIVE_REQUESTS - len(checks)
    for rel, target_url in validated_assets[: max(0, budget_left // 2)]:
        plain = _passive_get(target_url, {}, timeout)
        cross = _passive_get(
            target_url,
            {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"},
            timeout,
        )
        checks.append({"label": f"asset_plain:{rel}", **plain})
        checks.append({"label": f"asset_secfetch_cross:{rel}", **cross})

        ct = plain["headers"].get("content-type", "").lower()
        cc = plain["headers"].get("cache-control", "").lower()
        is_spa_fallback = (
            plain["status"] == 200
            and "text/html" in ct
            and plain["body_sha256_prefix"] == main_res["body_sha256_prefix"]
            and not rel.endswith(".html")
        )

        if rel.endswith(".map") and plain["status"] == 200 and not is_spa_fallback and '"mappings"' in plain["body_head"]:
            findings.append(
                _make_finding(
                    "F-SOURCEMAP-LIVE",
                    "high",
                    f"Live production source map publicly downloadable at {target_url}",
                    f"HTTP 200 ({ct}) with source-map mappings payload",
                    "Remove *.map from deployment artifacts and block *.map at CDN/Edge with HTTP 404.",
                    "Tier 1 / Tier 2",
                )
            )

        if is_spa_fallback and ("immutable" in cc or "max-age=31536000" in cc):
            findings.append(
                _make_finding(
                    "F-SPA-IMMUTABLE-CACHE",
                    "medium",
                    f"Missing asset {rel} falls back to SPA HTML with 1-year immutable Cache-Control",
                    f"{target_url} -> HTTP 200 text/html with cache-control: {cc}",
                    "Return an explicit 404 (cache-control: no-store) for missing sub-paths after filesystem lookup instead of falling through to `/`.",
                    "Tier 1",
                )
            )

        if plain["status"] == 200 and not is_spa_fallback and cross["status"] in (301, 302, 307, 308, 401, 403):
            findings.append(
                _make_finding(
                    "F-SECFETCH-BYPASS",
                    "high",
                    f"Sec-Fetch-* blacklist bypass on {rel} allows unauthenticated HTTP crawling",
                    f"Cross-site/document request returned HTTP {cross['status']}, but plain HTTP GET without Sec-Fetch-* returned HTTP 200",
                    "Switch Edge Middleware to a strict allowlist: require a short-lived HMAC-signed HttpOnly session ticket cookie plus `Sec-Fetch-Site: same-origin` on subresources.",
                    "Tier 1",
                )
            )

    return {
        "schema": "anti-rea.check-url/v1",
        "skill_version": SKILL_VERSION,
        "target_url": page_url,
        "requests_made": len(checks),
        "finding_count": len(findings),
        "findings": findings,
        "checks": checks,
    }


def _resolve_pack_registry_path(repo_root: Path, explicit_packs_dir: Path | None = None) -> Path:
    if explicit_packs_dir is not None:
        return _resolve_packs_dir_candidate(explicit_packs_dir) / "pack_registry.json"
    env_dir = os.environ.get("ANTI_REA_PACKS_DIR")
    if env_dir:
        return _resolve_packs_dir_candidate(Path(env_dir)) / "pack_registry.json"
    return repo_root / "_skill_packs" / "anti_rea" / "pack_registry.json"


def list_packs(repo_root: Path, explicit_packs_dir: Path | None = None) -> dict[str, Any]:
    reg_path = _resolve_pack_registry_path(repo_root, explicit_packs_dir)
    if not reg_path.is_file():
        raise FileNotFoundError(f"Missing dormant pack registry: {reg_path}")
    data = json.loads(reg_path.read_text(encoding="utf-8"))
    return {
        "schema": "anti-rea.packs/v1",
        "skill_version": SKILL_VERSION,
        "repo_root": str(repo_root),
        "packs_dir": str(reg_path.parent),
        "pack_count": len(data.get("packs", [])),
        "packs": data.get("packs", []),
        "finding_count": 0,
        "findings": [],
    }


def run_scan_score(target_dir: Path, min_resistance: float | None = None) -> dict[str, Any]:
    if not target_dir.exists():
        raise FileNotFoundError(f"Target path not found: {target_dir}")
    app_rep = antirea_scan_tree(str(target_dir))
    rep_dict = antirea_report.to_dict(app_rep)
    text_summary = antirea_report.render_text(app_rep)
    scores = rep_dict["scores"]
    findings: list[dict[str, str]] = []
    if min_resistance is not None and scores["resistance"] < min_resistance:
        findings.append(
            _make_finding(
                "F-MIN-RESISTANCE",
                "high",
                f"Static resistance score {scores['resistance']} is below threshold {min_resistance}",
                f"grade={scores['grade']} reversibility={scores['reversibility']}",
                "Strip source maps, move hardcoded secrets server-side, and apply minification/AST hardening.",
                "Tier 2",
            )
        )
    return {
        "schema": "anti-rea.scan-score/v1",
        "skill_version": SKILL_VERSION,
        "reversibility_score": scores["reversibility"],
        "resistance_score": scores["resistance"],
        "grade": scores["grade"],
        "report": rep_dict,
        "summary_text": text_summary,
        "finding_count": len(findings),
        "findings": findings,
    }


def run_gen_config(target_dir: Path, out_dir: Path, explicit_platforms: list[str] | None = None) -> dict[str, Any]:
    if not target_dir.exists():
        raise FileNotFoundError(f"Target path not found: {target_dir}")
    det = antirea_platforms.detect(str(target_dir))
    chosen = explicit_platforms if explicit_platforms else det.platforms
    written = antirea_configs.write_configs(str(out_dir), chosen or None)
    return {
        "schema": "anti-rea.gen-config/v1",
        "skill_version": SKILL_VERSION,
        "target_dir": str(target_dir.resolve()),
        "out_dir": str(out_dir.resolve()),
        "detected_platforms": det.platforms,
        "evidence": det.evidence,
        "written_files": written,
        "finding_count": 0,
        "findings": [],
    }


def run_harden_py(
    src_dir: Path,
    dst_dir: Path,
    *,
    rename: bool = False,
    strip_js_comments: bool = True,
    force_comments: bool = False,
    seed_hex: str | None = None,
) -> dict[str, Any]:
    if not src_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {src_dir}")
    seed_bytes = bytes.fromhex(seed_hex) if seed_hex else None
    manifest = antirea_harden_tree(
        str(src_dir),
        str(dst_dir),
        strip_js_comments=strip_js_comments,
        force_comments=force_comments,
        seed=seed_bytes,
        rename=rename,
    )
    return {
        "schema": "anti-rea.harden-py/v1",
        "skill_version": SKILL_VERSION,
        "manifest": manifest.as_dict(),
        "finding_count": 0,
        "findings": [],
    }


def _render_markdown(report: dict[str, Any]) -> str:
    schema_label = report.get("schema") or report.get("analysisKind") or "anti-rea"
    lines = [f"# Anti-REA Report (`{schema_label}`)", ""]
    if "packs" in report and "pack_count" in report:
        lines.append(f"- **Installed Dormant Packs:** `{report['pack_count']}`")
        lines.append("")
        lines.append("| ID | License | Subcommands | Playbook |")
        lines.append("| --- | --- | --- | --- |")
        for p in report["packs"]:
            lines.append(f"| `{p['id']}` | {p['license']} | `{', '.join(p['subcommands'])}` | `{p['playbook']}` |")
        return "\n".join(lines) + "\n"

    findings = report.get("findings", [])
    lines.append(f"- **Findings:** `{len(findings)}`")
    if "build_dir" in report:
        lines.append(f"- **Build Directory:** `{report['build_dir']}`")
    if "target_url" in report:
        lines.append(f"- **Target URL:** `{report['target_url']}` (`{report['requests_made']}` bounded passive requests)")
    if "resistance_score" in report:
        lines.append(
            f"- **Resistance Score:** `{report['resistance_score']}/100` (Grade `{report['grade']}`, Reversibility `{report['reversibility_score']}/100`)"
        )
    if "written_files" in report:
        lines.append(f"- **Generated Configs:** `{len(report['written_files'])}` in `{report['out_dir']}`")
    if report.get("analysisKind") == "apk-static-inspection":
        mf = report.get("manifest") or {}
        pkg = mf.get("package") or mf.get("packageName") or "unknown"
        lines.append(f"- **APK Package:** `{pkg}` (`{report['input']['bytes']:,}` bytes)")
    lines.append("")
    if not findings:
        lines.append("No exposure findings detected within the scanned scope.")
        return "\n".join(lines) + "\n"

    lines.append("| Code | Severity | Title | Evidence |")
    lines.append("| --- | --- | --- | --- |")
    for f in findings:
        code = f.get("code") or f.get("id") or "FINDING"
        sev = f.get("severity", "info")
        title = str(f.get("title") or f.get("message") or "").replace("|", "\\|")
        raw_ev = f.get("evidence") or f.get("path") or ""
        ev_text = "; ".join(str(x) for x in raw_ev) if isinstance(raw_ev, list) else str(raw_ev)
        ev = ev_text.replace("|", "\\|")
        lines.append(f"| `{code}` | **{sev}** | {title} | {ev} |")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit_anti_rea.py",
        description="Unified Anti-REA source-exposure auditor and dormant pack orchestrator.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {SKILL_VERSION}")
    parser.add_argument("--packs-dir", type=Path, default=None, help="Optional override path to _skill_packs/anti_rea")
    sub = parser.add_subparsers(dest="command", required=True)

    p_dir = sub.add_parser("audit-dir", help="Audit a local build/public output directory for REA exposure vectors.")
    p_dir.add_argument("build_dir", type=Path, help="Path to built/public artifact directory")
    p_dir.add_argument("--source-dir", type=Path, default=None, help="Optional unbundled source directory to compare GLSL coverage")
    p_dir.add_argument("--probe-symbol", action="append", default=[], help="High-value identifier/property name to check for plaintext survival")
    p_dir.add_argument("--format", choices=("json", "md"), default="json")
    p_dir.add_argument("--strict", action="store_true", help="Exit with code 1 if any high/medium finding is present")

    p_url = sub.add_parser("check-url", help="Run bounded passive HTTP header/crawlability checks on an authorized URL.")
    p_url.add_argument("url", help="Authorized target page URL (http/https)")
    p_url.add_argument("--asset-path", action="append", default=[], help="Relative sub-asset or .map path on the same origin to test (max 3)")
    p_url.add_argument("--allow-live", action="store_true", help="Explicit confirmation that live passive GET checks are authorized")
    p_url.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    p_url.add_argument("--format", choices=("json", "md"), default="json")
    p_url.add_argument("--strict", action="store_true", help="Exit with code 1 if any high/medium finding is present")

    p_packs = sub.add_parser("packs", help="List installed dormant Anti-REA packs in _skill_packs/anti_rea/.")
    p_packs.add_argument("--format", choices=("json", "md"), default="json")

    p_gates = sub.add_parser("lint-gates", help="Run 10 Counter-REA packaging-footgun gates + honesty soft-caps (bla-counter-rea).")
    p_gates.add_argument("target_path", type=Path, help="Directory or artifact file to lint")
    p_gates.add_argument("--format", choices=("json", "md"), default="json")
    p_gates.add_argument("--strict", action="store_true", help="Exit with code 1 if any gate reports findings")

    p_vb = sub.add_parser("verify-build", help="Stream-verify deployment directory for sourceMappingURL, .map.gz/.br, _headers, and renamed JSON maps.")
    p_vb.add_argument("build_dir", type=Path, help="Built deployment asset directory")
    p_vb.add_argument("--format", choices=("json", "md"), default="json")
    p_vb.add_argument("--strict", action="store_true", help="Exit with code 1 if any source-map leak is detected")

    p_sc = sub.add_parser("scan-score", help="Compute static 0-100 REA Reversibility / Resistance score for a directory or binary.")
    p_sc.add_argument("target_dir", type=Path, help="Target source or build tree")
    p_sc.add_argument("--min-resistance", type=float, default=None, help="Optional minimum Resistance score (0-100) before --strict fails")
    p_sc.add_argument("--format", choices=("json", "md"), default="json")
    p_sc.add_argument("--strict", action="store_true", help="Exit with code 1 if Resistance is below --min-resistance")

    p_gc = sub.add_parser("gen-config", help="Detect platforms and emit parse-valid hardening configs (terser, obfuscator, fuses, R8, pinning).")
    p_gc.add_argument("target_dir", type=Path, help="Project directory to inspect")
    p_gc.add_argument("--out-dir", type=Path, required=True, help="Output directory for generated config files")
    p_gc.add_argument("--platform", action="append", default=[], help="Optional explicit platform override (web, electron, android, ios, native, python)")
    p_gc.add_argument("--format", choices=("json", "md"), default="json")

    p_hp = sub.add_parser("harden-py", help="Out-of-tree Python AST string/identifier hardener + JS sourcemap/comment stripper.")
    p_hp.add_argument("src_dir", type=Path, help="Input source directory (never modified in place)")
    p_hp.add_argument("dst_dir", type=Path, help="New output directory outside src_dir")
    p_hp.add_argument("--rename", action="store_true", help="Enable scope-aware Python local identifier renaming")
    p_hp.add_argument("--no-strip-js-comments", action="store_true", help="Disable JS comment stripping")
    p_hp.add_argument("--force-comments", action="store_true", help="Strip C-like comments even when Node syntax verifier is absent")
    p_hp.add_argument("--seed-hex", default=None, help="Optional deterministic hex seed")
    p_hp.add_argument("--format", choices=("json", "md"), default="json")

    p_apk = sub.add_parser("inspect-apk", help="Bounded pure-Python static Android APK binary-AXML / DEX / WebView / ELF inspector.")
    p_apk.add_argument("apk_path", type=Path, help="Path to non-symlink regular .apk file (22 B .. 64 MiB)")
    p_apk.add_argument("--format", choices=("json", "md"), default="json")
    p_apk.add_argument("--strict", action="store_true", help="Exit with code 1 if high/medium APK exposure findings are present")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    repo_root = _discover_repo_root(args.packs_dir)

    try:
        if args.command == "audit-dir":
            report = audit_directory(args.build_dir, args.source_dir, args.probe_symbol)
        elif args.command == "check-url":
            report = check_live_url(args.url, args.asset_path, args.allow_live, args.timeout)
        elif args.command == "packs":
            report = list_packs(repo_root, args.packs_dir)
        elif args.command == "lint-gates":
            report = run_packaging_gates(args.target_path)
        elif args.command == "verify-build":
            report = verify_build_directory(args.build_dir)
        elif args.command == "scan-score":
            report = run_scan_score(args.target_dir, args.min_resistance)
        elif args.command == "gen-config":
            report = run_gen_config(args.target_dir, args.out_dir, args.platform or None)
        elif args.command == "harden-py":
            report = run_harden_py(
                args.src_dir,
                args.dst_dir,
                rename=args.rename,
                strip_js_comments=not args.no_strip_js_comments,
                force_comments=args.force_comments,
                seed_hex=args.seed_hex,
            )
        elif args.command == "inspect-apk":
            report = admit_and_inspect_apk(args.apk_path)
        else:
            parser.error(f"Unknown command: {args.command}")
            return 2
    except PermissionError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1

    if args.format == "md":
        sys.stdout.write(_render_markdown(report))
    else:
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    if getattr(args, "strict", False):
        findings = report.get("findings", [])
        if any(str(f.get("severity", "")).lower() in ("high", "medium", "error", "warning") for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
