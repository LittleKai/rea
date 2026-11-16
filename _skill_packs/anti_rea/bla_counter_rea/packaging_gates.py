#!/usr/bin/env python3
"""Counter-REA static packaging-footgun gates and defense-score honesty checks.

Source: https://github.com/qybaihe/bla@98e01cc47b3ac8eabeed69b91dc393c37467388f
License: MIT (Copyright (c) 2026 qybaihe)

Ports the 10 zero-@babel packaging-footgun lints, the 106-entry REA internal
resource limits catalog (src/identity.ts), and defense-score honesty soft-caps
(src/engine/defense-score-honesty.ts) into zero-dependency Python 3.10+ stdlib.
Defensive static inspection only; never executes target files or echoes secret values.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import struct
from pathlib import Path
from typing import Any

COUNTER_REA_VECTORS_COUNT = 24
PACKAGING_GATES_SCHEMA = "anti-rea.lint-gates/v1"
DEFENSE_SCORE_DISCLAIMER = (
    "Counter-REA gate score measures static exposure reduction and packaging hygiene only; "
    "it is NOT a cryptographic preimage-hardness or access-control guarantee."
)

SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        ".bla-hardened",
        "coverage",
        ".next",
        ".turbo",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
    }
)

WASM_MAGIC = b"\x00asm"
JS_HTML_EXT = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".html", ".htm"})
JS_ONLY_EXT = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})

REA_INTERNAL_LIMITS: dict[str, int | str] = {
    "SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT": 256,
    "SEMANTIC_EXPRESSION_DEPTH_LIMIT": 256,
    "SEMANTIC_GETTER_EXPANSION_LIMIT": 512,
    "SEMANTIC_ALIAS_SELECTION_LIMIT": 512,
    "SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT": 1048576,
    "ELECTRON_CALL_PATH_DEPTH_LIMIT": 128,
    "ELECTRON_CALL_PATH_VISIT_LIMIT": 1000000,
    "ELECTRON_FUSE_SENTINEL": "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX",
    "ELECTRON_MAX_SENTINELS_PER_SLICE": 32,
    "RUST_MAX_COMMIT_HASHES": 64,
    "RUST_DEP_V0_SECTION_BYTES": 1048576,
    "DART_MAX_SNAPSHOT_HASH_CANDIDATES": 64,
    "DART_MAX_TOOLCHAIN_LINES": 4,
    "MODEL_MAX_JSON_NESTING": 32,
    "MODEL_MAX_METADATA_NESTING": 32,
    "SQLITE_OUTPUT_BYTES_LIMIT": 16777216,
    "WASM_INTERFACE_REPRESENTATION_BYTES": 33554432,
    "MANAGED_METADATA_REPRESENTATION_BYTES": 67108864,
    "WEB_RUNTIME_SOURCE_BYTES": 33554432,
    "LLDB_MAX_TRACE_BYTES": 8388608,
    "LLDB_MAX_TRACE_FRAMES": 65536,
    "LLDB_MAX_OTHER_STOPS": 256,
    "LLDB_MAX_SELECTOR_BYTES": 1024,
    "GDB_MAX_COMMAND_OUTPUT_BYTES": 16777216,
    "GDB_MAX_COMMAND_OUTPUT_RECORDS": 16384,
    "RIZIN_MAX_FRAME_BYTES": 16777216,
    "RIZIN_MAX_COMMAND_FRAMES": 4096,
    "ENVIRONMENT_COMPARE_STEP_DIFF_LIMIT": 20,
    "GO_MAX_BUILD_INFO_BYTES": 1048576,
    "GO_MAX_HEADER_SEARCH_BYTES": 268435456,
    "DART_MAX_POOL_URIS": 500,
    "DART_MAX_POOL_TOKENS": 2000,
    "BEAM_MAX_CHUNKS": 256,
    "BEAM_MAX_ATOMS": 65536,
    "BEAM_DEFAULT_MAX_CHUNKS": 64,
    "BEAM_DEFAULT_MAX_ATOMS": 4096,
    "EVM_INPUT_BYTES": 4194304,
    "EVM_OUTPUT_BYTES": 16777216,
    "EVM_DIAGNOSTIC_BYTES": 1048576,
    "PCAP_TSHARK_JSON_MAX_BYTES": 8388608,
    "GPU_REPORT_BYTES": 16777216,
    "GPU_OBJECT_BYTES": 134217728,
    "FIRMWARE_MAX_STAGING_BYTES": 536870912,
    "FIRMWARE_MAX_EXTRACTION_DEPTH": 10,
    "ANDROID_MAPPING_FILE_BYTES": 67108864,
    "PROGUARD_MAPPING_INDEX_BYTES": 134217728,
    "PROGUARD_MAPPING_PROJECTION_BYTES": 8388608,
    "PROGUARD_MAPPING_MALFORMED_SAMPLES": 16,
    "PROGUARD_MAPPING_CANDIDATES": 8,
    "ANDROID_JNI_REPORT_BYTES": 16777216,
    "ANDROID_JNI_LIBRARY_BYTES": 67108864,
    "ANDROID_JNI_TOTAL_BYTES": 268435456,
    "ANDROID_JNI_FACTS_BYTES": 16777216,
    "ANDROID_JNI_LIBRARY_ENTRIES": 100000,
    "ANDROID_JNI_LIBRARIES": 2048,
    "MAX_NATIVE_EXPORT_ROWS": 262144,
    "ANDROID_MANIFEST_COMPONENTS": 512,
    "ANDROID_MANIFEST_INTENT_FILTERS": 32,
    "ANDROID_MANIFEST_INTENT_VALUES": 64,
    "ANDROID_MANIFEST_AUTHORITIES": 64,
    "ANDROID_MANIFEST_RESOLVED_NAME_BYTES": 1048576,
    "ANDROID_MANIFEST_AUTHORITY_BYTES": 1048576,
    "ANDROID_MANIFEST_PERMISSION_BYTES": 1048576,
    "ANDROID_MANIFEST_PROCESS_BYTES": 1048576,
    "ANDROID_MANIFEST_DETAIL_BYTES": 1048576,
    "ANDROID_EXTERNAL_XREF_BYTES": 1048448,
    "ANDROID_XREF_TEXT_BYTES": 8387584,
    "BUN_RECORD_BYTES_1_3_3": 36,
    "BUN_RECORD_BYTES_1_3_9": 52,
    "BUN_MAX_MODULE_COUNT": 100000,
    "BUN_MAX_RETAINED_BYTES": 268435456,
    "BUN_MAX_LOGICAL_PATH_PARTS": 256,
    "BUN_MAX_LOGICAL_PATH_NODES": 250000,
    "BUN_METADATA_CACHE_BYTES": 262144,
    "BUN_METADATA_CACHE_ENTRIES": 1024,
    "UF2_BLOCK_BYTES": 512,
    "UF2_DATA_BYTES": 476,
    "UF2_MAX_REGIONS": 65536,
    "ASAR_DEFAULT_MAX_HEADER_BYTES": 16777216,
    "ASAR_MAXIMUM_MAX_HEADER_BYTES": 268435456,
    "FRIDA_MAX_SESSION_CAPTURE_BYTES": 16777216,
    "FRIDA_MAX_MESSAGE_METADATA_BYTES": 131072,
    "FRIDA_MAX_MESSAGE_TYPE_BYTES": 4096,
    "FRIDA_MAX_MESSAGE_TEXT_BYTES": 32768,
    "FRIDA_MAX_CAPTURE_JSON_NODES": 250000,
    "FRIDA_MAX_JSON_DEPTH": 64,
    "REGEX_DEFAULT_MATCHING_DEADLINE_MS": 5000,
    "REGEX_DEFAULT_WORKER_HEAP_REQUEST_MIB": 128,
    "REGEX_MINIMUM_WORKER_HEAP_REQUEST_MIB": 7,
    "NATIVE_AOT_MAX_SOURCE_BYTES": 134217728,
    "NATIVE_AOT_MAX_REPORT_BYTES": 4194304,
    "NATIVE_AOT_MAX_WORK_UNITS": 67108864,
    "NATIVE_AOT_BASE_WORK_UNITS": 67108864,
    "NATIVE_AOT_WORK_UNITS_PER_SOURCE_BYTE": 8,
    "NATIVE_AOT_MAX_WORKING_MEMORY_BYTES": 67108864,
    "IL2CPP_METADATA_INPUT_BYTES": 268435456,
    "IL2CPP_METADATA_OUTPUT_BYTES": 67108864,
    "IL2CPP_BINARY_BYTES": 1073741824,
    "IL2CPP_V108_SAMPLE_STRINGS": 16,
    "IL2CPP_V108_SAMPLE_BYTES": 128,
    "IL2CPP_V108_SCAN_BATCH_BYTES": 65536,
    "DEX_ARRAY_DIMENSIONS": 255,
    "ANDROID_NATIVE_SPLIT_TYPES": 64,
    "ANDROID_NATIVE_SPLIT_TYPE_CHARS": 256,
    "JAVASCRIPT_MEMBER_MUTATION_ALIAS_STATES": 524288,
    "JAVASCRIPT_MEMBER_MUTATION_ALIAS_STATES_MAX": 8388608
}


def load_rea_internal_limits() -> dict[str, int | str]:
    return dict(REA_INTERNAL_LIMITS)


def walk_bounded_files(
    root: Path,
    *,
    max_depth: int = 6,
    max_files: int = 64,
    max_bytes: int = 32 * 1024 * 1024,
) -> list[Path]:
    if root.is_file():
        return [root] if not root.is_symlink() else []
    out: list[Path] = []

    def _visit(cur: Path, depth: int) -> None:
        if len(out) >= max_files or depth > max_depth:
            return
        try:
            entries = sorted(os.scandir(cur), key=lambda e: e.name)
        except OSError:
            return
        for ent in entries:
            if len(out) >= max_files:
                return
            try:
                if ent.is_symlink():
                    continue
                if ent.is_dir(follow_symlinks=False):
                    if ent.name in SKIP_DIRS:
                        continue
                    _visit(Path(ent.path), depth + 1)
                elif ent.is_file(follow_symlinks=False):
                    st = ent.stat(follow_symlinks=False)
                    if st.st_size <= max_bytes:
                        out.append(Path(ent.path))
            except OSError:
                continue

    _visit(root, 0)
    return out


# ---------------------------------------------------------------------------
# Gate 1: lane-independence
# ---------------------------------------------------------------------------
_BYTE_COMPARE_ARRAY = re.compile(r"\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d+)\s*){3,}\]")
_LANE_AND_REDUCE = re.compile(
    r"(?:lanes?|bytes?|parts?|chunks?)\s*(?:\.every\s*\(|\.all\s*\(|\.reduce\s*\([^)]*(?:&&|\band\b))",
    re.I,
)
_EVERY_INDEXED_LANE = re.compile(r"\.every\s*\([\s\S]{0,200}(?:lanes?|targets?|expect)\s*\[\s*[\w$]+\s*\]", re.I)
_INDEXED_ORACLE = re.compile(
    r"for\s*\(\s*(?:let|var|const)\s+\w+\s*=\s*0[^)]*\)\s*\{[^}]{0,200}(?:key|input|guess)\s*\[\s*\w+\s*\][^}]{0,120}===\s*(?:target|expect|lane|ref)",
    re.I,
)
_PER_BYTE_WASM_LANE = re.compile(
    r"charCodeAt\s*\(\s*\w+\s*\)[\s\S]{0,240}(?:mix|seal)\s*\([\s\S]{0,320}(?:LANE_TARGETS|laneTargets|targets?|lanes?)\s*\[\s*\w+",
    re.I,
)
_INDEXED_XOR_LANE_FOLD = re.compile(
    r"for\s*\(\s*(?:let|var|const)\s+\w+[^)]*\)\s*\{[\s\S]{0,400}charCodeAt[\s\S]{0,400}\^\s*\((?:LANE_TARGETS|laneTargets|targets?|lanes?)\s*\[",
    re.I,
)
_CHAINED_PER_INDEX = re.compile(
    r"(?:\b(?:key|input|guess|token|license|serial|code)\w*\s*(?:\.\s*(?:charCodeAt|codePointAt)\s*\(\s*\d+\s*\)|\[\s*\d+\s*\])\s*===?\s*(?:0x[0-9a-fA-F]+|\d+|['\"][^'\"]+['\"])\s*(?:&&|\band\b)\s*){2,}\b(?:key|input|guess|token|license|serial|code)\w*\s*(?:\.\s*(?:charCodeAt|codePointAt)\s*\(\s*\d+\s*\)|\[\s*\d+\s*\])\s*===?\s*(?:0x[0-9a-fA-F]+|\d+|['\"][^'\"]+['\"])",
    re.I,
)
_SPLIT_SEGMENT_LANE = re.compile(
    r"\.split\s*\(\s*['\"][^'\"]+['\"]\s*\)[\s\S]{0,300}\b(\w+)\s*\[\s*0\s*\]\s*===?\s*['\"][^'\"]+['\"]\s*(?:&&|\band\b)[\s\S]{0,160}\b\1\s*\[\s*1\s*\]\s*===?\s*['\"][^'\"]+['\"]",
    re.I,
)


def lint_lane_independence(text: str) -> list[dict[str, str]]:
    sample = text[:400_000]
    findings: list[dict[str, str]] = []
    m_arr = _BYTE_COMPARE_ARRAY.search(sample)
    if m_arr and re.search(r"(?:key|guess|input|lane)", sample, re.I):
        lit = m_arr.group(0)
        if not re.match(r"^\[\s*0\s*(?:,\s*0\s*){3,}\]$", lit):
            findings.append(
                {
                    "id": "per-lane-byte-compare-array",
                    "severity": "error",
                    "summary": "Literal multi-byte compare table near key/guess identifiers enables per-lane probes.",
                }
            )
    if _LANE_AND_REDUCE.search(sample) or _EVERY_INDEXED_LANE.search(sample):
        findings.append(
            {
                "id": "independent-lane-and-reduce",
                "severity": "error",
                "summary": "Lane/byte collection reduced with every/all/AND without whole-key chained mixing.",
            }
        )
    if _INDEXED_ORACLE.search(sample):
        findings.append(
            {
                "id": "indexed-lane-oracle-loop",
                "severity": "error",
                "summary": "Indexed loop comparing key[i] to per-lane target.",
            }
        )
    if _PER_BYTE_WASM_LANE.search(sample) or _INDEXED_XOR_LANE_FOLD.search(sample):
        findings.append(
            {
                "id": "per-byte-wasm-lane-oracle",
                "severity": "error",
                "summary": "Per-byte charCodeAt fed into WASM mix/seal against indexed targets.",
            }
        )
    if _CHAINED_PER_INDEX.search(sample):
        findings.append(
            {
                "id": "chained-per-index-compare",
                "severity": "error",
                "summary": "3+ chained per-index charCodeAt/bracket comparisons joined with &&/and.",
            }
        )
    if _SPLIT_SEGMENT_LANE.search(sample):
        findings.append(
            {
                "id": "split-segment-lane-compare",
                "severity": "error",
                "summary": "Key split into segments compared independently.",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Gate 2: seal-commitment
# ---------------------------------------------------------------------------
_ONE_WAY_ALGO = re.compile(r"^(?:sha-?(?:256|384|512)|sha3-?(?:256|512)|blake2[bs]|blake3|hmac-sha-?(?:256|384|512))$", re.I)
_SEAL_NAME_RE = re.compile(r"(?:^|[._-])seal\.json$", re.I)
_PUBLIC_SEED_KEYS = ("seed", "hardenSeed", "materializationSeed", "scheduleSeed")
_PUBLIC_KEY_DIGEST_KEYS = ("keySha256", "keyDigest", "secretKeySha256", "unlockKeySha256")


def lint_seal_commitment(path: Path) -> list[dict[str, str]]:
    if path.suffix.lower() != ".json":
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        obj = json.loads(raw)
    except (OSError, ValueError):
        return []
    if not isinstance(obj, dict):
        return []
    is_seal_name = bool(_SEAL_NAME_RE.search(path.name))
    schema_val = str(obj.get("schema") or obj.get("$schema") or "")
    has_seal_keys = any(k in obj for k in ("revision", "commitment", "certificateCipherHex", "certificate_cipher_hex")) and any(
        k in obj for k in ("scheduleSalt", "schedule_salt", "rounds")
    )
    if not (is_seal_name or re.search(r"seal|entitlement|license", schema_val, re.I) or has_seal_keys):
        return []

    findings: list[dict[str, str]] = []
    algo = str(obj.get("algorithm") or obj.get("digestAlgorithm") or obj.get("hash") or obj.get("kdf") or "").strip()
    one_way = bool(algo and _ONE_WAY_ALGO.match(algo.split(":")[0]))
    rounds = obj.get("rounds") if isinstance(obj.get("rounds"), (int, float)) else obj.get("roundCount")
    salt = next(
        (obj[k] for k in ("scheduleSalt", "schedule_salt", "arxSalt", "arx_salt") if isinstance(obj.get(k), (int, float))),
        None,
    )
    invertible = isinstance(rounds, (int, float)) and rounds >= 2 and salt is not None
    revision = next(
        (obj[k] for k in ("revision", "commitment", "digest", "expectedDigest", "publicDigest") if isinstance(obj.get(k), str) and obj[k]),
        None,
    )
    cipher = next(
        (obj[k] for k in ("certificateCipherHex", "certificate_cipher_hex", "certificateCipher", "cipherHex") if isinstance(obj.get(k), str) and obj[k]),
        None,
    )

    if is_seal_name or re.search(r"seal|entitlement", schema_val, re.I):
        findings.append(
            {
                "id": "plaintext-seal-sidecar",
                "severity": "error" if (invertible or bool(cipher)) else "warning",
                "summary": "Plaintext seal/entitlement JSON sidecar present beside shipped artifacts.",
            }
        )
    if revision and invertible and not one_way:
        findings.append(
            {
                "id": "reversible-public-commitment",
                "severity": "error",
                "summary": "Public commitment paired with numeric scheduleSalt+rounds without a one-way digest.",
            }
        )
    if cipher and revision and (invertible or not one_way):
        findings.append(
            {
                "id": "seal-offline-oracle-package",
                "severity": "error",
                "summary": "Seal packages commitment together with certificate ciphertext in cleartext.",
            }
        )
    for sk in _PUBLIC_SEED_KEYS:
        if isinstance(obj.get(sk), str) and obj[sk]:
            findings.append(
                {
                    "id": "public-materialization-seed",
                    "severity": "warning",
                    "summary": f"Public seal exposes materialization seed field '{sk}'.",
                }
            )
            break
    for dk in _PUBLIC_KEY_DIGEST_KEYS:
        if isinstance(obj.get(dk), str) and obj[dk]:
            findings.append(
                {
                    "id": "public-key-digest-oracle",
                    "severity": "warning",
                    "summary": f"Public seal publishes secret-key digest field '{dk}'.",
                }
            )
            break
    return findings


# ---------------------------------------------------------------------------
# WASM active data-section helper (shared by Gates 3, 6, 7)
# ---------------------------------------------------------------------------
def _read_uleb(buf: bytes, off: int) -> tuple[int, int]:
    res = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("uleb truncated")
        b = buf[off]
        off += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, off
        shift += 7


def _read_i32_leb(buf: bytes, off: int) -> tuple[int, int]:
    res = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("ileb truncated")
        b = buf[off]
        off += 1
        res |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < 32 and (b & 0x40):
                res |= -(1 << shift)
            return res, off


def extract_wasm_data_payloads(buf: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    if len(buf) < 8 or buf[:4] != WASM_MAGIC:
        return out
    off = 8
    while off < len(buf):
        sec_id = buf[off]
        off += 1
        try:
            size, off = _read_uleb(buf, off)
        except ValueError:
            break
        end = off + size
        if end > len(buf):
            break
        if sec_id == 11:
            p = off
            try:
                count, p = _read_uleb(buf, p)
                for _ in range(count):
                    if p >= end:
                        break
                    flags = buf[p]
                    p += 1
                    mem_off = 0
                    if flags in (0, 2):
                        if flags == 2:
                            _, p = _read_uleb(buf, p)
                        if p < end and buf[p] == 0x41:
                            p += 1
                            mem_off, p = _read_i32_leb(buf, p)
                            if p < end and buf[p] == 0x0B:
                                p += 1
                        else:
                            while p < end and buf[p] != 0x0B:
                                p += 1
                            if p < end:
                                p += 1
                    else:
                        dlen, p = _read_uleb(buf, p)
                        p += dlen
                        continue
                    dlen, p = _read_uleb(buf, p)
                    if p + dlen > end:
                        break
                    out.append((mem_off, buf[p : p + dlen]))
                    p += dlen
            except ValueError:
                pass
        off = end
    return out


# ---------------------------------------------------------------------------
# Gate 3: wasm-param-carrier
# ---------------------------------------------------------------------------
_TAGGED_MAGIC_RE = re.compile(rb"(?:R[0-9]|BLA|V[0-9]|K[0-9])(?:PARM|CIPH|SEAL|SALT)")


def lint_wasm_param_carrier(buf: bytes) -> list[dict[str, str]]:
    if len(buf) < 8:
        return []
    findings: list[dict[str, str]] = []
    for m in _TAGGED_MAGIC_RE.finditer(buf):
        magic = m.group(0).decode("ascii")
        after = m.end()
        if after >= len(buf) or buf[after] != 0:
            continue
        blob_start = after + (2 if (after + 1 < len(buf) and buf[after + 1] == 0) else 1)
        if magic.endswith(("CIPH", "SEAL")):
            if len(buf) - blob_start < 4:
                continue
            fid = "clear-wasm-cipher-carrier" if magic.endswith("CIPH") else "clear-wasm-seal-magic"
        else:
            window = buf[blob_start : min(len(buf), blob_start + 12)]
            if not window:
                continue
            non_print = sum(1 for b in window if b == 0 or b < 0x20 or b > 0x7E)
            if non_print < max(2, int(len(window) * 0.4)):
                continue
            fid = "clear-wasm-param-magic"
        findings.append(
            {
                "id": fid,
                "severity": "error",
                "summary": f"WASM embeds clear {magic} carrier magic followed by binary parameter/cipher payload.",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Gate 4: js-aes-unwrap
# ---------------------------------------------------------------------------
_CREATE_CIPHER_IV = re.compile(
    r"\bcreate(?:Decipher|Cipher)iv\b|\.create(?:Decipher|Cipher)iv\s*\(|\bsubtle\.(?:decrypt|encrypt|unwrapKey|wrapKey)\s*\("
)
_WRAP_KEY_NAME = re.compile(r"\b(?:WRAP_KEY|AES_KEY|SEAL_KEY|UNWRAP_KEY|BLOB_KEY)(?:_HEX|_B64|_BASE64|_BYTES)?\b")
_BUF_FROM_HEX_B64 = re.compile(r"Buffer\.from\s*\(\s*[^,)]+?\s*,\s*['\"](?:hex|base64)['\"]\s*\)|\bsubtle\.importKey\s*\(\s*['\"]raw['\"]")
_HEX_KEY_LIT = re.compile(r"['\"][0-9a-fA-F]{32}(?:[0-9a-fA-F]{32})?['\"]")
_NAMED_HDR = re.compile(r"\b(?:SEALED_HDR|SEAL_HDR|WRAP_HDR|MAGIC_HDR|BLOB_HDR|PARAM_HDR)\b")
_R4_BEACON = re.compile(r"['\"]d17ea004['\"]", re.I)
_FIXED_HDR_HEX = re.compile(r"Buffer\.from\s*\(\s*['\"][0-9a-fA-F]{8}['\"]\s*,\s*['\"]hex['\"]\s*\)")


def lint_js_aes_unwrap(text: str) -> list[dict[str, str]]:
    s = text[:800_000]
    has_cipher = bool(_CREATE_CIPHER_IV.search(s))
    has_key = bool(_WRAP_KEY_NAME.search(s) or (has_cipher and (_BUF_FROM_HEX_B64.search(s) or _HEX_KEY_LIT.search(s))))
    has_hdr = bool(_R4_BEACON.search(s) or _NAMED_HDR.search(s) or (_FIXED_HDR_HEX.search(s) and (has_cipher or has_key)))
    findings: list[dict[str, str]] = []
    if has_cipher and has_key and has_hdr:
        findings.append(
            {
                "id": "js-aes-sealed-blob-unwrap",
                "severity": "error",
                "summary": "JS holds AES wrap-key material + create*iv + fixed sealed header (recoverable via runtime crypto hook).",
            }
        )
    elif has_cipher and has_key:
        findings.append(
            {
                "id": "js-aes-wrap-key-material",
                "severity": "error",
                "summary": "JS pairs wrap-key material with createDecipheriv/createCipheriv.",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Gate 5: js-wasm-hydrate-dump
# ---------------------------------------------------------------------------
_MEM_BUF_READ = re.compile(
    r"(?:new\s+Uint8Array\s*\(\s*(?:[a-zA-Z_$][\w$]*\.)?buffer\b|Buffer\.from\s*\(\s*new\s+Uint8Array\s*\([^)]*\.buffer\b|instanceof\s+WebAssembly\.Memory)"
)
_HYDRATE_CALL = re.compile(r"\.hydrate\s*\(|\bhydrate\s*\(\s*\w+|\bexp\.hydrate\b|fn\.length\s*!==\s*1|fn\.length\s*===\s*1")
_WASM_INST = re.compile(r"WebAssembly\.instantiate\b")


def lint_js_wasm_hydrate_dump(text: str) -> list[dict[str, str]]:
    s = text[:800_000]
    has_mem = bool(_MEM_BUF_READ.search(s))
    has_hyd = bool(_HYDRATE_CALL.search(s))
    has_inst = bool(_WASM_INST.search(s))
    layout_bits = (
        int(bool(re.search(r"\.readU?Int32LE\s*\(", s)))
        + int(bool(re.search(r"\.readUInt16LE\s*\(", s)))
        + int(bool(re.search(r"\b(?:salt|SALT)\b", s) and re.search(r"\b(?:rounds|ROUNDS)\b", s)))
        + int(bool(re.search(r"\b(?:cipherHex|cipher|CIPHER|clen|cLen|cipherLen)\b", s)))
    )
    if has_mem and layout_bits >= 2 and (has_hyd or has_inst):
        return [
            {
                "id": "js-wasm-hydrate-param-dump",
                "severity": "error",
                "summary": "JS reads WebAssembly.Memory buffer and decodes salt/rounds/cipher layout on host side.",
            }
        ]
    return []


# ---------------------------------------------------------------------------
# Gate 6: wasm-xor-mask-sidecar
# ---------------------------------------------------------------------------
def lint_wasm_xor_mask_sidecar(buf: bytes) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for mem_off, payload in extract_wasm_data_payloads(buf):
        bases = [0, 64, 128, 256] if len(payload) > 256 else [0]
        for base in bases:
            if base >= len(payload):
                continue
            hit = False
            for n in range(40, min(120, len(payload) - base - 32) + 1):
                mask = payload[base + n : base + n + 32]
                if len(mask) != 32 or len(set(mask)) < 8:
                    continue
                plain = bytes(payload[base + i] ^ mask[i % 32] for i in range(n))
                if plain[5] or plain[6] or plain[7]:
                    continue
                rounds = plain[4]
                if not (8 <= rounds <= 200):
                    continue
                clen = struct.unpack_from("<H", plain, 24)[0]
                if not (8 <= clen <= 200) or 26 + clen != n:
                    continue
                words = struct.unpack_from("<iiii", plain, 8)
                if sum(1 for w in words if w != 0) < 2:
                    continue
                non_print = sum(1 for b in plain[26:n] if b < 0x20 or b > 0x7E)
                if non_print < max(2, clen // 4):
                    continue
                findings.append(
                    {
                        "id": "wasm-xor-mask-entitlement-pack",
                        "severity": "error",
                        "summary": f"WASM data section at {mem_off + base} stores XOR-masked pack beside plaintext 32-byte mask.",
                    }
                )
                hit = True
                break
            if hit:
                break
    return findings


# ---------------------------------------------------------------------------
# Gate 7: wasm-seal-xor-known-plaintext
# ---------------------------------------------------------------------------
def _resolve_sibling_seal_revision(wasm_path: Path) -> bytes | None:
    for name in ("seal.json", "bla-seal.json", ".bla-seal.json"):
        cand = wasm_path.parent / name
        if cand.is_file():
            try:
                obj = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
                rev = obj.get("revision") if isinstance(obj, dict) else None
                if isinstance(rev, str) and re.fullmatch(r"[0-9a-fA-F]{64}", rev):
                    return bytes.fromhex(rev)
            except (OSError, ValueError):
                continue
    return None


def lint_wasm_seal_xor_known_plaintext(wasm_path: Path, buf: bytes) -> list[dict[str, str]]:
    commit = _resolve_sibling_seal_revision(wasm_path)
    if commit is None or len(commit) != 32:
        return []
    findings: list[dict[str, str]] = []
    for mem_off, payload in extract_wasm_data_payloads(buf):
        bases = [0, 64, 128, 256] if len(payload) > 256 else [0]
        for base in bases:
            if len(payload) < base + 50:
                continue
            mask = bytearray(32)
            for i in range(8, 40):
                mask[i % 32] = payload[base + i] ^ commit[i - 8]
            if len(set(mask)) < 8:
                continue
            hdr = bytes(payload[base + i] ^ mask[i % 32] for i in range(42))
            if hdr[5] or hdr[6] or hdr[7]:
                continue
            rounds = hdr[4]
            clen = struct.unpack_from("<H", hdr, 40)[0]
            if not (8 <= rounds <= 200 and 8 <= clen <= 200 and len(payload) >= base + 42 + clen):
                continue
            non_print = sum(
                1 for i in range(clen) if (payload[base + 42 + i] ^ mask[(42 + i) % 32]) < 0x20 or (payload[base + 42 + i] ^ mask[(42 + i) % 32]) > 0x7E
            )
            if non_print < max(2, clen // 5):
                continue
            findings.append(
                {
                    "id": "wasm-seal-revision-mask-oracle",
                    "severity": "error",
                    "summary": f"WASM data at {mem_off + base} embeds public seal.revision under repeating 32-byte XOR mask.",
                }
            )
            break
    return findings


# ---------------------------------------------------------------------------
# Gate 8: panel-derive
# ---------------------------------------------------------------------------
_STABLE_PANEL_DERIVE = re.compile(r"__vaultPanelDerive(?:_[A-Za-z0-9]+)?")
_LOCAL_DERIVE_DECL = re.compile(r"\bfunction\s+deriveLocal\b|\b(?:const|let|var)\s+deriveLocal\s*=")
_PANEL_TOKEN_SHA = re.compile(r"\bpanelTokenSha256\b")
_CLASSIC_FNV = re.compile(r"\b0x811c9dc5\b|\b2166136261\b|\b0x01000193\b|\b16777619\b", re.I)


def lint_panel_derive(text: str, file_path: Path) -> list[dict[str, str]]:
    s = text[:500_000]
    findings: list[dict[str, str]] = []
    if _STABLE_PANEL_DERIVE.search(s):
        findings.append(
            {
                "id": "stable-panel-derive-global",
                "severity": "error",
                "summary": "Stable __vaultPanelDerive global survived in bundle.",
            }
        )
    has_local = bool(_LOCAL_DERIVE_DECL.search(s))
    if has_local:
        findings.append(
            {
                "id": "stable-local-derive",
                "severity": "error",
                "summary": "Stable local deriveLocal entrypoint survived in bundle.",
            }
        )
    if _CLASSIC_FNV.search(s):
        findings.append(
            {
                "id": "classic-fnv-prime-literal",
                "severity": "warning",
                "summary": "Classic FNV prime literal present near panel/token logic.",
            }
        )
    has_sha = bool(_PANEL_TOKEN_SHA.search(s))
    sibling_sha = False
    for name in ("seal.json", "bla-seal.json", ".bla-seal.json"):
        sp = file_path.parent / name
        if sp.is_file():
            try:
                if _PANEL_TOKEN_SHA.search(sp.read_text(encoding="utf-8", errors="replace")):
                    sibling_sha = True
                    break
            except OSError:
                pass
    if has_local and (has_sha or sibling_sha):
        findings.append(
            {
                "id": "panel-token-sha-oracle",
                "severity": "error",
                "summary": "Callable deriveLocal paired with plaintext panelTokenSha256 creates an offline oracle.",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Gate 9: plaintext-secret
# ---------------------------------------------------------------------------
_TARGET_SECRET_BASENAME = re.compile(
    r"^(?:panel\.html?|license\.cjs|license\.js|vault\.cjs|vault\.js|gate\.cjs|gate\.js|auth\.cjs|auth\.js|entitlement\.cjs|entitlement\.js|activate\.cjs|activate\.js)$",
    re.I,
)
_STRING_LIT_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\$]|\$(?!\{))*`")
_DERIVE_KEYNAME_RE = re.compile(r"\b(?:deriveLocal|panelTokenSha256|unwrapKey|unlockFlag|secretKey|masterKey|licenseKey)\b")


def _shannon_entropy(val: str) -> float:
    if not val:
        return 0.0
    counts: dict[str, int] = {}
    for ch in val:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(val)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def lint_plaintext_secrets(text: str, file_path: Path) -> list[dict[str, str]]:
    if not (_TARGET_SECRET_BASENAME.match(file_path.name) or re.search(r"(?:panel|license|vault|auth|gate|entitlement)", file_path.name, re.I)):
        return []
    s = text[:800_000]
    findings: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in _STRING_LIT_RE.finditer(s):
        lit = m.group(0)[1:-1]
        if len(lit) < 8:
            continue
        fid: str | None = None
        if re.search(r"FLAG\{[A-Za-z0-9_\-]{6,}\}", lit):
            fid = "plaintext-flag-literal"
        elif re.search(r"-----BEGIN [A-Z0-9 ]+-----", lit):
            fid = "plaintext-pem-header"
        elif len(lit) >= 24 and re.fullmatch(r"[0-9a-fA-F]+", lit) and len(lit) % 2 == 0:
            fid = "plaintext-b64-or-hex"
        elif len(lit) >= 16 and _shannon_entropy(lit) >= 4.0 and " " not in lit:
            fid = "plaintext-high-entropy"
        elif _DERIVE_KEYNAME_RE.search(lit):
            fid = "plaintext-derive-keyname"
        if fid and fid not in seen:
            seen.add(fid)
            findings.append(
                {
                    "id": fid,
                    "severity": "error",
                    "summary": f"Cleartext sensitive literal pattern ({fid}) in {file_path.name} (redacted).",
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Gate 10: release-hygiene (never stores or echoes secret values)
# ---------------------------------------------------------------------------
_SOLUTION_NAMES = frozenset({"solution.md", "solution.txt", "writeup.md", "flag.txt", "answer.txt"})
_DOTENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
_PRIVKEY_NAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"})
_DEBUG_SYM_EXTS = frozenset({".pdb", ".dwp", ".dsym", ".ilg"})
_ENV_ASSIGN_RE = re.compile(r"(?:^|\r?\n)\s*[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE|FLAG)[A-Z0-9_]*\s*=\s*\S+", re.I)


def lint_release_hygiene_file(path: Path) -> list[dict[str, str]]:
    lower = path.name.lower()
    ext = path.suffix.lower()
    findings: list[dict[str, str]] = []
    if lower in _SOLUTION_NAMES:
        findings.append(
            {
                "id": "leaked-solution-or-writeup",
                "severity": "error",
                "summary": f"Residual solution/writeup file '{path.name}' shipped in artifact directory.",
            }
        )
    is_dotenv = lower.startswith(".") and (
        lower[1:] == "env"
        or (lower[1:].startswith("env.") and not lower.endswith(_DOTENV_TEMPLATE_SUFFIXES))
    )
    if is_dotenv:
        try:
            with path.open("rb") as fh:
                head = fh.read(4096).decode("utf-8", errors="replace")
        except OSError:
            head = ""
        if _ENV_ASSIGN_RE.search(head):
            findings.append(
                {
                    "id": "leaked-dotenv-secrets",
                    "severity": "error",
                    "summary": f"Dotenv file '{path.name}' contains populated secret/key/token assignment (value redacted).",
                }
            )
    if lower in _PRIVKEY_NAMES:
        findings.append(
            {
                "id": "leaked-private-key",
                "severity": "error",
                "summary": f"Private key file '{path.name}' present in target directory.",
            }
        )
    elif ext in {".pem", ".key", ".p8"}:
        try:
            with path.open("rb") as fh:
                head = fh.read(4096).decode("utf-8", errors="replace")
        except OSError:
            head = ""
        if "PRIVATE KEY-----" in head:
            findings.append(
                {
                    "id": "leaked-private-key",
                    "severity": "error",
                    "summary": f"PEM private key '{path.name}' present in target directory.",
                }
            )
    if ext in _DEBUG_SYM_EXTS:
        findings.append(
            {
                "id": "leaked-debug-symbols",
                "severity": "warning",
                "summary": f"Unstripped debug database '{path.name}' shipped in target directory.",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Defense-score honesty soft-caps & coverage contract
# ---------------------------------------------------------------------------
def compute_honesty_soft_cap(
    raw_score: int,
    *,
    has_js: bool,
    has_wasm: bool,
    self_seal_enabled: bool = False,
    wasm_export_rename_applied: bool = False,
    sidecar_entangle_enabled: bool = False,
) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    if has_wasm and not wasm_export_rename_applied:
        gaps.append(
            {
                "id": "wasm-export-rename-pending",
                "scoreCap": 88,
                "summary": "WASM export rename not applied; public ABI names remain inspectable.",
            }
        )
    if has_js and not self_seal_enabled:
        gaps.append(
            {
                "id": "self-seal-not-enabled",
                "scoreCap": 92,
                "summary": "Self-seal sibling-module integrity binding not enabled for JS/HTML artifacts.",
            }
        )
    if (has_js or has_wasm) and not sidecar_entangle_enabled:
        gaps.append(
            {
                "id": "sidecar-entangle-not-enabled",
                "scoreCap": 93,
                "summary": "Opt-in sidecarEntangle strip->fail binding not enabled.",
            }
        )
    clamped = max(0, min(100, int(raw_score)))
    capped = clamped
    applied_cap: int | None = None
    for g in gaps:
        if capped > g["scoreCap"]:
            capped = g["scoreCap"]
            applied_cap = g["scoreCap"]
    return {
        "rawScore": clamped,
        "cappedScore": capped,
        "appliedCap": applied_cap,
        "gaps": gaps,
        "disclaimer": DEFENSE_SCORE_DISCLAIMER,
    }


def run_packaging_gates(target: Path) -> dict[str, Any]:
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")
    files = walk_bounded_files(target)
    gate_Order = (
        "lane-independence",
        "seal-commitment",
        "wasm-param-carrier",
        "js-aes-unwrap",
        "js-wasm-hydrate-dump",
        "wasm-xor-mask-sidecar",
        "wasm-seal-xor-known-plaintext",
        "panel-derive",
        "plaintext-secret",
        "release-hygiene",
    )
    buckets: dict[str, list[dict[str, Any]]] = {g: [] for g in gate_Order}
    has_js = False
    has_wasm = False

    base_dir = target if target.is_dir() else target.parent
    for fpath in files:
        rel = fpath.relative_to(base_dir).as_posix()
        ext = fpath.suffix.lower()

        for item in lint_release_hygiene_file(fpath):
            buckets["release-hygiene"].append({"file": rel, **item})

        if ext == ".json":
            for item in lint_seal_commitment(fpath):
                buckets["seal-commitment"].append({"file": rel, **item})

        if ext in JS_HTML_EXT:
            has_js = True
            try:
                txt = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                txt = ""
            if ext in JS_ONLY_EXT:
                for item in lint_lane_independence(txt):
                    buckets["lane-independence"].append({"file": rel, **item})
                for item in lint_js_aes_unwrap(txt):
                    buckets["js-aes-unwrap"].append({"file": rel, **item})
                for item in lint_js_wasm_hydrate_dump(txt):
                    buckets["js-wasm-hydrate-dump"].append({"file": rel, **item})
            for item in lint_panel_derive(txt, fpath):
                buckets["panel-derive"].append({"file": rel, **item})
            for item in lint_plaintext_secrets(txt, fpath):
                buckets["plaintext-secret"].append({"file": rel, **item})

        if ext == ".wasm":
            has_wasm = True
            try:
                buf = fpath.read_bytes()
            except OSError:
                buf = b""
            for item in lint_wasm_param_carrier(buf):
                buckets["wasm-param-carrier"].append({"file": rel, **item})
            for item in lint_wasm_xor_mask_sidecar(buf):
                buckets["wasm-xor-mask-sidecar"].append({"file": rel, **item})
            for item in lint_wasm_seal_xor_known_plaintext(fpath, buf):
                buckets["wasm-seal-xor-known-plaintext"].append({"file": rel, **item})

    gates_out: list[dict[str, Any]] = []
    flat_findings: list[dict[str, str]] = []
    error_gates = 0
    for gid in gate_Order:
        items = buckets[gid]
        has_err = any(x["severity"] == "error" for x in items)
        if has_err:
            error_gates += 1
        gates_out.append(
            {
                "gate": gid,
                "finding_count": len(items),
                "should_refuse_bankrupt": has_err,
                "findings": items,
            }
        )
        for x in items:
            flat_findings.append(
                {
                    "code": f"GATE-{gid.upper()}",
                    "severity": "high" if x["severity"] == "error" else "medium",
                    "tier": "Tier 2 / Tier 4",
                    "title": f"[{gid}] {x['id']} in {x['file']}",
                    "evidence": f"{x['file']} ({x['id']})",
                    "remediation": x["summary"],
                }
            )

    raw_score = max(0, 100 - (error_gates * 10))
    honesty = compute_honesty_soft_cap(raw_score, has_js=has_js, has_wasm=has_wasm)
    rea_limits = load_rea_internal_limits()

    return {
        "schema": PACKAGING_GATES_SCHEMA,
        "target": str(target.resolve()),
        "scanned_files": len(files),
        "rea_limits_count": len(rea_limits),
        "counter_rea_vectors": COUNTER_REA_VECTORS_COUNT,
        "gates": gates_out,
        "honesty": honesty,
        "coverage_contract": {
            "clientArtifact": {
                "scope": "static-reverse-engineering-and-automated-inspection-friction",
                "guaranteesConfidentialityOfShippedData": False,
                "enforcesAccessControl": False,
            },
            "serverAuthorization": {
                "responsibility": "external-application-backend",
            },
        },
        "finding_count": len(flat_findings),
        "findings": flat_findings,
    }
