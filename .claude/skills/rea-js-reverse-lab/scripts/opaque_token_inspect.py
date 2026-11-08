#!/usr/bin/env python3
# Source: https://github.com/WhiteNightShadow/hello_js_reverse_skill@9fb8e001d68a5e0b83f12285950f667f219623a9 | License: CC0-1.0
"""Inspect a batch of opaque tokens without assuming any site or SDK.

Reports text shape, decoded byte statistics, stable byte runs aligned from the
head and the tail, length-field candidates, optional per-token XOR masks, and
CRC32/Adler32 checksum key candidates.
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import sys
import zlib
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"
HEX = set("0123456789abcdefABCDEF")
STANDARD = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
URL_SAFE = (STANDARD - set("+/")) | set("-_")
CHECKSUMS = {"crc32": zlib.crc32, "adler32": zlib.adler32}


def extract_param(raw: str, param: str | None) -> str:
    if not param:
        return raw
    if "://" in raw or "?" in raw or "&" in raw or "=" in raw:
        query = urlsplit(raw).query if "://" in raw or "?" in raw else raw
        parsed = parse_qs(query, keep_blank_values=True)
        if param in parsed and parsed[param]:
            return parsed[param][0]
    return raw


def read_tokens(path: str, field: str | None = None, param: str | None = None) -> list[str]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        return [extract_param(str(item), param) for item in json.loads(text)]
    tokens: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if field:
            value = json.loads(line)
            for key in field.split("."):
                value = value[key]
            tokens.append(extract_param(str(value), param))
        else:
            tokens.append(extract_param(line.strip(), param))
    return tokens


def text_shape(tokens: list[str]) -> dict[str, object]:
    lengths = [len(token) for token in tokens]
    chars = set().union(*[set(token.rstrip("=")) for token in tokens]) if tokens else set()
    if chars <= HEX:
        guess = "hex"
    elif chars <= STANDARD:
        guess = "base64-or-custom-alphabet"
    elif chars <= URL_SAFE:
        guess = "base64url"
    else:
        guess = "other"
    return {
        "count": len(tokens),
        "length_min": min(lengths),
        "length_max": max(lengths),
        "distinct_lengths": len(set(lengths)),
        "all_length_multiple_of_4": all(n % 4 == 0 for n in lengths),
        "has_padding": any(token.endswith("=") for token in tokens),
        "distinct_chars": len(chars),
        "guess": guess,
    }


def decode_custom(token: str, alphabet: str) -> bytes:
    if not alphabet or len(alphabet) != 64 or len(set(alphabet)) != 64:
        raise ValueError("custom alphabet must contain exactly 64 distinct characters")
    table = {char: index for index, char in enumerate(alphabet)}
    bits = count = 0
    output = bytearray()
    for char in token.rstrip("="):
        if char not in table:
            raise ValueError(f"character {char!r} not in custom alphabet")
        bits = (bits << 6) | table[char]
        count += 6
        if count >= 8:
            count -= 8
            output.append((bits >> count) & 0xFF)
    return bytes(output)


def decode_token(token: str, encoding: str, alphabet: str | None = None) -> bytes:
    if encoding == "auto":
        shape = str(text_shape([token])["guess"])
        if shape == "hex" and len(token) % 2 == 0:
            encoding = "hex"
        elif shape == "base64url":
            encoding = "base64url"
        elif shape == "base64-or-custom-alphabet":
            encoding = "base64"
        else:
            encoding = "raw"
    if encoding == "hex":
        return bytes.fromhex(token)
    if encoding in ("raw", "none"):
        return token.encode("utf-8")
    if encoding == "custom":
        if not alphabet:
            raise ValueError("--encoding custom requires --alphabet")
        return decode_custom(token, alphabet)
    stripped = token.rstrip("=")
    padded = stripped + "=" * (-len(stripped) % 4)
    return base64.urlsafe_b64decode(padded) if encoding == "base64url" else base64.b64decode(padded)


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(value ^ key for value in data)


def anchor_score(rows: list[bytes], anchor: int) -> int:
    size = len(rows[0])
    return sum(1 for index in range(size) if len({row[index] ^ row[anchor] for row in rows}) == 1)


def align_xor(items: list[bytes], max_anchors: int = 64) -> tuple[list[int], int | None, float]:
    """Remove a per-token single-byte mask without knowing any key."""
    size = min(len(item) for item in items)
    best: tuple[int, int | None, list[bytes] | None] = (0, None, None)
    for tail in (False, True):
        rows = [item[-size:] if tail else item[:size] for item in items]
        for anchor in range(min(max_anchors, size)):
            position = size - 1 - anchor if tail else anchor
            score = anchor_score(rows, position)
            if score > best[0]:
                best = (score, position, rows)
    score, anchor, rows = best
    if rows is None or anchor is None or size == 0:
        return [0] * len(items), None, 0.0
    return [row[anchor] ^ rows[0][anchor] for row in rows], anchor, round(score / size, 4)


def pairwise_xor_alignment(items: list[bytes]) -> list[dict[str, str]]:
    if len(items) < 2:
        return []
    min_len = min(len(x) for x in items)
    results: list[dict[str, str]] = []
    base = items[0]
    for other in items[1:]:
        head_xor = bytes(a ^ b for a, b in zip(base[:min_len], other[:min_len])).hex()
        tail_xor = bytes(a ^ b for a, b in zip(base[-min_len:], other[-min_len:])).hex()
        results.append({"head": head_xor, "tail": tail_xor})
    return results


def find_reference_key(reference: bytes, magic: bytes, offset: int) -> list[int]:
    size = len(magic)
    return [key for key in range(256) if xor_bytes(reference[offset : offset + size], key) == magic]


def checksum_key(
    reference: bytes,
    name: str,
    offset: int = 0,
    size: int = 4,
    checksum_at: str = "head",
    endian: str | None = None,
) -> list[dict[str, object]]:
    if name not in CHECKSUMS or len(reference) <= size:
        return []
    keys: list[dict[str, object]] = []
    orders = (endian,) if endian in ("little", "big") else ("little", "big")
    for key in range(256):
        data = xor_bytes(reference, key)
        if checksum_at == "tail":
            stored = data[-size:]
            payload = data[:-size]
        else:
            stored = data[offset : offset + size]
            payload = data[offset + size :]
        computed = CHECKSUMS[name](payload) & 0xFFFFFFFF
        for order in orders:
            stored_val = int.from_bytes(stored, order)
            if stored_val == computed:
                keys.append({"key": key, "endian": order, "hex": f"0x{key:08x}"})
            elif key == 0:
                xor_diff = (stored_val ^ computed) & 0xFFFFFFFF
                keys.append({"key": xor_diff, "endian": order, "hex": f"0x{xor_diff:08x}"})
    return keys


def stable_runs(items: list[bytes], tail: bool = False, min_run: int = 2) -> list[dict[str, object]]:
    size = min(len(item) for item in items)
    rows = [item[-size:] if tail and size else item[:size] for item in items]
    runs: list[dict[str, object]] = []
    start: int | None = None
    for index in range(size + 1):
        stable = index < size and len({row[index] for row in rows}) == 1
        if stable and start is None:
            start = index
        elif not stable and start is not None:
            if index - start >= min_run:
                offset = start - size if tail else start
                runs.append({"offset": offset, "length": index - start, "hex": rows[0][start:index].hex()})
            start = None
    return runs


def stable_positions(items: list[bytes], tail: bool = False) -> list[int]:
    if len(items) < 2:
        return []
    size = min(len(item) for item in items)
    rows = [item[-size:] if tail and size else item[:size] for item in items]
    return [idx - size if tail else idx for idx in range(size) if len({row[idx] for row in rows}) == 1]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum(count / len(data) * math.log2(count / len(data)) for count in counts.values())


def length_fields(items: list[bytes], max_offset: int = 32, max_delta: int = 64) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    min_size = min(len(item) for item in items)
    limit = min(max_offset, max(min_size - 1, 0))
    for offset in range(limit):
        for width in (1, 2, 4):
            if offset + width > min_size:
                continue
            for order in ("little", "big"):
                if width == 1 and order == "big":
                    continue
                deltas = {len(item) - int.from_bytes(item[offset : offset + width], order) for item in items}
                if len(deltas) == 1 and 0 <= next(iter(deltas)) <= max_delta:
                    found.append({"offset": offset, "width": width, "endian": order, "delta": next(iter(deltas))})
    return found


def analyze(tokens: list[str], args: argparse.Namespace) -> dict[str, object]:
    shape = text_shape(tokens)
    report: dict[str, object] = {
        "count": len(tokens),
        "encoding": args.encoding,
        "text": shape,
    }
    items = [decode_token(token, args.encoding, args.alphabet) for token in tokens]
    if args.xor_align and len(items) > 1:
        keys, anchor, stable_ratio = align_xor(items)
        reference_key = 0
        xor_info: dict[str, object] = {
            "relative_keys": keys,
            "anchor": anchor,
            "stable_position_ratio": stable_ratio,
        }
        if args.magic:
            candidates = find_reference_key(items[0], bytes.fromhex(args.magic), args.magic_offset)
            xor_info["reference_key_candidates"] = candidates
            reference_key = candidates[0] if candidates else 0
        if args.checksum and args.checksum != "none":
            matches = checksum_key(
                items[0],
                args.checksum,
                offset=args.checksum_offset,
                checksum_at=args.checksum_at,
                endian=args.endian,
            )
            xor_info["checksum_matches"] = matches
            if matches and not args.magic and int(matches[0]["key"]) < 256:
                reference_key = int(matches[0]["key"])
        report["xor"] = xor_info
        report["xor_alignment"] = pairwise_xor_alignment(items)
        if any(k != 0 for k in keys):
            items = [xor_bytes(item, key ^ reference_key) for item, key in zip(items, keys)]

    if args.checksum and args.checksum != "none":
        matches = checksum_key(
            items[0],
            args.checksum,
            offset=args.checksum_offset,
            checksum_at=args.checksum_at,
            endian=args.endian,
        )
        report["checksum_key_candidates"] = [str(m["hex"]) for m in matches]

    joined = b"".join(items)
    min_len = min(map(len, items))
    max_len = max(map(len, items))
    avg_ent = round(sum(map(entropy, items)) / len(items), 3)
    report["min_len"] = min_len
    report["max_len"] = max_len
    report["avg_entropy"] = avg_ent
    report["bytes"] = {
        "length_min": min_len,
        "length_max": max_len,
        "mean_entropy_bits": avg_ent,
        "zero_byte_ratio": round(joined.count(0) / len(joined), 4) if joined else 0.0,
    }
    report["samples"] = [{"length": len(item), "hex": item.hex(), "entropy": round(entropy(item), 3)} for item in items]
    if len(items) > 1:
        report["head_stable_positions"] = stable_positions(items, tail=False)
        report["tail_stable_positions"] = stable_positions(items, tail=True)
        report["head_stable_runs"] = stable_runs(items, min_run=args.min_run)
        report["tail_stable_runs"] = stable_runs(items, tail=True, min_run=args.min_run)
        report["length_field_candidates"] = length_fields(items)
    else:
        report["head_stable_positions"] = []
        report["tail_stable_positions"] = []
        report["length_field_candidates"] = []
    return report


def collect_input_tokens(args: argparse.Namespace) -> list[str]:
    tokens: list[str] = []
    for item in args.token:
        tokens.append(extract_param(item, args.param))
    if args.token_file:
        tokens.extend(read_tokens(args.token_file, args.field, args.param))
    for item in args.samples:
        p = Path(item)
        if item == "-" or (p.exists() and p.is_file()):
            tokens.extend(read_tokens(item, args.field, args.param))
        else:
            tokens.append(extract_param(item, args.param))
    return [t for t in tokens if t]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("samples", nargs="*", help="token strings, file path, or - for stdin")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--token", action="append", default=[], help="explicit token string (repeatable)")
    parser.add_argument("--token-file", help="path to file containing tokens (one per line or JSON array)")
    parser.add_argument("--param", help="extract token from URL query parameter name")
    parser.add_argument("--field", help="dotted field when each line is a JSON object")
    parser.add_argument(
        "--encoding",
        default="auto",
        choices=["auto", "none", "raw", "hex", "base64", "base64url", "custom"],
    )
    parser.add_argument("--alphabet", help="64-character alphabet for --encoding custom")
    parser.add_argument("--xor-align", action="store_true", help="align and remove per-token XOR masks")
    parser.add_argument("--magic", help="known bytes as hex to resolve absolute XOR key")
    parser.add_argument("--magic-offset", default=0, type=int)
    parser.add_argument("--checksum", choices=["none", *sorted(CHECKSUMS)], default="none")
    parser.add_argument("--checksum-at", choices=["head", "tail"], default="head")
    parser.add_argument("--checksum-offset", default=0, type=int)
    parser.add_argument("--endian", choices=["little", "big"], default="little")
    parser.add_argument("--min-run", default=2, type=int, help="shortest stable run to report")
    args = parser.parse_args()

    if args.encoding == "custom" and (not args.alphabet or len(args.alphabet) != 64 or len(set(args.alphabet)) != 64):
        parser.error("--encoding custom needs --alphabet with 64 distinct characters")

    try:
        tokens = collect_input_tokens(args)
        if not tokens:
            parser.error("no tokens found")
        print(json.dumps(analyze(tokens, args), ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
