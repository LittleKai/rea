#!/usr/bin/env python3
# Source: https://github.com/WhiteNightShadow/hello_js_reverse_skill@9fb8e001d68a5e0b83f12285950f667f219623a9 | License: CC0-1.0
"""Keep an auditable ledger of online attempts and verify single-variable claims.

record   append one attempt with an explicit outcome class
gate     decide whether another online attempt is allowed
summary  count attempts without merging different outcome classes
audit    compare two saved requests and report only SHA-256 hashes and lengths
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

VERSION = "1.0.0"
OUTCOMES = ("not_sent", "transport_error", "rejected", "accepted", "target_ok")
SENT_OUTCOMES = ("rejected", "accepted", "target_ok")
EXIT_BLOCKED = 2


def read_ledger(path: str | Path) -> list[dict[str, object]]:
    ledger_path = Path(path)
    if not ledger_path.exists():
        return []
    rows: list[dict[str, object]] = []
    with ledger_path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def cmd_record(args: argparse.Namespace) -> int:
    entry: dict[str, object] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "batch": args.batch,
        "variant": args.variant,
        "outcome": args.outcome,
        "attempts": args.attempts,
    }
    if args.hypothesis:
        entry["hypothesis"] = args.hypothesis
    if args.changed:
        entry["changed"] = args.changed
    if args.fixed:
        entry["fixed"] = args.fixed
    if args.evidence:
        entry["evidence"] = args.evidence
    if args.note:
        entry["note"] = args.note
    ledger = Path(args.ledger)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(json.dumps({"status": "recorded", **entry}, ensure_ascii=False))
    return 0


def parse_instant(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("--expires-at needs a timezone or unix seconds")
        return parsed.timestamp()


def cmd_gate(args: argparse.Namespace) -> int:
    rows = [row for row in read_ledger(args.ledger) if row.get("batch") == args.batch]
    sent = [row for row in rows if row.get("outcome") in SENT_OUTCOMES]
    reasons: list[str] = []
    if not args.allow_rejections and any(row.get("outcome") == "rejected" for row in rows):
        reasons.append("server_rejection_recorded")
    if any(row.get("attempts") == "unknown" for row in rows if row.get("outcome") != "not_sent"):
        reasons.append("attempts_unknown")
    if len(sent) >= args.budget:
        reasons.append("budget_exhausted")
    if bool(args.sdk_local) != bool(args.sdk_page):
        raise SystemExit("--sdk-local and --sdk-page must be given together")
    if args.sdk_local and args.sdk_local != args.sdk_page:
        reasons.append("sdk_mismatch")
    remaining: float | None = None
    if args.expires_at:
        remaining = parse_instant(args.expires_at) - time.time()
        if remaining < args.min_remaining:
            reasons.append("credential_expiring")
    reason = reasons[0] if reasons else "ok"
    result = {
        "allowed": not reasons,
        "reason": reason,
        "reasons": reasons,
        "batch": args.batch,
        "sent": len(sent),
        "sent_attempts": len(sent),
        "budget": args.budget,
        "credential_remaining_seconds": None if remaining is None else int(remaining),
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["allowed"] else EXIT_BLOCKED


def cmd_summary(args: argparse.Namespace) -> int:
    batches: dict[str, dict[str, object]] = {}
    for row in read_ledger(args.ledger):
        batch_id = str(row.get("batch", "default"))
        outcome = str(row.get("outcome", "unknown"))
        variant = str(row.get("variant", ""))
        info = batches.setdefault(
            batch_id,
            {
                "total_records": 0,
                "sent_attempts": 0,
                "outcomes": {name: 0 for name in OUTCOMES},
                "variants": [],
                "attempts_unknown": False,
            },
        )
        info["total_records"] = int(info["total_records"]) + 1
        if outcome in SENT_OUTCOMES:
            info["sent_attempts"] = int(info["sent_attempts"]) + 1
        outcomes_map = info["outcomes"]
        if isinstance(outcomes_map, dict):
            outcomes_map[outcome] = int(outcomes_map.get(outcome, 0)) + 1
        variants_list = info["variants"]
        if isinstance(variants_list, list) and variant and variant not in variants_list:
            variants_list.append(variant)
        info["attempts_unknown"] = bool(info["attempts_unknown"]) or (row.get("attempts") == "unknown")
    print(json.dumps({"batches": batches}, ensure_ascii=False, indent=2))
    return 0


def load_request(path: str | Path) -> dict[str, object]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    headers = data.get("headers", [])
    pairs = list(headers.items()) if isinstance(headers, dict) else [tuple(item) for item in headers]
    cookies_raw = data.get("cookies")
    return {
        "method": str(data.get("method", "GET")).upper(),
        "url": str(data.get("url", "")),
        "headers": [(str(name), str(value)) for name, value in pairs],
        "cookies": cookies_raw,
        "body": data.get("body"),
    }


def flatten(request: dict[str, object], strict_order: bool = False) -> dict[str, str]:
    """Map a request to named fields so differences can be reported one by one."""
    fields: dict[str, str] = {"method": str(request["method"])}
    url = urlsplit(str(request["url"]))
    fields["url.base"] = f"{url.scheme}://{url.netloc}{url.path}"
    query = parse_qsl(url.query, keep_blank_values=True)
    if strict_order:
        fields["query.order"] = json.dumps([name for name, _ in query])
    for name in sorted({k for k, _ in query}):
        fields[f"query:{name}"] = json.dumps([value for key, value in query if key == name])

    names: list[str] = []
    headers_list = request.get("headers")
    if isinstance(headers_list, list):
        for name, value in headers_list:
            lowered = str(name).lower()
            names.append(lowered)
            if lowered == "cookie":
                pairs = [part.strip().split("=", 1) for part in str(value).split(";") if part.strip()]
                if strict_order:
                    fields["cookie.order"] = json.dumps([pair[0] for pair in pairs])
                for pair in pairs:
                    fields[f"cookie:{pair[0]}"] = pair[1] if len(pair) == 2 else ""
            else:
                key = f"header:{lowered}"
                fields[key] = str(value) if key not in fields else fields[key] + "\n" + str(value)

    cookies_field = request.get("cookies")
    if isinstance(cookies_field, dict):
        for k, v in sorted(cookies_field.items()):
            fields[f"cookie:{k}"] = str(v)
    elif isinstance(cookies_field, str) and cookies_field.strip():
        pairs = [part.strip().split("=", 1) for part in cookies_field.split(";") if part.strip()]
        for pair in pairs:
            fields[f"cookie:{pair[0]}"] = pair[1] if len(pair) == 2 else ""

    if strict_order:
        fields["header.order"] = json.dumps(names)
    if request.get("body") is not None:
        body = request["body"]
        fields["body"] = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False, sort_keys=True)
    return fields


def mask(value: str | None) -> dict[str, object] | None:
    if value is None:
        return None
    raw = value.encode("utf-8", "surrogatepass")
    return {"sha256": hashlib.sha256(raw).hexdigest()[:16], "length": len(raw)}


def matches(field: str, patterns: list[str]) -> bool:
    short = field.split(":", 1)[1] if ":" in field else field
    return any(
        fnmatch.fnmatchcase(field.lower(), item.lower()) or fnmatch.fnmatchcase(short.lower(), item.lower())
        for item in patterns
    )


def cmd_audit(args: argparse.Namespace) -> int:
    base = flatten(load_request(args.base), strict_order=args.strict_order)
    candidate = flatten(load_request(args.candidate), strict_order=args.strict_order)
    changed = sorted(key for key in base.keys() | candidate.keys() if base.get(key) != candidate.get(key))
    rows = [{"field": key, "base": mask(base.get(key)), "candidate": mask(candidate.get(key))} for key in changed]
    allowed_patterns = list(args.allow) + list(args.must_change)
    allowed_changes = [key for key in changed if matches(key, allowed_patterns)] if allowed_patterns else []
    unexpected = (
        [key for key in changed if not matches(key, allowed_patterns)]
        if allowed_patterns
        else (changed if len(changed) != 1 else [])
    )
    missing = [item for item in args.must_change if not any(matches(key, [item]) for key in changed)]
    single_var_ok = (len(changed) == 1) and not unexpected and not missing
    result = {
        "changed_count": len(changed),
        "changed_fields": changed,
        "allowed_changes": allowed_changes,
        "unexpected_changes": unexpected,
        "missing_expected_changes": missing,
        "single_variable_confirmed": single_var_ok,
        "diffs": rows,
        "changed": rows,
        "unexpected": unexpected,
        "missing_change": missing,
        "order_changed": any(key.endswith(".order") for key in changed),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["single_variable_confirmed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    item = commands.add_parser("record")
    item.add_argument("--ledger", required=True)
    item.add_argument("--batch", required=True)
    item.add_argument("--variant", required=True)
    item.add_argument("--outcome", required=True, choices=OUTCOMES)
    item.add_argument(
        "--attempts",
        default=1,
        type=lambda v: v if v == "unknown" else int(v),
        help='real attempt count; use "unknown" when a helper may have retried',
    )
    item.add_argument("--hypothesis")
    item.add_argument("--changed", action="append", default=[])
    item.add_argument("--fixed", action="append", default=[])
    item.add_argument("--evidence")
    item.add_argument("--note")
    item.set_defaults(run=cmd_record)

    item = commands.add_parser("gate")
    item.add_argument("--ledger", required=True)
    item.add_argument("--batch", required=True)
    item.add_argument("--budget", required=True, type=int)
    item.add_argument(
        "--allow-rejections",
        action="store_true",
        help="pre-declared stability batch: rejections are measurements, only the budget stops it",
    )
    item.add_argument("--sdk-local", help="hash of the local SDK copy")
    item.add_argument("--sdk-page", help="hash of the SDK the page loads now")
    item.add_argument("--expires-at", help="credential expiry: unix seconds or ISO-8601 with timezone")
    item.add_argument("--min-remaining", default=60, type=int, help="seconds of credential life this batch needs")
    item.set_defaults(run=cmd_gate)

    item = commands.add_parser("summary")
    item.add_argument("--ledger", required=True)
    item.set_defaults(run=cmd_summary)

    item = commands.add_parser("audit")
    item.add_argument("--base", required=True, help="JSON file with method, url, headers and body")
    item.add_argument("--candidate", required=True)
    item.add_argument("--allow", action="append", default=[], help="field or name that may differ; globs allowed")
    item.add_argument("--must-change", action="append", default=[], help="field or name that has to differ")
    item.add_argument("--strict-order", action="store_true", help="include query/header/cookie order fields")
    item.set_defaults(run=cmd_audit)

    args = parser.parse_args()
    return int(args.run(args))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
