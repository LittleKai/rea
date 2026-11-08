#!/usr/bin/env python3
# Source: https://github.com/zhaoxuya520/reverse-skill@cab634bd855fc287f6e420c1f36fd1a6b9245960 | License: MIT
"""Review a reverse-engineering case directory for scope, traceability, and Evidence SHA-256 integrity."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"

EVIDENCE_ID = re.compile(r"\bE-[A-Za-z0-9][A-Za-z0-9_-]*\b")
WORKITEM_ID = re.compile(r"\bW(?:I)?-[A-Za-z0-9][A-Za-z0-9_-]*\b")
FINDING_ID = re.compile(r"\bF-[A-Za-z0-9][A-Za-z0-9_-]*\b")
PATH_ID = re.compile(r"\bP-[A-Za-z0-9][A-Za-z0-9_-]*\b")
FIELD_LINE = re.compile(r"^\s*-\s+([A-Za-z0-9_]+):\s*(.*)$")
SECTION_HEADING = re.compile(r"^#{2,6}\s+(.+?)\s*$")
EVIDENCE_HEADING = re.compile(r"^#{1,3}\s+(E-[A-Za-z0-9][A-Za-z0-9_-]*)\b", re.MULTILINE)
FINDING_HEADING = re.compile(r"^#{1,3}\s+(F-[A-Za-z0-9][A-Za-z0-9_-]*)\b", re.MULTILINE)
PATH_HEADING = re.compile(r"^#{1,3}\s+(P-[A-Za-z0-9][A-Za-z0-9_-]*)\b", re.MULTILINE)

SEVERITIES = {"critical", "high", "medium", "low", "info", "n/a", "n/a_re"}
EVIDENCE_STATUSES = {
    "observed",
    "candidate",
    "validated",
    "confirmed",
    "verified",
    "false_positive",
    "accepted_risk",
    "superseded",
}
WORKITEM_STATUSES = {"pending", "in_progress", "blocked", "done", "completed", "cancelled"}
PATH_TYPES = {"attack", "callflow", "solve", "verification", "verified"}
NETWORK_MODES = {"offline", "lab_only", "authorized_target_only", "unrestricted_lab"}


def field_value(text: str, name: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = FIELD_LINE.match(line)
        if not match or match.group(1).lower() != name.lower():
            continue
        value = match.group(2).strip()
        if value != "|":
            return value
        block: list[str] = []
        for continuation in lines[index + 1 :]:
            if FIELD_LINE.match(continuation):
                break
            if SECTION_HEADING.match(continuation):
                break
            if continuation.strip():
                block.append(continuation.strip())
        return "\n".join(block).strip()
    return ""


def first_field(text: str, *names: str) -> str:
    for name in names:
        val = field_value(text, name)
        if val:
            return val
    return ""


def section_text(text: str, title: str) -> str:
    pattern = re.compile(r"(?ms)^##\s+" + re.escape(title) + r"\s*$\n?(.*?)(?=^##\s|\Z)")
    match = pattern.search(text)
    return match.group(1) if match else ""


def ids_in(value: str, pattern: re.Pattern[str]) -> list[str]:
    return sorted(set(pattern.findall(value or "")))


def issue(issues: list[dict[str, str]], level: str, code: str, message: str, path: str = "") -> None:
    issues.append({"level": level, "code": code, "message": message, "path": path})


def relative_path(root: Path, path: Path) -> str:
    try:
        norm_root = Path(os.path.normcase(str(root.resolve())))
        norm_path = Path(os.path.normcase(str(path.resolve())))
        rel_parts = norm_path.relative_to(norm_root).parts
        orig_parts = path.resolve().parts[-len(rel_parts) :] if rel_parts else ()
        return Path(*orig_parts).as_posix() if orig_parts else "."
    except ValueError:
        return str(path)


def split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def parse_workitems(root: Path, issues: list[dict[str, str]]) -> tuple[dict[str, dict[str, object]], list[tuple[str, str]]]:
    path = root / "workitems.md"
    records: dict[str, dict[str, object]] = {}
    references: list[tuple[str, str]] = []
    if not path.is_file():
        issue(issues, "error", "workitems.missing", "workitems.md is missing", "workitems.md")
        return records, references

    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        cells = split_table_row(line)
        if len(cells) >= 8 and WORKITEM_ID.fullmatch(cells[0]):
            workitem_id = cells[0]
            status = cells[5].lower()
            if status not in WORKITEM_STATUSES:
                issue(
                    issues,
                    "error",
                    "workitem.status",
                    "unsupported work item status: " + status,
                    f"workitems.md:{line_number}",
                )
            evidence_ids = ids_in(cells[6], EVIDENCE_ID)
            records[workitem_id] = {"status": status, "evidence_ids": evidence_ids}
            references.extend((eid, f"workitems.md:{line_number}") for eid in evidence_ids)
            continue

        bullet_m = re.match(r"^\s*-\s*\[([ xX~])\]\s*(W(?:I)?-[A-Za-z0-9_-]+)\b(.*)$", line)
        if bullet_m:
            mark, workitem_id, rest = bullet_m.groups()
            status = "done" if mark.lower() == "x" else ("in_progress" if mark == "~" else "pending")
            evidence_ids = ids_in(rest, EVIDENCE_ID)
            records[workitem_id] = {"status": status, "evidence_ids": evidence_ids}
            references.extend((eid, f"workitems.md:{line_number}") for eid in evidence_ids)

    if not records:
        issue(issues, "warning", "workitems.empty", "no work item rows were found", "workitems.md")
    return records, references


def parse_timeline(root: Path, issues: list[dict[str, str]]) -> tuple[int, list[tuple[str, str]]]:
    path = root / "timeline.md"
    references: list[tuple[str, str]] = []
    events = 0
    if not path.is_file():
        issue(issues, "error", "timeline.missing", "timeline.md is missing", "timeline.md")
        return events, references

    lines = path.read_text(encoding="utf-8-sig").splitlines()
    for index, line in enumerate(lines):
        if line.startswith("## ") and "|" in line:
            events += 1
            end = len(lines)
            for next_index in range(index + 1, len(lines)):
                if lines[next_index].startswith("## "):
                    end = next_index
                    break
            body = "\n".join(lines[index:end])
            evidence_ids = ids_in(field_value(body, "evidence_ids") or body, EVIDENCE_ID)
            references.extend((eid, f"timeline.md:{index + 1}") for eid in evidence_ids)
        elif re.match(r"^\s*-\s+\d{4}-\d{2}-\d{2}", line):
            events += 1
            evidence_ids = ids_in(line, EVIDENCE_ID)
            references.extend((eid, f"timeline.md:{index + 1}") for eid in evidence_ids)

    if events == 0:
        issue(issues, "warning", "timeline.empty", "no append-only timeline events were found", "timeline.md")
    return events, references


def parse_scope(root: Path, issues: list[dict[str, str]], strict: bool) -> dict[str, object]:
    path = root / "scope.md"
    result: dict[str, object] = {"auth_status": "", "network_mode": "", "ready_for_act": "", "assets": []}
    if not path.is_file():
        issue(issues, "error", "scope.missing", "scope.md is missing", "scope.md")
        return result

    text = path.read_text(encoding="utf-8-sig")
    auth = section_text(text, "auth")
    scope_section = section_text(text, "in_scope")
    network = section_text(text, "network_profile")
    signoff = section_text(text, "signoff")

    if auth or network or signoff:
        result["auth_status"] = field_value(auth, "status").lower()
        result["network_mode"] = field_value(network, "mode").lower()
        result["ready_for_act"] = field_value(signoff, "ready_for_act").lower()
        assets_match = re.search(
            r"(?ms)^\s*-\s+assets:\s*\n(?P<body>.*?)(?=^-\s+[A-Za-z0-9_]+:|\Z)",
            scope_section,
        )
        if assets_match:
            result["assets"] = [
                line.strip()[2:].strip()
                for line in assets_match.group("body").splitlines()
                if re.match(r"^\s+-\s+\S+", line) and line.strip()[2:].strip() != "[]"
            ]

        if not result["auth_status"]:
            issue(issues, "error", "scope.auth_missing", "auth.status is missing", "scope.md")
        elif result["auth_status"] not in {"pending", "granted", "denied", "unknown"}:
            issue(issues, "error", "scope.auth_invalid", "unsupported auth.status: " + str(result["auth_status"]), "scope.md")

        if not result["network_mode"]:
            issue(issues, "error", "scope.network_missing", "network_profile.mode is missing", "scope.md")
        elif result["network_mode"] not in NETWORK_MODES:
            issue(issues, "error", "scope.network_invalid", "unsupported network mode: " + str(result["network_mode"]), "scope.md")

        if not result["ready_for_act"]:
            issue(issues, "error", "scope.ready_missing", "signoff.ready_for_act is missing", "scope.md")
        elif result["ready_for_act"] not in {"true", "false"}:
            issue(issues, "error", "scope.ready_invalid", "ready_for_act must be true or false", "scope.md")

        if result["network_mode"] != "offline" and not result["assets"]:
            issue(issues, "error", "scope.assets_missing", "in_scope.assets is empty for a network case", "scope.md")

        if result["auth_status"] != "granted" or result["ready_for_act"] != "true":
            message = "scope is not ready for target ACT"
            if strict and result["network_mode"] != "offline":
                issue(issues, "error", "scope.not_ready", message, "scope.md")
            else:
                issue(issues, "warning", "scope.not_ready", message, "scope.md")
    else:
        target_val = first_field(text, "target", "asset")
        auth_val = first_field(text, "authorization", "auth_status", "status").lower()
        result["auth_status"] = "granted" if auth_val in {"local", "granted", "authorized", "true"} else (auth_val or "granted")
        result["network_mode"] = (first_field(text, "network_mode", "mode") or "offline").lower()
        result["ready_for_act"] = (first_field(text, "ready_for_act") or "true").lower()
        result["assets"] = [target_val] if target_val else []

    return result


def report_sections(text: str, heading_pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    matches = list(heading_pattern.finditer(text))
    sections: list[tuple[str, str]] = []
    for match in matches:
        end = len(text)
        for next_match in re.finditer(r"(?m)^#{1,3}\s+", text[match.end() :]):
            end = match.end() + next_match.start()
            break
        sections.append((match.group(1), text[match.start() : end]))
    return sections


def parse_reports(
    root: Path, issues: list[dict[str, str]]
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[tuple[str, str]]]:
    finding_records: list[dict[str, object]] = []
    path_records: list[dict[str, object]] = []
    references: list[tuple[str, str]] = []
    report_root = root / "report"
    report_files = sorted(report_root.rglob("*.md")) if report_root.is_dir() else []
    if not report_files:
        issue(issues, "warning", "report.missing", "no Markdown report was found", "report")
        return finding_records, path_records, references

    for report_path in report_files:
        text = report_path.read_text(encoding="utf-8-sig")
        rel_rep = relative_path(root, report_path)
        for finding_id, body in report_sections(text, FINDING_HEADING):
            status = (first_field(body, "status") or "validated").lower()
            confidence = (first_field(body, "confidence") or "high").lower()
            ev_raw = first_field(body, "evidence_ids", "evidence")
            evidence_ids = ids_in(ev_raw or body, EVIDENCE_ID)
            if status not in EVIDENCE_STATUSES:
                issue(issues, "error", "finding.status", finding_id + " has unsupported status", rel_rep)
            if status in {"validated", "confirmed"} and confidence == "low":
                issue(issues, "error", "finding.confidence", finding_id + " is validated with low confidence", rel_rep)
            if not evidence_ids:
                issue(issues, "error", "finding.evidence_missing", finding_id + " has no evidence_ids", rel_rep)
            references.extend((eid, rel_rep) for eid in evidence_ids)
            finding_records.append(
                {
                    "id": finding_id,
                    "status": status,
                    "evidence_ids": evidence_ids,
                    "path": rel_rep,
                }
            )

        for path_id, body in report_sections(text, PATH_HEADING):
            path_type = (first_field(body, "path_type", "status") or "callflow").lower()
            evidence_ids = ids_in(body, EVIDENCE_ID)
            if path_type not in PATH_TYPES:
                issue(issues, "error", "path.type", path_id + " has unsupported path_type", rel_rep)
            if not evidence_ids:
                issue(issues, "error", "path.evidence_missing", path_id + " has no evidence reference", rel_rep)
            references.extend((eid, rel_rep) for eid in evidence_ids)
            path_records.append(
                {
                    "id": path_id,
                    "path_type": path_type,
                    "evidence_ids": evidence_ids,
                    "path": rel_rep,
                }
            )
    return finding_records, path_records, references


def normalize_hash(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    if re.fullmatch(r"[0-9a-f]{64}", normalized):
        return normalized
    return ""


def is_within(root: Path, path: Path) -> bool:
    try:
        norm_root = os.path.normcase(str(Path(root).resolve()))
        norm_path = os.path.normcase(str(Path(path).resolve()))
        return os.path.commonpath([norm_root, norm_path]) == norm_root
    except ValueError:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(
    root: Path,
    artifact_path: str,
    expected_hash: str,
    issues: list[dict[str, str]],
    display_path: str,
) -> None:
    if not artifact_path:
        issue(
            issues,
            "warning",
            "artifact.path_missing",
            "content_hash is recorded without artifact_path",
            display_path,
        )
        return
    candidate = Path(artifact_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if not is_within(root.resolve(), candidate):
        issue(
            issues,
            "warning",
            "artifact.outside_case",
            "artifact_path points outside the case root",
            display_path,
        )
        return
    if not candidate.is_file():
        issue(issues, "error", "artifact.missing", "artifact_path does not exist", display_path)
        return
    digest = sha256_file(candidate)
    if digest != expected_hash:
        issue(
            issues,
            "error",
            "artifact.hash_mismatch",
            "artifact SHA-256 does not match content_hash",
            display_path,
        )


def parse_evidence(
    root: Path,
    workitems: dict[str, dict[str, object]],
    issues: list[dict[str, str]],
    verify_hashes: bool,
) -> tuple[dict[str, dict[str, str]], list[tuple[str, str]]]:
    evidence_root = root / "evidence"
    records: dict[str, dict[str, str]] = {}
    references: list[tuple[str, str]] = []
    if not evidence_root.is_dir():
        issue(issues, "error", "evidence.dir_missing", "evidence directory is missing", "evidence")
        return records, references

    evidence_files = sorted(path for path in evidence_root.glob("E-*.md") if path.name != "INDEX.md")
    if not evidence_files:
        issue(issues, "warning", "evidence.empty", "no Evidence records were found", "evidence")

    for path in evidence_files:
        evidence_id = path.stem
        text = path.read_text(encoding="utf-8-sig")
        rel_ev = relative_path(root, path)
        heading = EVIDENCE_HEADING.search(text)
        if not heading:
            issue(issues, "error", "evidence.heading_missing", "Evidence record has no matching heading", rel_ev)
        elif heading.group(1) != evidence_id:
            issue(issues, "error", "evidence.heading_mismatch", "Evidence heading does not match its filename", rel_ev)

        severity = (first_field(text, "severity") or "info").lower()
        status = (first_field(text, "status") or "validated").lower()
        if status.startswith("superseded by"):
            status = "superseded"
        repro_command = first_field(text, "repro_command", "reproduced", "locator")
        notes = first_field(text, "notes", "summary").lower()
        linked_workitems = ids_in(first_field(text, "linked_workitem"), WORKITEM_ID)
        content_hash_value = first_field(text, "content_hash", "sha256")
        artifact_path = first_field(text, "artifact_path", "source")

        if severity not in SEVERITIES:
            issue(issues, "error", "evidence.severity", "unsupported severity: " + severity, rel_ev)
        if status not in EVIDENCE_STATUSES:
            issue(issues, "error", "evidence.status", "unsupported status: " + status, rel_ev)
        offline_note = any(marker in notes for marker in ("offline", "not applicable", "verified"))
        if not repro_command or (repro_command.lower() in {"n/a", "n/a_re", "false"} and not offline_note):
            issue(
                issues,
                "error",
                "evidence.repro_missing",
                "Evidence requires a reproducible command/locator or documented offline limitation",
                rel_ev,
            )
        expected_hash = normalize_hash(content_hash_value) if content_hash_value.lower() not in {"", "n/a"} else ""
        if content_hash_value.lower() not in {"", "n/a"} and not expected_hash:
            issue(issues, "error", "evidence.hash_invalid", "content_hash must be SHA-256", rel_ev)
        if verify_hashes and expected_hash:
            verify_artifact(root, artifact_path, expected_hash, issues, rel_ev)
        for workitem_id in linked_workitems:
            if workitem_id not in workitems:
                issue(
                    issues,
                    "error",
                    "evidence.workitem_missing",
                    "linked work item does not exist: " + workitem_id,
                    rel_ev,
                )
        records[evidence_id] = {
            "severity": severity,
            "status": status,
            "artifact_path": artifact_path,
        }

    return records, references


def build_traceability(
    evidence_ids: dict[str, dict[str, str]],
    references: list[tuple[str, str]],
) -> dict[str, dict[str, int]]:
    graph = {evidence_id: {"workitems": 0, "timeline": 0, "reports": 0} for evidence_id in sorted(evidence_ids)}
    for evidence_id, source in references:
        if evidence_id not in graph:
            continue
        if source.startswith("workitems.md:"):
            graph[evidence_id]["workitems"] += 1
        elif source.startswith("timeline.md:"):
            graph[evidence_id]["timeline"] += 1
        else:
            graph[evidence_id]["reports"] += 1
    return graph


def review_case(case_root: str | Path, strict: bool = False, verify_hashes: bool = False) -> dict[str, object]:
    root = Path(case_root).expanduser().resolve()
    issues: list[dict[str, str]] = []
    if not root.is_dir():
        issue(issues, "error", "case.missing", "case root does not exist", str(root))
        return {
            "status": "FAIL",
            "case_root": str(root),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "errors": 1,
                "warnings": 0,
                "evidence": 0,
                "workitems": 0,
                "timeline_events": 0,
                "findings": 0,
                "paths": 0,
            },
            "issues": issues,
            "findings": issues,
            "traceability": {},
        }

    workitems, workitem_refs = parse_workitems(root, issues)
    timeline_events, timeline_refs = parse_timeline(root, issues)
    scope = parse_scope(root, issues, strict)
    evidence, evidence_refs = parse_evidence(root, workitems, issues, verify_hashes)
    findings, paths, report_refs = parse_reports(root, issues)
    references = workitem_refs + timeline_refs + evidence_refs + report_refs

    for evidence_id, source in references:
        if evidence_id not in evidence:
            issue(
                issues,
                "error",
                "reference.unknown_evidence",
                "reference points to missing Evidence: " + evidence_id,
                source,
            )

    traceability = build_traceability(evidence, references)
    for evidence_id, links in traceability.items():
        if not any(links.values()):
            issue(
                issues,
                "warning",
                "evidence.unlinked",
                "Evidence is not referenced by a work item, timeline, or report",
                "evidence/" + evidence_id + ".md",
            )

    errors = sum(1 for item in issues if item["level"] == "error")
    warnings = sum(1 for item in issues if item["level"] == "warning")
    status = "FAIL" if errors or (strict and warnings) else "WARN" if warnings else "PASS"
    return {
        "status": status,
        "case_root": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "summary": {
            "errors": errors,
            "warnings": warnings,
            "evidence": len(evidence),
            "workitems": len(workitems),
            "timeline_events": timeline_events,
            "findings": len(findings),
            "paths": len(paths),
        },
        "issues": issues,
        "findings": issues,
        "traceability": traceability,
    }


def render_markdown(report: dict[str, object]) -> str:
    summary = report["summary"]
    assert isinstance(summary, dict)
    issues = report["issues"]
    assert isinstance(issues, list)
    traceability = report["traceability"]
    assert isinstance(traceability, dict)

    lines = [
        "# Case review",
        "",
        "- status: " + str(report["status"]),
        "- case_root: " + str(report["case_root"]),
        "- generated_at: " + str(report["generated_at"]),
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key in ("errors", "warnings", "evidence", "workitems", "timeline_events", "findings", "paths"):
        lines.append("| " + key + " | " + str(summary[key]) + " |")

    lines.extend(["", "## Checks", "", "| Level | Code | Location | Detail |", "|---|---|---|---|"])
    if issues:
        for item in issues:
            location = str(item["path"]).replace("|", "\\|")
            detail = str(item["message"]).replace("|", "\\|")
            lines.append("| " + str(item["level"]) + " | " + str(item["code"]) + " | " + location + " | " + detail + " |")
    else:
        lines.append("| pass | none | n/a | No review issues found |")

    lines.extend(["", "## Traceability", "", "| Evidence | Work items | Timeline | Reports |", "|---|---:|---:|---:|"])
    if traceability:
        for evidence_id, links in traceability.items():
            lines.append(
                "| "
                + str(evidence_id)
                + " | "
                + str(links["workitems"])
                + " | "
                + str(links["timeline"])
                + " | "
                + str(links["reports"])
                + " |"
            )
    else:
        lines.append("| n/a | 0 | 0 | 0 |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review a reverse-engineering case for scope and Evidence graph integrity")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("case_root", help="Path to a target case directory")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as a failed review")
    parser.add_argument(
        "--verify-hashes",
        action="store_true",
        help="Verify SHA-256 content_hash/sha256 values against artifact_path/source",
    )
    args = parser.parse_args(argv)
    report = review_case(args.case_root, strict=args.strict, verify_hashes=args.verify_hashes)
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(report), end="")
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
