---
name: rea-case-review
version: "1.0.0"
description: Audit reverse-engineering case directories for Evidence-to-Finding traceability, scope compliance, and SHA-256 artifact fixity before finalizing reports.
allowed-tools: Read, Grep, Glob, Bash
---

# REA Reverse-Engineering Case Review (`rea-case-review`)

> Attribution: Derived from `zhaoxuya520/reverse-skill@cab634bd855fc287f6e420c1f36fd1a6b9245960` (`MIT`).

Use this skill to verify that a reverse-engineering target folder maintains complete `Evidence` provenance (`E-*` → `Finding F-*` → `Path P-*`), valid work item statuses, and intact SHA-256 artifact hashes before closing an investigation.

## Runtime Contract

Always invoke [`scripts/review_case.py`](scripts/review_case.py) with the locked Conda Python 3.12 runtime:

```powershell
D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B <path_to>/scripts/review_case.py <case_dir> --format json --verify-hashes --strict
```

## Case Directory Structure Checked by [`scripts/review_case.py`](scripts/review_case.py)

1. **`scope.md`** — Defines authorization status, network profile (`offline`, `lab_only`, `authorized_target_only`), and target assets.
2. **`workitems.md`** — Tracks investigation work items (`WI-001` or `W-001`) and linked `Evidence` IDs (`E-*`).
3. **`timeline.md`** — Append-only chronological log of investigation milestones and collected `Evidence` IDs.
4. **`evidence/E-*.md`** — Individual `Evidence` records containing:
   - Heading `# E-001` or `### E-001`
   - `artifact_path` (or `source`): Relative or inside-case path to the binary, trace, or snapshot
   - `content_hash` (or `sha256`): 64-hex SHA-256 digest verified on disk when `--verify-hashes` is passed
   - `repro_command` (or `locator` / `reproduced`): Deterministic reproduction command or address locator
5. **`report/*.md`** — Final Markdown report sections (`### F-001`, `### P-001`) whose claims must link to existing `E-*` records.

## Exit Codes & Verdict

- `status: "PASS"` (`exit 0`): All `E-*`, `F-*`, `P-*`, and `WI-*` links resolve and all `--verify-hashes` SHA-256 digests match on disk.
- `status: "WARN"` (`exit 0` without `--strict`, `exit 1` with `--strict`): Warnings found (such as unlinked `Evidence` records).
- `status: "FAIL"` (`exit 1`): Missing required files, broken `Evidence` references, or SHA-256 hash mismatch.
