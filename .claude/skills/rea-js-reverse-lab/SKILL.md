---
name: rea-js-reverse-lab
version: "1.0.0"
description: Analyze opaque tokens, JSVMP bytecode signers, and single-variable replay experiments for JavaScript/Electron/Web targets alongside REA. Use when inspecting custom Base64/XOR/CRC tokens, auditing request replay diffs without leaking secrets, or locking JS bundle SHA-256 baselines.
allowed-tools: Read, Write, Grep, Glob, Bash, WebFetch
---

# REA JavaScript Reverse Engineering Lab (`rea-js-reverse-lab`)

> Attribution: Derived from `WhiteNightShadow/hello_js_reverse_skill@9fb8e001d68a5e0b83f12285950f667f219623a9` (`CC0-1.0`).

Use this skill alongside REA's JavaScript and web investigation tools (`search_js_bundle`, `trace_js_function`, `capture_web_application`) when reversing opaque request tokens, JSVMP virtualized signers, or controlled request replay hypotheses.

## Runtime Contract

Always invoke the bundled CLI tools with the locked Conda Python 3.12 runtime:

```powershell
D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B <script_path> ...
```

## Bundled CLI Tools

1. **[`scripts/opaque_token_inspect.py`](scripts/opaque_token_inspect.py)** — Offline multi-sample opaque token analyzer:
   - Detects encoding (`hex`, `base64`, `base64url`, `raw`, or `--encoding custom --alphabet <64chars>`).
   - Computes byte-level Shannon entropy, head/tail stable byte positions (`head_stable_positions`, `tail_stable_positions`), and embedded length-field candidates (`length_field_candidates`).
   - Cancels per-token single-byte XOR masks (`--xor-align`) and solves CRC32/Adler32 key candidates (`--checksum crc32 --checksum-at tail --endian little`).
   - Extracts tokens directly from URLs via `--param <query_key>`.

2. **[`scripts/experiment_ledger.py`](scripts/experiment_ledger.py)** — Single-variable replay auditor and attempt budget gate:
   - `audit --base <json> --candidate <json> [--allow <pattern>...] [--must-change <pattern>...]`: Flattens HTTP requests (normalizing query order, header casing, and cookies), verifies `"single_variable_confirmed": true`, and masks all changed values to `{"sha256": "<16-hex>", "length": N}`.
   - `gate --ledger <jsonl> --batch <id> --budget <N> [--allow-rejections]`: Fails closed (`exit 2`) if budget is exhausted or a server rejection occurred in the batch.
   - `record` & `summary`: Tracks `not_sent`, `transport_error`, `rejected`, `accepted`, and `target_ok` outcomes separately so local transport errors never pollute server rejection counts.

3. **[`scripts/project_baseline.py`](scripts/project_baseline.py)** — Portable bundle SHA-256 fixity checker:
   - `create --root <dir> --manifest <rel_json> --files <rel_files...> [--identity k=v...]`
   - `check --root <dir> --manifest <rel_json>`: Returns `exit 0` (`"status": "unchanged"`) or `exit 1` (`"status": "changed"`).

## Reference Playbook

Read [`references/jsvmp-and-token-workflows.md`](references/jsvmp-and-token-workflows.md) for the step-by-step JSVMP boundary-logging methodology, token batch analysis workflow, and single-variable replay discipline.
