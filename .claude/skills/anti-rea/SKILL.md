---
name: anti-rea
version: "2.0.0"
description: Audit applications, websites, JS/WebGL bundles, Electron apps, Python packages, APKs, and binaries for source-code crawlability and reverse-engineering exposure against REA (rea-agents), Wakaru, JADX, CDP, and static crawlers, orchestrating dormant _skill_packs/anti_rea/ capability packs with zero context growth. Use when the user asks "anti rea", "chống dịch ngược", "có bị crawl mã nguồn không", "bảo vệ trước REA", "chống cào code/bundle/shader/3D asset", or wants to harden a project against reverse engineering.
allowed-tools: Read, Write, Bash, Glob, Grep, WebFetch
---

# Anti-REA — Unified Source-Exposure Auditor & Zero-Context Pack Orchestrator

Audit a target URL, build output directory, APK, or source repository from the perspective of **REA (`rea-agents`)** and automated crawlers, separate verified facts from inferences, and design a **fail-closed, 4-tier defense-in-depth upgrade** without inflating startup skill context.

## Zero-Context-Inflation Pack Architecture (`_skill_packs/`)

This skill is the **single active orchestrator frontmatter** for all Anti-REA capabilities in this workspace. Specialized domain playbooks and pure-Python analyzers live in dormant `_skill_packs/anti_rea/<pack_name>/` (never named `SKILL.md`, so adding future packs adds **0 tokens** to session startup context).

Before diving into a specialized target format, consult [`_skill_packs/INDEX.md`](../../../_skill_packs/INDEX.md) and load **only** the matching `PLAYBOOK.md`:

| Pack ID                   | When to Load `PLAYBOOK.md`                                                                                                                                                                       | CLI Subcommand(s)                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| `bla-counter-rea`         | Auditing JS/WASM/seal/entitlement gates against 10 Counter-REA packaging footguns, 106 REA internal resource limits, and `defenseScore` honesty caps                                             | `lint-gates`                            |
| `web-edge-metering`       | Streaming large-bundle (`> 10 MiB`) `sourceMappingURL` / `.map.gz` / `_headers` / renamed-JSON map checks, Vite/Next configs, and server-side quota/metering controls                            | `verify-build`, `audit-dir`             |
| `static-hardener-configs` | Measuring 0–100 Reversibility/Resistance scores, emitting valid `terser` / `javascript-obfuscator` / `electron-fuses` / `proguard` / OkHttp pinning configs, or out-of-tree Python AST hardening | `scan-score`, `gen-config`, `harden-py` |
| `apk-exposure-inspector`  | Static binary-AXML `AndroidManifest.xml`, DEX `035–040`, readable WebView JS, and `.so` ELF exposure inspection on `.apk` files without Docker/JADX                                              | `inspect-apk`                           |

## Safety & Execution Boundaries

1. **Local-first inspection:** Prefer auditing local build/public directories (`dist/`, `public/`, `build/`, APK/ASAR outputs) and source configs (`vercel.json`, `middleware.js`, bundler scripts) directly on disk.
2. **Bounded passive URL checks only when authorized:** Run live HTTP checks (`check-url --allow-live`) only when the user explicitly asks to check a specific URL they own or are authorized to assess (`<= 8` passive `GET` requests; zero fuzzing, brute-forcing, or exploitation).
3. **Defensive outputs & honesty boundaries:** Document exposure mechanics, structural fixes, and explicit `defenseScore` / client-artifact honesty limits. Never claim client-side obfuscation alone defeats runtime CDP/Frida hooks or replaces server-side authorization; never embed prompt-injection / deceptive LLM directives.

## Runtime Contract for Unified CLI (`scripts/audit_anti_rea.py`)

Run [`scripts/audit_anti_rea.py`](scripts/audit_anti_rea.py) using the locked Conda Python 3.12 `<python>` runtime declared in `AGENTS.md` (never system `python` or conda base):

```powershell
$py = "<python>"
$cli = ".agents/skills/anti-rea/scripts/audit_anti_rea.py"

# 1. List installed dormant Anti-REA capability packs
& $py -X utf8 -I -B $cli packs --format md

# 2. Offline Web/WebGL/Electron directory audit (+ streaming sourcemap/header/renamed-JSON verification)
& $py -X utf8 -I -B $cli audit-dir <build_or_public_dir> --source-dir <src_dir> --strict --format json

# 3. Bounded passive HTTP check on an explicitly user-requested URL
& $py -X utf8 -I -B $cli check-url <https://example.com/app> --asset-path <bundle.js> --asset-path <bundle.js.map> --allow-live --format json

# 4. Run 10 Counter-REA packaging-footgun gates + honesty soft-caps (bla-counter-rea)
& $py -X utf8 -I -B $cli lint-gates <target_dir_or_file> --strict --format json

# 5. Standalone streaming build source-map verifier (web-edge-metering)
& $py -X utf8 -I -B $cli verify-build <build_dir> --strict --format json

# 6. Static 0-100 REA Reversibility/Resistance score, multi-platform config emission & Python AST hardener
& $py -X utf8 -I -B $cli scan-score <target_dir> --min-resistance 60 --format json
& $py -X utf8 -I -B $cli gen-config <target_dir> --out-dir <out_configs_dir> --format json
& $py -X utf8 -I -B $cli harden-py <src_dir> <new_out_dir> --rename --format json

# 7. Bounded pure-Python Android APK static exposure inspector (apk-exposure-inspector)
& $py -X utf8 -I -B $cli inspect-apk <path_to.apk> --strict --format json
```

---

## 5-Step Audit & Hardening Workflow

### Step 1 — Route Target, Cross-Repo Context & Dormant Pack

1. Identify both the **shipped artifact surface** (URL, `public/`, `dist/`, ASAR, `.wasm`, Python package, `.apk`, or native binary) and the **owning source repository**.
2. If inspecting an external workspace, read its root `AGENTS.md` and `.claude/PROJECT_SUMMARY.md` first without mutating its worktree unless requested.
3. In the REA workspace, read `_reference/INDEX.md` first (storing case outputs under `_reference/targets/<slug>/`) and select only the relevant dormant pack from [`_skill_packs/INDEX.md`](../../../_skill_packs/INDEX.md).

### Step 2 — Measure Exposure Surface Deterministically

Run the matching `audit_anti_rea.py` subcommands (`audit-dir`, `verify-build`, `lint-gates`, `scan-score`, `inspect-apk`, and `check-url --allow-live` when authorized) so every finding has byte/file counts, SHA-256 digests, and `file:line` evidence.

### Step 3 — Classify Epistemic Categories

Separate findings into **Observations**, **Derivations**, **Inferences**, and **Unknowns / `UNVERIFIED`**.

### Step 4 — Design the 4-Tier Defense-in-Depth Plan

Read [`references/web-and-js-hardening.md`](references/web-and-js-hardening.md) or [`references/desktop-mobile-native-hardening.md`](references/desktop-mobile-native-hardening.md) plus the selected dormant pack's `PLAYBOOK.md`:

- **Tier 1 (`P0` Edge / Access Gate):** HMAC `HttpOnly` session tickets, strict `Sec-Fetch-*` allowlists, server-verified `?share=`, atomic server-side quotas (`recordIfBelow` + monotonic clock), Electron fuses.
- **Tier 2 (`P0` Build & Symbol Hygiene):** Streaming `*.map`/`.map.gz`/`_headers`/renamed-JSON purge, integer-slot vaults, 100% GLSL static quasi encryption, `mangleProps` with `reserveProps`, `gen-config` templates, `harden-py` AST transforms, R8 `@Metadata` stripping.
- **Tier 3 (`P1` Trust-Boundary Split / Iceberg Architecture):** Move authoritative PRO deliverables (`.DXF`, `.MVR`, engineering riders, license signing, sensitive rules) to authenticated Backend endpoints.
- **Tier 4 (`P2` Cryptographic Assets & WASM Gates):** Session-keyed WebCrypto `AES-256-GCM`, stripped WASM (`wasm-opt -Oz --strip-debug`) passing all 10 `lint-gates` without host-side AES/hydrate leaks or XOR-mask sidecars.

### Step 5 — Emit Report & Ready-to-Run Handoff Prompt

Write `REPORT.md` (with Executive Summary, Evidence Ledger, Epistemic Breakdown, 4-Tier Roadmap, Honesty Disclaimers, and `VERIFY` Checklist) plus a copy-paste TDD Execution Prompt when handing off to another repository. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for upstream attributions.
