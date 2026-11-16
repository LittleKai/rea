# Desktop, Mobile, Packaged & Native Hardening Against REA

Reference for hardening non-web targets against REA's specialized static and runtime analyzers (`inspect_electron_fuses`, `analyze_javascript_application` ASAR, `inspect_artifact`, `inspect_android_package`, `rea-android-kotlin-recovery`, `inspect_il2cpp_metadata`, `inspect_go_binary`, `inspect_rust_binary`, `inspect_managed_artifact`, and `inspect_binary_hardening`).

## Contents

1. [Electron & Packaged JS Executables](#1-electron--packaged-js-executables)
2. [Android, Kotlin, Flutter & Unity IL2CPP](#2-android-kotlin-flutter--unity-il2cpp)
3. [Native & Managed Binaries (Go, Rust, C/C++, .NET)](#3-native--managed-binaries-go-rust-cc-net)
4. [API Request Signers & Anti-AgentEnv Replay](#4-api-request-signers--anti-agentenv-replay)

---

## 1. Electron & Packaged JS Executables

### 1.1 Flip Electron Security Fuses (`@electron/fuses`)

REA's Electron workflow (`inspect_electron_fuses` -> `list_electron_targets`) checks packaged fuse bits before attempting V8 Inspector attachment or ASAR tampering. Configure `@electron/fuses` at build time:

- `FuseV1Options.EnableNodeCliInspectArguments: false` — blocks `--inspect` / `--inspect-brk` attachment to `electron-main`.
- `FuseV1Options.EnableNodeOptionsEnvironmentVariable: false` — blocks `NODE_OPTIONS` injection.
- `FuseV1Options.RunAsNode: false` — prevents invoking the shipped binary as a generic Node.js REPL.
- `FuseV1Options.EnableEmbeddedAsarIntegrityValidation: true` & `OnlyLoadAppFromAsar: true` — detects modified `app.asar` archives.

Combine fuses with `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, and narrow literal IPC channels in `preload.js` (avoid exposing generic `ipcRenderer.invoke(arbitraryChannel)` bridges).

### 1.2 Standalone JS/Python Packers (`Bun --compile`, `PyInstaller`)

REA's `open_binary` + `inspect_artifact` directly inventories and extracts stored module graphs from `Bun --compile` standalone executables and `PyInstaller` CArchives (treating the native binary as a thin bootloader prefix).

- Do not rely on `PyInstaller` or `Bun --compile` to conceal proprietary source or embedded secrets.
- Move secrets to authenticated server APIs; compile proprietary Python modules to native C extensions via **Nuitka** or **Cython** (with stripped symbols), and move proprietary JS algorithms into stripped native `.node` addons or **WebAssembly**.

---

## 2. Android, Kotlin, Flutter & Unity IL2CPP

### 2.1 Countering `@kotlin.Metadata` & `@DebugMetadata` Recovery

REA's `rea-android-kotlin-recovery` recovers R8/ProGuard-obfuscated class, method, and coroutine names directly from `@kotlin.Metadata` (`d1`/`d2` protobuf descriptors) and `@kotlin.coroutines.jvm.internal.DebugMetadata` (`c`, `f`, `l`, `m`), even when identifier renaming is enabled.

- Enable **R8 full mode** (`android.enableR8.fullMode=true`) and remove `-keepattributes RuntimeVisibleAnnotations` for internal packages that do not use `kotlin-reflect` or runtime serialization.
- Strip coroutine debug source/line metadata (`-assumenosideeffects` / R8 metadata shrinking) on non-public modules, and verify on the built APK (`audit_anti_rea.py` / `kotlin_apk_inspector.py`) that sensitive internal packages do not emit recoverable `mapping.json` names.
- Remove cleartext Retrofit/OkHttp logging interceptors from release variants and enforce certificate pinning or server-side Play Integrity attestation for high-value endpoints.

### 2.2 Flutter & Unity IL2CPP

- **Flutter:** Build release artifacts with `flutter build apk --obfuscate --split-debug-info=/secure/symbols` (archive symbol maps outside shipped artifacts).
- **Unity IL2CPP:** REA's `inspect_il2cpp_metadata` extracts full type, method, field, and string literal tables from `global-metadata.dat` without running a disassembler. Keep authoritative economy/licensing validation server-side and strip unused engine/editor assemblies via `ManagedStrippingLevel.High`.

---

## 3. Native & Managed Binaries (Go, Rust, C/C++, .NET)

- **Go (`inspect_go_binary`):** Compile release binaries with `go build -trimpath -ldflags="-s -w"` to strip symbol/DWARF tables and workspace filesystem paths; note that Go pclntab/buildinfo metadata may still retain module framing unless server boundaries protect sensitive logic.
- **Rust (`inspect_rust_binary`):** Set `strip = "symbols"`, `panic = "abort"`, `lto = true`, and `--remap-path-prefix` in release profiles so `/rustc/<commit>/` and developer home paths are not embedded; omit `cargo-auditable` `.dep-v0` sections when dependency list confidentiality outweighs binary SBOM auditing.
- **.NET (`inspect_managed_artifact`):** Standard CIL assemblies preserve full type/IL metadata; publish sensitive desktop components with **NativeAOT** (`<PublishAot>true</PublishAot>`, `<StripSymbols>true</StripSymbols>`) and keep trust boundaries on the server.
- **ELF / PE / Mach-O Mitigations (`inspect_binary_hardening`):** Enable `PIE` / `DYNAMICBASE` + `HIGHENTROPYVA`, `NX`, stack protector, full `RELRO` (ELF), and `CFG` / `CET` (PE/ELF) so shipped binaries pass binary hardening checks.

---

## 4. API Request Signers & Anti-AgentEnv Replay

REA's `rea-js-reverse-lab` (`opaque_token_inspect.py`, `experiment_ledger.py`) and `export_environment_bundle` (`AgentEnv`) target two common weaknesses:

1. **Client-embedded custom encodings & weak signers:** Custom 64-char Base64 alphabets, single-byte per-token XOR masks, and CRC32/Adler32 tail checksums are automatically solved from 2+ captured URLs. Even full client-side HMAC (`BM1-HMAC-SHA256` style) only proves the caller read the client bundle — because the secret key must live inside that same bundle.
2. **Stateless replayable APIs:** `capture_browser_scenario` + `export_environment_bundle` can record read/write traffic and synthesize a local mock MCP server (`AgentEnv`) if endpoints return bulk catalog datasets without per-user scoping.

**Defensive architecture:**

- Never ship global HMAC signing secrets in client code as a substitute for user authentication. Authenticate principals with short-lived `HttpOnly` cookies or OAuth/JWT tokens, bind sensitive mutations to server-verified entitlements, enforce per-principal rate/pagination budgets, and keep proprietary computation behind the API rather than returning raw bulk catalogs.
