# Dormant Pack: `apk-exposure-inspector` — Bounded Static Android APK Exposure Inspector

- **Source:** `https://github.com/zhcalvin/DeRea@7d4917b4e3c0acbbd1e1b384afb72024ecfbb860` (Apache-2.0)
- **Invoked via Hub CLI:**
  ```powershell
  D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B D:\Dev\7.REA\rea\.agents\skills\anti-rea\scripts\audit_anti_rea.py inspect-apk <path_to.apk> --strict --format json
  ```

## Capabilities & Honesty Boundaries

1. **Bounded Pure-Python Static Inspection (`inspect_apk.py`):**
   - Enforces non-symlink/non-reparse regular-file admission (`22 B .. 64 MiB`), single-FD snapshot stability (`os.fstat`), `<= 4096` ZIP entries, and `<= 200x` compression ratio bounds.
   - Parses binary AXML `AndroidManifest.xml` (`package`, `minSdkVersion`, `targetSdkVersion`, `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, SDK-aware `effectiveExported` components).
   - Validates `classes*.dex` (`035`–`040`) Adler-32/SHA-1 headers and class counts, detects readable WebView JavaScript (`APK_READABLE_JAVASCRIPT`), and inventories `lib/*/*.so` ELF binaries.
2. **Explicit Honesty Limitations:**
   - Static APK metadata observations do not execute DEX/JS/native code, do not verify APK v2/v3 cryptographic signatures, and do not prove resistance against runtime Frida instrumentation. Pair with `.agents/skills/rea-android-kotlin-recovery` and R8/Play Integrity controls ([`../static_hardener_configs/references/android.md`](../static_hardener_configs/references/android.md)).
   - Post-build APK WebView minifier (`packages/apk-hardener/assets/harden_apk.py`) is tracked as Phase 2 (`Deferred`).
