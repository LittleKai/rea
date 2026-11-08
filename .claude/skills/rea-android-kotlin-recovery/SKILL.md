---
name: rea-android-kotlin-recovery
version: "1.0.0"
description: Fingerprint Android APK/XAPK archives, recover R8/ProGuard-obfuscated Kotlin class and package names from @Metadata/@DebugMetadata annotations in JADX sources, and extract Retrofit/OkHttp/Ktor API endpoints.
allowed-tools: Read, Write, Grep, Glob, Bash
---

# REA Android & Kotlin Deobfuscation Recovery (`rea-android-kotlin-recovery`)

> Attribution: Derived from `SimoneAvogadro/android-reverse-engineering-skill@0c7cf89830993df7dfc178498f69952262808bea` (`Apache-2.0`).

Use this skill alongside REA's Android investigation tools (`inspect_android_package`, `jadx-mcp-server`) when analyzing R8/ProGuard-obfuscated Kotlin APKs, split XAPK bundles, or Android network clients.

## Runtime Contract

Always run the bundled pure-Python CLI via the locked Conda Python 3.12 runtime (no Bash, external `unzip`, or auto-installers required):

```powershell
D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B <path_to>/scripts/kotlin_apk_inspector.py <subcommand> ...
```

## Subcommands in [`scripts/kotlin_apk_inspector.py`](scripts/kotlin_apk_inspector.py)

1. **`fingerprint <apk_or_xapk_path> [--json]`**
   - Inspects `.apk` and nested `.xapk` / split APK entries in memory using Python `zipfile`.
   - Reports `container_type`, `primary_framework` (`flutter`, `react_native`, `unity`, `xamarin`, `cordova_capacitor`, `kotlin`, `native_android`), `abis`, `split_apks`, `dex_count`, and `has_kotlin_metadata`.

2. **`recover-kotlin <sources_dir> <out_dir>`**
   - Scans JADX-decompiled `.java` files for `@kotlin.Metadata` (`d2` class descriptors) and `@kotlin.coroutines.jvm.internal.DebugMetadata` (`c` and `f` attributes).
   - Writes `mapping.tsv`, `mapping.json`, and `packages.txt` into `<out_dir>` and prints a JSON summary to `stdout`.

3. **`lookup <mapping_dir> [query | -o <obf_fqn> | -p <pkg> | --grep <regex> --sources <sources_dir>]`**
   - Translates obfuscated class names (`-o a.b.c`) to original Kotlin FQNs, filters by original package prefix (`-p`), or performs a pure-Python regex search across JADX sources (`--grep <regex> --sources <sources_dir>`) annotated with `[real_fqn (obf_fqn)]`.

4. **`find-api <sources_dir> [--retrofit] [--okhttp] [--ktor] [--urls] [--all] [--json]`**
   - Extracts Retrofit route annotations, OkHttp builders/interceptors/pinners, Ktor client calls, and hardcoded HTTP(S)/WS(S) endpoints.

## Reference Playbook

Read [`references/kotlin-and-api-recovery.md`](references/kotlin-and-api-recovery.md) for details on how R8 preserves `@Metadata` descriptors and how to combine recovered mappings with REA evidence bundles.
