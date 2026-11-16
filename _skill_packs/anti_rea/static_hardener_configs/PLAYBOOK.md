# Dormant Pack: `static-hardener-configs` — Multi-Platform Configs, Score Simulator & Python AST Hardener

- **Source:** `https://github.com/Ameya343/Anti-REA@3251a2a96bcc8554c7acaf2d1ad2a6bcb16d7416` (MIT)
- **Invoked via Hub CLI:**
  ```powershell
  # 1. Measure static REA Reversibility / Resistance score (0-100)
  D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B D:\Dev\7.REA\rea\.agents\skills\anti-rea\scripts\audit_anti_rea.py scan-score <target_dir> --min-resistance 60 --format json

  # 2. Emit parse-valid hardening configs (terser, javascript-obfuscator, electron-fuses, R8/ProGuard, Android pinning)
  D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B D:\Dev\7.REA\rea\.agents\skills\anti-rea\scripts\audit_anti_rea.py gen-config <target_dir> --out-dir <out_dir> --format json

  # 3. Non-destructive out-of-tree Python AST string/identifier hardener + sourcemap stripper
  D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B D:\Dev\7.REA\rea\.agents\skills\anti-rea\scripts\audit_anti_rea.py harden-py <src_dir> <out_dir> --rename --format json
  ```

## Runtime & Safety Notes

- 100% pure Python 3.10+ stdlib (`coreinstall.py` binary downloader and optional Rust `fastscan` binary are excluded).
- `harden-py` writes to a **new output directory** outside `src_dir` (refuses in-tree writes), verifies transformed Python syntax via `compile()`, and uses `antirea_core/hardeners/jscheck.mjs` (`node --experimental-vm-modules`, syntax-only `vm.Script`) when `node` is on `PATH` (safely skipping JS comment stripping when `node` is absent).

## Progressive References

- [`references/javascript.md`](references/javascript.md) · [`references/android.md`](references/android.md) · [`references/native.md`](references/native.md) · [`references/runtime.md`](references/runtime.md)
