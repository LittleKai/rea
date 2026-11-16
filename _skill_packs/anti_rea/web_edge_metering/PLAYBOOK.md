# Dormant Pack: `web-edge-metering` — Streaming Build Verifier & Server-Side Controls

- **Source:** `https://github.com/dankezo/antiRea@bacba71ff082245913a8afed73bb374131d5e446` (MIT)
- **Invoked via Hub CLI:**
  ```powershell
  D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B D:\Dev\7.REA\rea\.agents\skills\anti-rea\scripts\audit_anti_rea.py verify-build <build_dir> --strict --format json
  ```

## Capabilities & Implementation Notes

1. **Streaming Source-Map & Deployment Verifier (`verify_build.py`):**
   - Scans arbitrarily large bundles (`1 MiB` chunks + `4096 B` carry buffer) for `sourceMappingURL` (inline `data:` and external), `.map`/`.map.gz`/`.map.br`, `_headers` `SourceMap:`, and renamed `.json` source maps (`"version": 3` + `"mappings"` + `"sources"`).
2. **Server-Side Metering & Concurrency Guardrail:**
   - Client-side guards offer zero protection against direct HTTP crawlers (`A4` in `references/THREAT_MODEL_REA.md`). Enforce per-tenant quotas, field allowlists, and short-lived session tickets on the server (`references/SERVER_SIDE_CONTROLS.md`, `references/ICEBERG_ARCHITECTURE.md`).
   - **Important concurrency warning:** When implementing sliding-window quota stores in Python/FastAPI (cf. upstream `examples/python-fastapi/quota_guard/core.py:558-571`), NEVER split `await store.peek(...)` and `await store.record(...)` across two non-atomic steps or rely on wall-clock `time.time()`; always use an atomic compare-and-record operation (`recordIfBelow` / Lua `EVAL` / SQLite transaction) and monotonic clocks (`time.monotonic_ns()`).

## Bundler Config Templates & References

- [`configs/vite.config.ts`](configs/vite.config.ts) · [`configs/next.config.mjs`](configs/next.config.mjs)
- [`references/THREAT_MODEL_REA.md`](references/THREAT_MODEL_REA.md) · [`references/SERVER_SIDE_CONTROLS.md`](references/SERVER_SIDE_CONTROLS.md) · [`references/ICEBERG_ARCHITECTURE.md`](references/ICEBERG_ARCHITECTURE.md)
