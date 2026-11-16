# Third-Party Notices — Anti-REA Multi-Pack Orchestrator

This directory and `.agents/skills/anti-rea/` incorporate selectively extracted and adapted defensive static-analysis components from the following open-source projects:

1. **`bla` (`bla-agents`)** — `https://github.com/qybaihe/bla` @ `98e01cc47b3ac8eabeed69b91dc393c37467388f`
   - **License:** MIT License (`_skill_packs/anti_rea/bla_counter_rea/LICENSE`)
   - **Scope:** 10 zero-`@babel` packaging-footgun lint rules, 106 `REA_INTERNAL_LIMITS` constants, defense-score honesty soft-caps, and Counter-REA format reference tables (ported to Python stdlib in `packaging_gates.py`; deceptive LLM directive modules excluded).

2. **`antiRea`** — `https://github.com/dankezo/antiRea` @ `bacba71ff082245913a8afed73bb374131d5e446`
   - **License:** MIT License (`_skill_packs/anti_rea/web_edge_metering/LICENSE`)
   - **Scope:** Streaming build source-map verifier (`verify_build.py`), Vite/Next hardening config templates, and threat-model / Iceberg / server-side controls documentation.

3. **`Anti-REA`** — `https://github.com/Ameya343/Anti-REA` @ `3251a2a96bcc8554c7acaf2d1ad2a6bcb16d7416`
   - **License:** MIT License (`_skill_packs/anti_rea/static_hardener_configs/LICENSE` & `NOTICE`)
   - **Scope:** Pure-Python platform detector, config generator, static REA signal simulator, Python AST string/identifier hardeners, `jscheck.mjs` syntax verifier, and platform hardening references (`coreinstall.py` and Rust `fastscan` excluded).

4. **`DeRea`** — `https://github.com/zhcalvin/DeRea` @ `7d4917b4e3c0acbbd1e1b384afb72024ecfbb860`
   - **License:** Apache License 2.0 (`_skill_packs/anti_rea/apk_exposure_inspector/LICENSE` & `THIRD_PARTY_NOTICES.md`)
   - **Scope:** Bounded pure-Python static Android APK inspector (`containers/inspect_apk.py`) combined with host-side regular-file / non-symlink / snapshot-stability admission checks adapted from `packages/apk-inspector/src/index.ts`.
