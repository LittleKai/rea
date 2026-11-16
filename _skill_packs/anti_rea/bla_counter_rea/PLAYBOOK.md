# Dormant Pack: `bla-counter-rea` — Counter-REA Packaging Gates & Honesty Caps

- **Source:** `https://github.com/qybaihe/bla@98e01cc47b3ac8eabeed69b91dc393c37467388f` (MIT)
- **Invoked via Hub CLI:**
  ```powershell
  D:\Dev\conda-envs\py312\python.exe -X utf8 -I -B D:\Dev\7.REA\rea\.agents\skills\anti-rea\scripts\audit_anti_rea.py lint-gates <target_dir_or_file> --strict --format json
  ```

## Scope & Defensive Posture

1. **10 Zero-`@babel` Packaging-Footgun Gates (`packaging_gates.py`):**
   - `lane-independence`: flags per-byte / per-segment independent key checks (`charCodeAt(i)` / `split` lanes) lacking whole-key chained mixing.
   - `seal-commitment`: flags plaintext `seal.json` sidecars with invertible numeric `scheduleSalt` + `rounds` or cleartext certificate ciphertext.
   - `wasm-param-carrier`: flags clear tagged ASCII magics (`R3PARM`, `R3CIPH`, `R2SEAL`) followed by binary payload in `.wasm`.
   - `js-aes-unwrap`: flags recoverable JS wrap-key material paired with `createDecipheriv`/`createCipheriv` and fixed sealed headers.
   - `js-wasm-hydrate-dump`: flags JS reading `WebAssembly.Memory.buffer` and decoding `salt`/`rounds`/`cipher` on the host side.
   - `wasm-xor-mask-sidecar`: flags `.wasm` active data sections storing an entitlement pack adjacent to its plaintext 32-byte XOR mask.
   - `wasm-seal-xor-known-plaintext`: flags `.wasm` active data sections embedding public `seal.revision` under a repeating 32-byte XOR mask.
   - `panel-derive`: flags surviving `__vaultPanelDerive*` / `deriveLocal` entrypoints and `panelTokenSha256` offline oracles.
   - `plaintext-secret`: flags cleartext `FLAG{...}`, PEM private-key headers, high-entropy key literals, and derive keynames (values redacted).
   - `release-hygiene`: flags leaked `.env` secrets (bounded 4096-byte check, values never echoed), SSH/PEM keys, solution notes, and `.pdb`/`.dSYM` debug files.
2. **106-Entry REA Resource Limits Catalog & 24-Vector Matrix:**
   - Catalogs 106 internal `morluto/rea` bounds (`REA_INTERNAL_LIMITS`) and 24 attack-surface vectors (`references/counter-rea-matrix.md`).
3. **Honesty Soft-Caps & Excluded Surfaces:**
   - Applies `defenseScore` soft-caps when `wasm-export-rename-pending` (`88`), `self-seal-not-enabled` (`92`), or `sidecar-entangle-not-enabled` (`93`) remain open.
   - Prompt-injection / deceptive in-band AI directives (`llm-directives.ts`, `prompt-completion-poison.ts`) are intentionally excluded.

## Progressive Format References

- [`references/counter-rea-matrix.md`](references/counter-rea-matrix.md)
- [`references/format-javascript.md`](references/format-javascript.md)
- [`references/format-wasm.md`](references/format-wasm.md)
- [`references/format-python.md`](references/format-python.md)
- [`references/format-android.md`](references/format-android.md)
