# Web, SPA & WebGL Bundle Hardening Against REA

Reference for hardening browser applications, WebGL/3D studios, and bundled JavaScript against REA's web/JS suite (`analyze_javascript_application`, `analyze_web_bundle`, `inspect_web_page` CDP, `capture_browser_scenario`, Wakaru `recover_javascript_sources`, and `rea-js-reverse-lab`).

## Contents

1. [Tier 1 — Edge Middleware, Crawl Gates & Share Links](#1-tier-1--edge-middleware-crawl-gates--share-links)
2. [Tier 2 — Bundler, Symbol Table, GLSL Shader & Sidecar Hygiene](#2-tier-2--bundler-symbol-table-glsl-shader--sidecar-hygiene)
3. [Tier 3 — Server-Authoritative Commercial Logic](#3-tier-3--server-authoritative-commercial-logic)
4. [Tier 4 — Session-Keyed AEAD Assets & Stripped WebAssembly](#4-tier-4--session-keyed-aead-assets--stripped-webassembly)

---

## 1. Tier 1 — Edge Middleware, Crawl Gates & Share Links

### 1.1 Replace `Sec-Fetch-*` Blacklists with Allowlists + Ticket Cookies

**Failure mode:** Rules that block only `Sec-Fetch-Site: cross-site` or `Sec-Fetch-Dest: document` allow any plain HTTP crawler (`curl`, Python `urllib`, Scrapy, Firecrawl) through with `HTTP 200`, because non-browser clients omit `Sec-Fetch-*` headers completely. Similarly, middleware matchers that exclude static extensions (`.*\.[^/]+$`) leave `.js`, `.glb`, and `.json` files unguarded.

**Target architecture:**

1. Expand Edge Middleware `matcher` to cover the entire sub-application prefix (e.g. `'/app-bundle/:path*'`).
2. When an authenticated user (or a visitor carrying a server-verified share token) loads the parent shell route, issue a short-lived HMAC-SHA256 signed cookie:
   `Set-Cookie: app_bundle_ticket=<ts>.<sig>; HttpOnly; Secure; SameSite=Strict; Path=/app-bundle; Max-Age=900`
3. Enforce a **positive allowlist** on subresources (`.js`, `.css`, `.wasm`, `.glb`, `.pack.js`):
   - Valid, non-expired `app_bundle_ticket` cookie, **AND**
   - `Sec-Fetch-Site === 'same-origin'`, **AND**
   - `Sec-Fetch-Dest` in `{'script', 'style', 'empty', 'image', 'iframe', 'worker'}`.
   - Reject missing headers or invalid cookies with `403 Forbidden` (`Cache-Control: no-store`).

### 1.2 Validate `?share=` Tokens Before Mounting `<iframe>` or Bundles

**Failure mode:** Rendering `<iframe src="/app-bundle/index.html?share=...">` whenever a query parameter is non-empty lets an unauthenticated Playwright/CDP session (`?share=dummy`) bypass `<ProtectedRoute>` and load the entire commercial JS bundle into V8 memory.

**Fix:** Call a lightweight metadata/ticket endpoint (`GET /api/projects/share-verify?token=...`) from the outer route first. Mount the iframe and load bundle scripts only after the server confirms the share token exists, has not expired, and issues the scoped ticket cookie.

### 1.3 Prevent SPA Fallback `200 OK` + `immutable` Cache Poisoning

**Failure mode:** Applying `Cache-Control: public, max-age=31536000, immutable` on `^/app-bundle/js/.+\.js$` with `continue: true` before filesystem lookup causes missing `.js` or `.map` URLs to fall through to `/` and serve SPA HTML as `200 OK` cached for one year.

**Fix:** Add a terminal post-filesystem rule for `^/app-bundle/.*` that returns an explicit `404` with `Cache-Control: no-store`, and add `Disallow:` entries in `robots.txt` alongside `Content-Security-Policy: frame-ancestors 'self'; object-src 'none'; base-uri 'self'`.

---

## 2. Tier 2 — Bundler, Symbol Table, GLSL Shader & Sidecar Hygiene

### 2.1 Replace String-Keyed Proxy Vaults with Integer Slot Arrays

**Failure mode:** Isolating globals behind `Proxy(window)` by binding every top-level core function/variable via `__bindVault(__str(idx), () => fn, v => { fn = v })` embeds hundreds of original source identifier names inside the string table — acting as an inline symbol map for Wakaru and AST analyzers.

**Fix:** During the build script:

1. Collect internal cross-chunk symbols into a build-time `Map<string, number>` with a Fisher–Yates shuffled slot order per build.
2. Rewrite `window.<coreSym>` / `globalThis.<coreSym>` references across core and feature modules into integer array accesses `__vaultSlot[slotId]`.
3. Remove custom asset/pack globals from `Proxy(window)` passthrough lists; pass lazy chunks through a randomized per-build registration callback.

### 2.2 Encrypt 100% of GLSL Shaders (Including `${...}` Quasis & Helper Blocks)

**Failure mode:** Regex encoders that skip template literals containing `${` (`if (body.includes('${')) return full;`) or check only `#version` / `gl_Position` leave shared GLSL libraries (`PROC_COMMON_GLSL`, `CROWD_ANIM_GLSL`) and interpolated shaders in plaintext.

**Fix:**

1. Split template literals at `TemplateElement` boundaries: register each static quasi chunk in the encrypted string table (`__str(i0) + (expr) + __str(i1)`).
2. Match shader strings across all GLSL signatures (`#version`, `gl_Position`, `precision highp`, `layout(location=`, `uniform `, `out vec`, `in vec`, `sampler2D`).
3. Add a fail-closed assertion in automated bundle tests rejecting any surviving `/\b(?:uniform|varying|in|out)\s+(?:highp\s+)?(?:vec[234]|mat[234]|sampler2D)/` match in the minified bundle.
4. Generate a fresh 128-bit per-build key (`crypto.randomBytes(16)`) and shuffled table indices on every build instead of a hardcoded XOR constant.

_(Architectural note: Static shader encryption blocks HTTP crawlers and offline AST tools; at runtime on an authorized GPU session, WebGL still passes compiled GLSL to `gl.shaderSource`. Never store secrets inside shaders.)_

### 2.3 Controlled `mangleProps` with Explicit Schema `reserveProps`

`esbuild` / Terser identifier minification leaves object property names intact (`computeEngineeringRider`, `generateStageDxf`, `isProUnlocked`). Configure `mangleProps` targeting internal module suffixes/prefixes while maintaining an explicit `reserveProps` allowlist covering:

- Saved project file schema keys and versioned migration fields
- `postMessage` IPC envelopes and DOM `dataset` attributes
- External REST API request/response JSON keys and third-party vendor globals

### 2.4 Strip Sidecar Manifests & Lock Production Origins Fail-Closed

- Exclude all `*.map` and `*.asset.json` sidecar files when syncing to public web directories so internal workspace paths (e.g. `design-mcp/...`) and raw unwrapped asset SHA-256 hashes are never published. Preserve required open-source `NOTICE.md` / `THIRD_PARTY_NOTICES.md` files.
- Strip `file:`, `about:`, `localhost`, `127.0.0.1`, and `[::1]` from the production domain lock (enable them only when `--allow-local` is passed for local smoke testing), require `window.top !== window.self` when the app is designed to run inside an authenticated shell iframe, and ensure watermark predicates fail closed (`return !isProUnlocked()`) in web builds.

---

## 3. Tier 3 — Server-Authoritative Commercial Logic

Client-side JavaScript flags (`isPro = true`) cannot withstand runtime inspection via REA's CDP/Playwright tools (`inspect_web_page`, `capture_browser_scenario`) by a logged-in user.

- **Keep on Client:** 60 FPS WebGL2 rendering, timeline scrubbing, real-time shader/lighting previews, and interactive gizmos.
- **Move to Backend API (`POST /api/.../exports/*`):** On-demand commercial deliverables (CAD `.DXF`, `.MVR`, XML console patches, structural/electrical engineering riders, unwatermarked quotations/PDFs) gated by server-side `authMiddleware` and database subscription state.
- **Preserve Local Offline Dev Mode:** Place local exporter implementations in a separate module loaded by the dev `index.html` (`file://`), and exclude/dead-code-eliminate that file when building the public web bundle (`__PUBLIC_WEB_BUILD__ = true`).

---

## 4. Tier 4 — Session-Keyed AEAD Assets & Stripped WebAssembly

1. **WebCrypto `AES-256-GCM` for Binary Assets:** Keyless PRNG wrappers (`xorshift32`) that store their 32-bit seed in bytes `8..11` of the asset header are trivially reversed by `rea-js-reverse-lab`. Encrypt proprietary `.glb`/pack payloads at build time with `AES-256-GCM` and deliver the decryption key (or short-lived presigned B2/S3 URLs) only through an authenticated session endpoint, unwrapping in memory via `crypto.subtle.decrypt`.
2. **Stripped WebAssembly (`WASM`) for Proprietary Algorithms:** Compile high-value CPU math (e.g., 66-bone inverse kinematics / mocap solvers, packing/routing solvers) from Rust/C++ to WASM with `wasm-opt -Oz --strip-debug --strip-producers`. As REA's `inspect_wasm_artifact` contract notes, WAT disassembly recovers low-level stack instructions, not original types, symbol names, or high-level control-flow abstractions.
