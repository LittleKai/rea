# Setup Report — REA (Reverse Engineer Anything)

**Ngày thiết lập:** 2026-11-07 · **Chuẩn áp dụng:** `4.Claude_Code_Set_up_v2.md` (mốc `2026-11-03`)

> Đây là snapshot **một lần** tại thời điểm thiết lập bộ Setup v2 cho `D:\Dev\7.REA\rea`. Không cập nhật về sau, không dùng làm changelog. Mọi thay đổi trạng thái hàng ngày ghi vào `.claude/PROJECT_SUMMARY.md`.

---

## 1. Các file đã tạo / cập nhật

| File                         | Hành động        | Vai trò                                                                                                                                                                                                                                                                            |
| ---------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AGENTS.md`                  | Hợp nhất (Merge) | Bộ định tuyến dùng chung cho Codex, Antigravity và Claude Code (< 200 dòng); bảo toàn toàn bộ luật gốc của REA, anchor `#performance`, tham chiếu `docs/public/product-catalog.json`, cảnh báo đọc UTF-8 không BOM trên PowerShell và khối `<!-- BEGIN:turborepo-agent-rules -->`  |
| `CLAUDE.md`                  | Tạo mới          | Shim đúng 1 dòng `@AGENTS.md` để Claude Code nạp cùng nguồn luật với Codex và Antigravity                                                                                                                                                                                          |
| `.claude/PROJECT_SUMMARY.md` | Tạo mới          | Trạng thái hiện tại của dự án (`Setup baseline: 2026-11-03`), luật cập nhật tại chỗ, bảng trạng thái 9 phân hệ, giả định đang giữ, cây thư mục, sơ đồ luồng dữ liệu, bảng `Invalidate / refresh rules` và `Known Issues & TODOs`                                                   |
| `.claude/CONVENTIONS.md`     | Tạo mới          | Quy ước đặt tên, kiến trúc tầng, thứ tự import, xử lý lỗi `Result<T, E>` / `AnalysisErrorTag`, quản lý vòng đời tiến trình, quy tắc Issue/PR (chuyển chi tiết từ `AGENTS.md` gốc sang để không mất luật), mục `Do / Don't` có nguồn rào chắn thật và bảng `Cưỡng chế bằng công cụ` |
| `.claude/SETUP_REPORT.md`    | Tạo mới          | Báo cáo snapshot lúc thiết lập (file này)                                                                                                                                                                                                                                          |

### Các bộ phận phần MÁY MÓC (§0.5) chưa lắp & lý do skip

Theo nguyên tắc §0.5 (_"Một file rỗng toàn placeholder tệ hơn không có file — lắp khi tín hiệu thật sự xuất hiện"_):

- `.claude/IMPORTANT_FIXED_BUGS.md`, `.claude/guard_check.py`, `.claude/archive/`: **Skip** — dự án vừa khởi tạo Setup v2 trên checkout hiện tại, chưa phát sinh bẫy nội bộ dạng văn xuôi; các bất biến kiến trúc và bẫy lịch sử của repo đã được cưỡng chế trực tiếp bằng code trong `scripts/verify/architecture-guards.mjs`, `scripts/lib/module-boundaries.mjs` và `.oxlintrc.json` (`scripts/lint/index.mjs`).
- `.claude/DESIGN_DECISIONS.md`: **Skip** — `.claude/PROJECT_SUMMARY.md` hiện gọn nhẹ (~20 KB, dưới xa ngưỡng 30 KB) và repo đã có các tài liệu thiết kế chuyên sâu trong `docs/tool-design.md`, `docs/capability-composition.md`, `docs/design/limits-and-recovery.md`.
- `.claude/SMOKE_TEST_CHECKLIST.md`: **Skip** — dự án là gói CLI/MCP có hệ thống kiểm thử tự động toàn diện (`tests/acceptance/`, `tests/boundary/`, `scripts/verify-*.mjs`).
- Tầng `_kit/` + `KIT.md`: **Skip** — repo là một sản phẩm đóng gói thống nhất (`rea-agents`), các thành phần dùng chung đã có tầng sở hữu rõ ràng tại `src/domain/`, `src/contracts/`, `src/process/`, `src/filesystem/`, `src/providers/`.
- `items.json` + `ITEMS.md` & `.claude/DECOMPOSITION.md`: **Skip** — chỉ tạo khi có task với đầu vào lớn (≥ 3 hạng mục tách rời).
- Hooks: ban đầu skip các hook phức tạp; sau đó đã cấu hình bộ hook phát hiện upstream gọn nhẹ (`.claude/settings.json`, `.agents/hooks.json`, `.codex/hooks.json` gọi `hooks/rea_upstream.py` với TTL 24h và cơ chế fail-open).

---

## 2. Loại dự án, Tech Stack & Kiến trúc tóm tắt

- **Loại dự án:** Công cụ dịch ngược cục bộ đa nền tảng cung cấp CLI (`rea` / `rea-agents`) và MCP Server (`io.github.morluto/rea`, `v6.8.0`).
- **Tech stack:** TypeScript 7 (`typescript@7.0.2`, `tsrs`), Node.js (`24.22.1` trong `.nvmrc`), `npm@11.16.0`, Turborepo, Rolldown, Vitest 5, Oxlint + Oxfmt, Knip, Stryker, VitePress, kèm cầu nối Python/Java/Swift/C++ (`bridge/`, `native/windows/`).
- **Kiến trúc:** Phụ thuộc chảy một chiều vào trong (`docs/architecture.mermaid`):
  1. `src/domain/` & `src/contracts/`: Ngữ nghĩa domain thuần, `Evidence`, `Result<T, E>`, `AnalysisErrorTag` và Zod schemas cho CLI/MCP.
  2. `src/process/`, `src/filesystem/`, `src/windows/`, `src/providers/`, `src/<provider>/`, `bridge/`: Giám sát tiến trình thuộc sở hữu, giới hạn tài nguyên và các adapter kết nối hơn 25 công cụ/định dạng dịch ngược.
  3. `src/application/`: Luồng điều tra dùng chung, `BinarySession`, `SessionProviderRouter`, `AnalysisProviderRegistry`, `AnalysisSnapshotCache`.
  4. `src/composition/`: Điểm kết nối (wiring) duy nhất cho production.
  5. `src/cli.ts`, `src/main.ts`, `src/server/`, `scripts/rea.mjs`: Entrypoints cho CLI và MCP server.

---

## 3. Artifact & Bằng chứng "xong" đã chốt

- **Artifact bàn giao:** Gói npm `rea-agents` (`dist/`, `scripts/rea.mjs`, `skills/`, `bridge/**`, `native/windows/build/rea-windows-x64.node`, `.claude-plugin/`, `.codex-plugin/`).
- **Bằng chứng "xong" (của lần chạy hiện tại):**
  - Với thay đổi tài liệu setup: `audit_setup_v2.py .` đạt `0 FAIL, 0 MISSING`, `node scripts/check-doc-facts.mjs` (hoặc `npm run docs:check`) và `npx oxfmt --check AGENTS.md` chạy xanh.
  - Với thay đổi mã nguồn TypeScript: `npm run check:fast`, `npm run verify:architecture-guards`, và `npm run test:local -- <PATH...>` (hoặc `npm run test:focused -- <PATH...>`) chạy xanh.
  - Với thay đổi runtime/CLI/MCP/skills: `npm run build:cached` + chạy thử trực tiếp `node scripts/rea.mjs` + `npm run docs:check`.

---

## 4. Đối chiếu Contract vận hành (§0.7)

| Hàng §0.7                                   | Trạng thái áp dụng trong REA                                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Root lẫn script và file tạm              | **Áp dụng:** Giữ nguyên mọi đường dẫn entrypoint trong `package.json#files` và `scripts/`; các file dẫn xuất (`docs/public/product-catalog.json`, `docs/verification/managed-conformance-*.json`, `skills/`) được `.gitignore` và sinh lại từ nguồn.                                                        |
| 2. Dependency hoặc nhiều runtime            | **Áp dụng:** Khoá Node.js `24.22.1` (`.nvmrc`) và `npm@11.16.0` (`package-lock.json`); tách biệt rõ với Python Conda env (`D:\Dev\conda-envs\py312\python.exe`) và các BYO engines (Ghidra, IDA, Hopper, Kuna, JADX, v.v.).                                                                                 |
| 3. Biến môi trường/đường dẫn máy            | **Áp dụng:** Parse biến môi trường tập trung bằng Zod tại `src/config/environment.ts` và `src/config/parseConfig.ts`; chụp nhanh môi trường đã chọn qua `src/process/snapshotEnvironment.ts`, không lưu ambient environment.                                                                                |
| 4. Bridge/IPC giữa tiến trình hoặc ngôn ngữ | **Áp dụng:** Đã ghi rõ kiến trúc cầu nối (`bridge/hopper_bridge.py`, `bridge/ghidra/*.java`, `bridge/android/ReaJadxBridge.java`, `bridge/cutter/rea_bridge.py`, `native/windows/`), kiểm tra JSON Schema MCP sau chuyển đổi SDK và gắn handler theo named contracts (`src/server/contractToolHandler.ts`). |
| 5. Plugin/add-on/native host                | **Áp dụng:** Đã quy định bước build lại (`npm run build:cached`, `npm run build:windows-native` + `npm run verify:windows-native:artifact`) và quy tắc `rea setup` cộng thêm, idempotent, có backup và xin phép trước khi ghi.                                                                              |
| 6. Job nặng hoặc thao tác phá huỷ           | **Áp dụng:** Ghidra dùng DB tạm thời không sửa binary; IDA hoàn toàn chỉ đọc; các producer bị giới hạn bởi `BOUNDED_PRODUCER_LIMITS` và `prlimitArgumentVector` (`src/process/LinuxResourceLimits.ts`).                                                                                                     |
| 7. Timeout hoặc worker chạy nền             | **Áp dụng:** Giám sát tiến trình thuộc sở hữu qua `src/process/` và Windows Job Object (`src/windows/`, `native/windows/`); giữ lại quyền sở hữu khi cleanup thất bại để thử lại (`CapabilityScope`) và kiểm thử lifecycle regressions.                                                                     |

---

## 5. Điểm mạnh, Điểm cần lưu ý & Việc nên làm tiếp

### Điểm mạnh của codebase

- Cưỡng chế kiến trúc bằng công cụ cực kỳ chặt chẽ: `scripts/verify/architecture-guards.mjs` (kiểm 2.519 file nguồn trong < 1 giây), `scripts/verify-module-boundaries.mjs`, custom Oxlint plugin `scripts/lint/index.mjs` (6 quy tắc riêng của REA), `knip`, `jscpd`, `scan-todos.mjs` và Stryker mutation testing.
- Phân tách rõ ràng giữa tầng `domain` thuần, `contracts` (Zod), `application` workflows và `composition` factories.

### Điểm cần lưu ý (Baseline hiện tại trên máy local)

- Thư mục `node_modules/` hiện chưa được cài đặt (`npm ci` chưa chạy) và Node.js mặc định trên `PATH` của máy là `v23.10.0` (trong khi `.nvmrc` ghim `24.22.1`).
- `scripts/run-python-tests.py` chứa các bài test bridge POSIX (`resource`, `fcntl`) nên cần chạy trên Linux/macOS/WSL để xanh đủ 22/22 bài (trên Windows native pass 9/22 bài).
- Kiểm tra `git check-ignore -v AGENTS.md CLAUDE.md .claude/PROJECT_SUMMARY.md`: cả 3 đường dẫn đều **không** nằm trong `.gitignore` hiện hành của repo (`AGENTS.md` đang được git track; `CLAUDE.md` và `.claude/*` đang là untracked files). Theo quy tắc §13, không tự ý sửa `.gitignore`.

### Việc nên làm tiếp

1. Chuyển Node.js sang phiên bản tương thích với `package.json#engines` (khuyến nghị `24.22.1` theo `.nvmrc`) và chạy `npm ci` khi bắt đầu task phát triển code TypeScript.
2. Quyết định xem muốn thêm `CLAUDE.md` và `.claude/` vào `.gitignore` (hoặc `.git/info/exclude`) để giữ sạch working tree khi đóng góp PR lên upstream `morluto/rea`, hay giữ theo dõi cục bộ.
