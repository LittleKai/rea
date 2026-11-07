# Instructions for agents — REA (Reverse Engineer Anything)

`REA` (`rea-agents`) là bộ công cụ dịch ngược (reverse engineering) chạy cục bộ với luồng phân tích dùng chung giữa CLI (`rea` / `rea-agents`) và MCP server, hỗ trợ phân tích binary thực thi, ứng dụng JavaScript/Electron, .NET assemblies, APK/Flutter, firmware, gói tin mạng, crash dumps và hành vi runtime kèm bằng chứng (`Evidence`) có truy vết nguồn gốc.

File này là **bộ định tuyến dùng chung cho Codex, Antigravity và Claude Code** (`CLAUDE.md` là shim 1 dòng `@AGENTS.md`) — nó nói _đọc gì_ và _luật nào không được bỏ qua_. Mọi chi tiết nằm ở file nó trỏ tới; **thêm vào đây là lựa chọn cuối cùng, không phải mặc định.**

Text files are UTF-8 without BOM. In PowerShell read them with `Get-Content -Encoding UTF8`; plain `Get-Content` under `-NoProfile` garbles Vietnamese, and writing that text back corrupts the file.

---

## 🎯 ĐẦU RA LÀ GÌ

Artifact bàn giao là gói npm `rea-agents` (`dist/`, `scripts/rea.mjs`, `skills/`, `bridge/**`, native Windows addon `native/windows/build/rea-windows-x64.node`, `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`, `.codex-plugin/mcp.json`) cung cấp CLI và MCP server dùng chung.

**Bàn giao bắt buộc:**

- Phân biệt rõ quan sát (`observations`), suy dẫn (`derivations`), suy luận (`inferences`) và phần chưa rõ (`unknowns`); bảo toàn nguồn gốc `Evidence` và ngữ nghĩa phiên (`session`) qua cả hai adapter CLI và MCP.
- Tuân thủ quy tắc phạm vi đóng góp và tích hợp fail-closed tại [CONTRIBUTING.md](CONTRIBUTING.md#contribution-scope): không tích hợp năng lực mới khi phạm vi, quyền hạn, tác dụng phụ hoặc yêu cầu kiểm chứng còn bỏ ngỏ; cần quyết định phạm vi của maintainer trước khi triển khai lớn cho provider/năng lực thực thi, tiêm mã, biến đổi (mutation) hoặc khôi phục bảo vệ.
- `docs/public/product-catalog.json`, `docs/verification/managed-conformance-*.json` và `skills/` là đầu ra sinh tự động (đã gitignore): chỉ sửa contract nguồn và `.agents/skills/reverse-engineer-anything/`, sau đó chạy lệnh generate tương ứng. `.cache/mcp-tool-catalog.json` là test metadata; không bao giờ commit binary, tài liệu project của provider, credential, `dist/`, `node_modules/` hay planning artifacts.

**Phạm vi:** "toàn workspace" giữ root và các thành phần liên quan; tên hoặc đường dẫn cụ thể chọn đúng đơn vị đó. Không tự chọn project từ memory/file vừa đọc; chỉ hỏi khi thông tin thiếu làm thay đổi kết quả.

---

## 📖 ĐỌC GÌ — theo việc đang làm

**Luôn luôn, trước mọi việc:** `.claude/PROJECT_SUMMARY.md` (trạng thái dự án — đọc nó, đừng đọc lại toàn bộ code). Bảng bên dưới định tuyến các tài liệu bổ sung theo task; nó không thay thế summary lõi.

| Task đụng tới                                                                                                  | Đọc trước                                                                                                                                                                                                 |
| -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Thêm/sửa code TypeScript, quy ước đặt tên, xử lý lỗi `Result`, kiểm rào chắn kiến trúc, hoặc chuẩn bị Issue/PR | `.claude/CONVENTIONS.md` + [CONTRIBUTING.md](CONTRIBUTING.md)                                                                                                                                             |
| Thiết kế hoặc sửa công cụ điều tra, hợp đồng CLI/MCP, schema JSON, hoặc ngữ nghĩa `Evidence`                   | [docs/tool-design.md](docs/tool-design.md) + `.agents/skills/rea-tool-design/SKILL.md`                                                                                                                    |
| Thay đổi cấu trúc liên tầng, đăng ký provider mới, hoặc vòng đời phiên / tài nguyên                            | [docs/architecture.mermaid](docs/architecture.mermaid) + [docs/capability-composition.md](docs/capability-composition.md)                                                                                 |
| Thay đổi giới hạn đầu vào, ngân sách bộ nhớ, timeout hoặc phục hồi lỗi                                         | [docs/design/limits-and-recovery.md](docs/design/limits-and-recovery.md)                                                                                                                                  |
| Thay đổi installer, tải file phát hành hoặc kiểm thử vòng đời / biên ranh giới                                 | [docs/testing.md#checking-installers-and-publisher-downloads](docs/testing.md#checking-installers-and-publisher-downloads) + [docs/testing.md#boundary-regressions](docs/testing.md#boundary-regressions) |
| Tối ưu hiệu năng phân tích, giảm token ngữ cảnh agent, thiết kế cache hoặc giảm độ trễ/bộ nhớ                  | `.agents/skills/rea-analysis-optimization/SKILL.md` + mục [Performance](#performance) bên dưới                                                                                                            |
| Thêm/sửa test, kiểm thử vòng đời (lifecycle regressions), hoặc kiểm toán CI/test suite                         | [docs/testing.md](docs/testing.md) + `.agents/skills/rea-ci-tests-audit/SKILL.md`                                                                                                                         |
| Cập nhật changelog phát hành hoặc ghi chú Release Please                                                       | `.agents/skills/rea-changelog-update/SKILL.md`                                                                                                                                                            |
| Dùng REA phân tích repo/binary/ứng dụng mục tiêu hoặc tiếp tục phiên phân tích trước đó                        | [`_reference/INDEX.md`](_reference/INDEX.md) + `.agents/skills/reverse-engineer-anything/SKILL.md`                                                                                                        |
| Kiểm tra bản mới từ repo gốc (`upstream/main`) hoặc đồng bộ upstream mà không mất cấu hình Setup v2            | `.agents/skills/rea-upstream-sync/SKILL.md` + `hooks/rea_upstream.py`                                                                                                                                     |
| Tóm tắt output/log lớn (`> 150` dòng), đọc lướt 3+ file lạ, giao code 1 file cô lập hoặc điều phối worker Orca | `~/.agents/skills/delegate/SKILL.md` (`$HOME/.agents/skills/delegate/scripts/delegate.mjs`, không clone vào repo)                                                                                         |

**KHÔNG đọc:**

- ❌ Toàn bộ `src/` hoặc `tests/` chỉ để "hiểu dự án" khi đã có `.claude/PROJECT_SUMMARY.md`
- ❌ File đã được tóm tắt trong `.claude/PROJECT_SUMMARY.md` nếu task không đụng tới
- ❌ `.claude/archive/` — lịch sử đã hết hiệu lực; chỉ mở để biết **vì sao** một quyết định cũ được đưa ra, và không bao giờ làm theo nó
- ❌ Các thư mục build/vendor/generated và bản dịch README: `dist/`, `build/`, `node_modules/`, `third_party/`, `_reference/` (trừ `_reference/INDEX.md` và `_reference/targets/<slug>/` của mục tiêu đang phân tích), `website/_site/`, `skills/`, `docs/readme/README_*.md`, `CHANGELOG.md` (trừ khi task yêu cầu sửa đúng file đó)

---

## ⚙️ CONTRACT VẬN HÀNH (§0.7)

1. **Entrypoint, script và file tạm:** Giữ nguyên đường dẫn entrypoint đang được `package.json`, plugin và CI sử dụng (`scripts/rea.mjs`, `scripts/plugin-mcp-launcher.mjs`, `scripts/prepack.mjs`, `scripts/prepare.mjs`, `src/cli.ts`, `src/main.ts`, `bridge/**`, `native/windows/build/**`). Chỉ dời script/alias sau khi truy vết mọi tham chiếu động, verifier, subprocess và test theo `CONTRIBUTING.md`.
2. **Dependency & nhiều runtime:** Dùng đúng toolchain khoá trong [.nvmrc](.nvmrc) (`24.22.1`) và `package.json#packageManager` (`npm@11.16.0` + `package-lock.json`; cài bằng `npm ci`). Trên Cursor Cloud có thể cần tiền tố `PATH="/usr/local/bin:$PATH"` trước `node` và `npm`. Dùng Node.js và npm cho build và verifier scripts (hỗ trợ Bun chỉ dành cho package đã cài). Trên máy Windows này, mọi lệnh Python chạy qua Conda env đã khoá (`D:\Dev\conda-envs\py312\python.exe` hoặc `D:\Dev\conda-envs\py310\python.exe`), cấm dùng Python hệ thống hay conda base. Ghidra và IDA là bring-your-own; installer không tự cài/nâng cấp Homebrew, Node.js, npm, Java hay Ghidra.
3. **Biến môi trường & cấu hình:** Cấu hình thay đổi bởi `rea setup` phải chỉ cộng thêm (additive), idempotent, có tạo backup và hiển thị kế hoạch chờ người dùng duyệt trước khi ghi file hoặc cài Hopper. Không lưu trữ môi trường xung quanh (ambient environment) chỉ vì tiến trình con kế thừa nó (`src/process/snapshotEnvironment.ts`).
4. **Kiến trúc tầng & Bridge/IPC:** Phụ thuộc chảy vào trong (`docs/architecture.mermaid`): Domain (`src/domain/`) + Contracts (`src/contracts/`) → Provider Adapters (`src/<provider>/`, `src/providers/`, `src/process/`) → Shared Application Workflows (`src/application/`) → Composition & Entry Adapters (`src/composition/`, `src/cli.ts`, `src/main.ts`, `src/server/`). Giữ giao thức engine và code đặc thù provider ngoài domain/application. Kiểm tra JSON Schema quảng cáo sau khi chuyển đổi SDK với dialect đã khai báo và client thực tế; gắn handler vào named contracts với kiểu chính xác (`src/server/contractToolHandler.ts`), thứ tự catalog không bao giờ được dùng để chọn thao tác hay schema.
5. **Quyền hạn Provider & An toàn dữ liệu:** Ghidra dùng database tạm thời không sửa byte thực thi hay điều khiển GUI (Windows Ghidra P0 không có quyền mutate). Phân tích IDA là chỉ đọc — tuyệt đối không lưu hoặc đóng database GUI đang đính kèm. Giới hạn tài nguyên phải bám sát ràng buộc thực tế của định dạng/giao thức (`docs/design/limits-and-recovery.md`, `src/process/LinuxResourceLimits.ts`), tính cả độ nở biểu diễn trước khi cấp phát.
6. **Sở hữu tài nguyên, Timeout & Vòng đời tiến trình:** Mỗi diễn giải và tài nguyên phải có một chủ sở hữu (owner) rõ ràng; consumer dùng dữ kiện đã parse của owner thay vì đọc lại nguồn thô. Tái sử dụng nguyên hàm giám sát và định danh trong `src/process/`; chỉ PID và đường dẫn thực thi không đủ chứng minh quyền sở hữu sau khi tiến trình thoát hoặc tái sử dụng. Tách biệt bằng chứng sở hữu với tính hợp lệ, khả năng chỉnh sửa và trạng thái sẵn sàng; dữ liệu thuộc sở hữu bị lỗi định dạng vẫn có thể được dọn an toàn. Giữ lại quyền sở hữu tài nguyên có bước dọn dẹp thất bại để thử lại (`CapabilityScope`, `src/providers/`). Thay đổi vòng đời phải tuân thủ [ownership and completion invariants](docs/tool-design.md#own-the-lifecycle) và kiểm thử [lifecycle regressions](docs/testing.md#lifecycle-regressions) (bắt tay muộn, huỷ trong lúc dọn dẹp cuối cùng, kết quả con hỗn hợp và thử lại dọn dẹp).
7. **Lưu trữ phân tích & Cache cục bộ tại root (`_reference/`):** Khi dùng REA phân tích bất kỳ repo/binary/ứng dụng nào, lưu toàn bộ cache công cụ (`_reference/cache/`, ví dụ `REA_KUNA_CACHE_DIR=D:\Dev\7.REA\rea\_reference\cache\kuna`), snapshot (`_reference/targets/<slug>/snapshots/`), evidence bundle (`_reference/targets/<slug>/evidence/`), artifact/repo (`_reference/targets/<slug>/artifacts/`) và báo cáo (`_reference/targets/<slug>/REPORT.md`) ngay tại `D:\Dev\7.REA\rea\_reference\` (đã gitignore). Luôn đọc `_reference/INDEX.md` đầu phiên để nạp lại snapshot/evidence cũ và cập nhật lại `_reference/INDEX.md` khi kết thúc phiên.

<a id="performance"></a>

## Performance

Thiết kế luồng phân tích và giao diện agent tối ưu ngay từ đầu trong khi giữ nguyên tính đúng đắn, `Evidence` provenance, lựa chọn của caller và giới hạn tài nguyên an toàn. Thứ tự ưu tiên:

1. **Agent tokens và context:** Trả về câu trả lời nhỏ nhất đủ dùng kèm provenance, độ phủ và giới hạn cần thiết. Dùng chọn lọc tác vụ, tóm tắt (`detail: "summary"`), phân trang và `Evidence` lưu giữ nơi hỗ trợ; tính chi phí trên toàn bộ tác vụ (gồm cả schema, lệnh gọi phụ và retry).
2. **Thời gian phân tích:** Tái sử dụng kết quả đã xác thực và công việc dùng chung. Khóa cache phải bao phủ mọi đầu vào ảnh hưởng kết quả; xác định rõ điều kiện vô hiệu hóa/vòng đời và kiểm tra độ mới trước khi báo trạng thái live đã cache là hiện hành.
3. **CPU và bộ nhớ:** Tránh công việc và sao chép thừa; giới hạn độ đồng thời, trạng thái lưu giữ và độ phình tuần tự hóa.

Chỉ đo hiệu năng khi thay đổi nhắm vào hiệu năng hoặc có nguy cơ suy giảm cụ thể (dọn dẹp thông thường dùng kiểm tra tính đúng đắn). Khi đo, so sánh tác vụ hoàn chỉnh tương đương trước/sau, báo cáo token, thời gian thực thi, CPU time và đỉnh bộ nhớ họ tiến trình (tách riêng lần chạy lạnh/ấm, gắn nhãn ước tính và nêu phần chưa đo). Phối hợp các phép kiểm nặng giữa các agent; nếu test ngốn CPU bất thường, dừng họ tiến trình thuộc sở hữu của nó và profile một ca đại diện giới hạn trước khi chạy lại ([docs/testing.md](docs/testing.md#developer-commands)).

---

## 🧪 VERIFY — chưa nhìn thấy thì chưa xong

Bắt buộc chạy và nhìn thấy kết quả **của lần chạy này** trước khi kết thúc task (nêu rõ phạm vi chưa kiểm hoặc provider thật không có sẵn là `UNVERIFIED` / `NOT_ENOUGH_INFO`, không dùng simulated provider để tuyên bố hành vi real-provider):

1. **Chỉ sửa tài liệu setup (`AGENTS.md`, `CLAUDE.md`, `.claude/*`):** Chạy `D:\Dev\conda-envs\py312\python.exe D:\Dev\3.lib_pj\hybrid-ai-skills\.claude\0.Claude_set_up\audit_setup_v2.py .` (`0 FAIL, 0 MISSING`), `node scripts/check-doc-facts.mjs` (hoặc `npm run docs:check`), và `npx oxfmt --check AGENTS.md`.
2. **Sửa code TypeScript / contracts / adapters (`src/`, `tests/`, `scripts/`):**
   - `npm run check:fast` (typecheck + `oxlint` + `verify:module-boundaries`) và `npm run verify:architecture-guards`.
   - `npm run test:local -- <PATH...>` (test nguồn không cần build) hoặc `npm run test:focused -- <PATH...>` (test kèm artifact cần thiết). Thêm/dời file test phải chạy `npm run verify:test-discovery`.
3. **Sửa CLI / MCP / skills / docs projections:** Chạy `npm run build:cached`, chạy thử artifact CLI/MCP thật (`node scripts/rea.mjs --help` hoặc lệnh phân tích liên quan), và `npm run docs:check`.
4. **Sửa bridge Python (`bridge/**/*.py`, `scripts/run-python-tests.py`):** Chạy `npm run test:python` (trên Linux/macOS hoặc qua `D:\Dev\conda-envs\py312\python.exe scripts/run-python-tests.py`; lưu ý các bridge POSIX cần `resource`/`fcntl` chạy trên Linux/WSL).
5. **Thay đổi rộng hoặc chẩn đoán CI:** Chạy `npm run check:pr`.

---

## ✍️ SAU MỖI TASK — viết lại vào đâu

Cập nhật `.claude/PROJECT_SUMMARY.md` theo luật ngay đầu file đó. Học được điều **đúng cho cả lần sau** thì nâng lên tầng dùng chung:

| Loại                                                            | Ghi vào                                                                                          | Viết thế nào                                                                                                      |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Quy ước code, đặt tên, kiến trúc, PR/Issue                      | `.claude/CONVENTIONS.md`                                                                         | Câu mệnh lệnh kèm ≥2 ví dụ `file::symbol`; quy ước công cụ đã cưỡng chế thì đưa vào bảng công cụ và xoá văn xuôi  |
| Lỗi im lặng, dễ tái phát (khi phát sinh bẫy đầu tiên theo §0.5) | `.claude/IMPORTANT_FIXED_BUGS.md`                                                                | Triệu chứng → nguyên nhân → Do Not Repeat + một dòng trong Bảng bẫy (có CỬA RA ✅/🔶/❌ xuống `.claude/archive/`) |
| Rào chắn AST / biên module / quy tắc lint dùng chung            | `scripts/verify/architecture-guards.mjs` · `scripts/lib/module-boundaries.mjs` · `scripts/lint/` | Cưỡng chế trực tiếp bằng code trong luồng `npm run check`                                                         |

---

## 🔒 BẢO MẬT

- **Không** ghi API key, token, password, credential hay dữ liệu mục tiêu nhạy cảm thật vào bất kỳ file nào bị Git theo dõi — kể cả comment, test fixture và markdown. Chỉ dùng placeholder `<YOUR_API_KEY>`.
- Bảo toàn đầu vào do caller chọn và bằng chứng cục bộ (output, URL, đường dẫn, digest, metadata). Che dấu (redact) thông tin xác thực transport và các giá trị nhạy cảm được đánh dấu tường minh; không suy đoán tính bí mật chỉ từ tên biến hay mẫu văn bản.

---

## 🧭 CÁCH LÀM

1. **Đừng đoán & không mở rộng phạm vi ngầm:** Trước khi thêm độ phức tạp cho một race condition hoặc góc cạnh bảo mật suy đoán/hiếm gặp, giải thích rõ chế độ lỗi cụ thể, xác suất và chi phí độ phức tạp cho người dùng để xin ý kiến.
2. **Sửa tận gốc độ giòn (brittleness):** Khi sửa lỗi hoặc trả lời review thread, kiểm tra biên sản sinh dữ liệu (producing boundary) và mọi consumer/sibling adapter có diễn giải trùng lặp hoặc sở hữu mơ hồ. Chuẩn hóa một lần tại biên sở hữu bằng parser hiểu định dạng; hoàn tất refactor trực tiếp và xoá biểu diễn/wrapper/test dư thừa trong cùng thay đổi. Trước khi đóng review thread, giải thích nguyên nhân gốc, cách sửa cấu trúc, bước kiểm chứng và phần dọn dẹp còn lại.
3. **Mô hình hóa lỗi tường minh:** Parse các giá trị chưa biết ở biên và mô hình hóa lỗi dự kiến bằng đại số lỗi gắn thẻ (`AnalysisErrorTag` trong `src/domain/analysisErrorBase.ts`) và `Result` (`src/domain/result.ts`). Bảo toàn dữ kiện một phần (partial facts) và lý do thất bại có nghĩa; tách biệt giá trị định danh/tra cứu với định dạng hiển thị; giữ nguyên giá trị gốc và trạng thái `unknown` tường minh khi chuẩn hóa làm mất thông tin (đường dẫn tuyệt đối, `file://` URL và đường dẫn HTTP có ngữ nghĩa khác nhau).
4. **Báo cáo Issue & Pull Request Readiness:** Tuân thủ [CONTRIBUTING.md](CONTRIBUTING.md#reporting-issues), [human ownership and readiness](CONTRIBUTING.md#pull-request-ownership-and-readiness) và chi tiết tại `.claude/CONVENTIONS.md`. Dùng Conventional Commits và tiêu đề PR chuẩn (`feat:`, `fix:`, v.v.), đánh dấu breaking changes bằng `!` hoặc `BREAKING CHANGE:`. Giữ nguyên trạng thái draft của PR trừ khi được yêu cầu đổi; **để trống** các ô **Author readiness** cho chủ sở hữu con người tự đánh dấu, tuyệt đối không xác nhận thay mặt họ.
5. **Sửa lỗi công cụ trước, hướng dẫn skill là phụ:** Khi người dùng hoặc agent gặp vấn đề về công cụ, ưu tiên sửa hành vi sở hữu, hợp đồng và kết quả/phục hồi khả thi ngay tại điểm sử dụng. Chỉ bổ sung hướng dẫn skill cho phán đoán workflow hoặc ngữ cảnh mà công cụ không thể truyền tải hợp lý; không dùng skill làm giải pháp chính cho lỗi hợp đồng hoặc khả năng phát hiện.

---

## 🗂️ BỘ KHUNG

**Công cụ:** TypeScript 7 (`tsgo` / `tsrs`), Node.js (`24.22.1` theo `.nvmrc`), `npm@11.16.0`, Turborepo, Rolldown, Vitest 5, Oxlint + Oxfmt, Knip, Stryker, VitePress; Python tooling: `D:\Dev\conda-envs\py312\python.exe`.

| Tầng                       | Ở đâu                                                                                                            | Vai trò                                                                                                                     |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Điều hướng                 | `AGENTS.md` (file này) + `CLAUDE.md` shim                                                                        | Định tuyến tài liệu, hợp đồng vận hành §0.7 và cổng `VERIFY`                                                                |
| Văn bản dùng chung         | `.claude/*.md` + `docs/*.md` + `.agents/skills/`                                                                 | Tóm tắt trạng thái, quy ước code, hướng dẫn thiết kế công cụ/kiểm thử và skills (`archive/` là lịch sử, **không làm theo**) |
| Lõi nền tảng & hợp đồng    | `src/domain/`, `src/contracts/`, `src/process/`, `src/filesystem/`, `src/providers/`, `src/config/`              | Ngữ nghĩa domain thuần, schema CLI/MCP, giám sát tiến trình con, quản lý file và cấu hình                                   |
| Luồng nghiệp vụ & Adapters | `src/application/`, `src/composition/`, `src/server/`, `src/cli.ts`, `src/main.ts`, `src/<provider>/`, `bridge/` | Luồng điều tra dùng chung, фабрика kết nối provider, CLI/MCP entrypoints và cầu nối engine                                  |

---

## ⚠️ TRƯỜNG HỢP RIÊNG

- **"Review toàn bộ dự án"** hoặc **`.claude/PROJECT_SUMMARY.md` không có** → đọc toàn bộ cấu trúc và dựng lại summary đầy đủ.
- **`.claude/PROJECT_SUMMARY.md` lệch so với code** → sửa drift trong cùng task nếu code xác nhận được; chỉ hỏi user khi có nhiều cách hiểu làm thay đổi kết quả.
- **Phát hiện thay đổi dang dở của phiên khác** → không tự ý revert hay gộp; ghi rõ trong báo cáo cuối những file nào do phiên hiện tại sửa.

---

**📌 Tài liệu = nguồn sự thật duy nhất. Artifact đã build & lệnh kiểm chứng chạy xanh ở lần chạy này = bằng chứng duy nhất.**

<!-- BEGIN:turborepo-agent-rules -->

# This is NOT the Turborepo you know

Turborepo configuration, task behavior, and CLI commands can vary between installed versions and may differ from your training data. Resolve the `turbo` package from this file's directory or relevant workspace; in monorepos, it may not be visible from the repository root. For example, run `node -p "require.resolve('turbo/package.json')"` from a workspace that depends on `turbo`.

Read `docs/README.md` inside that installed package first, then read the relevant pages from its `docs/` directory before changing Turborepo configuration or commands. Heed deprecation notices. These bundled docs match the installed package version and are available without network access.

This block is written and re-added by `turbo` before repository-scoped commands when an AI agent is detected. In the Turborepo source repository, its template is defined in `crates/turborepo-cli/src/cli/agent_guidance.rs`. Removing the managed block while updates are enabled means a later qualifying invocation will add it again. Set `"agentGuidance": false` in the root `turbo.json` or `turbo.jsonc` to opt out; this does not remove an existing block. Keep the block committed with your work to avoid an uncommitted change on the next agent invocation.
<!-- END:turborepo-agent-rules -->
