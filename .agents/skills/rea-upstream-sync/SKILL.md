---
name: rea-upstream-sync
description: Safely fetch and synchronize REA with upstream (upstream/main at morluto/rea) while preserving local Setup v2 customizations (AGENTS.md, CLAUDE.md, .claude/*, hooks/*, and _reference/*) and keeping origin pointed to LittleKai/rea. Use when the SessionStart/PreInvocation hook reports a new upstream commit or when the user asks to update/sync REA from upstream.
---

# REA Upstream Sync

Đồng bộ an toàn repo `D:\Dev\7.REA\rea` (remote `origin`: `https://github.com/LittleKai/rea`) với nhánh gốc `upstream/main` (`https://github.com/morluto/rea`) mà **không làm mất** bất kỳ cấu hình Setup v2 (`AGENTS.md`, `CLAUDE.md`, `.claude/*`), bộ hook (`hooks/rea_upstream.py`, `.agents/hooks.json`, `.codex/hooks.json`) hay dữ liệu phân tích đã lưu trong `_reference/`.

## Khi nào sử dụng

- Khi hook đầu phiên (`SessionStart` / `PreInvocation`) báo `[REA Upstream] Phát hiện bản mới trên upstream/main` và người dùng đồng ý cập nhật.
- Khi người dùng yêu cầu kiểm tra bản mới, `fetch` hoặc cập nhật REA theo repo gốc.

## Quy trình 5 bước bắt buộc

### Bước 1: Kiểm tra thay đổi từ Upstream trước khi đồng bộ

Chạy lệnh kiểm tra chi tiết bằng môi trường Conda đã khoá:

```powershell
D:\Dev\conda-envs\py312\python.exe hooks/rea_upstream.py status
```

Đọc JSON trả về (`up_to_date`, `commit_count`, `commits`, `changed_files`, `agents_md_changed_upstream`, `needs_npm_ci`, `needs_build`) và báo ngắn gọn cho người dùng biết upstream có bao nhiêu commit mới và chạm tới những phần nào.

### Bước 2: Chạy đồng bộ an toàn (Backup + Fast-Forward + 3-way merge `AGENTS.md`)

Khi người dùng xác nhận đồng bộ, chạy:

```powershell
D:\Dev\conda-envs\py312\python.exe hooks/rea_upstream.py sync
```

Cơ chế tự động của `sync`:

1. Kiểm tra working tree: nếu có file tracked ngoài `AGENTS.md` đang sửa dở, dừng lại ngay và báo người dùng `stash`/`commit` trước.
2. Tạo bản sao lưu đầy đủ (`AGENTS.md`, `CLAUDE.md`, `.claude/`, `.codex/hooks.json`, `.agents/hooks.json`, `.agents/skills/rea-upstream-sync/`, `hooks/rea_upstream.py`) vào `_reference/cache/setup-backup/<timestamp>/`.
3. Thực hiện `git merge --ff-only <upstream_head>` cho toàn bộ mã nguồn dự án (giữ nguyên toàn bộ `_reference/`, `.claude/`, `CLAUDE.md`).
4. Với `AGENTS.md`:
   - Nếu upstream **không** sửa `AGENTS.md`: khôi phục nguyên vẹn bản `AGENTS.md` Setup v2 hiện tại.
   - Nếu upstream **có** sửa `AGENTS.md`: lưu diff của upstream vào `upstream-AGENTS.diff` trong thư mục backup và chạy `git merge-file` (3-way merge).

### Bước 3: Xử lý thay đổi trên `AGENTS.md` (nếu `agents_md_changed_upstream == true`)

- Mở file `upstream_agents_diff` trong thư mục backup để xem tác giả gốc đã thêm/sửa quy tắc gì trên `AGENTS.md`.
- Nếu `agents_md_conflicts > 0` (hoặc có quy tắc mới từ upstream), chuyển nội dung quy tắc mới đó vào đúng mục tương ứng trong `AGENTS.md` (hoặc `.claude/CONVENTIONS.md`) theo chuẩn Setup v2 (< 200 dòng), xoá sạch conflict markers `<<<<<<<` / `=======` / `>>>>>>>`.

### Bước 4: Cập nhật Dependencies & Build lại Artifact (nếu cần)

- Nếu `needs_npm_ci == true` (`package.json` hoặc `package-lock.json` thay đổi): chạy `npm ci`.
- Nếu `needs_build == true` (`src/`, `scripts/`, `bridge/`, hoặc `.agents/skills/reverse-engineer-anything/` thay đổi): chạy `npm run build:cached` và `npm run check:fast`.

### Bước 5: Cập nhật `.claude/PROJECT_SUMMARY.md` & Chạy cổng kiểm chứng (`VERIFY`)

1. Cập nhật ngày/phiên bản trong `.claude/PROJECT_SUMMARY.md` nếu version gói hoặc kiến trúc provider thay đổi.
2. Luôn chạy lệnh kiểm chứng bắt buộc trước khi báo hoàn tất:

```powershell
npx oxfmt AGENTS.md .claude/*.md .claude/settings.json .codex/hooks.json .agents/hooks.json .agents/skills/rea-upstream-sync/SKILL.md
D:\Dev\conda-envs\py312\python.exe D:\Dev\3.lib_pj\hybrid-ai-skills\.claude\0.Claude_set_up\audit_setup_v2.py D:\Dev\7.REA\rea  # quét toàn bộ tracked files, khuyến nghị timeout >= 120s
npx oxfmt --check AGENTS.md .claude/*.md .claude/settings.json .codex/hooks.json .agents/hooks.json .agents/skills/rea-upstream-sync/SKILL.md
```
