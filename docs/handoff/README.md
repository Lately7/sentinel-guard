# Bàn giao cho phiên Claude / Codex mới

| Tệp | Dùng cho |
|---|---|
| `PROJECT_CONTEXT.md` | Ngữ cảnh chung cho cả hai: trạng thái, quyết định đã chốt, kế hoạch commit, known issues, quy tắc an toàn |
| `PROMPT_CLAUDE.md` | Prompt dán vào phiên Claude Code mới (Blue Team) |
| `PROMPT_CODEX.md` | Prompt cho Codex (chỉ có prompt, để pipe thẳng vào `codex exec`) |
| `codex-review-r1.md` … `r3.md` | Ba vòng thảo luận thiết kế Claude ↔ Codex (câu hỏi + câu trả lời nguyên văn) |

## Chạy Codex

PowerShell 5.1 mặc định pipe chữ sang chương trình ngoài bằng ASCII, nên luôn
đặt UTF-8 trước.

**Review / thảo luận (chỉ đọc), khi chưa có `CODEX_TASK_1a.md`:**

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
cd "C:\Users\lately07\Desktop\Folder Group\sentinel-guard"
Get-Content -Raw -Encoding UTF8 .\docs\handoff\PROMPT_CODEX.md | codex exec --sandbox read-only -C . -
```

**Vòng test** (sau khi Claude đã commit C3f và viết `CODEX_TASK_1a.md`), trong
worktree sạch trên nhánh riêng:

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
git worktree add ..\sentinel-guard-codex-1a <hash-C3f> -b codex/round-1a
cd ..\sentinel-guard-codex-1a
Get-Content -Raw -Encoding UTF8 .\CODEX_TASK_1a.md | codex exec --sandbox workspace-write -C . -
```

Sau vòng test, Claude kiểm tra `git status` và chạy
`tools/check_codex_scope.ps1`: `workspace-write` không tự giới hạn tệp nào
Codex được ghi.

**Tiếp tục đúng phiên thảo luận cũ của Codex (giữ ngữ cảnh 3 vòng):**

```powershell
codex exec resume 01a19b4d-b7b0-7240-a851-dbd9aab366ce -c 'sandbox_mode="read-only"' "<câu hỏi>"
```
