# Lộ trình Sentinel Guard

Một trang duy nhất để theo dõi tiến độ. Chi tiết kỹ thuật vẫn nằm trong
`docs/handoff/PROJECT_CONTEXT.md`; khi hai nơi khác nhau thì code là đúng.

**Cập nhật:** 2026-11-02 · **Nhánh:** `gate-baseline` (chưa push)

## Ai làm gì

| Phe | Ai | Việc |
|---|---|---|
| Blue Team | Claude | Viết toàn bộ code, sửa lỗi, test, tài liệu, commit |
| Red Team | Codex | Review chỉ-đọc, nghiên cứu, viết test trong `tests/codex/**`, làm icon trong `assets/brand/**` |

Mọi phát hiện của Codex được Claude kiểm chứng rồi mới sửa hoặc từ chối (có lý do).

## Ba tính năng bắt buộc

| Tính năng | Hiện có | Còn thiếu |
|---|---|---|
| **Quét / Quét sâu** | Quét tệp, thư mục, quét nhanh, toàn máy; 4 lớp (Lõi → Luật+YARA → ClamAV → Defender) | Kết quả "một phần" hoặc engine lỗi vẫn có thể hiện "sạch"; chưa có Quét sâu đúng nghĩa và nút Quét một chạm |
| **Bảo vệ web trên Helium** | Extension MV3 chặn ~550.000 tên miền, trang cảnh báo, quét tệp tải về qua agent | Chờ Codex r6 đánh giá |
| **Bảo vệ thời gian thực** | Theo dõi Downloads, Desktop, Documents, Startup, %TEMP%, khoá Run | Chỉ phát hiện sau khi tệp đã ghi xuống đĩa (không có driver); chưa loại trừ thư mục dữ liệu của chính Sentinel |

## Các giai đoạn

| # | Giai đoạn | Trạng thái |
|---|---|---|
| 0 | **Nền tảng**: C1 icon cũ, C2a cổng quét, C2b baseline, giao diện tối, bộ icon | ✅ xong (icon đang làm lại bản 2) |
| 1 | **Sửa lỗi cổng quét** (C3a–C3f + RT-010, RT-011, RT-015) | ⏭ việc tiếp theo |
| 2 | **Red Team viết test** (Codex vòng 1a, 1b) | chờ giai đoạn 1 |
| 3 | **Contract v1**: tách trạng thái quét khỏi kết luận; "một phần"/lỗi không bao giờ là "sạch" | chờ |
| 4 | **Chính sách ClamAV + cách ly an toàn** | chờ |
| 5 | **Ba tính năng chính hoàn chỉnh**: Quét thông minh + Quét sâu với pipeline trực tiếp, thời gian thực, extension | chờ |
| 6 | **Tính năng bổ sung** (chọn từ nghiên cứu r6, r7) | chờ |
| 7 | **Đo báo nhầm (FP) lần 2**, chuẩn bị phát hành | chờ |

### Giai đoạn 1 — từng commit

| Commit | Nội dung | Sửa |
|---|---|---|
| C3a | Kết quả Defender có kiểu (sạch/độc/lỗi/hết giờ/không có) | RT-008 |
| C3b | Định danh cổng quét theo nội dung luật; không cache kết quả chưa đầy đủ | RT-009 |
| C3c | Giữ trạng thái "bỏ qua"/"một phần" cho ZIP quá lớn | một phần RT-004 |
| C3d | Sửa 2 test đang khoá quyết định sai; sổ RT; `tools/check_codex_scope.ps1`; vai trò Codex trong `AGENTS.md` | — |
| C3e | Native host đọc đủ thân thông điệp | RT-006 |
| C3f | Chỗ cắm test cho ClamAV client | — |
| C3g | Mã thoát CLI đúng thứ tự 2 > 3 > 1 > 0 | RT-011 |
| C3h | Cập nhật chữ ký thất bại thì thử lại sớm | RT-010 |
| C3i | Đặt đường dẫn trong `clamd.conf` vào ngoặc kép | RT-015 |
| C4 | `CODEX_TASK_1a.md`, `CODEX_TASK_1b.md` ghim vào commit C3i | — |

## Sổ lỗi (RT)

| Id | Vấn đề | Mức | Sửa ở |
|---|---|---|---|
| RT-001 | Tên ClamAV yếu (vd. `Win.Trojan.Suspect-34`) bị coi là chắc chắn độc → tự cách ly | Cao | GĐ 4 |
| RT-002 | Khôi phục tệp = tin cậy hash trên toàn máy | Cao | GĐ 4 |
| RT-003 | Thời gian thực quét cả dữ liệu của Sentinel | TB | GĐ 4 |
| RT-004 | Quét một phần có thể hiện "sạch" | Cao | C3c + GĐ 3 |
| RT-005 | Các lớp có thể đọc hai phiên bản khác nhau của tệp | Cao | GĐ 3–4 |
| RT-006 | Native host đọc thông điệp một lần | TB | C3e |
| RT-007 | CLI/quét theo yêu cầu không loại trừ dữ liệu Sentinel nhất quán | TB | GĐ 4 |
| RT-008 | Defender lỗi/hết giờ bị báo "sạch" | Cao | C3a |
| RT-009 | Cache giữ kết quả cũ hoặc chưa đầy đủ | Cao | C3b |
| RT-010 | Cập nhật lỗi vẫn ghi mốc thành công | TB | C3h |
| RT-011 | Mã thoát CLI sai thứ tự ưu tiên | TB | C3g |
| RT-012 | `AlertExceedsMax no` giấu việc ClamAV chạm giới hạn | Cao | GĐ 3 |
| RT-013 | ClamAV lỗi/không chạy mà kết luận chung vẫn "sạch" | Cao | GĐ 3 |
| RT-014 | Lưu trữ/tài liệu mã hoá không được ghi là "chưa kiểm tra được" | TB | GĐ 3 |
| RT-015 | Đường dẫn trong `clamd.conf` không có ngoặc kép | Thấp | C3i |

## Nghiên cứu của Codex

| Vòng | Chủ đề | Trạng thái | Tệp |
|---|---|---|---|
| r1–r3 | Thiết kế cổng quét, kế hoạch commit, pipeline | ✅ | `docs/handoff/codex-review-r1..r3.md` |
| r4 | Review trạng thái hiện tại (tài khoản mới) | ✅ RT-008…011 | `docs/handoff/codex-review-r4.md` |
| r5 | Điểm yếu ClamAV, so với Bitdefender/Malwarebytes | ✅ RT-012…015 | `docs/handoff/codex-research-r5.md` |
| r6 | Sản phẩm: 3 tính năng, so sánh, lỗ hổng, giao diện bớt "AI" | ⏳ đang chạy | — |
| r7 | Tổng quan tài liệu khoa học về các loại mã độc và cách phát hiện | ⏳ chờ r6 xong | — |
| Icon | Bộ icon: v1 xong; v2 một màu, vuông nhỏ, viền xa | ⏳ đang làm v2 | `assets/brand/` |

## Kiểm thử gần nhất

pytest **78 passed, 4 skipped** (không có clamd) / **82 passed** (có clamd) ·
extension **8 passed** — xem `docs/baseline.md`.
