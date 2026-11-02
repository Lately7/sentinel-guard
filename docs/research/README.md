# Chương trình nghiên cứu sâu — chuẩn bị cổng quét mới (Gate v2)

Mục tiêu (chủ dự án, 2026-11-02): Codex nghiên cứu thật kỹ ClamAV đến từng
dòng code, Malwarebytes và các antivirus khác, các loại mã độc; tổng hợp lại
cho Claude đọc; chuẩn bị kiến thức để **Codex viết một cổng quét hoàn toàn
mới** — "cánh cửa cuối cùng" trước khi một tệp được coi là an toàn.

Đây là thay đổi vai trò so với quyết định cũ (Claude viết toàn bộ code
production): chủ dự án quyết định Codex sẽ viết Gate v2. Codex làm trong
nhánh/worktree riêng; Claude review, chạy test và tích hợp. Các nguyên tắc an
toàn của `PROJECT_CONTEXT.md` §12 vẫn giữ nguyên.

## Các vòng

| Vòng | Chủ đề | Nguồn | Kết quả |
|---|---|---|---|
| R8a | ClamAV: kiến trúc, đường đi của một lần quét, bộ so khớp, giới hạn, kết quả trả về | mã nguồn ClamAV 1.5.4 | `R8a-clamav-engine.md` |
| R8b | ClamAV: nhận dạng loại tệp, bộ phân tích/giải nén (PE, archive, OLE2, PDF…), điều kiện thiếu | mã nguồn ClamAV 1.5.4 | `R8b-clamav-parsers.md` |
| R8c | ClamAV: định dạng chữ ký, CVD/freshclam, clamd và INSTREAM, đối chiếu với cách Sentinel dùng | mã nguồn + docs | `R8c-clamav-signatures-clamd.md` |
| R9 | Malwarebytes và các antivirus lớn: từng lớp, chính sách kết luận và hành động, khi mất kết nối | tài liệu công khai | `R9-commercial-av.md` |
| R10 | Mã độc nhìn từ cổng quét tệp: đường vào, dấu vết trên đĩa, cái cổng thấy/không thấy, ATT&CK | tài liệu công khai | `R10-malware-file-gate.md` |
| R12a | YARA-X: kiến trúc, binding Python, module PE/.NET/LNK, giới hạn, chất lượng luật | mã nguồn v1.22.1 | `R12a-yara-x.md` |
| R12b | capa + capa-rules: cách nhận diện khả năng, chi phí, dùng an toàn để giải thích | mã nguồn v10.0.0 | `R12b-capa.md` |
| R12c | osquery: cách đọc trạng thái Windows ở user mode (khởi động, tác vụ, tiến trình, Authenticode) | mã nguồn 5.24.0 | `R12c-osquery.md` |
| R12d | Wazuh: agent, FIM, rootcheck, luật và tương quan sự kiện, active response | mã nguồn v4.14.9 (một phần) | `R12d-wazuh.md` |
| R11 | Tổng hợp: bộ kiến thức + đặc tả Gate v2 (bất biến, giao diện, chính sách, kế hoạch test) | R5–R12 | `R11-gate-v2-knowledge-pack.md` |

Brief của từng vòng nằm trong `briefs/`. Kết quả của Codex được Claude đọc,
ghi chú chỗ đã kiểm chứng, rồi mới lưu vào thư mục này.

## Nguyên tắc cho mọi vòng

* Chỉ đọc. Không tải hay chạy mẫu mã độc; không viết cách né tránh.
* Mỗi khẳng định về code có `tệp:dòng`; mỗi khẳng định bên ngoài có nguồn.
* Tách rõ sự thật có tài liệu và suy luận.

Mã nguồn đã tải (tải nông, bỏ thư mục test-data để không kéo mẫu mã độc): `Folder Group\research\` — clamav-1.5.4, yara-x-1.22.1, capa-10.0.0, capa-rules, osquery-5.24.0, wazuh-4.14.9 (chỉ agent/FIM/rootcheck/analysisd/ruleset/architecture).
