# Kế hoạch toàn bộ Sentinel Guard

Viết 2026-11-02 tối, sau khi đọc lại code, đặc tả R11/R13b và chạy test. Tài liệu
này thay mục 3–5 của `NEXT_SESSION.md` về thứ tự công việc. Các quy tắc mục 7 của
`NEXT_SESSION.md` giữ nguyên, không nới lỏng.

## 0a. Trạng thái sau lần cài thật thứ hai, 2026-11-03

Lần cài đầu (Claude khởi chạy `tools\install_service.cmd`, trái mục 7) cho 13 PASS, 1 FAIL, 2 SKIP: worker
không khởi động được; xem `REVIEWS.md` vòng thứ sáu. Lần cài thứ hai do chính chủ dự án mở, khoảng 9:25,
với các vòng SVC1–SVC16 và phần nối ETW: **0 FAIL, 14 PASS, 3 SKIP**. `worker_scan` PASS ("worker answered:
clean") và `clean_stop_and_start` PASS: dịch vụ chạy LocalSystem và quét được tệp thật. Nguyên nhân lỗi worker
lần đầu vẫn chưa xác định; window station có tên là nghi phạm chính, nhưng worker không lỗi nên bước tự chẩn
đoán không chạy. Cảnh báo `no journal for G:\` là đúng: ổ G: không có USN journal.

ETW tự tắt với `schema_process_missing`. Trong vài giây kiểm tra mất 373.432 sự kiện, chỉ phân tích được
1.380: sự kiện tệp của cả máy đến nhanh hơn Python xử lý được và kéo mất cả sự kiện tiến trình. Chỉ có 61
sự kiện DCStart (danh sách tiến trình đang chạy), không có Start nào. Vòng SVC17 chỉ bật sự kiện tiến trình
và bỏ hẳn sự kiện tệp qua ETW. Hệ quả: chấm điểm ransomware (shadow) không có nguồn sự kiện tệp, 30 ngày quan
sát chưa bắt đầu, và trạng thái ghi `waiting_for_file_events` thay vì đếm ngày trống.

Lần cài thứ ba (9:57, có SVC17) vẫn 0 FAIL, nhưng ETW vẫn tắt. Byte thật trong log cho thấy trường SID có
16 byte header TOKEN_USER đứng trước, nên trước giờ chưa sự kiện tiến trình nào được đọc đúng; `8b6f043` sửa bộ
đọc và chỉ còn kiểm bằng sự kiện Start của tiến trình con. Xem `REVIEWS.md` vòng thứ chín.

Bước tiếp theo: chính chủ dự án tự mở lại `tools\install_service.cmd` để kiểm ETW cho tiến trình; Claude
không được mở hộp UAC. Dòng `etw` của verify cho kết quả và số sự kiện mất; nếu ETW vẫn tắt, các dòng
`etw check:` trong log có 160 byte đầu của sự kiện DCStart của chính dịch vụ. Đừng bấm vào cửa sổ cài: cú
bấm đưa nó vào chế độ chọn (tiêu đề bắt đầu bằng "Select") và mọi thứ nó in ra bị dừng lại; bấm Esc để chạy
tiếp. `sentinel service status` chạy được từ cửa sổ thường. Codex được dùng tích cực; các vòng chạy trong
worktree `..\sentinel-guard-svcN`, theo `NEXT_SESSION.md` mục 4.

Đã xong và đẩy lên `main`: M5, M6, A3 (code), M7, M8, A4, A5, A6, RT-002, R15-2, R15-8, RT-003, RT-007,
RT-024. Hai nhánh Codex (`codex/scope-a5`, `codex/reputation-etw`) đã review và gộp; nhiều chỗ viết lại,
xem `REVIEWS.md`. ETW đã chạy trên phiên thật một lần (xem trên) và giờ chỉ dùng sự kiện tiến trình;
layout payload DCStart/Start lấy từ tài liệu, chưa xác nhận trên byte thật. Ba mươi ngày quan sát cần một
nguồn sự kiện tệp, hiện chưa có. Tệp mồi chờ câu hỏi 11 của chủ dự án.
Chủ dự án quyết định ngày 2026-11-03: tiếp tục user-mode với dịch vụ LocalSystem, không dùng driver,
và dùng ETW bên cạnh bộ chụp tiến trình. Giới hạn vẫn là thấy tệp hoặc tiến trình sau khi xuất hiện,
không chặn ở mức kernel trước khi chạy.

Lệnh cài của chủ dự án chụp snapshot vào `%TEMP%\sentinel-snapshot`, cài rồi chạy `verify --restart`;
PASS/FAIL/SKIP từng mục nằm ở `%TEMP%\sentinel-install.log`. Gỡ bằng `sentinel service uninstall`
(giữ khu cách ly và nhật ký).

Trước lần cài đầu, vòng rà soát thứ năm (`REVIEWS.md`) tìm và sửa 13 lỗi sẽ làm hỏng lần chạy thật: bộ cài
(quyền đọc cấu hình, `SeRestorePrivilege`, group, cách Windows ghi lại ACL, gỡ khi dịch vụ đã mất, dọn khi
cài hỏng, ghi log khi khởi động hỏng), `verify` chạy quá sớm, worker chết ngay khi khởi động dưới token hạn
chế (hai nguyên nhân), bộ luật quá 1 MiB không tới được worker, và khay không tìm được helper UAC.

**Còn lại:**

* Kiểm tiếp worker trên bản cài thật; ETW, clamd với cơ sở dữ liệu thật và MpCmdRun chưa được xác nhận
  ở lần cài này.
* `tools/admin_acceptance.ps1` chưa có fixture: chờ câu hỏi 13. Trong lúc đó dùng `sentinel service verify`.
* Bước 9: đo báo nhầm có đủ engine, chủ dự án chốt ngân sách, rồi mới cân nhắc `evidence-v1`.
* Bước 10: kiểm ETW trên phiên thật, hỏi chủ dự án về tệp mồi (câu 11); tự dừng tiến trình cần 30 ngày quan sát (R14).
* M7, A6 và phần dịch vụ đã qua rà soát độc lập hai vòng, xem `REVIEWS.md`. Tải về từ URL bị chặn trong
  dịch vụ nay chỉ cảnh báo, không cách ly theo URL: URL do client gửi nên không được quyền quyết định
  (câu hỏi 2 vẫn mở cho chế độ không có dịch vụ).

## 0. Cập nhật tối 2026-11-02 (chủ dự án)

* **Đồng ý mục tiêu ≈7/10** so với Malwarebytes = 10, tự chạy hoàn toàn, săn edge case. Bước 10 không
  còn chờ duyệt. Ngoại lệ không đổi: Claude không tự nâng quyền, không đổi cài đặt hệ thống hay Defender,
  không tải gì, không chạy mã độc. Sản phẩm được viết để chạy quyền admin; lệnh cài do chủ dự án chạy.
* `gate-baseline` đổi tên thành `main`, đẩy lên `github.com/Lately7/sentinel-guard`, commit dần lên đó.
  Không force, không viết lại lịch sử.
* **Ước tính:** phần tự động khoảng 20 giờ máy chạy (15–25), nhiều khả năng qua 2–3 phiên; phần chủ dự án
  khoảng 1 giờ chạy script admin; tự động dừng tiến trình ransomware cần thêm 30 ngày quan sát (R14).
  Là ước lượng, không phải số đo. "7/10" cũng là ước lượng: không có lab mẫu thật để đo tỉ lệ phát hiện.
* Không làm được trong dự án này: ML tĩnh cho PE, vì cần bộ dữ liệu mẫu mà quy tắc không cho tải.
* Xong tới giờ: bước 1 (M5), bước 2 (M6, sản phẩm đã chạy qua Gate v2, Helium e2e đạt), phần code của
  bước 3 (A3: runtime bảo vệ, đăng ký dịch vụ, ACL, hộp xác nhận), R15 trừ R15-8 (vào M7), edge case E1–E6.
* **Làm tiếp theo thứ tự:** M7 (`gate_v2/actions.py`, backend thật của `ServiceCore`, `entry.main`, chuyển
  khay và native host sang IPC, R15-8, RT-002) → review và merge nhánh `codex/scope-a5` (bản nháp 1.050 dòng,
  chưa có test) và `codex/reputation-etw` (1.543 dòng, chưa chạy) → fixture cho `tools/admin_acceptance.ps1`
  → bước 8–9. Hai nhánh đó do Codex viết, dừng vì hết hạn mức lúc 21:09 và **chưa review**.
* Việc cần chủ dự án: `sentinel service snapshot --source <thư mục>`, xem lại, rồi `sentinel service install
  --source <thư mục>` trong cửa sổ admin; chỉ làm được sau M7 vì dịch vụ chưa có backend thật.

## 1. Nguyên tắc từ giờ

* **Claude chịu trách nhiệm toàn bộ** code, test, tích hợp, tài liệu. Kế hoạch này
  phải làm xong được mà không cần Codex.
* **Codex chỉ tận dụng nốt hạn mức còn lại** (ảnh chủ dự án gửi: 5h còn 74%, tuần còn
  96%, gói Plus) cho việc dài chạy nền. Không bước nào được chờ Codex. Hết hạn mức
  hoặc lượt chạy bị ngắt thì Claude làm tiếp từ bản đã có, ghi rõ trong `REVIEWS.md`.
* Mọi thứ Codex viết vẫn qua `tools/check_codex_scope.ps1`, Claude đọc từng dòng và tự
  chạy test trước khi merge.
* **Giữ lại phản biện độc lập khi không còn Codex:** mỗi mốc lớn, một subagent đọc code
  mới mà không được xem kết luận của Claude; test mới phải đỏ trên commit cũ; thử phá
  có chủ đích (mutation) cho các nhánh an toàn; lỗi nào cũng thêm vào bảng review.
* Không có bước nào Claude tự nâng quyền. Việc cần quyền admin nằm ở mục 5.

## 2. Trạng thái đo được (2026-11-02, khoảng 20:20)

| Mục | Kết quả |
|---|---|
| `gate-baseline` | commit `2b43cc0`, chưa push; pytest **393 passed, 4 skipped, 2 xfailed**; extension **39 passed** (tôi chạy lại tối nay) |
| 4 skip / 2 xfail | test clamd thật (clamd không chạy) / RT-001, RT-002 (có chủ đích) |
| Helium e2e | chưa chạy lại tối nay; lần cuối đạt theo báo cáo đêm |
| Lỗi mới phát hiện | `test_identity_changed_and_cancelled_between_chunks` đỏ 6/12 lần: ghi cùng nhịp đồng hồ thì NTFS không đổi timestamp (đo 204/300). Con số "393 passed" trong handoff là may. Đã sửa test (`2b43cc0`), đạt 30/30 |
| Bản M5 Codex bị ngắt | commit `b66cb3f` trên `codex/gate-v2-m5`; scope sạch; `tests/gate_v2` 236 đạt, 1 đỏ. Claude tìm ra 17 lỗi K1–K17, tái hiện được 11 lỗi |
| Sản phẩm | vẫn dùng `engine/scanner.py` cũ; chưa có gì gọi `gate_v2` |

### Codex đang chạy nền (bắt đầu 20:13)

| Việc | Loại | Kết quả ở | Khi xong Claude làm gì |
|---|---|---|---|
| M5 vòng 2 (K1–K17) | viết code, worktree `sentinel-guard-gate-v2` | `%TEMP%\sg-codex\gate-v2-m5-r2.md` | Kiểm scope, đọc từng dòng, chạy test mới trên `b66cb3f`, merge nếu xanh |
| M6 phần 1 (`cache.py`, `legacy.py`) | viết code, worktree `sentinel-guard-gate-v2-m6` | `gate-v2-m6-p1.md` | Như trên, sau khi M5 vào |
| R15 review độc lập Gate v2 + dịch vụ | chỉ đọc | `R15.md` | Kiểm chứng từng phát hiện, ghi vào `REVIEWS.md`, sửa trước M7 |
| R14 nghiên cứu ETW + tệp mồi | chỉ đọc, có tra cứu web | `R14.md` | Lưu vào `docs/research/`; chỉ là nghiên cứu, chưa làm code (bước 10) |
| R16 cài dịch vụ an toàn, ACL | chỉ đọc, có tra cứu web | `R16.md` | Đầu vào của bước 3 |

Lượt chạy nền chết nếu phiên Claude này bị đóng (lý do bản M5 bị ngắt lúc 19:53).

## 3. Thứ tự toàn bộ

| Bước | Việc | Phụ thuộc | Xong khi | Cỡ |
|---|---|---|---|---|
| 1 | Hoàn tất M5 | — | Merge, full suite xanh | S |
| 2 | M6: cache + legacy, nối vào sản phẩm | 1 | RT-004/009/013/033 đóng cho người dùng | **L, rủi ro cao nhất** |
| 3 | A3: cài dịch vụ, hộp UAC, ACL, script kiểm thử admin | R16 | Chủ dự án chạy script đạt | L |
| 4 | M7: hành động qua dịch vụ | 2, 3 | RT-002 đóng, cách ly có giao dịch | L |
| 5 | M8 + A4: phạm vi quét thông minh/sâu, nguồn admin | 4 | Mọi nguồn có độ phủ | M |
| 6 | A5: USN journal, chụp tiến trình 500 ms, quét lại tệp tải về | 4 | Chủ dự án chạy thử đạt | M |
| 7 | A6: Quét và sửa | 4, 5 | Có nhật ký hoàn tác | L |
| 8 | Hoàn thiện 3 tính năng + giao diện (giai đoạn 5, 6) | 5, 6 | Một nút Quét, luồng trực tiếp | M |
| 9 | Đo báo nhầm, chuẩn bị phát hành (giai đoạn 7) | 8 | Có báo cáo FP, chủ dự án chốt ngân sách | M |
| 10 | Đề xuất ≈7/10 | 9 + **chủ dự án đồng ý** | — | L |

Bước 3 làm song song với bước 2 được vì khác file. Bước 5 và 6 cũng vậy.

## 4. Chi tiết từng bước

### Bước 1 — Hoàn tất M5

Lỗi nặng nhất trong bản nháp (đều đã tái hiện):

* **Phát hiện có tên bị mất:** hai tên threat hoặc một tên lặp lại thành lỗi (K1); tệp biến
  mất ngay sau khi có tên, đúng tình huống AV khác vừa xoá nó, mất sạch bằng chứng (K3);
  kết quả về sát hạn chót bị vứt (K4).
* **Mọi tệp có đường dẫn tiếng Việt thành `unknown`** (K2) vì `MpCmdRun` in đường dẫn theo
  code page, không phải UTF-8.
* **LNK trỏ tới `cmd.exe` có tham số lại ra "sạch đáng tin"** (K5); chèn 5.000 dấu cách vào
  tham số là mất luôn tín hiệu (K11).
* **Một lần `WinVerifyTrust` treo làm mọi lần quét sau chờ hết hạn chót** (K8).
* Mọi tệp thường bị ghi `LNK_MALFORMED`, thiếu MotW bị coi là engine lỗi (K10, K12): nếu
  không sửa thì M6 không cache được gì.

Xong khi: scope sạch; từng test K đỏ trên `b66cb3f`, xanh sau khi sửa; test Job Object thật
chạy với tiến trình con vô hại; `git merge --no-ff`; full suite xanh; bảng K vào `REVIEWS.md`.
Không chạy `MpCmdRun` thật được vì Defender bị động trên máy này: định dạng đầu ra thật vẫn
chưa kiểm chứng, phải ghi rõ.

### Bước 2 — M6: bước nối dây, rủi ro cao nhất

**Phần 1** (Codex đang viết): `cache.py`, `legacy.py`, không nối gì. **Phần 2** Claude viết,
vì đây là chỗ quyết định hành vi người dùng. File được đổi: `engine/scanner.py`, `engine/verdict.py`,
`db.py`, `protection.py`, `scanjob.py`, `watcher.py`, `__main__.py`, `nativehost.py`, `tray.py`,
`gate_ui.py`, `overview_ui.py`, `report.py`, `engine_status.py`, `extension/src/background.js`.

Những việc rà soát từng dòng cho thấy phải làm, không chỉ "thay lời gọi":

1. **Nhãn mới `unknown` đang bị đọc sai.** `scanjob._account` đếm mọi thứ khác `clean` là phát
   hiện/nghi ngờ; `__main__` in ra và gọi `act_on`; `gate_ui.LABEL_VI` và `background.js:327`
   không biết nhãn này. `unknown` phải đi riêng: không tính là mối đe doạ, CLI thoát mã 3,
   giao diện ghi "chưa kiểm tra xong".
2. **`legacy-v0` phải giữ nguyên (quyết định đã khoá).** `act_on` đang xét theo `label`, nên nếu
   chỉ thay nhãn thì tên ClamAV yếu sẽ im lặng thôi bị cách ly: hành vi đổi mà không ai duyệt.
   `act_on` phải ưu tiên `decision.action_decision`. Hệ quả: RT-001 vẫn mở cho tới khi chủ dự án
   bật `evidence-v1`; `tests/test_known_issues.py` chỉ đổi khi hành vi đổi thật.
3. **Stage bắt buộc phụ thuộc máy.** Mặc định orchestrator coi mọi adapter là bắt buộc. Trên máy
   này Defender bị động: để nguyên thì **mọi tệp thành `unknown`**. Đề xuất mặc định (câu hỏi R11
   §9, xem mục 6):

   | Engine | Bắt buộc khi |
   |---|---|
   | core | luôn luôn |
   | json_rules, yara_x | có luật đã cài; luật hỏng thì `unknown` |
   | clamav | người dùng bật và đã cài; cài rồi mà không chạy → `unknown` (đây chính là RT-013) |
   | defender | đang chủ động; bị động/không có → không bắt buộc, không tính là đã kiểm |
   | lnk, signer, motw | không bao giờ |

4. **ClamAV phải có dữ kiện thật.** `ClamdAdapter` cần `DatabaseFacts` (digest danh mục CVD/CLD,
   digest `clamd.conf`) và `ExpectedDaemon`. Khó nhất: CLI hoặc native host gắn vào clamd do
   khay khởi động, nên phải dò tiến trình theo PID + thời điểm tạo + đường dẫn ảnh. Cổng là
   33310 (`SENTINEL_CLAMD_PORT`), không phải mặc định 3310. Test giả dùng `verifier=`, `facts=`.
5. **Bảng đối chiếu phát hiện cũ, tránh tụt lùi.** `core.py` chưa có: `office.macros`,
   `archive.encrypted_executable`, `archive.bomb`, `archive.too_many_members`,
   `archive.directory_too_large`, `pe.inflated`, `pe.unsigned`, `hash.<nguồn>` (adapter chỉ trả
   đúng/sai), ZIP lớn hơn 64 MB đọc từ đĩa, quét đầu + đuôi tệp lớn. Mỗi mục: chuyển sang hoặc ghi
   lý do bỏ. Không tệp nào được từ "có phát hiện" thành "sạch" mà không có lý do.
6. **Container mờ khi thiếu ClamAV.** RAR/7z/CAB chỉ được đánh dấu mờ trong `clamd.py`. Không có
   ClamAV thì Defender trả 0 sẽ thành "sạch đáng tin", trái R11 §6. Chuyển danh sách magic sang
   core hoặc dùng chung.
7. **Giới hạn cỡ tệp.** Orchestrator mặc định 512 MiB → `TOO_LARGE` → `unknown`; code cũ băm mọi
   cỡ. Cần chốt con số (mục 6).
8. **`allow_hashes`, hạn chót theo tệp, cache v2:** bảng mới, tăng `SCHEMA_VERSION`, `prune`
   cả bảng mới; `exception_generation` đổi khi tin cậy thay đổi.
9. **`tray.py:208` gán `scanner.sigs`** sau khi cập nhật YARA: phải dựng lại adapter.
10. **Test cũ:** khoảng 80 chỗ trong 9 tệp dùng API cũ, nhiều nhất `tests/test_gate.py` (50).
    Chạy nguyên trạng trước; mỗi test phải sửa đều ghi lý do, không sửa để cho xanh.

Xong khi: full suite xanh; so sánh cũ/mới trên cùng bộ mẫu tổng hợp ra bảng khác biệt có giải
thích; quét thật với `SENTINEL_HOME` tạm; Helium e2e đạt; RT-004, 009, 013, 033 đóng; subagent
review độc lập.

### Bước 3 — A3: cài dịch vụ, hộp xác nhận UAC

**Mối nguy phải xử lý trước:** code đang nằm trong `.venv` trên Desktop, người dùng ghi được. Dịch
vụ LocalSystem nạp Python từ đó tức là trao SYSTEM cho mọi tiến trình của user. Vì vậy
`sentinel service install` phải chép interpreter, stdlib, `yara_x`, code sang vị trí chỉ admin ghi
được (ví dụ `%ProgramFiles%\SentinelGuard`), chạy `-I -B`, chứng minh `sys.path` sạch. Chép từ
Python đã có, không tải gì.

Việc: `install|uninstall` bằng `ctypes` (recovery, SID dịch vụ, privilege tối thiểu, preshutdown,
DACL dịch vụ); `%ProgramData%\SentinelGuard` với ACL, **phòng user tạo sẵn thư mục hoặc reparse point
trước**, kiểm lại mỗi lần khởi động; hộp UAC (chương trình riêng, `ShellExecuteW` verb `runas`, lấy
kế hoạch từ dịch vụ theo id, tiếng Việt do dịch vụ viết, chống giả mạo cửa sổ); `tools/admin_acceptance.ps1`
theo 8 kiểm tra R13b P8: từ chối chạy khi không nâng quyền, không đụng Defender.

Xong khi: test không cần admin xanh; **chủ dự án** chạy script và mọi kiểm tra `PASS`.

### Bước 4 — M7: hành động qua dịch vụ

`gate_v2/actions.py`: cách ly có kiểm lại định danh ngay trước khi làm, rào thế hệ bảo vệ, nhật ký
hoàn tác hoàn tất-hoặc-lùi; khôi phục chỉ tạo ngoại lệ path+hash (**RT-002**); "Tin cậy" là thao tác
riêng; `Backend` thật của `ServiceCore`; tray, CLI, native host chuyển sang IPC; native host hết
quyền ghi allowlist, hết import `Scanner`/`Database`; chạy adapter đọc tệp lạ trong worker quyền thấp
(thêm `lnk`, `signer`, `motw` vào `workermain.ENGINES`; worker có handle chỉ-đọc); bàn giao
"action lease" với tray cũ (R13b P9); sửa phát hiện R15 trước khi nối. Phụ thuộc câu hỏi 1, 2, 5.

### Bước 5–7 — phạm vi, thời gian thực, sửa

* **M8 + A4:** `gate_v2/scope.py`: Startup, Run/RunOnce cả 2 view, Task Scheduler qua COM, tiến trình
  đang chạy; dedupe theo định danh tệp; đếm mục không truy cập được (RT-024); Quét sâu không hạ ngưỡng.
  Thêm nguồn admin: mọi user, dịch vụ, WMI.
* **A5:** USN journal đối chiếu sau khi tràn hàng đợi; chụp tiến trình 500 ms báo rõ "lấy mẫu"; quét lại
  tệp tải về khi chữ ký cập nhật hoặc khi chạy lần đầu. Không có driver thì **không chặn được trước khi
  chạy**: báo cáo phải nói rõ. RT-003, RT-007 đóng ở đây hoặc sớm hơn ở M6 nếu tiện.
* **A6:** xem trước kế hoạch sửa, từng thao tác có xác nhận, nhật ký hoàn tác; không bao giờ đụng tệp hệ
  thống Windows hay Defender.

### Bước 8–9 — sản phẩm và phát hành

Một nút Quét ngay, luồng pipeline trực tiếp từ `ScanEvent`, màn hình 3 thẻ; trạng thái theo tab của
extension; "Luôn tin cậy" đi qua UAC; các tính năng giai đoạn 6 theo thứ tự trong `ROADMAP.md`. Rồi đo báo
nhầm với `SENTINEL_HOME` tạm, tắt tự cách ly, không dùng mẫu độc; so bản cũ/bản mới; **chủ dự án chốt ngân
sách** rồi mới cân nhắc chuyển `evidence-v1`.

### Bước 10 — ≈7/10 (ETW và chấm điểm đã nối, chưa kiểm trên phiên thật)

Danh tiếng hash/URL, chống ransomware ETW + tệp mồi, Defender làm engine khi đang chủ động,
ML tĩnh cho PE mức "đáng ngờ". ETW và chấm điểm shadow đã nối vào dịch vụ nhưng chưa kiểm trên
phiên thật; tệp mồi chờ câu hỏi 11, còn tự dừng tiến trình chờ 30 ngày quan sát kể từ khi ETW bật.

## 5. Việc chỉ chủ dự án làm được

* Chạy `sentinel service install|uninstall` và `tools/admin_acceptance.ps1` với quyền admin (bước 3, trở
  đi), nên dùng máy thử nếu có.
* Chạy thử A5 trên máy thật. Xác nhận đầu ra `MpCmdRun` thật nếu có máy mà Defender đang chủ động.
* Tự bật Controlled Folder Access nếu muốn; Claude không đổi cài đặt Defender.
* Trả lời mục 6.

## 6. Câu hỏi và quyết định của chủ dự án

| # | Câu hỏi | Đề xuất | Chặn bước |
|---|---|---|---|
| 1 | "Luôn tin cậy": đòi UAC hay chỉ tin cậy trong trình duyệt | đòi UAC | 4 |
| 2 | Tải từ URL bị chặn: cảnh báo + quét, cách ly khi tệp có bằng chứng; hay giữ cách ly theo URL | cảnh báo + quét (M6 giữ hành vi cũ cho tới khi có quyết định) | 4 |
| 3 | Cô lập mạng worker: cam kết "không có code mạng" hay ép bằng hệ điều hành | cam kết trước | 4 |
| 4 | Theo dõi tiến trình: chụp 500 ms hay ETW | Chủ dự án quyết ngày 2026-11-03: ETW bên cạnh bộ chụp; chưa kiểm trên phiên thật | đã quyết |
| 5 | Gỡ cài đặt giữ lại khu cách ly và nhật ký | giữ | 3 |
| 6a | Engine nào bắt buộc để "sạch đáng tin" (R11 §9) | bảng ở bước 2 | **2** |
| 6b | Giới hạn cỡ tệp, ngân sách số (worker, bộ nhớ, thời gian) | 4 GiB; 60 s thời gian thực, 120 s quét sâu; đo rồi chốt | **2** |
| 6c | Khi nào chuyển `legacy-v0` → `evidence-v1`; ngân sách báo nhầm | sau báo cáo FP | 9 |
| 6d | Cách xác minh clamd, container ClamAV không mở được, phạm vi "Tin cậy", Quét sâu, PE ML | theo R11 §9 | 2–8 |
| 7 | Thêm `pywin32`/`comtypes` | không cần | — |
| 8 | Gói Claude | đã trả lời: tài khoản đang là **Max**, hạn mức 5h và tuần ở 0% lúc 19:56, reset tuần 2026-11-09 | — |
| 10 | **Mới:** ClamAV trong dịch vụ: clamd phân tích tệp độc nên không được chạy LocalSystem. Chạy bằng token hạn chế, hay bỏ hẳn khỏi dịch vụ | chạy token hạn chế; hiện dịch vụ không chạy clamd, phát hiện của ClamAV do tiến trình của người dùng xử lý | 8 |
| 11 | **Mới:** cho phép đặt tệp mồi trong Documents và Pictures không (R14) | có, nhưng chỉ sau khi ETW được kiểm | 10 |
| 12 | **Mới:** tạo khóa abuse.ch miễn phí; khóa VirusTotal nếu muốn | có abuse.ch: thêm hash và URL mới; VirusTotal chưa nối | 10 |
| 13 | **Mới:** kiểm thu trên dịch vụ dùng một lần, hay trực tiếp trên bản cài bằng `sentinel service verify` | `verify`; đơn giản hơn nhiều | 3 |
| 14 | **Mới:** danh sách tin cậy cũ không tự sang dịch vụ khi cài, phải tin cậy lại qua UAC | giữ vậy: danh sách cũ do tiến trình quyền thấp ghi nên không nên kế thừa | 3 |
| 9 | **Mới:** tên Defender loại PUA (`PUA:`, `Adware:`…) không còn tự cách ly, dù hành vi cũ có (K6, theo invariant 6) | chấp nhận | 1 |

Bước 2 có thể làm với đề xuất mặc định; chỉ cần chủ dự án báo nếu muốn khác.

## 7. Rủi ro chính

| Rủi ro | Cách giữ |
|---|---|
| Nối M6 làm sản phẩm tệ đi mà test cũ không thấy | Bảng đối chiếu cũ/mới; thử phá; Helium e2e; làm trên nhánh, `gate-baseline` luôn xanh |
| Đổi hành vi cách ly ngoài ý muốn | `act_on` đi theo `action_decision`; test riêng cho `legacy-v0` |
| Fake tốt hơn đồ thật (J1 từng xảy ra) | Mỗi adapter có một test chạy thật; clamd thật chưa chạy được, Defender thật không có: ghi là chưa kiểm chứng |
| Leo thang quyền qua đường cài đặt | Bước 3 xử lý trước khi có gì chạy LocalSystem |
| Test chập chờn như tối nay | Chạy full suite nhiều lần trước mỗi merge lớn |
| Mất phản biện độc lập khi hết Codex | Subagent review, mutation, test đỏ trên commit cũ (mục 1) |
