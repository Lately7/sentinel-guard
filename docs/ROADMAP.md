# Lộ trình Sentinel Guard

Một trang duy nhất để theo dõi tiến độ. Chi tiết kỹ thuật vẫn nằm trong
`docs/handoff/PROJECT_CONTEXT.md`; khi hai nơi khác nhau thì code là đúng.

**Cập nhật:** 2026-11-03, xem `docs/handoff/PLAN.md` §0a · **Nhánh:** `main` (đổi tên từ `gate-baseline`), đẩy lên `github.com/Lately7/sentinel-guard` · **Kế hoạch toàn bộ:** `docs/handoff/PLAN.md` · **Bàn giao:** `docs/handoff/NEXT_SESSION.md`

## Ai làm gì

Quyết định của chủ dự án (2026-11-02 tối): Claude chịu trách nhiệm toàn bộ; Codex chỉ tận
dụng nốt hạn mức còn lại cho việc dài chạy nền, không bước nào được chờ Codex.

| Ai | Việc |
|---|---|
| Claude | Toàn bộ code, sửa lỗi, tích hợp, test, tài liệu, commit; đọc từng dòng Codex viết |
| Codex | Khi còn hạn mức: review chỉ-đọc, nghiên cứu, các phần được giao trong brief, chạy trong worktree riêng |

Mọi phát hiện của Codex được Claude kiểm chứng rồi mới sửa hoặc từ chối (có lý do).

## Hướng mới (2026-11-02): Gate v2 do Codex viết

Chủ dự án quyết định: Codex nghiên cứu sâu (mã nguồn ClamAV, Malwarebytes và
các antivirus khác, các loại mã độc — `docs/research/`), rồi viết một cổng quét
hoàn toàn mới. Claude review, chạy test, tích hợp. Gate v2 gộp luôn Contract v1
(giai đoạn 3) và phần cổng của giai đoạn 4.

Vì vậy trong giai đoạn 1, các sửa lỗi **bên trong cổng quét cũ** (C3b cache,
C3c độ phủ ZIP) tạm dừng — Gate v2 định nghĩa lại chúng. Các sửa lỗi **ngoài
cổng** vẫn làm ngay: native host (C3e, C3j), extension (C3k), mã thoát CLI
(C3g), cập nhật chữ ký (C3h), `clamd.conf` (C3i).

## Quyết định mới (2026-11-02 đêm): xoay quanh quyền admin

Chủ dự án quyết định: ứng dụng chạy với quyền admin và được thiết kế xoay
quanh quyền đó; tối ưu bảo vệ thời gian thực; kiểm tra kỹ tệp tải về; Codex
nghiên cứu tiếp Quét, Quét sâu và **Quét và sửa**. Quyết định này thay giả
định "agent không cần admin" trong R11/R12d.

Nghiên cứu xong: `docs/research/R13-admin-realtime-remediation.md`. Thiết kế
được chọn (theo R13):

* **Dịch vụ Windows có quyền** (mỏng) + khay hệ thống và native host **không
  quyền**, nói chuyện qua named pipe có ACL, kiểm tra người gọi và từng lệnh.
* **Đọc tệp lạ trong tiến trình quyền thấp** (restricted token, low
  integrity, Job Object); dịch vụ có quyền chỉ cách ly/sửa sau khi kiểm lại.
* Thời gian thực: USN journal để đối chiếu lại sau khi tràn hàng đợi, ETW để
  quét chương trình lúc khởi chạy — vẫn **không chặn được trước khi chạy**
  (cần driver ký số).

* Tệp tải về: phát hiện ở mọi trình duyệt qua thư mục + Mark of the Web, quét
  lại khi chữ ký cập nhật hoặc khi chạy lần đầu.
* **Quét và sửa**: kế hoạch sửa có nhật ký hoàn tác; tự động chỉ cách ly tệp
  có bằng chứng chắc chắn; diệt tiến trình, gỡ khởi động cùng Windows, dịch
  vụ, WMI… cần xác nhận; không bao giờ đụng tệp hệ thống Windows hay Defender.

Ngày 2026-11-03, chủ dự án chọn tiếp tục ở user-mode với dịch vụ LocalSystem,
không dùng driver, và dùng ETW bên cạnh bộ chụp tiến trình. Chương trình thấy tệp
hoặc tiến trình sau khi nó xuất hiện; chặn ở mức kernel trước khi chạy nằm ngoài
phạm vi hiện tại.

Thảo luận thiết kế với Codex (`docs/research/R13b-design-discussion.md`)
đã chốt thêm: dịch vụ LocalSystem mỏng viết bằng `ctypes` (không thêm thư
viện); **lệnh làm yếu bảo vệ** (tắt bảo vệ, "Luôn tin cậy", khôi phục tệp,
loại trừ, duyệt sửa) **phải xác nhận qua UAC**, vì mã độc chạy dưới quyền
user cũng nói chuyện được với pipe; native host chỉ được tra cứu và báo tệp
tải về; worker quét quyền thấp chạy sẵn 2 tiến trình (tối đa 4); theo dõi
tiến trình bằng chụp danh sách 500 ms trước, ETW để sau.

| Mốc | Việc | Ghi chú |
|---|---|---|
| G3–G6 | Gate v2 mốc 3–6 (core/luật, ClamAV, Defender, cache + adapter) | song song với A1 |
| A1 | Giao thức pipe + phân quyền lệnh + `ServiceCore` + named pipe thật + client + vỏ dịch vụ | ✅ phần không cần admin: `c156366`, `57347f7`, `4de3072`, `ff4d283` (41 test); còn: hộp xác nhận UAC, cài dịch vụ, script kiểm thử admin |
| A2 | Worker quét quyền thấp + Job Object | ✅ `2b7e569`, `76d0950`: worker low integrity chạy adapter core/luật JSON/YARA-X trên handle được nhân bản; worker chết/treo/huỷ → lỗi có kiểu, không bao giờ sạch |
| A3 | Gate v2 mốc 7 qua dịch vụ: cách ly có kiểm lại, nhật ký hoàn tác, hộp xác nhận UAC | |
| A4 | Gate v2 mốc 8 + nguồn quét admin (mọi user, dịch vụ, tác vụ, WMI…) | |
| A5 | USN journal, chụp danh sách tiến trình 500 ms, quét lại tệp tải về | cần chủ dự án chạy thử với quyền admin |
| A6 | Xem trước kế hoạch sửa, rồi từng thao tác sửa có xác nhận | |

Cài và chạy dịch vụ cần quyền admin: chủ dự án tự chạy; Claude không tự nâng
quyền và không đổi cài đặt Defender.

## Đề xuất: mục tiêu ≈7/10 so với Malwarebytes (chờ chủ dự án đồng ý)

Claude ước lượng (không phải số đo): hiện ≈3/10; xong Gate v2 + A1–A6 ≈4,5–5,5.
Lên ≈7 làm được trong dự án này, sau mốc 7, theo thứ tự:

1. Danh tiếng hash/URL (MalwareBazaar, URLhaus, ThreatFox; tra VirusTotal chỉ
   cho tệp mới tải về).
2. Chống ransomware ở user-mode bằng ETW + tệp mồi: ETW và chấm điểm shadow đã
   nối vào dịch vụ nhưng chưa kiểm trên phiên thật. Chưa bắt đầu 30 ngày quan sát;
   chỉ bắt đầu khi ETW bật. Tệp mồi chờ chủ dự án trả lời câu hỏi 11; chưa tạm
   dừng tiến trình.
3. Dùng Defender làm một engine khi nó đang chạy; chủ dự án tự bật Controlled
   Folder Access nếu muốn (Claude không đổi cài đặt Defender).
4. Đo báo nhầm thật, rồi mới chuyển `legacy-v0` → `evidence-v1`.
5. ML tĩnh cho PE, chỉ ở mức "đáng ngờ".

Lên 8 cần thứ ngoài code: driver minifilter ký số (chứng chỉ EV, ký
attestation của Microsoft, pháp nhân), ELAM/PPL (thành viên Microsoft Virus
Initiative), feed mối đe doạ trả phí/cloud, lab thử mẫu thật cách ly (dự án
không tải hay chạy mã độc).

## Ba tính năng bắt buộc

| Tính năng | Hiện có | Còn thiếu |
|---|---|---|
| **Quét / Quét sâu** | Quét tệp, thư mục, quét nhanh, toàn máy; 4 lớp (Lõi → Luật+YARA → ClamAV → Defender) | Kết quả "một phần" hoặc engine lỗi vẫn có thể hiện "sạch"; chưa có Quét sâu đúng nghĩa và nút Quét một chạm |
| **Bảo vệ web trên Helium** | Extension MV3 chặn ~550.000 tên miền, trang cảnh báo có "Mở một lần" và "Luôn tin cậy" (đều mở được trang thật), quét tệp tải về qua agent, danh sách tin cậy không giới hạn 5.000 | Trạng thái riêng cho từng tab (đang kiểm tra / hạn chế / agent offline / đã cho phép) |
| **Bảo vệ thời gian thực** | Theo dõi Downloads, Desktop, Documents, Startup, %TEMP%, khoá Run; thử lại tệp bị khoá; hàng đợi có giới hạn; tắt là không cách ly thêm | Chỉ phát hiện sau khi tệp đã ghi xuống đĩa (không có driver); chưa quét đối chiếu lại thư mục khi hàng đợi tràn |

## Các giai đoạn

| # | Giai đoạn | Trạng thái |
|---|---|---|
| 0 | **Nền tảng**: C1 icon cũ, C2a cổng quét, C2b baseline, giao diện tối, bộ icon v2 | ✅ xong |
| 1 | **Sửa lỗi** (C3a, d, e, g, h, j, k ✅; C3b/c/f vào Gate v2; C3i bỏ) | ✅ xong |
| R | **Nghiên cứu sâu cho Gate v2** (R8a–R12d, R11 đặc tả) | ✅ xong |
| G | **Gate v2** do Codex viết theo đặc tả R11 (8 mốc), Claude review | mốc 1 ✅ `a168e6a` · mốc 2 ✅ `b2ae29b` · mốc 3 ✅ `4cedf02` · mốc 4 ✅ `92ae65f` (ClamAV) · tiếp: mốc 5 (Defender + phân tích cấu trúc) |
| 2 | **Red Team viết test** (Codex vòng 1a, 1b) | chờ giai đoạn 1 |
| 3 | **Contract v1**: tách trạng thái quét khỏi kết luận; "một phần"/lỗi không bao giờ là "sạch" | chờ |
| 4 | **Chính sách ClamAV + cách ly an toàn** | chờ |
| 5 | **Ba tính năng chính hoàn chỉnh**: Quét thông minh + Quét sâu với pipeline trực tiếp, thời gian thực, extension | chờ |
| 6 | **Tính năng bổ sung** (chọn từ nghiên cứu r6, r7) | chờ |
| 7 | **Đo báo nhầm (FP) lần 2**, chuẩn bị phát hành | chờ |

### Giai đoạn 1 — từng commit

| Commit | Nội dung | Sửa | Trạng thái |
|---|---|---|---|
| C3a | Kết quả Defender có kiểu (sạch/độc/lỗi/hết giờ/không có) | RT-008 | ✅ `2cfcf1e` |
| C3b | Định danh cổng quét theo nội dung luật; không cache kết quả chưa đầy đủ | RT-009 | ⏸ chuyển vào Gate v2 |
| C3c | Giữ trạng thái "bỏ qua"/"một phần" cho ZIP quá lớn | một phần RT-004 | ⏸ chuyển vào Gate v2 |
| C3d | Sửa 2 test đang khoá quyết định sai; sổ RT; `tools/check_codex_scope.ps1`; vai trò Codex trong `AGENTS.md` | — | ✅ `798f0c2` |
| C3e | Native host đọc đủ thân thông điệp | RT-006 | ✅ `d3c10cb` |
| C3f | Chỗ cắm test cho ClamAV client | — | ⏸ chuyển vào Gate v2 |
| C3g | Mã thoát CLI đúng thứ tự 2 > 3 > 1 > 0 | RT-011 | ✅ `d6ee116` |
| C3h | Cập nhật chữ ký thất bại thì thử lại sau 60 phút | RT-010 | ✅ `6ff9802`, `a22d74d` |
| C3i | Đặt đường dẫn trong `clamd.conf` vào ngoặc kép | RT-015 | ✖ bỏ: không phải lỗi |
| C3j | Native host bắt buộc đúng origin của extension | RT-019 | ✅ `d3c10cb` |
| C3k | Extension kiểm tra số/độ dài trong thông điệp từ trang | RT-020 | ✅ `72c7781` |
| C4 | `CODEX_TASK_1a.md`, `CODEX_TASK_1b.md` ghim vào commit C3k | — | xem lại sau R11 |

### Giai đoạn 5 — ba tính năng chính (theo Codex r6, đã chỉnh theo ý chủ dự án)

**Quét**: nút chính **Quét ngay** = quét thông minh (thư mục theo dõi, Startup,
khoá Run cả 32/64-bit, tác vụ theo lịch, tệp của tiến trình đang chạy).
**Quét sâu…** ở menu phụ, cần xác nhận: thêm toàn bộ ổ cố định, giới hạn nén
sâu hơn, ngân sách thời gian 2 giờ, tiếp tục được. Quét sâu không bao giờ hạ
ngưỡng phát hiện. Kết quả luôn ghi rõ: đầy đủ / một phần / không đọc được /
bỏ qua theo chính sách / engine không sẵn sàng. Sửa RT-024.

**Thời gian thực**: thử lại tệp bị khoá, hàng đợi có giới hạn, tắt là dừng
hẳn, trạng thái "Cần chú ý" khi không theo dõi được gì, đọc khoá Run cả hai
view. Ghi rõ giới hạn: phát hiện sau khi tệp được ghi. Sửa RT-016, 017, 018,
026, 027.

**Web (Helium)**: "Vẫn tiếp tục" chỉ cho một lần, "Luôn tin cậy" là lựa chọn
riêng; tải về lỗi thì giữ hàng chờ và thử lại; mỗi tab có trạng thái
(đang kiểm tra / đã kiểm tra / hạn chế / agent offline / đã cho phép);
đồng bộ allowlist theo trang. Sửa RT-021, 022, 023, 025.

**Giao diện**: màn hình chính gồm 3 thẻ (Thời gian thực · Web · Quét) và
"Hoạt động gần đây"; chi tiết từng engine đưa vào "Chi tiết kỹ thuật". Tab:
Tổng quan, Quét, Lịch sử, Cách ly, Cài đặt. Chữ ~10 pt, tiêu đề 13–15 pt.
Animation: giữ đèn trạng thái (167 ms), chấm "đang khởi động" dừng khi quá hạn,
thanh tiến trình có phần trăm khi biết tổng, bỏ vệt quét trên logo, chỉ dòng
cần xử lý mới sáng lên (333 ms); tắt hết khi Windows tắt hiệu ứng.

### Giai đoạn 6 — tính năng bổ sung (xếp hạng của Codex r6)

1. Lịch sử quét kèm độ phủ, quét lại, xuất báo cáo
2. Quét thông minh theo lịch
3. Tự kiểm tra sức khoẻ bảo vệ (feed cũ, clamd tắt, extension mất kết nối…)
4. Giao diện loại trừ có phạm vi (đường dẫn + hash, có hạn)
5. "Quét bằng Sentinel" trong menu chuột phải Explorer
6. Quét USB khi cắm vào
7. Xem lại chương trình khởi động cùng Windows
8. Chữ ký số Authenticode và (tuỳ chọn) danh tiếng hash

## Sổ lỗi (RT)

| Id | Vấn đề | Mức | Sửa ở |
|---|---|---|---|
| RT-001 | Tên ClamAV yếu (vd. `Win.Trojan.Suspect-34`) bị coi là chắc chắn độc → tự cách ly | Cao | GĐ 4 |
| RT-002 | Khôi phục tệp = tin cậy hash trên toàn máy | Cao | ✅ `3d372ed` |
| RT-003 | Thời gian thực quét cả dữ liệu của Sentinel | TB | ✅ `088041a` |
| RT-004 | Quét một phần có thể hiện "sạch" | Cao | C3c + GĐ 3 |
| RT-005 | Các lớp có thể đọc hai phiên bản khác nhau của tệp | Cao | GĐ 3–4 |
| RT-006 | Native host đọc thông điệp một lần | TB | ✅ C3e |
| RT-007 | CLI/quét theo yêu cầu không loại trừ dữ liệu Sentinel nhất quán | TB | ✅ `088041a` (theo định danh tệp) |
| RT-008 | Defender lỗi/hết giờ bị báo "sạch" | Cao | ✅ C3a (lớp); nhãn chung: Gate v2 |
| RT-009 | Cache giữ kết quả cũ hoặc chưa đầy đủ | Cao | C3b |
| RT-010 | Cập nhật lỗi vẫn ghi mốc thành công | TB | ✅ C3h |
| RT-011 | Mã thoát CLI sai thứ tự ưu tiên | TB | ✅ C3g |
| RT-012 | `AlertExceedsMax no` giấu việc ClamAV chạm giới hạn | Cao | GĐ 3 |
| RT-013 | ClamAV lỗi/không chạy mà kết luận chung vẫn "sạch" | Cao | GĐ 3 |
| RT-014 | Lưu trữ/tài liệu mã hoá không được ghi là "chưa kiểm tra được" | TB | GĐ 3 |
| RT-015 | Đường dẫn trong `clamd.conf` không có ngoặc kép | Thấp | ✖ từ chối: `common/optparser.c:1094-1135` của ClamAV lấy cả phần còn lại của dòng làm giá trị, dấu cách vẫn đúng |
| RT-016 | Thời gian thực không thử lại tệp đang bị khoá | Cao | ✅ `0f348f3` (5 lần trong ~40 s, rồi báo "Chưa quét được tệp") |
| RT-017 | Hàng đợi chống dội không có giới hạn | TB | ✅ `0f348f3` (tối đa 10.000 tệp, tệp thay đổi liên tục vẫn được quét sau 30 s) |
| RT-018 | Tắt bảo vệ không dừng lượt quét/cách ly đang chạy | TB | ✅ `0f348f3` (sau khi tắt không cách ly thêm; phát hiện vẫn được ghi) |
| RT-019 | Native host chấp nhận khi thiếu origin | Thấp | ✅ C3j |
| RT-020 | Thông điệp từ trang thiếu kiểm tra số (NaN) và độ dài | Thấp | ✅ C3k |
| RT-021 | Allowlist bị cắt im lặng sau 5.000 tên miền | TB | ✅ `566c57d` |
| RT-022 | "Vẫn tiếp tục" tạo ngoại lệ vĩnh viễn cho cả tên miền | TB | ✅ `75ba989` — nguyên nhân thật: luật DNR không ghi `resourceTypes` thì bỏ qua `main_frame`, nên cả "Mở một lần" lẫn "Luôn tin cậy" đều không mở được trang bị chặn |
| RT-023 | Tải về không gửi được tới agent vẫn đếm là đã quét | TB | ✅ |
| RT-024 | Quét bỏ sót (junction, đường dẫn dài, thiếu quyền) không ghi vào độ phủ | TB | ✅ `088041a` |
| RT-025 | Popup nói "Không phát hiện vấn đề" khi chưa kiểm tra | TB | ✅ |
| RT-026 | Thời gian thực báo "bật" dù không theo dõi thư mục nào | TB | ✅ |
| RT-027 | Chỉ đọc một view registry của khoá Run | TB | ✅ |
| RT-028 | Tên ClamAV `BC.Heuristics.*` bị coi là chắc chắn độc (ClamAV coi là "có thể không mong muốn") | TB | Gate v2 |
| RT-029…036 | (RT-029 ✅ `6450b0d`) Bộ chuyển ClamAV: cập nhật/RELOAD/độ sẵn sàng/định dạng trả lời/định danh cache/tuổi chữ ký (chi tiết trong `REVIEWS.md`, R8c) | TB–Cao | Gate v2 |
| RT-037…052 | Lớp YARA-X: nuốt lỗi/timeout, chép 64 MB, chia đầu/đuôi, mất nguồn gốc luật, cache chỉ theo số luật… (R12a) | TB–Cao | Gate v2 |

Đã kiểm chứng trong code: RT-008…013, 019, 022, 023, 026. Các mục còn lại
được kiểm chứng bằng test khi sửa.

## Nghiên cứu của Codex

| Vòng | Chủ đề | Trạng thái | Tệp |
|---|---|---|---|
| r1–r3 | Thiết kế cổng quét, kế hoạch commit, pipeline | ✅ | `docs/handoff/codex-review-r1..r3.md` |
| r4 | Review trạng thái hiện tại (tài khoản mới) | ✅ RT-008…011 | `docs/handoff/codex-review-r4.md` |
| r5 | Điểm yếu ClamAV, so với Bitdefender/Malwarebytes | ✅ RT-012…015 | `docs/handoff/codex-research-r5.md` |
| r6 | Sản phẩm: 3 tính năng, so sánh, lỗ hổng, giao diện bớt "AI" | ✅ RT-016…027 | `docs/handoff/codex-product-r6.md` |
| r7 | Tổng quan tài liệu khoa học về các loại mã độc và cách phát hiện | ✅ top 10 cải tiến | `docs/handoff/codex-literature-r7.md` |
| Icon | v2: lõi một màu (đen; bộ xám có sẵn), vuông nhỏ, viền tách rời | ✅ | `assets/brand/` |

## Kiểm thử gần nhất

pytest **1050 passed, 10 skipped, 1 xfailed** (sau bản sửa `8b6f043`; 1048 hai lần liền trước đó) · extension **40 passed**. Helium e2e không chạy lại; trên máy đã cài dịch vụ, bộ e2e dừng nếu không có `--with-service`.
Baseline tại C2a: `docs/baseline.md`.
