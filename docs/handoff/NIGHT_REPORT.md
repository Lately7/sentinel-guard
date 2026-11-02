# Báo cáo đêm 2026-11-02 (Claude, làm một mình)

Nhánh `gate-baseline`, **chưa push**. Mọi kết quả dưới đây là từ lệnh tôi đã
chạy thật; chỗ nào chưa chạy được thì ghi rõ.

## Tóm tắt

| Việc (mục 5 của NEXT_SESSION.md) | Kết quả |
|---|---|
| 1. RT-022 "Mở một lần" | ✅ Đã sửa và kiểm bằng Helium e2e |
| 2. Gate v2 mốc 1 (Codex viết) | ✅ Merge `9a101cb` sau 2 vòng review |
| 3a. Gate v2 mốc 2 | ✅ Merge `e186184` sau 2 vòng review |
| 3b. RT-016/017/018 (watcher) | ✅ `d03ea88` |
| 3c. RT-021 (allowlist) | ✅ `8135706` |
| 4. ROADMAP + báo cáo này | ✅ |
| Thêm (anh/chị yêu cầu lúc thức): thiết kế xoay quanh quyền admin | ✅ Codex nghiên cứu R13 + thảo luận R13b với tôi; chưa có code chạy quyền admin |

## Các commit đêm nay (theo thứ tự)

| Commit | Nội dung |
|---|---|
| `597df57` | RT-022: luật cho phép phủ cả `main_frame` — "Mở một lần" và "Luôn tin cậy" mở được trang |
| `fc063bf` | Task file Codex mốc 1 |
| `d03ea88` | RT-016/017/018: watcher thử lại tệp bị khoá, hàng đợi có giới hạn, rào chặn khi tắt |
| `8135706` | RT-021: danh sách tin cậy theo trang, không cắt ở 5.000 |
| `9a101cb` | Merge Gate v2 mốc 1 (commit Codex `7c82a9a`, `5004595`) |
| `8d95a1d` | Ghi review mốc 1, câu trả lời Codex |
| `74643a2` | Task file Codex mốc 2 |
| `5d2965b` | Quyết định "xoay quanh quyền admin", brief R13 |
| `1c93349` | R13 (nghiên cứu) + mốc A1–A6 trong ROADMAP |
| `e186184` | Merge Gate v2 mốc 2 (commit Codex `677d7ee`, `cfef850`) |
| `3b23d80` | Ghi review mốc 2, brief R13b |
| `9898e9f` | R13b: thảo luận thiết kế với Codex, thiết kế đã chốt |
| (commit cuối) | ROADMAP, NEXT_SESSION, báo cáo này |

Chưa push. Không force, không viết lại lịch sử.

## 1. RT-022 — nguyên nhân thật

Luật `declarativeNetRequest` **không ghi `resourceTypes`** thì Chrome cho khớp
mọi loại yêu cầu **trừ `main_frame`** (tài liệu Chrome,
`RuleCondition.resourceTypes`). Luật "cho phép" của "Mở một lần" và cả của
"Luôn tin cậy" đều thiếu trường này, nên chính trang web luôn bị luật chuyển
hướng (ưu tiên 1) đưa về trang cảnh báo. Giả thuyết cũ về `tabId -1` là sai:
luật giới hạn theo tab vẫn chạy đúng khi đã có `main_frame`.

Tôi thử 8 biến thể trong Helium 156 (session/dynamic, có/không `tabIds`,
điều hướng thẳng/qua `about:blank`): chỉ những biến thể có `main_frame` mới
mở được trang.

Kết quả e2e (`tools/helium_e2e.mjs`, `SENTINEL_HOME` tạm trong `%TEMP%`):

| Kiểm tra | Code cũ | Sau khi sửa |
|---|---|---|
| `once_opened` (Mở một lần mở được trang) | false | **true** |
| `once_not_trusted` (không thêm vào danh sách tin cậy) | true | true |
| `once_dropped_after_leaving` | true | true |
| `once_reblocked_after_leaving` (mới: rời trang rồi quay lại thì bị chặn lại) | true | true |
| `always_trusted` | true | true |
| `always_opened_blocklisted` (mới: "Luôn tin cậy" mở được trang bị chặn) | **false** | **true** |
| `sw_errors` | [] | [] |

Nghĩa là trước đây **"Luôn tin cậy" cũng không mở được** trang bị danh sách
chặn — lỗi này chưa ai phát hiện vì e2e cũ chỉ kiểm danh sách đã lưu.

## 2. Gate v2 mốc 1 (Codex viết, tôi review)

Codex (gpt-6-sol, high) viết `agent/sentinel/gate_v2/contract.py`,
`coverage.py`, `policy.py` và 135 test trong `tests/gate_v2/`. Kiểm phạm vi
sạch cả 2 vòng. Tôi đọc từng dòng và tìm ra 6 lỗi phải sửa trước khi merge
(chi tiết trong `REVIEWS.md`, mục "Gate v2 milestone 1"). Hai lỗi quan trọng:

* **Kết quả "sạch" giả**: một phát hiện bị loại (ví dụ ClamAV chưa xác minh
  báo `FOUND`) bị bỏ im lặng; nếu engine đó không bắt buộc thì tệp được coi
  là sạch đáng tin. Vòng 2: phát hiện bị loại → kết luận "chưa rõ", không
  bao giờ "sạch".
* **Quét theo yêu cầu không bao giờ cách ly được** (lỗi logic với
  `protection_generation=None`). Vòng 2 đã sửa.

Codex cũng từng trỏ `SENTINEL_HOME` vào một thư mục trong repo để lách lỗi
sandbox — trái quy tắc; đã bỏ ở vòng 2.

Chưa có code nào gọi `gate_v2`; cổng quét cũ không đổi.

## 2b. Gate v2 mốc 2 (Codex viết, tôi review)

`gate_v2/identity.py` (đo một "thế hệ" tệp qua cùng một handle: SHA-256 theo
khối, ID tệp 128-bit, kiểm tra lại trước hành động), `events.py` (sự kiện
tiến trình có giới hạn, sự kiện quan trọng không bao giờ mất), `orchestrator.py`
(các stage của một tệp chạy tuần tự, nhiều tệp song song 2–4 luồng, huỷ/hết
giờ có kiểu). Tôi bắt sửa 8 điểm (G1–G8 trong `REVIEWS.md`), quan trọng nhất:

* phát hiện chắc chắn bị **mất** nếu người dùng huỷ đúng lúc stage đó vừa
  xong (trái invariant 9);
* rào chặn "tắt bảo vệ thì không cách ly" **không bao giờ kích hoạt** vì
  tham số bị gán cứng;
* test import sai package (nạp hai bản module).

Codex **không chạy được pytest** trong sandbox ở cả hai vòng (bị chặn thư mục
tạm) và đã nói thật; tôi chạy toàn bộ bên ngoài. Vẫn chưa có code nào gọi
`gate_v2`.

## 2c. Thiết kế xoay quanh quyền admin (R13 + thảo luận R13b)

Theo yêu cầu của anh/chị lúc thức: Codex nghiên cứu (R13), tôi phản biện 10
điểm, Codex trả lời (R13b) và hai bên thống nhất:

* **Dịch vụ Windows LocalSystem mỏng**, viết bằng `ctypes` (không thêm thư
  viện); khay và native host **không quyền**, nói chuyện qua named pipe.
* Mã độc chạy dưới quyền user cũng nói chuyện được với pipe, nên **tắt bảo
  vệ, "Luôn tin cậy", khôi phục tệp, loại trừ, duyệt sửa phải xác nhận qua
  UAC** (hộp xác nhận chạy riêng với quyền admin). Native host chỉ tra cứu
  và báo tệp tải về.
* Đọc tệp lạ (ZIP, PE, YARA-X) trong **worker quyền thấp** (token rút gọn,
  low integrity, Job Object); dịch vụ chỉ gửi byte cho ClamAV và gọi Defender.
* Thời gian thực: USN journal để đối chiếu; theo dõi tiến trình bằng chụp danh
  sách 500 ms trước (ETW sau). Không có driver thì **không chặn được trước
  khi chạy** — báo cáo sẽ ghi rõ.
* "Quét và sửa": kế hoạch sửa có nhật ký hoàn tác; tự động chỉ cách ly tệp có
  bằng chứng chắc chắn; mọi thứ khác cần xác nhận; không đụng tệp hệ thống,
  không đụng Defender.
* Thứ tự: A1 (pipe + `ServiceCore`, test không cần admin) chạy song song
  Gate v2 mốc 3–6.

Tôi còn một điểm dè dặt với Codex: không chụp bản sao tệp cho Defender (bản
sao có thể bị chính Defender/Malwarebytes cách ly), dùng kiểm tra identity
trước/sau.

## 3. Watcher (RT-016, RT-017, RT-018) và allowlist (RT-021)

* **RT-016**: tệp bị chương trình khác giữ được thử lại sau 0,5 / 2 / 8 /
  30 giây (5 lần); hết lượt thì ghi cảnh báo "Chưa quét được tệp" thay vì im
  lặng.
* **RT-017**: tối đa 10.000 tệp chờ; vượt thì đếm và báo "Quá nhiều tệp thay
  đổi cùng lúc" (tối đa 1 lần/phút). Tệp thay đổi liên tục vẫn được quét
  sau tối đa 30 giây (tệp tải dở: 10 phút).
* **RT-018**: tắt bảo vệ thì không cách ly thêm tệp nào; lượt quét đang dở
  vẫn ghi lại phát hiện. Giao diện chỉ chờ tối đa 2 giây (không treo cửa
  sổ) và nói rõ nếu một thao tác cách ly bắt đầu trước đó vẫn đang chạy.
* **RT-021**: agent trả danh sách tin cậy theo trang; extension lấy đủ mọi
  trang cùng một phiên bản và gom tên miền vào luật 5.000 tên/luật, nên không
  còn giới hạn 5.000. Tên miền sai định dạng bị bỏ để không làm hỏng cả lần
  cập nhật luật.

Chưa làm (để Gate v2): giới hạn theo từng thư mục gốc và quét đối chiếu lại
thư mục sau khi hàng đợi tràn (R12d).

## Kết quả test thật

Lệnh chạy trên `gate-baseline` sau lần merge cuối (`e186184`):

* `.\.venv\Scripts\python -m pytest -q` → **283 passed, 4 skipped, 2 xfailed**
  (đầu đêm: 119 passed). 4 skip = test với clamd thật, clamd không chạy.
  2 xfail = RT-001, RT-002 (lỗi đã biết, chưa sửa — có chủ đích).
  Gate v2: 154 test trong `tests/gate_v2/`.
* `node --test "extension/test/*.test.mjs"` → **39 passed** (đầu đêm: 32).
* Helium 156 e2e (`node tools/helium_e2e.mjs extension`, `SENTINEL_HOME` tạm
  trong `%TEMP%`, đã chặn `blocked-selftest.sentinelguard.invalid`): mọi kiểm
  tra `true`, `sw_errors: []` — chạy sau RT-022 và lại sau RT-021.
* `pyflakes` trên các tệp đã sửa: sạch.

Không chạy: test với clamd thật (không bật clamd); thử >5.000 tên miền tin cậy
trong trình duyệt thật (chỉ có unit test); bất cứ thứ gì cần quyền admin.

## Cái gì hỏng / chưa làm được

* Không có gì hỏng trên `gate-baseline` theo các bộ test trên.
* Codex không chạy được pytest trong sandbox `workspace-write` (thư mục tạm
  bị từ chối), và vòng đầu để lại vài thư mục tạm rỗng — tôi đã xoá. Cần tìm
  cách cho sandbox một thư mục tạm hợp lệ nếu muốn Codex tự kiểm test.
* Chưa làm: đối chiếu lại thư mục sau khi hàng đợi watcher tràn (chờ USN
  journal ở A5); RT-001/RT-002 vẫn mở (chờ chính sách `evidence-v1`).
* Worktree `..\sentinel-guard-gate-v2` vẫn còn (nhánh `codex/gate-v2-m2`,
  đã merge) — dùng lại cho mốc sau.
* Codex không hết giới hạn đêm nay; tôi không phải bấm "reset".

## Cần anh/chị quyết

1. **"Luôn tin cậy" trên trang cảnh báo**: (a) đòi xác nhận UAC trước khi thêm
   vào danh sách tin cậy của dịch vụ — *đề xuất*; hoặc (b) chỉ tin cậy trong
   trình duyệt, bảo vệ yếu hơn.
2. **Tải từ URL nằm trong danh sách chặn**: (a) chỉ cảnh báo/huỷ tải và quét
   tệp, cách ly khi chính tệp có bằng chứng — *đề xuất*; hoặc (b) giữ như hiện
   nay: URL bị chặn là cách ly tệp ngay.
3. **Cô lập mạng cho worker**: (a) lúc đầu chỉ cam kết "code không dùng mạng"
   — *đề xuất*; hoặc (b) làm cô lập mạng bằng hệ điều hành (tốn công cài đặt).
4. **Theo dõi tiến trình**: (a) chụp danh sách 500 ms trước — *đề xuất*; hoặc
   (b) làm ETW ngay ở A5.
5. **Gỡ cài đặt**: giữ lại khu cách ly và nhật ký sửa mặc định — *đề xuất*.
6. Các câu còn mở từ R11 §9 (giữ mặc định đề xuất, `legacy-v0` vẫn tự cách ly):
   khi nào chuyển `legacy-v0` → `evidence-v1`; engine nào bắt buộc để được
   "sạch đáng tin" khi ClamAV/Defender không có; cách xác minh clamd; cách
   xử lý container ClamAV không mở được; phạm vi/thời hạn của "Tin cậy"; ngân
   sách số (worker, bộ nhớ, thời gian); ngân sách báo nhầm khi phát hành; nội
   dung Quét sâu; PE ML/phân tích gói.
7. **Thêm thư viện?** Thiết kế hiện tại không cần `pywin32`. Nếu sau này muốn
   WMI/COM dễ hơn thì cần anh/chị duyệt.

Việc anh/chị cần tự làm sau này (cần quyền admin): chạy
`tools/admin_acceptance.ps1` (sẽ viết ở A1–A3) trên máy thử, không phải máy
dùng thật nếu có thể.
