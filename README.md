# Sentinel Guard

Lớp bảo vệ bổ sung cho Windows: quét tệp và theo dõi thời gian thực, cùng một
extension chặn trang web nguy hiểm cho **Helium** (cũng chạy trên Chrome, Edge,
Brave).

> **Không thay thế phần mềm diệt virus.** Sentinel Guard không có driver nhân,
> không chặn tiến trình trước khi chạy, không có engine phân tích hành vi hay
> danh tiếng đám mây. Hãy giữ Malwarebytes/Defender làm lớp chính; Sentinel Guard
> thêm blocklist web lớn, quét tệp tải về và một bảng điều khiển.

## Có gì

**Agent trên máy** (`agent/sentinel`, Python 3.12+)

* Quét tệp qua nhiều bước: danh sách tin cậy → chữ ký hash/EICAR → nhận dạng
  loại tệp và tên đánh lừa (đuôi kép, ký tự đảo chiều) → gói luật người dùng và
  YARA-X → mở tệp nén (kể cả > 64 MB, từng tệp con) → nguồn tải về
  (Mark-of-the-Web) → Microsoft Defender khi Defender đang là AV chính.
* Theo dõi thời gian thực Downloads, Desktop, Documents (theo đường dẫn thật, kể
  cả khi OneDrive chuyển chỗ), thư mục Startup, %TEMP%, và khoá Run trong
  registry.
* Cách ly an toàn (kiểm tra lại hash trước khi đụng tệp, ghi sổ trước khi xoá),
  khôi phục không ghi đè.
* Dữ liệu mối đe dọa: malware-filter (urlhaus, phishing, pup), OpenPhish,
  HaGeZi TIF và fake, Phishing.Database, NoCoin — khoảng 550.000 tên miền.
  Tranco top 100.000 không bao giờ bị chặn nguyên tên miền.
* Khay hệ thống + bảng điều khiển, báo cáo HTML/JSON, CLI.

**Extension** (`extension/`, Manifest V3)

* Chặn ở tầng mạng mọi loại yêu cầu (trang, script, iframe, XHR, WebSocket …)
  tới tên miền độc hại; trang chính được chuyển tới trang cảnh báo.
* Tra cứu từng điều hướng với agent (bắt cả URL cụ thể và phần vượt giới hạn
  quy tắc của trình duyệt), chấm điểm cấu trúc URL.
* Cảnh báo form mật khẩu đáng ngờ, chặn tải xuống từ URL độc hại, quét tệp tải
  về bằng agent.

## Cài đặt

```powershell
cd sentinel-guard
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[ui,dev]"
.\.venv\Scripts\sentinel update              # tải dữ liệu mối đe dọa (~30 giây)
.\.venv\Scripts\sentinel install             # đăng ký native host + tự chạy khi đăng nhập
```

Trong Helium: mở `chrome://extensions`, bật **Developer mode**, chọn
**Load unpacked** và trỏ tới thư mục `extension`. ID extension luôn là
`ljnncmaoolpbiifaidkgekkeimmjlcgn`.

Chạy agent: shortcut **Sentinel Guard** trên Desktop, hoặc
`.\.venv\Scripts\pythonw -m sentinel tray`. Mở lần nữa chỉ đưa bảng điều khiển
lên, không chạy bản thứ hai.

## Lệnh

```powershell
sentinel scan <tệp|thư mục> [--quarantine] [--json]   # 0 sạch, 1 đáng ngờ, 2 độc hại, 3 không truy cập được
sentinel check-url <url>
sentinel block <tên miền> / sentinel unblock <tên miền>
sentinel quarantine list | restore <id> | delete <id>
sentinel watch [thư mục...]                           # bảo vệ thời gian thực trong terminal
sentinel report                                       # báo cáo HTML + JSON
sentinel uninstall
```

## Hiệu quả đo được

`python benchmarks/web_eval.py` đo trên dữ liệu thật với tập giữ lại
(`reports/web-eval.json`):

| Chỉ số | Kết quả |
|---|---|
| URL lừa đảo mới của OpenPhish bị chặn bởi các nguồn *khác* | 23% |
| Báo nhầm của blocklist trên Tranco hạng 100.001–110.000 | 0,1% |
| Heuristic URL ≥ 70 trên lừa đảo thật / trên site thật | 0% / 0% |

OpenPhish nằm trong dữ liệu khi dùng thật, nên URL của nó bị chặn; con số 23%
cho thấy độ phủ với trang lừa đảo *mới* — blocklist luôn đi sau kẻ tấn công.
Heuristic URL hầu như không bắt được lừa đảo thật; nó chỉ là tín hiệu phụ.

## Kiểm thử

```powershell
.\.venv\Scripts\python -m pytest              # agent
node --test "extension/test/*.test.mjs"       # extension
sentinel block blocked-selftest.sentinelguard.invalid
node tools/helium_e2e.mjs extension           # Helium thật, profile tạm
sentinel unblock blocked-selftest.sentinelguard.invalid
```

Đánh giá của Codex và cách xử lý từng phát hiện: `REVIEWS.md`.

## Giới hạn đã biết

* Phát hiện sau khi tệp đã ghi xuống đĩa, không chặn trước khi chạy.
* abuse.ch (MalwareBazaar, URLhaus, ThreatFox) giờ yêu cầu khoá tài khoản nên
  chưa có nguồn hash mã độc; phát hiện tệp chủ yếu dựa vào Defender (nếu đang
  bật), gói luật/YARA bạn thêm vào `%LOCALAPPDATA%\SentinelGuard\rules`, và
  nguồn tải về.
* Agent chạy bằng quyền người dùng; mã độc chạy cùng quyền có thể can thiệp.
* Trình duyệt giới hạn số quy tắc; ~400.000 tên miền được chặn ở tầng mạng,
  phần còn lại được bắt khi điều hướng.
