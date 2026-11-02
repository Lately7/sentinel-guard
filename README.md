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

* **Cổng quét nhiều lớp** — mỗi tệp phải đi qua lần lượt:

  | Lớp | Engine | Bắt được |
  |---|---|---|
  | 1 | Lõi Sentinel | hash đã biết, EICAR, tên đánh lừa (đuôi kép, ký tự đảo chiều), cấu trúc PE, PE bị độn phình, ZIP lồng nhau |
  | 2 | Luật + YARA-X | gói luật của bạn và ~5.000 luật YARA Forge core (mã nguồn mở) |
  | 3 | ClamAV (mã nguồn mở) | ~3,6 triệu chữ ký; tự mở 7z, RAR, CAB, ISO, tar/gz/bz2/xz, MSI, PDF, Office, thư email |
  | 4 | Microsoft Defender | ý kiến thứ hai cho tệp rủi ro, chỉ khi Defender là AV đang chạy |

  Kết quả ghi lại từng lớp đã nói gì ("sạch", "PHÁT HIỆN", "một phần",
  "không có"), nên "sạch" không bao giờ bị nhầm với "không ai kiểm tra".
  ClamAV chạy như một `clamd` riêng của Sentinel trên 127.0.0.1, nhận đúng các
  byte agent đã băm qua luồng INSTREAM. Tệp > 400 MB vẫn được kiểm tra phần đầu.
* Nguồn tải về (Mark-of-the-Web) kế thừa kết quả blocklist URL.
* Theo dõi thời gian thực Downloads, Desktop, Documents (theo đường dẫn thật, kể
  cả khi OneDrive chuyển chỗ), thư mục Startup, %TEMP%, và khoá Run trong
  registry.
* Cách ly qua handle đã giữ, nên tráo junction không đổi được mục tiêu; gỡ mọi
  hard link; nhật ký phục hồi sau sự cố; khôi phục không ghi đè và chỉ miễn trừ đúng
  tệp ở đúng vị trí. Chương trình đang chạy: xem trước các bước, xác nhận, rồi dừng
  và cách ly, tự khởi động quay lại nếu khôi phục tệp.
* Quét thông minh: khởi động cùng máy, tác vụ, dịch vụ, tiến trình và thư mục theo
  dõi. Mục không xem được được đếm, không coi là sạch.
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
.\.venv\Scripts\sentinel clamav update       # chữ ký ClamAV (~110 MB lần đầu; cần cài ClamAV)
.\.venv\Scripts\sentinel rules update        # luật YARA Forge core
.\.venv\Scripts\sentinel install             # đăng ký native host + tự chạy khi đăng nhập
```

Trong Helium: mở `chrome://extensions`, bật **Developer mode**, chọn
**Load unpacked** và trỏ tới thư mục `extension`. ID extension luôn là
`ljnncmaoolpbiifaidkgekkeimmjlcgn`.

Chạy agent: shortcut **Sentinel Guard** trên Desktop, hoặc
`.\.venv\Scripts\pythonw -m sentinel tray`. Mở lần nữa chỉ đưa bảng điều khiển
lên, không chạy bản thứ hai.

### Dịch vụ quyền quản trị (tuỳ chọn, mới)

Không cài thì mọi thứ chạy bằng quyền người dùng như trên. Cài rồi thì dịch vụ
chạy nền là bên duy nhất được hành động: khay, CLI và native host chỉ báo tệp cho
dịch vụ, dịch vụ tự quét và tự quyết. Khôi phục, tin cậy, tắt bảo vệ, xử lý chương
trình đang chạy đều phải qua hộp xác nhận quản trị. Cách cài: nháy đúp `tools\install_service.cmd`,
bấm **Có** ở hộp UAC; kết quả kiểm tra nằm ở `%TEMP%\sentinel-install.log`. Làm tay thì trong PowerShell
chạy Administrator:

```powershell
.\.venv\Scripts\python -m sentinel service snapshot --source C:\SentinelSnapshot
# xem lại thư mục đó, rồi:
.\.venv\Scripts\python -m sentinel service install --source C:\SentinelSnapshot
.\.venv\Scripts\python -m sentinel service verify --restart   # PASS/FAIL/SKIP từng mục
.\.venv\Scripts\python -m sentinel service uninstall          # giữ khu cách ly và nhật ký
```

Chưa chạy thật ở bản này: chưa ai cài dịch vụ dưới LocalSystem, `verify` là lần đầu.

## Lệnh

```powershell
sentinel scan [--smart | --deep | <tệp|thư mục>] [--quarantine] [--json] [-v]   # 0 sạch, 1 đáng ngờ, 2 độc hại, 3 có phần chưa kiểm tra được; -v in kết quả từng lớp
sentinel service snapshot | install | verify | uninstall
sentinel clamav update | start | stop | status
sentinel rules update
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
* abuse.ch (MalwareBazaar, URLhaus, ThreatFox) yêu cầu khoá tài khoản miễn phí;
  có `abusech_auth_key` trong settings thì ba nguồn này tự được dùng. Không có
  thì phát hiện tệp dựa vào ClamAV, YARA Forge, Defender (nếu đang là AV chính) và
  nguồn tải về. Không cài ClamAV thì lớp 3 hiện "không có" và kết quả quét ghi rõ
  tệp chỉ được lõi kiểm tra.
* Dịch vụ chưa chạy ClamAV: `clamd` phân tích tệp độc nên không được chạy dưới
  LocalSystem. Khay vẫn dùng ClamAV và tự xử lý phát hiện của nó.
* Không có driver: dịch vụ thấy tệp và tiến trình sau khi chúng xuất hiện (nhật ký
  USN, lấy mẫu 500 ms), không ngăn được chúng chạy. Tiến trình sống dưới một mẫu có
  thể không được thấy.
* Không có dịch vụ thì agent chạy bằng quyền người dùng; mã độc chạy cùng quyền có
  thể can thiệp.
* Trình duyệt giới hạn số quy tắc; ~400.000 tên miền được chặn ở tầng mạng,
  phần còn lại được bắt khi điều hướng.
