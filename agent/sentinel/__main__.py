"""Command line: `python -m sentinel <command>`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import config


def _walk(paths: list[str], errors: list[str] | None = None):
    for base in paths:
        if os.path.isfile(base):
            yield base
            continue
        on_error = (lambda e: errors.append(f"{e.filename}: {e.strerror}")) if errors is not None else None
        for root, _d, files in os.walk(base, onerror=on_error):
            for f in files:
                yield os.path.join(root, f)


def cmd_scan(args: argparse.Namespace) -> int:
    from .db import Database
    from .engine.scanner import Scanner
    from .protection import act_on, top_reason
    from .scanjob import discovery
    from .service.bridge import install as install_lease

    install_lease()
    db = Database()
    settings = config.Settings.load()
    settings.auto_quarantine = args.quarantine
    scanner = Scanner(db, use_defender=not args.no_defender and settings.use_defender,
                      use_clamav=not args.no_clamav and settings.use_clamav)
    # clamd takes about 20 s to load; without this wait every file would be unknown.
    if scanner.clamav is not None:
        scanner.clamav.start(wait=60)
    malicious = suspicious = False
    results = []
    missing = [p for p in args.paths if not os.path.exists(p)]
    for p in missing:
        print(f"ERROR      cannot access {p}", file=sys.stderr)
    failures: list[str] = list(missing)
    profile = "deep" if args.deep else "smart" if args.smart or not args.paths else None
    found = discovery(profile, settings) if profile else None
    files = (t.path for t in found) if found else _walk([p for p in args.paths if p not in missing], failures)
    for f in files:
        v = scanner.scan_file(f, use_cache=not args.no_cache)
        if v.skipped and v.skipped.startswith(("unreadable", "changed while")):
            failures.append(f"{f}: {v.skipped}")
            print(f"ERROR      {f}: {v.skipped}", file=sys.stderr)
        # An engine that was asked and failed did not check the file; a layer
        # that is off or not installed is a configuration, not a failure.
        broken = [f"{k} {s}" for k, s in v.engines.items() if s.split(":", 1)[0] in ("error", "timeout")]
        if broken:
            failures.append(f"{f}: {'; '.join(broken)}")
            print(f"ERROR      {f}: {'; '.join(broken)}", file=sys.stderr)
        # Not checked must never read as clean to a script (exit 3).
        if v.label == "unknown":
            failures.append(f"{f}: {v.skipped or 'not fully checked'}")
        malicious |= v.label == "malicious"
        suspicious |= v.label == "suspicious"
        if args.json:
            results.append(v.to_dict())
        elif v.label != "clean" or args.verbose:
            note = f" [{v.skipped}]" if v.skipped else ""
            print(f"{v.label.upper():10} {v.score:3}  {f}  {top_reason(v)}{note}")
            if args.verbose and v.engines:
                print("           " + " · ".join(f"{k}: {s}" for k, s in v.engines.items()))
        if v.label != "clean":
            out = act_on(db, v, settings, "scan")
            if out["quarantined"] and not args.json:
                print(f"           -> quarantined as {out['quarantine_id']}")
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    # Precedence agreed in design round 3 (R5): a known threat matters most;
    # then anything that could not be checked, which must never read as clean
    # or merely suspicious to a script; then suspicious; then clean.
    if malicious:
        return 2
    if failures:
        return 3
    return 1 if suspicious else 0


def cmd_update(args: argparse.Namespace) -> int:
    from . import feeds
    from .db import Database

    db = Database()
    moved = db.check_and_repair()
    if moved:
        print(f"database was damaged; moved to {moved} and rebuilt")
    res = feeds.update_all(db)
    for name, status in res.items():
        print(f"{name:20} {status}")
    return 0 if all(s.startswith("ok") for s in res.values()) else 1


def cmd_check_url(args: argparse.Namespace) -> int:
    from . import urlintel
    from .db import Database

    r = urlintel.check(Database(), args.url)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 2 if r["verdict"] == "malicious" else 0


def cmd_block(args: argparse.Namespace) -> int:
    from . import feeds
    from .db import Database

    host = args.host.lower().strip().rstrip(".")
    if not feeds._HOST_RE.match(host):
        print(f"invalid host: {args.host}", file=sys.stderr)
        return 2
    db = Database()
    if args.cmd == "block":
        db.add_hosts([(host, "custom", "user")])
    elif not db.remove_local_host(host):
        print(f"{host} is not in the custom blocklist")
        return 1
    # New blocklist version: the browser extension picks the change up on its next sync.
    db.bump_generation()
    db.set_meta("blocklist_version", str(db.generation()))
    print(f"{args.cmd}ed {host}")
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    from . import quarantine
    from .db import Database
    from .service.bridge import lease

    db = Database()
    quarantine.reconcile(db)
    held = lease.quarantine_items() or []
    if args.action == "list":
        for q in [*held, *db.quarantine_items()]:
            print(f"{q['id']}  {q['original_path']}  {q['sha256'][:16]}")
    elif any(q["id"] == args.id for q in held):
        # Held by the service: only its confirmation can release it.
        kind = "restore_quarantine" if args.action == "restore" else "delete_quarantine"
        if not lease.approve(kind, {"quarantine_id": args.id}):
            print("Chưa thực hiện: cần xác nhận của quản trị viên.", file=sys.stderr)
            return 1
    elif args.action == "restore":
        print(quarantine.restore(db, args.id))
    elif args.action == "delete":
        quarantine.delete(db, args.id)
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    from . import install

    for line in install.install(autostart=not args.no_autostart):
        print(line)
    print(f"\nExtension folder: {install.extension_dir()}")
    print(f"Extension ID:     {config.EXTENSION_ID}")
    if install.helium_exe():
        print("Helium: bật 'Developer mode' trong chrome://extensions, chọn 'Load unpacked' và trỏ tới thư mục extension ở trên.")
        if args.open:
            install.open_helium_extensions()
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    from . import install

    for line in install.uninstall():
        print(line)
    return 0


def cmd_service(args: argparse.Namespace) -> int:
    from . import __version__
    from .service import installer

    try:
        if args.action == "snapshot":
            digest = installer.snapshot_runtime(Path(args.source))
            print(f"Bản sao để xem xét: {args.source}\nSHA-256 tổng: {digest}")
            print("Xem lại thư mục này, rồi chạy `sentinel service install --source <thư mục>` với quyền admin.")
        elif args.action == "install":
            installer.install(Path(args.source), args.version_id or __version__, dry_run=args.dry_run)
        elif args.action == "verify":
            from .service import verify

            return verify.main(restart=args.restart)
        else:
            print(installer.uninstall())
    except installer.ElevationRequired:
        print("Lệnh này cần cửa sổ dòng lệnh chạy với quyền Administrator.", file=sys.stderr)
        return 1
    except (installer.InstallError, OSError) as e:
        print(f"Không thực hiện được: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from . import report
    from .db import Database

    paths = report.write_report(Database(), config.Settings.load(), Path(args.out) if args.out else None)
    print(paths["html"])
    print(paths["json"])
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    import time

    from .db import Database
    from .engine.scanner import Scanner
    from .service.bridge import install as install_lease
    from .watcher import RealtimeProtection

    install_lease()
    settings = config.Settings.load()
    if args.dirs:
        settings.watch_dirs = args.dirs
    db = Database()

    def show(r: dict) -> None:
        v = r["verdict"]
        if v["label"] != "clean":
            print(f"{v['label'].upper():10} {v['score']:3}  {v['path']}  quarantined={r['quarantined']}", flush=True)

    scanner = Scanner(db, use_defender=settings.use_defender, use_clamav=settings.use_clamav)
    rt = RealtimeProtection(db, settings, scanner, on_result=show)
    rt.start()
    print("watching:", ", ".join(rt.files.dirs), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        rt.stop()
    return 0


def cmd_clamav(args: argparse.Namespace) -> int:
    from .engine import clamav

    if clamav.install_dir() is None:
        print("ClamAV chưa được cài (https://www.clamav.net/downloads)", file=sys.stderr)
        return 1
    if args.action == "update":
        res = clamav.update()
        print(res)
        return 0 if res == "ok" else 1
    eng = clamav.ClamAVEngine(autostart=False)
    if args.action == "start":
        ok = eng.start(wait=120)
        print("clamd ready" if ok else f"clamd not started: {eng.status()}")
        return 0 if ok else 1
    if args.action == "stop":
        try:
            clamav.Clamd().command(b"zSHUTDOWN\0", timeout=5)
            print("clamd stopped")
        except OSError:
            print("clamd was not running")
        return 0
    print(f"{eng.status()}  {eng.client.version() or ''}  db={clamav.db_dir()}")
    return 0 if eng.status() == "ready" else 1


def cmd_rules(args: argparse.Namespace) -> int:
    from . import yarafeed

    res = yarafeed.update()
    print(res)
    return 0 if res.startswith("ok") else 1


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Browsers launch the host executable directly with the caller origin
    # (and on Windows a --parent-window flag) as its arguments.
    if argv and (argv[0] == "native-host" or argv[0].startswith("chrome-extension://")):
        from . import nativehost

        return nativehost.main([a for a in argv if a != "native-host"])

    ap = argparse.ArgumentParser(prog="sentinel", description="Sentinel Guard — bảo vệ mã độc và web thời gian thực")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="quét tệp/thư mục")
    s.add_argument("paths", nargs="*")
    s.add_argument("--smart", action="store_true", help="quét thông minh: khởi động cùng máy, tiến trình, thư mục theo dõi")
    s.add_argument("--deep", action="store_true", help="quét sâu: như trên, thêm mọi ổ cố định")
    s.add_argument("--quarantine", action="store_true", help="cách ly tệp độc hại")
    s.add_argument("--no-defender", action="store_true")
    s.add_argument("--no-clamav", action="store_true")
    s.add_argument("--no-cache", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_scan)

    sub.add_parser("update", help="tải dữ liệu mối đe dọa").set_defaults(fn=cmd_update)
    cl = sub.add_parser("clamav", help="lớp quét ClamAV: update | start | stop | status")
    cl.add_argument("action", choices=["update", "start", "stop", "status"])
    cl.set_defaults(fn=cmd_clamav)
    ru = sub.add_parser("rules", help="tải luật YARA mã nguồn mở (YARA Forge core)")
    ru.add_argument("action", choices=["update"])
    ru.set_defaults(fn=cmd_rules)
    c = sub.add_parser("check-url", help="tra cứu URL")
    c.add_argument("url")
    c.set_defaults(fn=cmd_check_url)

    for name, help_text in (("block", "tự chặn một tên miền"), ("unblock", "bỏ chặn tên miền đã tự chặn")):
        b = sub.add_parser(name, help=help_text)
        b.add_argument("host")
        b.set_defaults(fn=cmd_block)

    q = sub.add_parser("quarantine", help="quản lý cách ly")
    q.add_argument("action", choices=["list", "restore", "delete"])
    q.add_argument("id", nargs="?")
    q.set_defaults(fn=cmd_quarantine)

    w = sub.add_parser("watch", help="bảo vệ thời gian thực trong terminal")
    w.add_argument("dirs", nargs="*")
    w.set_defaults(fn=cmd_watch)

    i = sub.add_parser("install", help="đăng ký native host + tự khởi động")
    i.add_argument("--no-autostart", action="store_true")
    i.add_argument("--open", action="store_true", help="mở trang extensions của Helium")
    i.set_defaults(fn=cmd_install)
    sub.add_parser("uninstall").set_defaults(fn=cmd_uninstall)

    v = sub.add_parser("service", help="dịch vụ Windows: snapshot | install | verify | uninstall (ba lệnh sau cần quyền admin)")
    v.add_argument("action", choices=["snapshot", "install", "verify", "uninstall"])
    v.add_argument("--source", help="thư mục bản sao runtime đã xem xét")
    v.add_argument("--version-id")
    v.add_argument("--dry-run", action="store_true", help="in kế hoạch, không thay đổi gì")
    v.add_argument("--restart", action="store_true", help="verify: dừng rồi khởi động lại dịch vụ để kiểm tra rào dừng")
    v.set_defaults(fn=cmd_service)

    r = sub.add_parser("report", help="xuất báo cáo HTML + JSON")
    r.add_argument("--out")
    r.set_defaults(fn=cmd_report)

    sub.add_parser("tray", help="chạy agent với biểu tượng khay").set_defaults(fn=lambda a: __import__("sentinel.tray", fromlist=["main"]).main() or 0)

    args = ap.parse_args(argv)
    if args.cmd == "quarantine" and args.action != "list" and not args.id:
        ap.error("quarantine restore/delete needs an id")
    if args.cmd == "service" and args.action in ("snapshot", "install") and not args.source:
        ap.error("service snapshot/install needs --source")
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
