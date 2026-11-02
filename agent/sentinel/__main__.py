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

    db = Database()
    settings = config.Settings.load()
    settings.auto_quarantine = args.quarantine
    scanner = Scanner(db, use_defender=not args.no_defender and settings.use_defender)
    worst = 0
    results = []
    missing = [p for p in args.paths if not os.path.exists(p)]
    for p in missing:
        print(f"ERROR      cannot access {p}", file=sys.stderr)
    failures: list[str] = list(missing)
    for f in _walk([p for p in args.paths if p not in missing], failures):
        v = scanner.scan_file(f, use_cache=not args.no_cache)
        if v.skipped and v.skipped.startswith(("unreadable", "changed while")):
            failures.append(f"{f}: {v.skipped}")
            print(f"ERROR      {f}: {v.skipped}", file=sys.stderr)
        rank = {"clean": 0, "suspicious": 1, "malicious": 2}[v.label]
        worst = max(worst, rank)
        if args.json:
            results.append(v.to_dict())
        elif v.label != "clean" or args.verbose:
            note = f" [{v.skipped}]" if v.skipped else ""
            print(f"{v.label.upper():10} {v.score:3}  {f}  {top_reason(v)}{note}")
        if v.label != "clean":
            out = act_on(db, v, settings, "scan")
            if out["quarantined"] and not args.json:
                print(f"           -> quarantined as {out['quarantine_id']}")
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    # A target that couldn't be scanned must not look like a clean result to scripts.
    return 3 if failures and worst == 0 else worst


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

    db = Database()
    if args.action == "list":
        for q in db.quarantine_items():
            print(f"{q['id']}  {q['original_path']}  {q['sha256'][:16]}")
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
    from .watcher import RealtimeProtection

    settings = config.Settings.load()
    if args.dirs:
        settings.watch_dirs = args.dirs
    db = Database()

    def show(r: dict) -> None:
        v = r["verdict"]
        if v["label"] != "clean":
            print(f"{v['label'].upper():10} {v['score']:3}  {v['path']}  quarantined={r['quarantined']}", flush=True)

    rt = RealtimeProtection(db, settings, Scanner(db, use_defender=settings.use_defender), on_result=show)
    rt.start()
    print("watching:", ", ".join(rt.files.dirs), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        rt.stop()
    return 0


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
    s.add_argument("paths", nargs="+")
    s.add_argument("--quarantine", action="store_true", help="cách ly tệp độc hại")
    s.add_argument("--no-defender", action="store_true")
    s.add_argument("--no-cache", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_scan)

    sub.add_parser("update", help="tải dữ liệu mối đe dọa").set_defaults(fn=cmd_update)
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

    r = sub.add_parser("report", help="xuất báo cáo HTML + JSON")
    r.add_argument("--out")
    r.set_defaults(fn=cmd_report)

    sub.add_parser("tray", help="chạy agent với biểu tượng khay").set_defaults(fn=lambda a: __import__("sentinel.tray", fromlist=["main"]).main() or 0)

    args = ap.parse_args(argv)
    if args.cmd == "quarantine" and args.action != "list" and not args.id:
        ap.error("quarantine restore/delete needs an id")
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
