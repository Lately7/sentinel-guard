"""Real-time protection: honest "on" state (RT-026) and both registry views (RT-027)."""

from __future__ import annotations

import pytest

from sentinel import config
from sentinel.watcher import RUN_KEYS, NothingToWatch, RealtimeProtection, read_run_entries


def test_nothing_to_watch_is_an_error_not_running(db, scanner, tmp_path):
    s = config.Settings(watch_dirs=[str(tmp_path / "does-not-exist")], use_defender=False)
    rt = RealtimeProtection(db, s, scanner)
    with pytest.raises(NothingToWatch):
        rt.start()
    assert not rt.running


def test_existing_folder_starts(db, scanner, tmp_path):
    s = config.Settings(watch_dirs=[str(tmp_path)], use_defender=False)
    rt = RealtimeProtection(db, s, scanner)
    rt.start()
    try:
        assert rt.running and rt.files.dirs == [str(tmp_path)]
    finally:
        rt.stop()


class FakeReg:
    """Just enough of winreg: per (hive, view) value lists."""

    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE = 1, 2
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 0x20019, 0x0100, 0x0200

    def __init__(self, data):
        self.data = data
        self.opened = []

    def OpenKey(self, hive, key, reserved, access):
        view = access & (self.KEY_WOW64_64KEY | self.KEY_WOW64_32KEY)
        self.opened.append((hive, view))
        values = self.data.get((hive, view, key))
        if values is None:
            raise OSError("no such key")
        reg = self

        class Key:
            def __enter__(self):
                return values

            def __exit__(self, *a):
                return False
        reg._values = values
        return Key()

    def EnumValue(self, key, i):
        if i >= len(key):
            raise OSError("no more")
        name, value = key[i]
        return name, value, 1


def test_run_keys_are_read_from_both_hklm_views():
    r = FakeReg
    run = RUN_KEYS[0]
    reg = FakeReg({
        (r.HKEY_CURRENT_USER, 0, run): [("Chat", r"C:\Users\u\chat.exe")],
        (r.HKEY_LOCAL_MACHINE, r.KEY_WOW64_64KEY, run): [("Driver", r"C:\Program Files\drv.exe")],
        (r.HKEY_LOCAL_MACHINE, r.KEY_WOW64_32KEY, run): [("Updater", r"C:\Program Files (x86)\upd.exe")],
    })
    entries = read_run_entries(reg)
    assert entries == {
        f"HKCU\\{run}\\Chat": r"C:\Users\u\chat.exe",
        f"HKLM\\{run}\\Driver": r"C:\Program Files\drv.exe",
        f"HKLM32\\{run}\\Updater": r"C:\Program Files (x86)\upd.exe",
    }
    assert (r.HKEY_LOCAL_MACHINE, r.KEY_WOW64_32KEY) in reg.opened
