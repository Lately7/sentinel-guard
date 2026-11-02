# Baseline — scan gate as first committed (C2a)

Measured 2026-11-02 on the owner's machine, in a clean detached checkout of
commit `6e7bb03` (C2a, "feat: multi-layer scan gate …"), using the project
`.venv`. Every number below was produced by the command next to it.

## Environment

| Item | Value |
|---|---|
| OS | Windows 11 Home 10.0.26200 |
| Python | 3.15.1 (`.venv`) |
| Node | v24.20.0 |
| ClamAV | 1.5.4, database daily 28172 (`Mon Nov  2 13:24:10 2026`), from clamd `VERSION` |
| ClamAV DB | `%LOCALAPPDATA%\SentinelGuard\clamav\db` (main 63, daily 28172, bytecode 339) |
| YARA Forge | not installed in the real data dir (tests use their own rule files) |
| Defender | passive (Malwarebytes is the active AV) |

## Results

| Command | clamd | Result |
|---|---|---|
| `python -m pytest -q -rs -p no:cacheprovider` | stopped | **78 passed, 4 skipped** — the 4 `test_real_clamav_*` tests skip: "no clamd running" |
| `python -m pytest -q -rs -p no:cacheprovider` | running (`sentinel clamav start`) | **82 passed** |
| `node --test "extension/test/*.test.mjs"` | — | **8 passed**, 0 failed |

clamd was stopped again afterwards (`sentinel clamav stop`), as it was before.

## Notes

* `node --test extension/test/` (the form in `AGENTS.md` and
  `PROJECT_CONTEXT.md`) fails on Node 24 because it treats the directory as a
  test file; use the glob form above.
* `pyflakes` reports one pre-existing warning: `agent/sentinel/watcher.py:7`
  `queue` imported but unused.
* `agent/sentinel/db.py`, `tests/test_agent.py` and `tests/test_robustness.py`
  are stored with CRLF line endings, although the repo otherwise uses LF.
* C2a is not a release: RT-001…RT-015 (`docs/handoff/PROJECT_CONTEXT.md` §9,
  `codex-review-r4.md`, `codex-research-r5.md`) are open.
* No false-positive measurement exists yet.
