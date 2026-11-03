# Codex red team rounds: common rules

Sentinel Guard is a Windows anti-malware prototype: a LocalSystem service (`agent/sentinel/service/`), a restricted
scan worker, a tray app, a browser extension with a native host, and quarantine. You are the red team. Claude
reviews every finding, runs the tests and decides the fixes; you change no product code.

## Attacker models

1. A process running as the ordinary user (medium integrity, not elevated) on the same machine.
2. A malicious web page in the user's browser, talking to the extension and native host only as a page can.
3. A file the user downloads or that lands on disk: crafted names, contents, archives, timestamps, attributes.
4. A crash, a power loss, a sleep or a full disk at the worst moment.

## What counts

Make the product miss what it should detect, quarantine or delete the wrong file, act on bytes it did not measure,
report clean for something it did not check, give a medium-integrity process anything the service or an
administrator holds, hang or crash the service or worker, lose or corrupt state, leak another user's data, or
mislead the user through the UI. Ignore style and theory with no concrete path.

## Output

* `tests/codex/test_red<N>_<area>.py`: one test per finding that fails today and passes once fixed, in process,
  with `tmp_path` and the temporary `SENTINEL_HOME` from `tests/conftest.py`. One-line comment on top of each:
  the attacker, the effect. Never xfail or skip a finding test.
* `docs/research/RED<N>-<area>.md`: per finding: attacker model, steps, effect, the exact lines, a proposed fix,
  severity (critical, high, medium, low), and whether it is proven by the test or inferred.

## Hard rules

* Files outside your two output files are read-only.
* Never elevate, never touch the installed service, `C:\Program Files\SentinelGuard` or `C:\ProgramData\
  SentinelGuard`, never change system or Defender settings, no network, no downloads.
* No malware, no evasion techniques beyond what a test needs to show a gap: use the harmless marker rule and EICAR
  assembled in memory (`tests/conftest.py`); never write EICAR to disk.
* You cannot run pytest in this sandbox; re-read each test against the code. Claude runs them.
* Final answer under 400 words: the findings by severity with their test names.
