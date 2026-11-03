# Codex task SVC12: ransomware scoring in shadow

R14 requires 30 days of observation before any automatic suspension. `service/burst.py` has the scoring state
machine and nothing feeds it. This round makes the observation possible. It never acts.

## Allowed paths

Changed: `agent/sentinel/service/burst.py`. New: `agent/sentinel/service/shadow.py`, `tests/test_svc12.py`. Everything
else is read-only. Read `docs/research/R14-etw-ransomware-detection.md`, `service/burst.py`, `service/etw.py`
(`ParsedEvent`) and `service/canary.py`.

## Build

* `ShadowObserver` in `shadow.py`: `feed(event: ParsedEvent) -> None` turns file events into `burst` operations,
  and `report() -> dict`. Another round calls `feed` from ETW's `on_file_event`. It is thread-safe and bounded.
* **It never stops, suspends, quarantines or prompts.** There is no code path from here to `repair`, `quarantine`
  or a process handle. A test checks that `shadow.py` imports none of them, and that a burst changes nothing but
  counters and the log.
* What a 30-day review needs: for each decision the scorer would have made, the time, the process image name, the
  counts of documents and folders, and the state reached, written to a bounded rolling file in the state tree,
  through an injected writer so tests stay in memory. No file names of the user's documents, and no content:
  counts only. The rolling file has a size bound and keeps the newest entries.
* `report()` gives first-seen time, days observed, events fed, would-have-suspended count, and gaps. Gaps count:
  a period with lost events must be visible, because a quiet 30 days with holes in it proves nothing. Time the
  machine was off is not observed time.
* Canaries stay out of this round. Placing them in Documents and Pictures is the owner's open question 11, so a
  canary signal must be an optional input that nothing supplies.
* `WINDOW_SECONDS` and the burst thresholds are R14 hypotheses. Keep them, and record them in the report so that
  the review knows what was measured.
