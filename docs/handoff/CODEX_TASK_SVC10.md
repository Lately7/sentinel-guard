# Codex task SVC10: a false-positive sample with every engine

Step 9 of `docs/handoff/PLAN.md` needs a false-positive rate. `tools/fp_sample.py` measured 6,000 files with no
ClamAV, no Defender and no downloaded rules, so that result is not a product rate. The owner has not set a
budget yet; this round only builds the measuring tool. It runs nothing against the real product state.

## Allowed paths

Changed: `tools/fp_sample.py`. New: `tests/test_fp_sample_engines.py`. Everything else is read-only.

## Build

* An option that says which engines take part, with the same gate the product uses, and that records, per
  engine, whether it really ran. An engine that was asked for but did not run makes the report say so at the
  top: a number from a partial set of engines must not read as the full rate.
* An option for a rules folder, so that a copy of a downloaded rule set can be used. The tool never downloads.
* The report gives: files sampled, by file type; verdict counts; files per second; each suspicious, malicious or
  unknown file with the rule or reason, and the engine; the snapshot and rule generations; the time; and a
  confidence bound for the rate, with the rule of three when there are no false positives. No file content in
  the report, and paths shown as the tool already shows them.
* Uses a temporary `SENTINEL_HOME`, as it does now, and never acts on a file: quarantine stays off whatever the
  settings say. Check this in a test.
* Sampling stays read-only and deterministic for a given seed. A file that cannot be opened is counted, not
  skipped silently.

Say what you could not exercise here. Keep the existing command line working.
