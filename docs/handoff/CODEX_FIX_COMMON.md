# Codex fix rounds: common rules

You fix findings that a red team or edge-case round found and that Claude's triage confirmed: a triager judged
each failing test and a second agent tried to refute it. You work in the worktree where the finding's tests live.
Claude reviews every line, runs the suites and merges. Do not commit.

* **Product bug or hardening:** change the product so the finding's test passes, with the smallest change that
  does it. If the triage's proposed fix is wrong or would break something the code relies on, do it differently
  and say why. A test that turns out wrong after all: fix the test and say why.
* **Test bug:** fix the test so it tests what it meant to, against real behaviour.
* **Deferred** (an owner decision or a later round): mark the test
  `@pytest.mark.xfail(strict=True, reason="<why, and where it is recorded>")`; never delete it.
* **By design:** delete the test and add one line to the round's report saying why it was dropped.
* Every other test in the suite must keep passing; say which existing tests you read to be sure.
* Same hard rules as the service rounds: no elevation, never touch the installed service, Program Files or
  ProgramData, no system or Defender settings, no network, no downloads, harmless inputs only. You cannot run
  pytest in this sandbox; re-read your code against every test. Code and comments in English, user text in
  Vietnamese, LF line endings, comments explain why.
* Final answer under 400 words: per finding, done or not and why, files touched.
