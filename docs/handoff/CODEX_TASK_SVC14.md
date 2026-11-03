# Codex task SVC14: catching up after a lost journal

When a journal wraps or is recreated, the records are gone, and `backend._machine_observers` runs a reconciliation
over the `smart` scope only, so a changed file outside it is never looked at. A full walk in one go is too heavy for
a machine in use. This round writes the walk; Claude wires it in.

## Allowed paths

New: `agent/sentinel/service/reconcile.py`, `tests/test_svc14.py`. Everything else is read-only, including
`backend.py` and `gate_v2/scope.py`. Read `backend._machine_observers`, `gate_v2/scope.py` and `service/observers.py`.

## Build

A class, `Reconciler`, that `backend.py` can call in place of its `reconcile()` function: same signature, returns True
when the walk has finished and False when there is more to do, so that `Observers` keeps the debt and calls again.

* First the `smart` scope, as now. Then the `deep` scope over fixed drives, resumable: a cursor stored through an
  injected `get`/`set` pair, saved at intervals, so a restart carries on and does not start over.
* A pass is bounded by a time budget, about 60 s, and by a number of offers. It stops early when `submit` refuses, and
  does not count refused items as done. `submit` is the same `backend.observe` call the observers use.
* Only files with a risky suffix are offered, using `observers.RISKY_SUFFIXES`, and the service's own data root
  stays out, as `Observers.wanted` does.
* Scope entries reported as gaps, such as `cloud_placeholder` or access denied, are counted, not retried, and the
  counts are available through a `report()` method.
* When the journal is lost again during a walk, the walk starts over from the beginning of the scope, since what
  it has passed may have changed. Provide `restart()`.
* Nothing here scans or acts: it only offers paths.
* With a machine of a few million files the walk must not keep them in memory: no list of everything, and the
  cursor stays small.
