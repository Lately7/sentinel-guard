# Codex task SVC16: approvals and the browser, with a service installed

## Allowed paths

Changed: `agent/sentinel/service/core.py`, `agent/sentinel/service/consent.py`, `agent/sentinel/service/bridge.py`,
`agent/sentinel/tray.py`, `agent/sentinel/nativehost.py`, `agent/sentinel/db.py`, `extension/src/background.js`,
`tools/helium_e2e.mjs`, `tests/test_service_consent.py`, `tests/test_service_ipc.py`.
New: `tests/test_svc16.py`. Everything else is read-only, including `service/backend.py`.

## Findings

**1. `approve_plan` accepts a plan nobody claimed.** `core.py:308`: the claim check is conditional, so an elevated
client can approve without having shown the plan through `get_plan`. Approval must require a matching claim on the
same connection. Single use stays as it is.

**2. A plan expires before the tray stops waiting.** `core.py:27` gives a plan 120 s; `consent.py:115` waits up to 150 s
after UAC. A slow UAC prompt or a user reading the box meets an expired plan. Give the plan about 300 s and make the
tray's wait match, so the wait ends first or at the same time. Keep the claim's own rules.
`test_service_claim_expiry_and_changed_target` pins 121 s; update it to the new value, keeping what it protects.

**3. Every failure reads the same.** `bridge.py:134`, `lease.approve` returns False for a cancelled UAC, a refusal, an
expired plan, a helper failure and a service that went away, and `tray.py:376` shows one restore error. Return a
typed result, keeping a falsy failure so callers that test truth still work, and show the user in Vietnamese what
happened. A user who cancels is told nothing went wrong. Log the rest. `pythonw` has no console: the helper must
write failures where they can be read, with an exit code the tray can tell apart, and an uncaught exception must not
vanish.

**4. A standard user cannot approve.** `plan.requester == caller.key` refuses an admin whose SID differs, by design
so far: this is owner question R16. Do not change it. Make the message say so, instead of the generic failure.

**5. The allow list's version can collide.** `background.js:153`, with `nativehost.py`: a service with a fresh database
can reuse `s0`, so a cached extension list stays as it was until a forced sync. Give the store an id, created once,
so a new store cannot read as the old one. Keep the version compare in the extension working, and old stored values
must trigger one sync, not an error.

**6. The first sync empties the user's trusted hosts without a word.** Owner question 14 keeps the list from moving
to the service. That decision stands. When the extension's first sync with a service replaces a non-empty list with
an empty one, tell the user once, in Vietnamese, what happened and that they can trust a site again through the
confirmation.

**7. Helium e2e cannot be trusted on a machine with the service.** `tools/helium_e2e.mjs` launches the registered host,
which delegates to the installed service, so some checks fail and `crafted_proceed_rejected` and `once_not_trusted`
can pass because nothing was trusted. Do not try to make it pass: detect the installed service at the start and
stop with a clear message, unless `--with-service` is given, in which case the report says which checks are
meaningful there.
