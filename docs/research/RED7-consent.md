# RED7: approvals, consent helper, tray

The tests below are in-process regression tests. They were read against the production code, not run in this sandbox.

## Medium: repair prompt silently omits actions

- **Attacker model:** An ordinary-user process can create a file and long Run value names that become part of a proposed repair.
- **Steps:** A repair with four long Run value names produces a description over 500 characters (`repair.describe`, `agent/sentinel/service/repair.py:181-199`). Request `approve_repair`. `ServiceCore._op_request_plan` stores only `summary[:MAX_SUMMARY]`, where `MAX_SUMMARY = 500` (`agent/sentinel/service/core.py:32,267-290`). The elevated helper displays that shortened string (`agent/sentinel/service/consent.py:44-59`), while approval executes the original repair plan (`agent/sentinel/service/core.py:314-329`; `agent/sentinel/service/backend.py:648-660`).
- **Effect:** The administrator can approve a repair without seeing its complete action description. The cut may end in the middle of a Run value name and does not disclose that text was omitted.
- **Fix:** Refuse a plan whose complete summary cannot fit in the prompt, or create a bounded complete description before storing it. Never silently slice the summary.
- **Evidence:** Proven by `test_long_repair_plan_is_not_silently_cut` as a code-path regression test. The test has not been run here.

## Medium: overview says protected while service reports off

- **Attacker model:** A service crash or a protection-off action approved through another client leaves the tray's local watcher running.
- **Steps:** Let the local watcher report running and the service status report `{"realtime": false, "worker_failure": ""}`. The backend exposes this service state (`agent/sentinel/service/backend.py:346-362`). `protection_state` checks only the local watcher and `worker_failure`, then returns the green protected state (`agent/sentinel/overview_ui.py:33-54`). The overview passes the polled service status to that function (`agent/sentinel/overview_ui.py:185-215`).
- **Effect:** The main status says `Đang bảo vệ` although service protection is off. The user is not told that machine-wide service protection is absent.
- **Fix:** Treat an explicit `realtime: false` service report as off or attention, and reconcile the local switch with the service state.
- **Evidence:** Proven by `test_overview_reports_service_protection_off` as a code-path regression test. The test has not been run here.

## Medium: tray ignores a failed service enable

- **Attacker model:** A service failure, crash, or full disk at the enable boundary.
- **Steps:** `ServiceLease.enable_protection` returns false if the service does not answer (`agent/sentinel/service/bridge.py:141-142`). In the tray's enable branch, that return is ignored; it sets `settings.realtime = True` and starts the local watcher (`agent/sentinel/tray.py:183-190`). The overview uses that watcher for its protected state (`agent/sentinel/overview_ui.py:37-54`).
- **Effect:** A rejected service enable can be presented as protection enabled. The local watcher does not establish that the privileged service resumed.
- **Fix:** Check the service result before setting the enabled state; on failure, show the service error and keep the status degraded. If portable mode is intended, distinguish it explicitly.
- **Evidence:** Proven by `test_tray_does_not_claim_enabled_after_service_rejects` as a code-path regression test. The test has not been run here.

The fixed-hex plan ID and isolated Python invocation in `agent/sentinel/service/consent.py:32-35,90-110` do not provide an argv injection path. The helper uses a no-default-Yes prompt and `ServiceCore` binds the plan to the requester, claimed connection, current description, and single use (`agent/sentinel/service/consent.py:56-59`; `agent/sentinel/service/core.py:294-329`). `repair._plain` strips non-printable bidi controls and newlines (`agent/sentinel/service/repair.py:40-56`); no finding is reported for those inputs.
