# Codex task SVC18: a phased ETW check that one install can settle

## Allowed paths

Changed: `agent/sentinel/service/etw.py`. New: `tests/test_svc18.py`. `tests/test_svc11.py` and `tests/test_svc17.py`
only where they pin behaviour this round changes (the native enable, short clock iterators in check tests,
`_check_child`, the loss sum, the stop join budget). Everything else is read-only; `verify.py` is changed by round
SVC18V at the same time.

## What the real sessions showed

The service runs as LocalSystem; a private real-time system-logger session enables only `SYSTEM_PROCESS_PROVIDER`
(keyword 0x1). At start a check spawns a child `python.exe` and waits for its Process Start (class `3d6fa8d0-…`,
opcode 1). Raw counts during the check, classGuid/opcode:

| Session | Providers | Process/3 (DCStart) | Process/1 | EventTrace 68fdd900 /5 /8 /32 | Loss: check / total |
|---|---|---|---|---|---|
| 1 | process + IO | 61 | 0 | 3 2 3 | – / 373,432 |
| 2 (restart) | process + IO | 340 | 2 (the child's, payload captured) | 3 3 3 | – |
| 3 | process | 43 | child not spawned | 2 1 2 | – |
| 4 (restart) | process | 188 | child not spawned | 2 1 2 | 3 / 1,390 |
| 5 (`8b6f043`) | process | 11 | 0 in 5 s | 2 1 2 | 3 / 1,378 |

An eight-agent investigation (docs, four libraries' source, a code audit, the evidence) found:

* The ctypes layouts, handles and callback are correct; the call order (StartTrace, EnableTraceEx2, OpenTrace,
  ProcessTrace on a thread) is what krabsetw, ferrisetw and pywintrace do; FlushTimer 1 s is standard.
* `ProcessTrace`'s return code is discarded (`NativeBackend.process`), so a consumer that died is invisible.
* About 1,380 events reached the Python callback only when the session stopped: events were held in the session,
  not lost in Python. Why is open: unflushed per-CPU buffers (H1), ProcessTrace merging per-CPU streams by
  timestamp and waiting on quiet ones (H7), a rundown written before the consumer connected (H2), a GIL stall at
  service start (H8), or child A created before the asynchronous enable (`EnableTraceEx2` Timeout 0) took effect (H9).
* The loss figure adds unlike units: `truncated` events were delivered with a clipped payload; a failed QUERY
  adds 1 to `events_lost`; RealTimeBuffersLost counts 64 KB buffers.
* `68fdd900-…` is EventTraceGuid. PEVENT_RECORD_CALLBACK says a consumer that connects first receives synthetic
  EventTrace events, then buffered ones. So do not read EventTrace/8 as "rundown complete"; and the first callback
  is the documented sign that the consumer is connected.
* ControlTrace docs size the properties buffer for QUERY/STOP/FLUSH with room for 1024-character session and log
  file names; the code passes only the struct plus the session name.

## Build

### NativeBackend

1. `start()` does StartTraceW and OpenTraceW only. A new `enable()` runs today's EnableTraceEx2 loop with the same
   results (DENIED on 5, ERROR with the code, STARTED) and its own `try/except (OSError, ValueError)` returning
   `StartResult("ERROR", ctypes.get_last_error())`. `enable()` never stops the session; its caller does.
2. `process()` records `process_entered` (monotonic) before ProcessTrace and `process_result = (rc, monotonic)`
   after it returns.
3. `_control_properties(guid)`: `sizeof(EVENT_TRACE_PROPERTIES)` + 2 × 1024 WCHAR, `LoggerNameOffset` and
   `LogFileNameOffset` set, session name copied. Use it for every ControlTraceW call (QUERY, FLUSH, STOP, and
   `cleanup_orphan`). StartTraceW keeps `_properties`.
4. `_stats(buf)` returns BufferSize, MinimumBuffers, MaximumBuffers, FlushTimer, NumberOfBuffers, FreeBuffers,
   BuffersWritten, EventsLost, RealTimeBuffersLost, LogBuffersLost. `stats()` is a QUERY that raises
   `OSError(rc, …)` on failure, as `loss()` does; `loss()` returns its three fields from `stats()`. `flush()`
   returns the rc of ControlTraceW code 3 (EVENT_TRACE_CONTROL_FLUSH), or -1 when not owned.
5. `stop()`: keep the props of the first STOP as `final_stats` (with `stop_rc`); a later STOP never overwrites it.
   Then, before CloseTrace, call `self.wait_consumer()` if it is set: CloseTrace docs say ProcessTrace receives
   nothing after CloseTrace, and ProcessTrace may take seconds to return after a stop.
6. `RawEvent` gets `cpu: int = -1` as its last field; `receive()` passes `record.BufferContext & 0xFFFF`
   (ETW_BUFFER_CONTEXT ProcessorIndex).

### Collector

7. `enable()` calls the backend's `enable()` when it has one, else returns STARTED. `start()` does not enable.
   After its consumer thread has started, `start()` sets `backend.wait_consumer` (only if the backend has that
   attribute) to a 3 s bounded join of that thread.
8. The aggregator drains until `_stop` is set **and** the consumer thread has ended **and** both queues are empty,
   so the stop burst is counted, not dropped. No loss queries after `_stop`.
9. `stop()` is idempotent under a lock (a second call returns at once) and sets `phase = "S"` when measuring.
   Keep one overall join budget (6 s); adjust `test_stop_shares_one_five_second_join_budget`.
10. `poll_loss`: a failed query increments a new `counters.query_failures` (part of `gap`), not `events_lost`.
    `EtwObserver._loss_total` drops `truncated`. Status adds `etw_truncated` and `etw_query_failures`.
11. Measurement inside `callback`, only while `self.phase` is not None, in its own `try/except` that counts
    `tally_errors`, and only after checking the payload is bytes. Per phase, count keys: the kind (`p<op>` process
    class or PROCESS_PROVIDER, `e<op>` EventTrace `68fdd900-4a3e-11d1-84f4-0000f80464e3`, `l<op>` RT_LostEvent
    `6a399ae0-4bc6-4de9-870b-3657f8947e7e`, `s` SystemConfig `01853a65-418f-4f36-aefc-dc0f1d2fd235`, `f` FileIo,
    `o` other); `trunc_<kind>`; `<kind>@<cpu>` for p1 and p3; `own_p3` (payload pid at offset 8 is the service);
    `child_p1`/`child_p2` (payload parent at offset 12 is the service: race-free, needs no stored pid); `ts_back`
    when the event timestamp is older than the newest delivered so far, with `ts_back_max_ms`; age buckets
    `age<1s`/`age<3s`/`age>=3s` (now as FILETIME minus the event timestamp: ProcessTrace converts to system time
    because RAW_TIMESTAMP is not set); `dcgap_sum_us` and `dcgap_max_ms` between consecutive DCStart callbacks.
    Keep the first-seen phase and `perf_counter` time of each child Start by pid (`kids`, at most 8). Update under a
    small lock; `measured()` returns a dict copy under the same lock. Cache `os.getpid()`.
12. `flush()` (rc's kept in a deque of 8), `session_stats()` (the stats dict, or `{"qrc": code}`), `lifecycle()`
    (consumer alive, process rc, entered and returned times), and `flush_every` seconds: when non-zero the
    aggregator flushes on that period (0 = off).

### EtwObserver

13. `_start`: create the collector with `phase = "P"` and start it inside `_lifecycle`; then, outside the lock, if
    the backend has `enable()`: wait up to 2 s, interruptible by `_stopping`, for the first callback; record the
    path (`callback` or `timeout`) and ms; log the connect line; set phase `W`; `collector.enable()`. A failed
    enable sets state `enable_<status>[_<code>]` and stops the collector. Backends without `enable()` (all test
    fakes) skip this with no wait.
14. `_check_schema` runs a fixed 7 s schedule from the enable whatever happens: child A at 0 (phase W), child B at
    3 s (phase B), FLUSH at 5 s and 6 s (phase F), end at 7 s. Read the clock once per iteration and test for a
    match before any phase change. A match is a Start in `_checking` whose pid is one of the children, whose parent
    is the service and whose image matches. Record the first phase that matched. Matched in W or B: pass. Matched
    only in F: pass with `flush_assist = True`; after the check the collector flushes every second. No match:
    `schema_process_mismatch` if a raw Start of either child arrived, else `no_start_events`. Both Popen objects in
    one `contextlib.ExitStack`. Sleep through a helper that measures lateness with `perf_counter` (sleeps, sleeps
    over 50 ms late, worst ms). `collector` may be None, as tests pass it.
15. Logging, WARNING, prefix `etw check:`, every call wrapped so a failure can never change the state or stop the
    collector:
    * `connect`: path, ms, callbacks, the number of running processes (`procwatch.windows_snapshot()`, a count
      only), session stats, phase P tallies;
    * `phase <X>` at the end of each phase: its tallies, cpu tallies, session stats, the sleep gauge, so a stop
      loses at most one phase;
    * `result`: pass / reason / interrupted, the pass phase, each child's seen phase and spawn-to-callback ms (or
      none), flush rc's, lifecycle, every loss counter separately, callbacks, queued, high water, max_delivery_ms,
      tally_errors;
    * after a failed or interrupted check, `stop`: phase S tallies, `final_stats`, lifecycle.
    After a pass set `collector.phase = None`: no tallies in normal operation.
16. `_log_check_failure` samples the service's own DCStart and raw Starts whose pid is a child (at most 2 in all);
    `_check_child` goes.
17. `status()` adds `etw_flush_assist`, `etw_check_phase`, `etw_truncated`, `etw_query_failures`.

Privacy: no pid, name, command line or payload of any process other than the service and its two children reaches
the log; counts only. Tests take no real seconds (patch the clock and sleep). Build payloads with test_svc17's
`process_payload`, which follows the captured layout.
