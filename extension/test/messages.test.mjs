import { test } from "node:test";
import assert from "node:assert/strict";
import { VALID, validPageSignals, PAGE_SIGNAL_IDS } from "../src/messages.js";

const ok = { id: "password_over_http", score: 25, detail: "trang yêu cầu mật khẩu qua kết nối không mã hoá" };

test("page_signals accepts what page_guard.js sends", () => {
  assert.ok(validPageSignals({ signals: [] }));
  assert.ok(validPageSignals({ signals: [ok, { id: "bare_login_page", score: 10, detail: "x" }] }));
});

test("page_signals rejects non-finite, fractional and out-of-range scores", () => {
  for (const score of [NaN, Infinity, -Infinity, -1, 41, 2.5, "25", null]) {
    assert.equal(validPageSignals({ signals: [{ ...ok, score }] }), false, `score ${score}`);
  }
});

test("page_signals rejects unknown ids, oversized fields and repeats", () => {
  assert.equal(validPageSignals({ signals: [{ ...ok, id: "made_up" }] }), false);
  assert.equal(validPageSignals({ signals: [{ ...ok, id: "x".repeat(10_000) }] }), false);
  assert.equal(validPageSignals({ signals: [{ ...ok, detail: "d".repeat(301) }] }), false);
  assert.equal(validPageSignals({ signals: [ok, ok] }), false);
  assert.equal(validPageSignals({ signals: Array(PAGE_SIGNAL_IDS.size + 1).fill(ok) }), false);
  assert.equal(validPageSignals({ signals: [null] }), false);
  assert.equal(validPageSignals({ signals: "nope" }), false);
});

test("other message shapes keep their checks", () => {
  assert.ok(VALID.trust_site({ host: "example.test" }));
  assert.equal(VALID.trust_site({ host: "Example.test/../x" }), false);
  assert.equal(VALID.set_enabled({ enabled: "yes" }), false);
  assert.equal(VALID.proceed({ url: "u".repeat(8000) }), false);
});
