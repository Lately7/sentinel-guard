import { test } from "node:test";
import assert from "node:assert/strict";
import { pageStatus } from "../src/page_status.js";

test("no reputation answer is never 'no problem found'", () => {
  assert.equal(pageStatus({}, 0).cls, "warn");
  assert.equal(pageStatus(undefined, 0).cls, "warn");
  assert.equal(pageStatus({ reputation: null }, 0).cls, "warn");
  assert.match(pageStatus({}, 0).text, /Chưa kiểm tra/);
});

test("pending navigation says checking", () => {
  assert.equal(pageStatus({ pending: true }, 0).text, "Đang kiểm tra…");
});

test("checked and not listed is ok", () => {
  assert.deepEqual(pageStatus({ reputation: { verdict: "unknown" } }, 5), { text: "Không phát hiện vấn đề", cls: "ok" });
});

test("listed, trusted and high-score pages keep their states", () => {
  assert.equal(pageStatus({ reputation: { verdict: "malicious", kind: "phishing", source: "openphish" } }, 0).cls, "bad");
  assert.equal(pageStatus({ reputation: { verdict: "allowed" } }, 90).cls, "muted");
  assert.equal(pageStatus({ total: 75 }, 0).cls, "bad");
  assert.equal(pageStatus({ total: 45, reputation: { verdict: "unknown" } }, 0).cls, "warn");
});
