import { test } from "node:test";
import assert from "node:assert/strict";
import { recordFailure, recordSuccess, refused, retryable, MAX_ATTEMPTS, MAX_PENDING } from "../src/pending.js";

const item = (id) => ({ id, path: `C:\\Users\\u\\Downloads\\f${id}.exe`, url: "https://example.test/f", name: `f${id}.exe` });

test("a failed scan stays pending and counts attempts", () => {
  let l = recordFailure([], item(1), new Error("agent offline"), 1000);
  l = recordFailure(l, item(1), "timeout", 2000);
  assert.equal(l.length, 1);
  assert.equal(l[0].attempts, 2);
  assert.equal(l[0].lastTry, 2000);
  assert.deepEqual(retryable(l).map((p) => p.id), [1]);
});

test("success removes the entry", () => {
  const l = recordFailure([], item(1), "x", 1);
  assert.deepEqual(recordSuccess(l, 1), []);
});

test("gives up after MAX_ATTEMPTS but keeps the record visible", () => {
  let l = [];
  for (let i = 0; i < MAX_ATTEMPTS; i++) l = recordFailure(l, item(7), "x", i);
  assert.equal(l.length, 1);
  assert.ok(l[0].gaveUp);
  assert.deepEqual(retryable(l), []);
});

test("list is bounded, oldest dropped first", () => {
  let l = [];
  for (let i = 0; i < MAX_PENDING + 5; i++) l = recordFailure(l, item(i), "x", i);
  assert.equal(l.length, MAX_PENDING);
  assert.equal(l[0].id, 5);
});

test("a refusal is an answer, a lost agent is not", () => {
  assert.equal(refused(new Error("not approved")), true);
  assert.equal(refused(new Error("disconnected")), false);
  assert.equal(refused(undefined), false);
});
