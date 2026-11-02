import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchAllowlist } from "../src/allowlist.js";
import { buildAllowRules, ALLOW_BASE_ID, ONCE_BASE_ID } from "../src/rules.js";

function agent(hosts, pageSize, versions = () => "7") {
  let calls = 0;
  const request = async (offset) => {
    calls++;
    return { allow_version: versions(calls), total: hosts.length, offset, hosts: hosts.slice(offset, offset + pageSize) };
  };
  return { request, calls: () => calls };
}

const many = (n) => Array.from({ length: n }, (_, i) => `site${String(i).padStart(5, "0")}.example`);

test("RT-021: every page of a large trusted list is fetched", async () => {
  const hosts = many(12001);
  const a = agent(hosts, 5000);
  const res = await fetchAllowlist(a.request);
  assert.deepEqual(res, { hosts, version: "7" });
  assert.equal(a.calls(), 3);
});

test("a list that changes mid-sync is fetched again from the start", async () => {
  const hosts = many(10);
  const a = agent(hosts, 4, (n) => (n === 2 ? "8" : n < 2 ? "7" : "8"));
  const res = await fetchAllowlist(a.request);
  assert.equal(res.version, "8");
  assert.deepEqual(res.hosts, hosts);
});

test("a list that never settles gives up instead of mixing versions", async () => {
  const a = agent(many(10), 4, (n) => String(n));
  assert.equal(await fetchAllowlist(a.request, 3), null);
});

test("an older agent without paging answers in one page", async () => {
  const res = await fetchAllowlist(async () => ({ allow_version: "3", hosts: ["a.example", 5, "b.example"] }));
  assert.deepEqual(res, { hosts: ["a.example", "b.example"], version: "3" });
});

test("RT-021: more than 5,000 trusted hosts all become allow rules", () => {
  const hosts = many(12001);
  const rules = buildAllowRules(hosts);
  const covered = rules.flatMap((r) => r.condition.requestDomains);
  assert.equal(covered.length, 12001);
  assert.ok(rules.every((r) => r.id >= ALLOW_BASE_ID && r.id < ONCE_BASE_ID));
  assert.ok(rules.length <= 5, "hosts are grouped, so the dynamic rule budget is not the limit");
});

test("malformed hosts are dropped so one bad entry cannot reject the whole rule update", () => {
  const rules = buildAllowRules(["ok.example", "", "a..b", ".lead", "trail.", "UPPER.example", "spa ce.example", "ok.example"]);
  assert.deepEqual(rules.flatMap((r) => r.condition.requestDomains), ["ok.example"]);
});
