import { test } from "node:test";
import assert from "node:assert/strict";
import { buildBlockRules, buildAllowRules, CHUNK, ALLOW_BASE_ID } from "../src/rules.js";

test("block rules: one redirect + one block rule per chunk and kind", () => {
  const hosts = [];
  for (let i = 0; i < CHUNK + 10; i++) hosts.push([`h${i}.example`, "phishing"]);
  hosts.push(["m.example", "malware"]);
  const rules = buildBlockRules(hosts);
  assert.equal(rules.length, 6); // phishing: 2 chunks x 2, malware: 1 chunk x 2
  const ids = new Set(rules.map((r) => r.id));
  assert.equal(ids.size, rules.length);
  for (const r of rules) assert.ok(r.id < ALLOW_BASE_ID);
  const main = rules.filter((r) => r.condition.resourceTypes?.includes("main_frame"));
  assert.equal(main.length, 3);
  assert.ok(main.every((r) => r.action.type === "redirect" && r.condition.resourceTypes.length === 1));
  const block = rules.filter((r) => r.action.type === "block");
  assert.ok(block.every((r) => !r.condition.resourceTypes && r.condition.excludedResourceTypes.join() === "main_frame"));
});

test("block rules drop malformed entries and unknown kinds become custom", () => {
  const rules = buildBlockRules([["Bad Host!", "phishing"], ["nodot", "malware"], 5, ["ok.example", "weird"]]);
  assert.equal(rules.length, 2);
  assert.deepEqual(rules[0].condition.requestDomains, ["ok.example"]);
  assert.match(rules[0].action.redirect.extensionPath, /k=x$/);
});

test("allow rules outrank block rules", () => {
  const [r] = buildAllowRules(["trusted.example", "bad host"]);
  assert.equal(r.id, ALLOW_BASE_ID);
  assert.ok(r.priority > 1);
  // Scoped allow: a trusted page must not unblock the malware hosts it embeds.
  assert.equal(r.action.type, "allow");
  assert.deepEqual(r.condition.requestDomains, ["trusted.example"]);
});
