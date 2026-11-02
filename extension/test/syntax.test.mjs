// Every extension script must parse as an ES module. Unit tests import only the
// pure modules, and `node --check file.js` does not use module grammar, so a
// syntax error in background.js once shipped unnoticed (RT-023 commit).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = new URL("../src/", import.meta.url);
const files = [];
for (const dir of ["", "content/"]) {
  for (const f of readdirSync(new URL(dir, SRC))) if (f.endsWith(".js")) files.push(dir + f);
}

for (const f of files) {
  test(`${f} parses`, () => {
    const code = readFileSync(new URL(f, SRC), "utf8");
    // Content scripts are classic scripts; everything else is a module.
    const type = f.startsWith("content/") ? "commonjs" : "module";
    const r = spawnSync(process.execPath, [`--input-type=${type}`, "--check"], { input: code, encoding: "utf8", shell: false });
    assert.equal(r.status, 0, `${join("src", f)}: ${r.stderr}`);
  });
}
