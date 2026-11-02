# TASKS.md

## Milestone 1 — working agent + extension

Acceptance:

* `python -m sentinel scan <path>` prints a verdict per file; exit code 2 if
  anything is malicious, 1 if suspicious, 0 otherwise.
* Real-time watcher scans new/changed files in the watched folders and
  quarantines `malicious` ones; quarantine can be listed and restored.
* Feeds (MalwareBazaar hashes, URLhaus, OpenPhish, crypto-miner hosts) update
  into the local SQLite DB; failures of one feed don't stop the others.
* Extension (Helium/Chrome/Edge) blocks blocklisted domains for every request
  type, warns on risky top-level URLs, sends finished downloads to the agent.
* `pytest` and `node --test extension/test/` pass.

## Codex tasks

### C1 — URL risk heuristics (`extension/src/url_heuristics.js`)

Files Codex may create/change: `extension/src/url_heuristics.js`,
`extension/test/url_heuristics.test.mjs`. Everything else is read-only.

Contract (ES module, no `chrome.*`, no network, no dependencies):

```js
export function scoreUrl(url /* string */) /* -> { score: 0..100, reasons: [{id, score, detail}] } */
export function registrableDomain(hostname /* string */) /* -> string */
```

* Invalid URLs, `chrome:`, `about:`, `chrome-extension:`, `file:` → score 0.
* Structural signals only (examples): raw IPv4/IPv6 host, punycode (`xn--`)
  labels, mixed-script hostnames, very long hostname or many subdomain levels,
  `@` userinfo in the URL, non-default port on http(s), plain `http:` for a
  page whose path looks like a login, a well-known brand name appearing in a
  subdomain/path while the registrable domain is a different one (small
  built-in brand list: paypal, apple, microsoft, google, facebook, amazon,
  netflix, binance, metamask, vietcombank, techcombank, mbbank, momo, zalo,
  shopee), lookalike of those brands by edit distance 1 in the registrable
  label.
* Heuristics alone must stay below 70 for every URL in the test's list of
  popular legitimate sites (include at least 40, e.g. google.com,
  accounts.google.com, login.microsoftonline.com, github.com, vnexpress.net,
  shopee.vn, momo.vn, vietcombank.com.vn, paypal.com, localhost:3000 ...).
* `registrableDomain` handles common multi-part suffixes (co.uk, com.vn,
  edu.vn, gov.vn, net.vn, org.vn, com.au, co.jp, com.br ...) without a full
  public-suffix list.
* Tests use `node:test` and `node:assert/strict`.

### C2 — file type identification (`agent/sentinel/engine/filetype.py`)

Files Codex may create/change: `agent/sentinel/engine/filetype.py`,
`tests/test_filetype.py`. Everything else is read-only.

Contract (stdlib only):

```python
def sniff(head: bytes) -> str          # "pe", "elf", "macho", "zip", "ole", "pdf", "rar", "7z", "gzip", "lnk", "script", "text", "image", "unknown"
def check_name(name: str, head: bytes) -> list[Finding]   # Finding from engine/verdict.py
```

`check_name` reports, with `engine="filetype"`:

* `filetype.double_extension` (MEDIUM, 25): a document/image/media extension
  followed by an executable or script extension (`invoice.pdf.exe`), including
  when padded with spaces before the last dot.
* `filetype.rtlo` (HIGH, 40): name contains U+202E or other bidi overrides.
* `filetype.mismatch` (MEDIUM, 25): content is `pe` but the extension is a
  document/image/media extension.
* `filetype.executable` (INFO, 0): content is `pe`/`lnk`/`script` (context
  only).

Never raises on any input; tests cover empty input and random bytes.

## Codex log

(Claude fills this in after reviewing each task.)
