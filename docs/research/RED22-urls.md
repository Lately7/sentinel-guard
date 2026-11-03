# RED22 — URL, host, and domain handling

No network, installed service, or pytest run was used. The five regression tests use the isolated `db`, `tmp_path`, and `sentinel_home` fixtures. Browser behavior described below is the expected Chromium URL serialization; the in-process tests prove the agent and feed-side decisions.

## High — A public suffix can be trusted as one site

**Test:** `test_red22_public_suffix_cannot_be_trusted_as_site` (proven in the native-host fallback and URL checker; service approval path inferred from its validator).

**Attacker model and steps:** A medium-integrity user requests permanent trust for `co.uk` while the service is absent, or asks an administrator to approve that same host when it is running. The trust prompt describes one website. The requester then visits an unrelated blocked `attacker.example.co.uk` site. `on_allow_host` accepts `co.uk`; the service's `_host` validator also accepts it; `parent_hosts` reaches `co.uk`; `check` returns `allowed` before consulting the blocklist. The extension's `requestDomains` allow rule also covers descendants.

**Effect:** A trust grant for a public suffix suppresses protection across unrelated registrants under that suffix.

**Lines:** `agent/sentinel/nativehost.py:191-205`; `agent/sentinel/service/backend.py:597-599,630-635,684-691`; `agent/sentinel/urlintel.py:61-66,102-113`; `extension/src/rules.js:72-86`.

**Proposed fix:** Reject public suffixes in both trust entry points, including private suffixes such as `github.io` and `pages.dev`, using a maintained public-suffix source. Show the exact scope of any trust grant in the approval text.

## Medium — Trust for one host exempts a blocked descendant

**Test:** `test_red22_trust_exact_host_does_not_exempt_blocked_descendant` (proven).

**Attacker model and steps:** A user trusts `trusted.example`; an attacker controls or compromises `attacker.trusted.example`, which is already in the host blocklist. The URL checker checks allowed parent hosts first and returns `allowed`. The extension's local allow check and DNR allow rule also match descendants.

**Effect:** The blocked descendant is treated as trusted even though only `trusted.example` was approved. This matters for sites with user-controlled subdomains or a compromised subdomain.

**Lines:** `agent/sentinel/urlintel.py:61-66,102-113`; `extension/src/background.js:73-75,259-267`; `extension/src/rules.js:72-86`; `agent/sentinel/service/backend.py:597-599`.

**Proposed fix:** Make permanent trust exact-host by default in the agent, extension, and DNR rules. If subdomain trust is offered, require a separate explicit choice and display its scope.

## Medium — Unicode URL indicators do not match punycode browser URLs

**Test:** `test_red22_idn_feed_url_matches_browser_host` (agent mismatch proven; Chromium-to-agent path inferred).

**Attacker model and steps:** A phishing feed lists `https://bücher.example/landing`. Feed parsing stores that Unicode spelling. Chromium serializes the same navigated host as `xn--bcher-kva.example` and sends that URL through the extension. `normalize_url` lowercases the host but does no IDNA conversion, so the exact URL lookup misses; there is no host entry for this URL-only fixture.

**Effect:** A listed phishing URL can receive `unknown` reputation in the browser.

**Lines:** `agent/sentinel/feeds.py:78-82`; `agent/sentinel/urlintel.py:28-42,94-113`; `agent/sentinel/db.py:402-406,464-465`; `extension/src/background.js:250-267`.

**Proposed fix:** Convert hosts to the same ASCII IDNA form when ingesting feeds and checking URLs. Apply the canonicalizer to host indicators and trust decisions too.

## Medium — Numeric IPv4 URL indicators do not match browser URLs

**Test:** `test_red22_decimal_ipv4_feed_url_matches_browser_host` (agent mismatch proven; Chromium-to-agent path inferred).

**Attacker model and steps:** A malicious URL feed lists `http://2130706433/landing`, a decimal spelling of `127.0.0.1`. Feed parsing keeps the decimal host. Chromium serializes a navigation to the dotted IPv4 host, which the extension passes to the agent. The agent's exact URL lookup misses. Equivalent octal and hexadecimal IPv4 spellings have the same class of mismatch.

**Effect:** URL-level reputation can report `unknown` for a listed numeric-address URL. The extension also exempts `127.0.0.1` from heuristic scoring.

**Lines:** `agent/sentinel/feeds.py:78-82`; `agent/sentinel/urlintel.py:28-42,94-113`; `extension/src/background.js:250-267`; `extension/src/url_heuristics.js:97-105`.

**Proposed fix:** Canonicalize browser-supported numeric IPv4 spellings to dotted decimal before storing and looking up URL indicators; use the same host representation at every boundary.

## Medium — Shared-platform tenant hosts are dropped from host feeds

**Test:** `test_red22_shared_platform_tenant_host_is_kept` (proven for feed parsing and resulting lookup).

**Attacker model and steps:** A malicious tenant operates `attacker.pages.dev`; a host feed lists that exact hostname. `parse_hosts` treats every descendant of `pages.dev` as an indivisible shared platform and skips it. No host indicator reaches the database.

**Effect:** A feed's specific malicious tenant hostname is silently lost, although blocking that tenant would leave other tenants unaffected.

**Lines:** `agent/sentinel/urlintel.py:12-24,61-66,90-91`; `agent/sentinel/feeds.py:85-95`; `agent/sentinel/urlintel.py:110-113`.

**Proposed fix:** Exclude a shared platform's apex or genuinely shared serving hosts, but retain exact tenant subdomains from host feeds. Use public-suffix or provider-specific tenant boundaries when deciding whether a host has independent ownership.

## Other probes

The URL path uses `urllib.parse.urlsplit` (`urlintel.py:28-50`) while the extension uses `new URL` (`extension/src/background.js:65-70`), so percent-encoded authorities and backslashes merit a browser integration test. No finding is asserted here without an observed browser-to-agent mismatch. Trailing dots are removed by the agent (`urlintel.py:36,50`), while extension host extraction retains the browser's spelling (`background.js:65-75`); that could make a trusted trailing-dot host behave differently, but does not show a protection bypass in these tests. Userinfo and ports are parsed by `urlsplit` (`urlintel.py:31-42`); IPv6 literals are recognized by `is_ip` (`urlintel.py:53-58`) but `normalize_url` removes their brackets when rebuilding the URL (`urlintel.py:36-42`). Very long labels are limited by the native-host trust request (`nativehost.py:191-196`) but not by reputation normalization. The hand-written public-suffix approximation (`urlintel.py:69-87`, `extension/src/url_heuristics.js:4-15,50-59`) is not sufficient as a trust boundary, as the `co.uk` test shows.
