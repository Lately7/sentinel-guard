// Fetches the agent's trusted-site list page by page (RT-021: it used to stop
// silently at 5,000 hosts). Pure apart from the injected request function, so
// it is unit-tested without a browser.

/**
 * request(offset) -> {allow_version, total?, hosts}. Returns {hosts, version},
 * or null when the list kept changing between pages on every attempt.
 */
export async function fetchAllowlist(request, attempts = 3) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    const hosts = [];
    let version;
    let offset = 0;
    let mixed = false;
    for (;;) {
      const page = await request(offset);
      // All pages must come from one version, or a site removed in the app
      // could survive (or a new one go missing) in the merged list.
      if (version === undefined) version = page.allow_version;
      else if (page.allow_version !== version) {
        mixed = true;
        break;
      }
      const raw = Array.isArray(page.hosts) ? page.hosts : [];
      hosts.push(...raw.filter((h) => typeof h === "string"));
      offset += raw.length;
      // An agent from before paging sends one page without a total.
      const total = Number.isInteger(page.total) ? page.total : offset;
      if (!raw.length || offset >= total) break;
    }
    if (!mixed) return { hosts, version };
  }
  return null;
}
