// Downloads the agent has not checked yet. A completed download whose scan
// request failed (agent offline, timeout) stays here and is retried, so it is
// never counted or shown as "scanned" when nothing looked at it.

export const MAX_PENDING = 50;
export const MAX_ATTEMPTS = 5;

/** Record a failed attempt; returns the new list. Oldest entries go first when full. */
export function recordFailure(list, item, error, now) {
  const prev = list.find((p) => p.id === item.id);
  const attempts = (prev?.attempts || 0) + 1;
  const rest = list.filter((p) => p.id !== item.id);
  const entry = { ...item, attempts, lastError: String(error).slice(0, 200), lastTry: now, gaveUp: attempts >= MAX_ATTEMPTS };
  return [...rest, entry].slice(-MAX_PENDING);
}

export function recordSuccess(list, id) {
  return list.filter((p) => p.id !== id);
}

/** Entries still worth retrying. */
export function retryable(list) {
  return list.filter((p) => !p.gaveUp);
}

// A confirmation may wait on an administrator; the native host gives up first.
export const APPROVAL_MS = 180000;

/** The agent answered and the answer was no, as opposed to no answer at all. */
export function refused(error) {
  return error?.message === "not approved";
}
