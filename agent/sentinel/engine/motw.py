"""Mark-of-the-Web: where a file was downloaded from.

Browsers write a `Zone.Identifier` alternate data stream on downloads. The
source URL lets a local file inherit a URL blocklist hit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Origin:
    zone: int | None
    host_url: str | None
    referrer_url: str | None

    @property
    def from_internet(self) -> bool:
        return self.zone is not None and self.zone >= 3


def read(path: str) -> Origin | None:
    if os.name != "nt":
        return None
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            text = f.read(8192)
    except OSError:
        return None
    zone = host = ref = None
    for line in text.splitlines():
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "zoneid":
            try:
                zone = int(value)
            except ValueError:
                pass
        elif key == "hosturl":
            host = value or None
        elif key == "referrerurl":
            ref = value or None
    return Origin(zone, host, ref)
