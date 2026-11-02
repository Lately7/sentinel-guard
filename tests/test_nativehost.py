"""Native-messaging framing (RT-006) and caller-origin check (RT-019)."""

from __future__ import annotations

import io
import json
import struct

from sentinel import config
from sentinel.nativehost import origin_allowed, read_message


class TrickleStream(io.RawIOBase):
    """Hands back at most `chunk` bytes per read, as a pipe may."""

    def __init__(self, data: bytes, chunk: int) -> None:
        self.buf = io.BytesIO(data)
        self.chunk = chunk

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        return self.buf.read(min(self.chunk, n if n >= 0 else self.chunk))


def frame(obj: object) -> bytes:
    body = json.dumps(obj).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def test_short_reads_are_joined_into_whole_frames():
    msgs = [{"id": 1, "type": "hello"}, {"id": 2, "type": "check_url", "url": "https://example.test/" + "a" * 500}]
    stream = TrickleStream(b"".join(frame(m) for m in msgs), chunk=3)
    assert [read_message(stream), read_message(stream), read_message(stream)] == [*msgs, None]


def test_stream_ending_mid_frame_is_end_of_input():
    data = frame({"id": 1, "type": "hello"})
    assert read_message(TrickleStream(data[:-2], chunk=5)) is None
    assert read_message(TrickleStream(data[:3], chunk=5)) is None


def test_oversized_frame_is_drained_and_framing_continues(monkeypatch):
    from sentinel import nativehost

    monkeypatch.setattr(nativehost, "MAX_IN", 16)
    big = frame({"id": 1, "pad": "x" * 100})
    stream = TrickleStream(big + frame({"id": 2}), chunk=7)
    assert read_message(stream) == {"type": "__too_large__"}
    assert read_message(stream) == {"id": 2}


def test_only_our_extension_origin_is_accepted():
    ours = f"chrome-extension://{config.EXTENSION_ID}/"
    assert origin_allowed([ours, "--parent-window=0"])
    assert not origin_allowed(["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"])
    assert not origin_allowed([])  # started by hand: no origin
    assert not origin_allowed(["--parent-window=0"])
    assert origin_allowed(["--diagnostic"])
