"""Native messaging framing and hostile JSON, all in memory."""

from __future__ import annotations

import io
import json
import struct

import pytest

from sentinel import nativehost


class SplitReader(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(min(size, 1) if size >= 0 else 1)


def frame(body: bytes) -> bytes:
    return struct.pack("<I", len(body)) + body


def test_every_frame_byte_can_arrive_separately() -> None:
    # R11 invariant 8: a fragmented pipe cannot desynchronise consecutive messages.
    stream = SplitReader(frame(b'{"type":"hello","id":1}') + frame(b'{"type":"hello","id":2}'))
    assert nativehost.read_message(stream) == {"type": "hello", "id": 1}
    assert nativehost.read_message(stream) == {"type": "hello", "id": 2}


@pytest.mark.parametrize("size", [0, 1, nativehost.MAX_IN - 1, nativehost.MAX_IN, nativehost.MAX_IN + 1])
def test_frame_length_boundary(size: int) -> None:
    # R11 invariant 8: the 1 MiB input cap is exact, including a one-byte excess.
    body = b" " * size
    stream = io.BytesIO(frame(body) + frame(b"{}"))
    message = nativehost.read_message(stream)
    expected = {"type": "__too_large__"} if size > nativehost.MAX_IN else {"type": "__bad_json__"}
    assert message == expected
    assert nativehost.read_message(stream) == {}


def test_invalid_utf8_is_typed_bad_json() -> None:
    # R11 invariant 7: malformed input never escapes the native-host parser.
    assert nativehost.read_message(io.BytesIO(frame(b'{"type":"\xff"}'))) == {"type": "__bad_json__"}


def test_deep_json_nesting_is_typed_bad_json() -> None:
    # R11 invariant 8: deep nesting must fail within the frame bound.
    body = b"[" * 2000 + b"0" + b"]" * 2000
    assert nativehost.read_message(io.BytesIO(frame(body))) == {"type": "__bad_json__"}


def test_huge_json_integer_is_typed_bad_json() -> None:
    # R11 invariant 8: numeric tokens cannot cause unbounded parser work.
    body = b'{"id":' + b"9" * 100_000 + b',"type":"hello"}'
    assert nativehost.read_message(io.BytesIO(frame(body))) == {"type": "__bad_json__"}


def test_surrogate_escaped_download_path_returns_error() -> None:
    # R11 invariant 7: malformed path text becomes a request error, never a host crash.
    host = nativehost.Host.__new__(nativehost.Host)
    message = json.loads(r'{"type":"scan_download","path":"C:\\bad\ud800.txt"}')
    response = host.handle(message)
    assert response["ok"] is False


def test_truncated_large_frame_terminates_without_allocation() -> None:
    # R11 invariant 8: a 4 GiB claim with a closed pipe ends promptly.
    stream = io.BytesIO(struct.pack("<I", 0xffffffff) + b"short")
    assert nativehost.read_message(stream) is None
