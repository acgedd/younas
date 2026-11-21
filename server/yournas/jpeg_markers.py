"""The one file format the server reads: the JPEG thumbnail a client sends (docs/SECURITY.md §6).

A crafted small JPEG decodes on folder open with no tap, so a thumbnail is checked before anyone
else's phone sees it. This walks the marker structure of a byte string and nothing else: no I/O, no
pixel is ever decoded, and the entropy-coded data is only searched for the next marker.

Accepted: SOI, then segments, then EOI as the very last two bytes, with exactly one 8-bit baseline
SOF0 whose sides are both 1 to 512. Everything the walker does not know is refused, so progressive,
arithmetic, 12-bit and lossless files, a second image, bytes after EOI and marker fill bytes all
fail. The result has every APPn (APP0 included) and COM removed, so what is stored is only DQT,
DHT, SOF0, DRI, SOS and the scan data between SOI and EOI: a client's promise to strip location
data is not relied on, and APP0 cannot carry up to 64 KiB of anything (or a JFXX thumbnail). A
JPEG without the JFIF APP0 decodes the same everywhere.
"""

from __future__ import annotations

MAX_SIDE = 512

_PREFIX = 0xFF
_STUFFED = 0x00
_SOF0 = 0xC0
_DHT = 0xC4
_RST0 = 0xD0
_RST7 = 0xD7
_SOI = 0xD8
_EOI = 0xD9
_SOS = 0xDA
_DQT = 0xDB
_DRI = 0xDD
_APP0 = 0xE0
_APP15 = 0xEF
_COM = 0xFE
_SOI_BYTES = bytes((_PREFIX, _SOI))
_EOI_BYTES = bytes((_PREFIX, _EOI))
_KEPT = frozenset((_DQT, _DHT, _DRI))
_STRIPPED = frozenset((*range(_APP0, _APP15 + 1), _COM))


class InvalidJpeg(ValueError):
    """The bytes are not an acceptable thumbnail. The message is a fixed reason code; `marker` is
    the refused marker byte for "marker-not-allowed" (0xC2 is a progressive frame), for logs."""

    def __init__(self, reason: str, marker: int | None = None) -> None:
        super().__init__(reason)
        self.marker = marker


def _check_frame(payload: bytes) -> int:
    """Check a SOF0 payload and return its number of components."""
    if len(payload) < 6:
        raise InvalidJpeg("short-frame")
    precision = payload[0]
    height = int.from_bytes(payload[1:3], "big")
    width = int.from_bytes(payload[3:5], "big")
    components = payload[5]
    if precision != 8:
        raise InvalidJpeg("not-8-bit")
    if not (1 <= height <= MAX_SIDE and 1 <= width <= MAX_SIDE):
        raise InvalidJpeg("bad-dimensions")
    if not 1 <= components <= 4 or len(payload) != 6 + 3 * components:
        raise InvalidJpeg("bad-frame")
    return components


def _check_scan(payload: bytes, components: int) -> None:
    """Check a SOS payload: baseline parameters and no more parts than the frame has."""
    if not payload or not 1 <= payload[0] <= components:
        raise InvalidJpeg("bad-scan")
    parts = payload[0]
    if len(payload) != 1 + 2 * parts + 3 or payload[-3:] != b"\x00\x3f\x00":
        raise InvalidJpeg("bad-scan")


def _end_of_scan(data: bytes, start: int) -> int:
    """Offset of the first marker after entropy-coded data: past stuffed bytes and restarts."""
    pos = start
    while True:
        found = data.find(_PREFIX, pos)
        if found < 0 or found + 1 >= len(data):
            raise InvalidJpeg("truncated-scan")
        following = data[found + 1]
        if following != _STUFFED and not _RST0 <= following <= _RST7:
            return found
        pos = found + 2


def sanitize(data: bytes) -> bytes:
    """The thumbnail as it should be stored, or InvalidJpeg if the walk cannot finish cleanly."""
    if data[:2] != _SOI_BYTES:
        raise InvalidJpeg("no-soi")
    kept = [_SOI_BYTES]
    pos = 2
    components = 0
    scans = 0
    while True:
        if pos + 2 > len(data):
            raise InvalidJpeg("truncated")
        if data[pos] != _PREFIX:
            raise InvalidJpeg("expected-marker")
        marker = data[pos + 1]
        if marker == _EOI:
            if not scans:
                raise InvalidJpeg("no-scan")
            if pos + 2 != len(data):
                raise InvalidJpeg("bytes-after-eoi")
            kept.append(_EOI_BYTES)
            return b"".join(kept)
        if marker not in _KEPT and marker not in _STRIPPED and marker not in (_SOF0, _SOS):
            raise InvalidJpeg("marker-not-allowed", marker)
        if pos + 4 > len(data):
            raise InvalidJpeg("truncated")
        length = int.from_bytes(data[pos + 2 : pos + 4], "big")
        end = pos + 2 + length
        if length < 2 or end > len(data):
            raise InvalidJpeg("bad-segment-length")
        payload = data[pos + 4 : end]
        if marker == _SOF0:
            if components:
                raise InvalidJpeg("second-frame")
            components = _check_frame(payload)
        elif marker == _SOS:
            if not components:
                raise InvalidJpeg("scan-before-frame")
            _check_scan(payload, components)
            scans += 1
            # In a sequential JPEG every component is in exactly one scan.
            if scans > components:
                raise InvalidJpeg("too-many-scans")
            end = _end_of_scan(data, end)
        if marker not in _STRIPPED:
            kept.append(data[pos:end])
        pos = end
