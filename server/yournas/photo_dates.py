"""The date a photo was taken, read from the first bytes of the file (docs/MONTHS-SPEC.md).

The second, narrow exception to "the server never interprets file contents" (docs/SECURITY.md §6):
the owner answered "可以，只讀日期（建議）". Only the date-taken field is read. Nothing else
from a file (place, camera, names, XMP) is looked at or kept, and no string from a file leaves
this module: the result is a number of wall-clock seconds.

Pure: no I/O. The caller hands over `read_at(offset, n)`, a reader that enforces its own budget
(storage.photo_scan: 256 KiB and 32 reads per file) and returns at most `n` bytes. Every size a
file declares is checked against fixed limits before it is used, nothing is allocated from one,
and every loop has a hard iteration cap, so a hostile file costs at most a few reads.

Any limit hit, any malformed structure and any unexpected value raise `NoDate`, which `examine`
turns into "no date". Two things pass through unchanged: what the reader itself raises for a read
that failed (the storage reader raises a StorageError; a failed read is not a missing date, the
caller counts it as unreadable), and an exception of a type the parser does not expect (a bug, not
ValueError/IndexError/OverflowError/TypeError), which the caller treats as a failed job.
"""

from __future__ import annotations

import calendar
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal

# Stored with every row: a better parser later re-reads the files the old one indexed.
PARSER_VERSION = 1

ReadAt = Callable[[int, int], bytes]

KIB = 1024
HEAD_BYTES = 4 * KIB  # what `sniff` needs, and the size of one read window
EXIF_MAX = 64 * KIB
JPEG_MAX_OFFSET = 1024 * KIB
JPEG_MAX_SEGMENTS = 64
JPEG_MAX_FILL = 7
HEIF_FTYP_MAX = 4 * KIB
HEIF_MAX_TOP_BOXES = 16
HEIF_MAX_META_BOXES = 64
HEIF_META_MAX = 256 * KIB
HEIF_MAX_ENTRIES = 4096  # infe entries, iloc items, iloc extents (counted by iterations)
PNG_MAX_CHUNKS = 64
WEBP_MAX_CHUNKS = 64
TIFF_MAX_ENTRIES = 512
DATE_MIN_COUNT = 19
DATE_MAX_COUNT = 32
FUTURE_SLACK_SECONDS = 2 * 86400

_HEIF_BRANDS = frozenset((b"heic", b"heix", b"heim", b"heis", b"hevc", b"mif1", b"msf1"))
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_EXIF_PREFIX = b"Exif\x00\x00"
_DATE = re.compile(rb"([0-9]{4}):([0-9]{2}):([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2})")
_TAG_EXIF_IFD = 0x8769
_TAG_DATE_ORIGINAL = 0x9003
_TAG_DATE_DIGITIZED = 0x9004
_TYPE_ASCII = 2
_TYPE_LONG = 4
_TYPE_IFD = 13
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# Markers that end the search: SOI again, EOI, SOS, a stray 0x00, and every SOFn frame.
_JPEG_STOP = frozenset(
    (0xD8, 0xD9, 0xDA, 0x00, *(m for m in range(0xC0, 0xD0) if m not in (0xC4, 0xC8, 0xCC)))
)
Order = Literal["little", "big"]


class NoDate(Exception):
    """No usable date. The message is a fixed reason code, never anything from the file."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- reading


class _Source:
    """Exact reads over `read_at`, served from one cached window, so walking small headers does
    not spend a read per header. Every offset is checked against the file size first."""

    def __init__(self, read_at: ReadAt, size: int, head: bytes = b"") -> None:
        self._read_at = read_at
        self.size = size
        self._start = 0
        self._buf = head

    def get(self, offset: int, n: int) -> bytes:
        if offset < 0 or n < 0 or offset + n > self.size:
            raise NoDate("out-of-range")
        start = self._start
        if start <= offset and offset + n <= start + len(self._buf):
            return self._buf[offset - start : offset - start + n]
        want = min(max(n, HEAD_BYTES), self.size - offset)
        data = self._read_at(offset, want)
        if len(data) < n:
            raise NoDate("short-read")
        self._start, self._buf = offset, data
        return data[:n]


def _u16(data: bytes, at: int, order: Order = "big") -> int:
    return int.from_bytes(data[at : at + 2], order)


def _u32(data: bytes, at: int, order: Order = "big") -> int:
    return int.from_bytes(data[at : at + 4], order)


# --------------------------------------------------------------------------- format


def sniff(head: bytes) -> str | None:
    """The photo format of a file from its first bytes (at most 4 KiB): 'jpeg', 'heif', 'png',
    'webp', 'gif', or None for anything else. By content, never by name."""
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if head[:8] == _PNG_SIGNATURE:
        return "png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if _is_heif(head):
        return "heif"
    return None


def _is_heif(head: bytes) -> bool:
    if len(head) < 16 or head[4:8] != b"ftyp":
        return False
    size = _u32(head, 0)
    if size < 16 or size > HEIF_FTYP_MAX or size > len(head) or size % 4:
        return False
    brands = [head[8:12]] + [head[i : i + 4] for i in range(16, size, 4)]
    return any(brand in _HEIF_BRANDS for brand in brands)


# --------------------------------------------------------------------------- the date itself


def _year_of(seconds: float) -> int:
    return (_EPOCH + timedelta(seconds=seconds)).year


def wall_seconds_to_month(seconds: int) -> str:
    """'YYYY-MM' of a wall-clock time given as seconds since 1970-01-01 00:00 (no zone)."""
    moment = _EPOCH + timedelta(seconds=seconds)
    return f"{moment.year:04d}-{moment.month:02d}"


def wall_seconds_to_iso(seconds: int) -> str:
    """'YYYY-MM-DDTHH:MM:SS' of a wall-clock time, without a zone (none is known)."""
    return (_EPOCH + timedelta(seconds=seconds)).replace(tzinfo=None).isoformat(timespec="seconds")


def parse_date(raw: bytes, *, now: float) -> int:
    """An Exif ASCII date as wall-clock seconds, with every field checked by integer arithmetic
    (no strptime, no time zone). The month is the one recorded; OffsetTime is never applied."""
    text = raw.rstrip(b"\x00")
    if any(not 0x20 <= byte <= 0x7E for byte in text):
        raise NoDate("date-not-ascii")
    m = _DATE.match(text)
    if m is None:
        raise NoDate("date-format")
    year, month, day, hour, minute, second = (int(g) for g in m.groups())
    if not 1900 <= year <= _year_of(now) + 1:
        raise NoDate("date-year")
    if not 1 <= month <= 12:
        raise NoDate("date-month")
    if not 1 <= day <= calendar.monthrange(year, month)[1]:
        raise NoDate("date-day")
    if hour > 23 or minute > 59 or second > 59:
        raise NoDate("date-time")
    seconds = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    if seconds > now + FUTURE_SLACK_SECONDS:
        raise NoDate("date-future")
    return seconds


# --------------------------------------------------------------------------- TIFF / Exif


def _ifd(blob: bytes, offset: int, order: Order) -> dict[int, tuple[int, int, bytes]]:
    """The entries of one IFD: tag -> (type, count, the 4 value bytes). The first entry of a tag
    wins. The whole table must fit in the blob."""
    if offset < 8 or offset + 2 > len(blob):
        raise NoDate("ifd-offset")
    count = _u16(blob, offset, order)
    if count > TIFF_MAX_ENTRIES or offset + 2 + 12 * count > len(blob):
        raise NoDate("ifd-size")
    entries: dict[int, tuple[int, int, bytes]] = {}
    for i in range(count):
        at = offset + 2 + 12 * i
        tag = _u16(blob, at, order)
        if tag not in entries:
            kind, count = _u16(blob, at + 2, order), _u32(blob, at + 4, order)
            entries[tag] = (kind, count, blob[at + 8 : at + 12])
    return entries


def tiff_date(blob: bytes, *, now: float) -> int:
    """DateTimeOriginal, else DateTimeDigitized, from the Exif IFD of a TIFF structure held in
    memory (at most 64 KiB). IFD0 is read only for the pointer to the Exif IFD: never IFD1, GPS,
    Interop, MakerNote or DateTime (0x0132)."""
    if len(blob) < 8:
        raise NoDate("tiff-short")
    order: Order
    if blob[:2] == b"II":
        order = "little"
    elif blob[:2] == b"MM":
        order = "big"
    else:
        raise NoDate("tiff-order")
    if _u16(blob, 2, order) != 42:
        raise NoDate("tiff-magic")
    ifd0 = _u32(blob, 4, order)
    visited = {ifd0}
    pointer = _ifd(blob, ifd0, order).get(_TAG_EXIF_IFD)
    if pointer is None:
        raise NoDate("no-exif-ifd")
    kind, count, value = pointer
    if kind not in (_TYPE_LONG, _TYPE_IFD) or count != 1:
        raise NoDate("exif-pointer")
    exif_ifd = int.from_bytes(value, order)
    if exif_ifd in visited:
        raise NoDate("ifd-loop")
    entries = _ifd(blob, exif_ifd, order)
    for tag in (_TAG_DATE_ORIGINAL, _TAG_DATE_DIGITIZED):
        entry = entries.get(tag)
        if entry is None:
            continue
        kind, count, value = entry
        if kind != _TYPE_ASCII or not DATE_MIN_COUNT <= count <= DATE_MAX_COUNT:
            continue
        at = int.from_bytes(value, order)
        if at + count > len(blob):
            continue
        try:
            return parse_date(blob[at : at + count], now=now)
        except NoDate:
            continue
    raise NoDate("no-date-tag")


def _exif_payload(blob: bytes, *, now: float) -> int:
    """An Exif block with or without the `Exif\\0\\0` prefix."""
    if blob.startswith(_EXIF_PREFIX):
        blob = blob[len(_EXIF_PREFIX) :]
    return tiff_date(blob, now=now)


# --------------------------------------------------------------------------- JPEG


def _jpeg(src: _Source, *, now: float) -> int:
    pos = 2
    segments = 0
    limit = min(src.size, JPEG_MAX_OFFSET)
    while True:
        if pos + 2 > limit:
            raise NoDate("jpeg-end")
        if src.get(pos, 1)[0] != 0xFF:
            raise NoDate("jpeg-marker")
        fills = 0
        while src.get(pos + 1, 1)[0] == 0xFF:  # fill bytes before the marker
            fills += 1
            if fills > JPEG_MAX_FILL:
                raise NoDate("jpeg-fill")
            pos += 1
            if pos + 2 > limit:
                raise NoDate("jpeg-end")
        marker = src.get(pos + 1, 1)[0]
        pos += 2
        segments += 1
        if segments > JPEG_MAX_SEGMENTS:
            raise NoDate("jpeg-segments")
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:  # RSTn and TEM carry no length
            continue
        if marker in _JPEG_STOP:
            raise NoDate("jpeg-no-exif")  # SOI again, EOI, SOS, a frame: no Exif before the image
        if pos + 2 > limit:
            raise NoDate("jpeg-end")
        length = _u16(src.get(pos, 2), 0)
        if length < 2:
            raise NoDate("jpeg-length")
        if (
            marker == 0xE1
            and length >= 2 + len(_EXIF_PREFIX)
            and pos + length <= src.size
            and src.get(pos + 2, len(_EXIF_PREFIX)) == _EXIF_PREFIX
        ):
            # The first Exif APP1 is the only one looked at (at most 65,533 bytes).
            body = length - 2 - len(_EXIF_PREFIX)
            return tiff_date(src.get(pos + 2 + len(_EXIF_PREFIX), body), now=now)
        pos += length


# --------------------------------------------------------------------------- HEIF


class _Box:
    __slots__ = ("type", "start", "body", "end")

    def __init__(self, kind: bytes, start: int, body: int, end: int) -> None:
        self.type = kind
        self.start = start
        self.body = body  # first byte after the header
        self.end = end


def _box(src: _Source, pos: int, parent_end: int, *, top: bool) -> _Box:
    """The box at `pos`. Size 1 means a 64-bit size follows; size 0 (to the end of the file) only
    for a top-level box; anything else must hold its header and fit in its parent."""
    if pos + 8 > parent_end:
        raise NoDate("box-header")
    head = src.get(pos, 8)
    size = _u32(head, 0)
    kind = head[4:8]
    header = 8
    if size == 1:
        if pos + 16 > parent_end:
            raise NoDate("box-header")
        size = int.from_bytes(src.get(pos + 8, 8), "big")
        header = 16
    elif size == 0:
        if not top:
            raise NoDate("box-size-zero")
        size = parent_end - pos
    if size < header or pos + size > parent_end:
        raise NoDate("box-size")
    return _Box(kind, pos, pos + header, pos + size)


def _full_box(src: _Source, box: _Box) -> tuple[int, int]:
    """(version, offset of the body after version and flags)."""
    if box.body + 4 > box.end:
        raise NoDate("fullbox")
    return src.get(box.body, 1)[0], box.body + 4


def _exif_item_id(src: _Source, iinf: _Box) -> int:
    version, pos = _full_box(src, iinf)
    if version == 0:
        if pos + 2 > iinf.end:
            raise NoDate("iinf")
        count = _u16(src.get(pos, 2), 0)
        pos += 2
    else:
        if pos + 4 > iinf.end:
            raise NoDate("iinf")
        count = _u32(src.get(pos, 4), 0)
        pos += 4
    if count > HEIF_MAX_ENTRIES:
        raise NoDate("iinf-count")
    for _ in range(count):
        infe = _box(src, pos, iinf.end, top=False)
        if infe.type != b"infe":
            raise NoDate("iinf-child")
        pos = infe.end
        version, at = _full_box(src, infe)
        if version == 2:
            need, item_id_size = 2 + 2 + 4, 2
        elif version == 3:
            need, item_id_size = 4 + 2 + 4, 4
        else:
            continue  # only v2/v3 entries carry an item type
        if at + need > infe.end:
            raise NoDate("infe")
        data = src.get(at, need)
        if data[item_id_size + 2 : item_id_size + 6] == b"Exif":
            return int.from_bytes(data[:item_id_size], "big")
    raise NoDate("no-exif-item")


class _Fields:
    """Fixed-width big-endian fields of one box, read in order. A width of 0 reads 0."""

    def __init__(self, src: _Source, pos: int, end: int) -> None:
        self._src = src
        self.pos = pos
        self._end = end

    def take(self, width: int) -> int:
        if width == 0:
            return 0
        if self.pos + width > self._end:
            raise NoDate("iloc-short")
        value = int.from_bytes(self._src.get(self.pos, width), "big")
        self.pos += width
        return value


def _exif_location(src: _Source, iloc: _Box, item_id: int) -> tuple[int, int, int]:
    """(construction method, offset, length) of the Exif item. Iterations, not bytes, are capped:
    with every field size 0 an extent takes no bytes at all and must still end the loop."""
    version, pos = _full_box(src, iloc)
    if version > 2:
        raise NoDate("iloc-version")
    f = _Fields(src, pos, iloc.end)
    sizes = f.take(1)
    offset_size, length_size = sizes >> 4, sizes & 0x0F
    sizes = f.take(1)
    base_size, index_size = sizes >> 4, (sizes & 0x0F if version in (1, 2) else 0)
    if any(size not in (0, 4, 8) for size in (offset_size, length_size, base_size, index_size)):
        raise NoDate("iloc-field-size")
    count = f.take(4 if version == 2 else 2)
    if count > HEIF_MAX_ENTRIES:
        raise NoDate("iloc-count")
    extents_seen = 0
    for _ in range(count):
        this_id = f.take(4 if version == 2 else 2)
        method = f.take(2) & 0x0F if version in (1, 2) else 0
        reference = f.take(2)
        base = f.take(base_size)
        extents = f.take(2)
        found: list[tuple[int, int]] = []
        for _ in range(extents):
            extents_seen += 1
            if extents_seen > HEIF_MAX_ENTRIES:
                raise NoDate("iloc-extents")
            f.take(index_size)
            found.append((f.take(offset_size), f.take(length_size)))
        if this_id != item_id:
            continue
        if reference != 0:
            raise NoDate("iloc-reference")
        if method not in (0, 1):
            raise NoDate("iloc-method")
        if len(found) != 1 or found[0][1] <= 0:
            raise NoDate("iloc-extent")
        offset, length = found[0]
        return method, base + offset, length
    raise NoDate("iloc-no-item")


def _heif(src: _Source, *, now: float) -> int:
    pos = 0
    meta: _Box | None = None
    for _ in range(HEIF_MAX_TOP_BOXES):
        if pos >= src.size:
            break
        box = _box(src, pos, src.size, top=True)
        if box.type == b"meta":
            meta = box
            break
        pos = box.end  # ftyp, mdat and every other box are skipped unread
    if meta is None:
        raise NoDate("no-meta")
    if meta.end - meta.start > HEIF_META_MAX:
        raise NoDate("meta-size")
    version, pos = _full_box(src, meta)
    if version != 0:
        raise NoDate("meta-version")
    iinf = iloc = idat = None
    for _ in range(HEIF_MAX_META_BOXES):
        if pos >= meta.end:
            break
        child = _box(src, pos, meta.end, top=False)
        if child.type == b"iinf" and iinf is None:
            iinf = child
        elif child.type == b"iloc" and iloc is None:
            iloc = child
        elif child.type == b"idat" and idat is None:
            idat = child
        pos = child.end  # hdlr, pitm, iref, iprp and the rest are never read
    if iinf is None or iloc is None:
        raise NoDate("no-iinf-or-iloc")
    method, offset, length = _exif_location(src, iloc, _exif_item_id(src, iinf))
    if method == 1:
        if idat is None or offset + length > idat.end - idat.body:
            raise NoDate("idat-range")
        start = idat.body + offset
    else:
        start = offset
    if start + length > src.size:
        raise NoDate("item-range")
    if length < 4:
        raise NoDate("item-short")
    tiff_offset = _u32(src.get(start, 4), 0)
    if tiff_offset >= length - 4:
        raise NoDate("item-tiff-offset")
    tiff_start = start + 4 + tiff_offset
    take = min(EXIF_MAX, start + length - tiff_start)
    return tiff_date(src.get(tiff_start, take), now=now)


# --------------------------------------------------------------------------- PNG, WebP


def _png(src: _Source, *, now: float) -> int:
    pos = len(_PNG_SIGNATURE)
    for _ in range(PNG_MAX_CHUNKS):
        if pos + 8 > src.size:
            raise NoDate("png-end")
        head = src.get(pos, 8)
        length, kind = _u32(head, 0), head[4:8]
        if length > 2**31 - 1:
            raise NoDate("png-length")
        if kind in (b"IDAT", b"IEND"):
            raise NoDate("png-no-exif")
        if kind == b"eXIf":
            if length > EXIF_MAX:
                raise NoDate("png-exif-size")
            return _exif_payload(src.get(pos + 8, length), now=now)  # never decompressed
        pos += 12 + length
    raise NoDate("png-chunks")


def _webp(src: _Source, *, now: float) -> int:
    riff = int.from_bytes(src.get(4, 4), "little")
    end = min(8 + riff, src.size)
    pos = 12
    for _ in range(WEBP_MAX_CHUNKS):
        if pos + 8 > end:
            raise NoDate("webp-end")
        head = src.get(pos, 8)
        kind, size = head[:4], int.from_bytes(head[4:8], "little")
        if pos + 8 + size > end:
            raise NoDate("webp-chunk-size")
        if kind == b"EXIF":
            if size > EXIF_MAX:
                raise NoDate("webp-exif-size")
            return _exif_payload(src.get(pos + 8, size), now=now)
        pos += 8 + size + (size & 1)
    raise NoDate("webp-chunks")


# --------------------------------------------------------------------------- entry points


def examine(read_at: ReadAt, size: int, *, now: float) -> tuple[str | None, int | None]:
    """(format, taken) of a file of `size` bytes: the photo format by content (None: not a photo
    this server knows) and the taken wall-clock seconds (None: no usable date). NoDate never
    leaves this function; what the reader raises does (the storage reader: a StorageError), and
    so does an exception of a type the parser does not expect (see the module docstring)."""
    if size <= 0:
        return None, None
    try:
        src = _Source(read_at, size)
        head = src.get(0, min(size, HEAD_BYTES))
    except NoDate:
        return None, None
    fmt = sniff(head)
    if fmt is None or fmt == "gif":
        return fmt, None
    try:
        return fmt, taken_at(src, fmt, now=now)
    except NoDate:
        return fmt, None


def taken_at(src: _Source, fmt: str, *, now: float) -> int:
    """Taken wall-clock seconds of a file already sniffed as `fmt`, or NoDate."""
    try:
        if fmt == "jpeg":
            return _jpeg(src, now=now)
        if fmt == "heif":
            return _heif(src, now=now)
        if fmt == "png":
            return _png(src, now=now)
        if fmt == "webp":
            return _webp(src, now=now)
    except NoDate:
        raise
    except OSError:
        raise
    except (ValueError, IndexError, OverflowError, TypeError) as exc:
        raise NoDate("malformed") from exc
    raise NoDate("no-parser")
