import struct
import zlib

SIGNATURE = b"\x89PNG\r\n\x1a\n"


class PngError(Exception):
    pass


def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def unfilter(kind: int, row: bytearray, prev: bytearray, bpp: int) -> None:
    if kind == 0:
        return
    for i in range(len(row)):
        left = row[i - bpp] if i >= bpp else 0
        up = prev[i]
        if kind == 1:
            row[i] = (row[i] + left) & 255
        elif kind == 2:
            row[i] = (row[i] + up) & 255
        elif kind == 3:
            row[i] = (row[i] + ((left + up) >> 1)) & 255
        elif kind == 4:
            upleft = prev[i - bpp] if i >= bpp else 0
            row[i] = (row[i] + paeth(left, up, upleft)) & 255
        else:
            raise PngError(f"filtro PNG desconocido: {kind}")


def parse(data: bytes):
    if not data.startswith(SIGNATURE):
        raise PngError("no es un PNG")
    pos = 8
    header = None
    idat = bytearray()
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos : pos + 8])
        body = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
    if header is None:
        raise PngError("PNG sin IHDR")
    width, height, depth, color, _, _, interlace = header
    if depth != 8 or interlace != 0 or color not in (2, 6):
        raise PngError("formato PNG no soportado")
    return width, height, (3 if color == 2 else 4), zlib.decompress(bytes(idat))


def rows(data: bytes):
    width, height, bpp, raw = parse(data)
    stride = width * bpp
    prev = bytearray(stride)
    offset = 0
    for _ in range(height):
        kind = raw[offset]
        row = bytearray(raw[offset + 1 : offset + 1 + stride])
        offset += stride + 1
        unfilter(kind, row, prev, bpp)
        yield row, bpp
        prev = row


def is_black(data: bytes) -> bool | None:
    try:
        for row, bpp in rows(data):
            if any(row[0::bpp]) or any(row[1::bpp]) or any(row[2::bpp]):
                return False
    except (PngError, zlib.error, struct.error, IndexError):
        return None
    return True
