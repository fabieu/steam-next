"""Readers for Steam's appcache binary formats (appinfo.vdf, packageinfo.vdf).

Each on-disk format version has its own reader class. Choice of reader is
driven by the 4-byte magic at the start of the file.
"""

import struct
from typing import IO, Any, ClassVar, Iterator

from vdf import binary_load

uint32 = struct.Struct('<I')
uint64 = struct.Struct('<Q')
float32 = struct.Struct('<f')


class AppinfoReader:
    """Base for appinfo formats. End-of-stream sentinel is appid == 0."""
    MAGIC: ClassVar[bytes]
    HAS_DATA_SHA1: ClassVar[bool] = False

    def __init__(self, fp: IO[bytes]) -> None:
        self.fp = fp
        self.universe = self._read_uint32()

    def _read_byte(self) -> int:
        b = self.fp.read(1)
        if not b:
            raise EOFError()
        return b[0]

    def _read_uint32(self) -> int:
        return uint32.unpack(self.fp.read(4))[0]

    def _read_uint64(self) -> int:
        return uint64.unpack(self.fp.read(8))[0]

    def _read_float(self) -> float:
        return float32.unpack(self.fp.read(4))[0]

    def _read_cstring(self) -> str:
        chars = bytearray()
        while True:
            c = self.fp.read(1)
            if not c or c == b'\x00':
                break
            chars.extend(c)
        return chars.decode('utf-8', errors='replace')

    @property
    def header(self) -> dict[str, Any]:
        return {'magic': self.MAGIC, 'universe': self.universe}

    def __iter__(self) -> Iterator[dict[str, Any]]:
        while True:
            entry = self._read_entry()
            if entry is None:
                break
            yield entry

    def _read_entry(self) -> dict[str, Any] | None:
        appid_bytes = self.fp.read(4)
        if len(appid_bytes) < 4:
            return None
        appid = uint32.unpack(appid_bytes)[0]
        if appid == 0:
            return None

        app: dict[str, Any] = {
            'appid': appid,
            'size': self._read_uint32(),
            'info_state': self._read_uint32(),
            'last_updated': self._read_uint32(),
            'access_token': self._read_uint64(),
            'sha1': self.fp.read(20),
            'change_number': self._read_uint32(),
        }

        if self.HAS_DATA_SHA1:
            app['data_sha1'] = self.fp.read(20)
        app['data'] = self._read_payload()

        return app

    def _read_payload(self) -> dict[str, Any]:
        return binary_load(self.fp)


class AppinfoV27Reader(AppinfoReader):
    MAGIC = b"'DV\x07"
    HAS_DATA_SHA1 = False


class AppinfoV28Reader(AppinfoReader):
    MAGIC = b"(DV\x07"
    HAS_DATA_SHA1 = True


class AppinfoV29Reader(AppinfoReader):
    """v29 stores its inner KeyValues payload with uint32 indexes into a global
    string table instead of inline null-terminated keys, so the payload reader
    is implemented inline rather than delegated to ``vdf.binary_load``.
    """
    MAGIC = b")DV\x07"
    HAS_DATA_SHA1 = True

    def __init__(self, fp: IO[bytes]) -> None:
        super().__init__(fp)
        self.string_table = self._read_string_table()

    def _read_string_table(self) -> list[str]:
        offset = self._read_uint64()
        resume = self.fp.tell()
        self.fp.seek(offset)
        count = self._read_uint32()
        strings = [self._read_cstring() for _ in range(count)]
        self.fp.seek(resume)
        return strings

    def _read_payload(self) -> dict[str, Any]:
        return self._read_node()

    def _read_key(self) -> str:
        return self.string_table[self._read_uint32()]

    def _read_node(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            try:
                type_byte = self._read_byte()
            except EOFError:
                break

            if type_byte == 0x08:  # end of dict
                break

            key = self._read_key()

            if type_byte == 0x00:  # nested dict
                result[key] = self._read_node()
            elif type_byte == 0x01:  # string
                result[key] = self._read_cstring()
            elif type_byte == 0x02:  # int32
                result[key] = self._read_uint32()
            elif type_byte == 0x03:  # float32
                result[key] = round(self._read_float(), 6)
            elif type_byte == 0x04:  # pointer (int32)
                result[key] = self._read_uint32()
            elif type_byte == 0x05:  # wide string
                result[key] = self._read_cstring()
            elif type_byte == 0x06:  # color (int32)
                val = self._read_uint32()
                result[key] = f"#{val:08x}"
            elif type_byte == 0x07:  # uint64
                result[key] = self._read_uint64()
            else:
                raise ValueError(f"Unknown VDF type 0x{type_byte:02x}")
        return result


class PackageinfoReader:
    """Base for packageinfo formats. End-of-stream sentinel is packageid == 0xFFFFFFFF."""
    MAGIC: ClassVar[bytes]
    HAS_TOKEN: ClassVar[bool] = False

    def __init__(self, fp: IO[bytes]) -> None:
        self.fp = fp
        self.universe = uint32.unpack(fp.read(4))[0]

    @property
    def header(self) -> dict[str, Any]:
        return {'magic': self.MAGIC, 'universe': self.universe}

    def __iter__(self) -> Iterator[dict[str, Any]]:
        while True:
            entry = self._read_entry()
            if entry is None:
                break
            yield entry

    def _read_entry(self) -> dict[str, Any] | None:
        pkgid = uint32.unpack(self.fp.read(4))[0]
        if pkgid == 0xFFFFFFFF:
            return None

        pkg: dict[str, Any] = {
            'packageid': pkgid,
            'sha1': self.fp.read(20),
            'change_number': uint32.unpack(self.fp.read(4))[0],
        }
        if self.HAS_TOKEN:
            pkg['token'] = uint64.unpack(self.fp.read(8))[0]
        pkg['data'] = binary_load(self.fp)
        return pkg


class PackageinfoV05Reader(PackageinfoReader):
    MAGIC = b"'UV\x06"


class PackageinfoV06Reader(PackageinfoReader):
    MAGIC = b"(UV\x06"
    HAS_TOKEN = True


_APPINFO_READERS: dict[bytes, type[AppinfoReader]] = {
    AppinfoV27Reader.MAGIC: AppinfoV27Reader,
    AppinfoV28Reader.MAGIC: AppinfoV28Reader,
    AppinfoV29Reader.MAGIC: AppinfoV29Reader,
}

_PACKAGEINFO_READERS: dict[bytes, type[PackageinfoReader]] = {
    PackageinfoV05Reader.MAGIC: PackageinfoV05Reader,
    PackageinfoV06Reader.MAGIC: PackageinfoV06Reader,
}


def get_appinfo_reader(fp: IO[bytes]) -> AppinfoReader:
    """Read the 4-byte magic from *fp* and return the matching appinfo reader."""
    magic = fp.read(4)
    cls = _APPINFO_READERS.get(magic)
    if cls is None:
        raise SyntaxError("Invalid magic, got %s" % repr(magic))
    return cls(fp)


def get_packageinfo_reader(fp: IO[bytes]) -> PackageinfoReader:
    """Read the 4-byte magic from *fp* and return the matching packageinfo reader."""
    magic = fp.read(4)
    cls = _PACKAGEINFO_READERS.get(magic)
    if cls is None:
        raise SyntaxError("Invalid magic, got %s" % repr(magic))
    return cls(fp)
