"""
Parsing entry points for Steam's ``appcache/`` binary files.

``parse_appinfo`` supports appinfo.vdf versions v27 (``'DV\\x07``), v28
(``(DV\\x07``), and v29 (``)DV\\x07``). ``parse_packageinfo`` supports
packageinfo.vdf v05 (``'UV\\x06``) and v06 (``(UV\\x06``). Each function
reads the 4-byte magic, dispatches to the matching reader class in
:mod:`steam.utils.appcache_readers`, and returns ``(header, iterator)``.

Examples:

.. code:: python

    >>> from steam.utils.appcache import parse_appinfo, parse_packageinfo

    >>> header, apps = parse_appinfo(open('/d/Steam/appcache/appinfo.vdf', 'rb'))
    >>> header
    {'magic': b"(DV\\x07", 'universe': 1}
    >>> next(apps)
    {'appid': 5,
     'size': 79,
     'info_state': 1,
     'last_updated': 1484735377,
     'access_token': 0,
     'sha1': b'\\x87\\xfaCg\\x85\\x80\\r\\xb4\\x90Im\\xdc}\\xb4\\x81\\xeeQ\\x8b\\x825',
     'change_number': 4603827,
     'data_sha1': b'\\x87\\xfaCg\\x85\\x80\\r\\xb4\\x90Im\\xdc}\\xb4\\x81\\xeeQ\\x8b\\x825',
     'data': {'appinfo': {'appid': 5, 'public_only': 1}}}

    >>> header, pkgs = parse_packageinfo(open('/d/Steam/appcache/packageinfo.vdf', 'rb'))
    >>> header
    {'magic': b"'UV\\x06", 'universe': 1}

    >>> next(pkgs)
    {'packageid': 7,
     'sha1': b's\\x8b\\xf7n\\t\\xe5 k#\\xb6-\\x82\\xd2 \\x14k@\\xfeDQ',
     'change_number': 7469765,
     'data': {'7': {'packageid': 7,
       'billingtype': 1,
       'licensetype': 1,
       'status': 0,
       'extended': {'requirespreapproval': 'WithRedFlag'},
       'appids': {'0': 10, '1': 80, '2': 100, '3': 254430},
       'depotids': {'0': 0, '1': 95, '2': 101, '3': 102, '4': 103, '5': 254431},
       'appitems': {}}}}

"""

from typing import IO, Any, Iterator

from steam.utils.appcache_readers import get_appinfo_reader, get_packageinfo_reader


def parse_appinfo(fp: IO[bytes]) -> tuple[dict[str, Any], Iterator[dict[str, Any]]]:
    """Parse appinfo.vdf from the Steam appcache folder.

    Dispatches on the file's magic to the matching reader (v27 / v28 / v29).

    :param fp: file-like object
    :raises: SyntaxError
    :rtype: (:class:`dict`, :class:`Generator`)
    :return: (header, apps iterator)
    """
    reader = get_appinfo_reader(fp)
    return reader.header, iter(reader)


def parse_packageinfo(fp: IO[bytes]) -> tuple[dict[str, Any], Iterator[dict[str, Any]]]:
    """Parse packageinfo.vdf from the Steam appcache folder.

    Dispatches on the file's magic to the matching reader (v05 / v06).

    :param fp: file-like object
    :raises: SyntaxError
    :rtype: (:class:`dict`, :class:`Generator`)
    :return: (header, packages iterator)
    """
    reader = get_packageinfo_reader(fp)
    return reader.header, iter(reader)
