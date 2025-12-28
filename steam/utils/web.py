import gzip
from binascii import hexlify

import requests

from steam import __version__
from steam.core.crypto import sha1_hash, random_bytes


def make_requests_session():
    """
    :returns: requests session
    :rtype: :class:`requests.Session`
    """
    session = requests.Session()
    session.headers['User-Agent'] = f"python-steam/{__version__} {session.headers['User-Agent']}"
    session.hooks["response"].append(decode_gzip)

    return session


def decode_gzip(response, *args, **kwargs):
    # Ensure urllib3 decoding is enabled
    try:
        response.raw.decode_content = True
    except Exception:
        pass

    # Fallback: manually decompress if still gzipped
    raw = response.content
    if raw.startswith(b"\x1f\x8b"):
        try:
            decompressed = gzip.decompress(raw)
            response._content = decompressed  # override safely
            response.encoding = response.encoding or "utf-8"
        except Exception:
            pass

    return response


def generate_session_id():
    """
    :returns: session id
    :rtype: :class:`str`
    """
    return hexlify(sha1_hash(random_bytes(32)))[:32].decode('ascii')
