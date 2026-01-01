from binascii import hexlify

import requests

from steam import __version__
from steam.core.crypto import sha1_hash, random_bytes


def make_requests_session(headers: dict = None) -> requests.Session:
    """
    :returns: requests session
    :rtype: :class:`requests.Session`
    """
    session = requests.Session()
    session.headers.update({
        'User-Agent': f"python-steam/{__version__} {session.headers['User-Agent']}",
    })

    if headers:
        session.headers.update(headers)

    return session


def generate_session_id():
    """
    :returns: session id
    :rtype: :class:`str`
    """
    return hexlify(sha1_hash(random_bytes(32)))[:32].decode('ascii')
