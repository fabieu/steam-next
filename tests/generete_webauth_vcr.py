from __future__ import print_function

import os
import sys
from typing import Iterable

filepath = os.path.dirname(os.path.realpath(__file__))
rootdir = os.path.abspath(os.path.join(filepath, '..'))
os.chdir(rootdir)
sys.path.insert(0, rootdir)

from getpass import getpass
import json
import vcr

from steam import webauth as wa

_input = input


# personal info scrubbers
# -----------------------
# The recorded vcr is anonymized and should not contain
# any personal info. MAKE SURE TO CHECK THE VCR BEFORE COMMIT TO REPO
def _pop_headers(headers: dict, names: Iterable[str]):
    """Pop header(s) regardless of casing (VCR stores keys as plain dict)."""
    targets = {name.lower() for name in names}

    for key in list(headers.keys()):
        if key.lower() in targets:
            headers.pop(key, None)


def request_scrubber(r):
    _pop_headers(r.headers, [
        'Cookie',
        'Content-Length',
    ])

    r.headers['Accept-Encoding'] = 'identity'

    r.body = ''

    return r


def response_scrubber(r):
    _pop_headers(r.get('headers', {}), [
        'Date',
        'Expires',
        'Cookie',
        'Content-Length',
        'Content-Encoding',
    ])

    if 'set-cookie' in r['headers'] and 'steamLogin' in ''.join(r['headers']['set-cookie']):
        r['headers']['set-cookie'] = [
            'steamLogin=0%7C%7C{}; path=/; httponly'.format('A' * 16),
            'steamLoginSecure=0%7C%7C{}; path=/; httponly; secure'.format('B' * 16),
            'steamMachineAuth0={}; path=/; httponly'.format('C' * 16),
        ]
    else:
        r['headers'].pop('set-cookie', None)

    if r.get("body") and r["body"].get("string") is not None:
        raw = r["body"]["string"]

        # vcrpy normally stores bytes here; be defensive
        if isinstance(raw, bytes):
            text = raw.decode("utf-8")
        else:
            text = raw

        data = json.loads(text)

        if "response" in data:
            replacements = {
                "timestamp": 12345678,
                "steamid": "0",
                "account_name": "<ACCOUNT_NAME>",
                "request_id": "<REQUEST_ID>",
                "client_id": "<CLIENT_ID>",
                "refresh_token": "<REFRESH_TOKEN>",
                "access_token": "<ACCESS_TOKEN>",
            }

            for key, value in replacements.items():
                if key in data["response"]:
                    data["response"][key] = value

        body_bytes = json.dumps(data).encode("utf-8")  # <-- bytes
        r["body"]["string"] = body_bytes

        print(r)

    return r


anon_vcr = vcr.VCR(
    before_record_request=request_scrubber,
    before_record_response=response_scrubber,
    serializer='yaml',
    record_mode='new_episodes',
    cassette_library_dir=os.path.join(rootdir, 'vcr'),
    filter_query_parameters=['account_name'],
)


# scenarios
# -----------------

def user_pass_only():
    print("Please enter a user that can login with just password.")
    u = _input("Username: ")
    p = getpass("Password (no echo): ")

    user_pass_only_success(u, p)
    user_pass_only_fail(u, p + '123')


@anon_vcr.use_cassette('webauth_user_pass_only_success.yaml')
def user_pass_only_success(u, p):
    wa.WebAuth(u, p).login()


@anon_vcr.use_cassette('webauth_user_pass_only_fail.yaml')
def user_pass_only_fail(u, p):
    try:
        wa.WebAuth(u, p).login()
    except wa.LoginIncorrect:
        pass


# run
# -----------------
if __name__ == '__main__':
    user_pass_only()
