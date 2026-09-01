import unittest
from types import SimpleNamespace

from mock import MagicMock

from steam.client import SteamClient
from steam.enums import EResult
from steam.steamid import SteamID

STEAMID64 = SteamID('76561197960287930').as_64


def resp(eresult=EResult.OK, **body):
    return SimpleNamespace(header=SimpleNamespace(eresult=int(eresult)),
                           body=SimpleNamespace(**body))


class WebSessionCookies(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.logged_on = True
        self.client.refresh_token = 'REFRESH'
        self.client.steam_id = SteamID(STEAMID64)
        self.client.send_um_and_wait = MagicMock(return_value=resp(access_token='ACCESS', refresh_token=''))

    def test_cookie_derived_from_generated_access_token(self):
        cookies = self.client.get_web_session_cookies()

        self.client.send_um_and_wait.assert_called_once_with(
            'Authentication.GenerateAccessTokenForApp#1',
            {'refresh_token': 'REFRESH', 'steamid': STEAMID64})
        self.assertEqual(cookies, {'steamLoginSecure': '%s%%7C%%7CACCESS' % STEAMID64})

    def test_none_when_not_logged_on_or_without_token(self):
        self.client.logged_on = False
        self.assertIsNone(self.client.get_web_session_cookies())

        self.client.logged_on = True
        self.client.refresh_token = None
        self.assertIsNone(self.client.get_web_session_cookies())
        self.client.send_um_and_wait.assert_not_called()

    def test_none_on_failure(self):
        self.client.send_um_and_wait = MagicMock(return_value=None)
        self.assertIsNone(self.client.get_web_session_cookies())

        self.client.send_um_and_wait = MagicMock(return_value=resp(EResult.AccessDenied, access_token=''))
        self.assertIsNone(self.client.get_web_session_cookies())

    def test_session_carries_cookies_for_steam_domains(self):
        session = self.client.get_web_session()

        self.assertIsNotNone(session)
        for domain in ('store.steampowered.com', 'help.steampowered.com', 'steamcommunity.com'):
            names = {c.name for c in session.cookies if c.domain == domain}
            self.assertEqual(names, {'steamLoginSecure', 'Steam_Language', 'birthtime',
                                     'sessionid', 'clientsessionid'})

        # cached while logged on
        self.assertIs(self.client.get_web_session(), session)
        self.client.send_um_and_wait.assert_called_once()


if __name__ == '__main__':
    unittest.main()
