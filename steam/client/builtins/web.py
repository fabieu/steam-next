"""
Web related features
"""
from binascii import hexlify
from os import urandom

from steam.enums import EResult
from steam.utils.web import make_requests_session, generate_session_id


class Web:
    _web_session = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.on(self.EVENT_DISCONNECTED, self.__handle_disconnect)

    def __handle_disconnect(self):
        self._web_session = None

    def get_web_session_cookies(self):
        """Get web authentication cookies for the logged on user.

        An access token is generated from the logon's :attr:`refresh_token` over the CM
        (``IAuthenticationService/GenerateAccessTokenForApp``) and used as the ``steamLoginSecure``
        cookie.

        .. note::
            The cookies are valid only while :class:`.SteamClient` instance is logged on.

        :return: dict with authentication cookies
        :rtype: :class:`dict`, :class:`None`
        """
        if not self.logged_on or not self.refresh_token:
            return None

        resp = self.send_um_and_wait('Authentication.GenerateAccessTokenForApp#1',
                                     {'refresh_token': self.refresh_token,
                                      'steamid': self.steam_id.as_64})

        if resp is None or resp.header.eresult != EResult.OK or not resp.body.access_token:
            self._LOG.debug("get_web_session_cookies failed: %s",
                            'timeout' if resp is None else repr(EResult(resp.header.eresult)))
            return None

        return {
            'steamLoginSecure': '%s%%7C%%7C%s' % (self.steam_id.as_64, resp.body.access_token),
        }

    def get_web_session(self, language='english'):
        """Get a :class:`requests.Session` that is ready for use

        See :meth:`get_web_session_cookies`

        .. note::
            Auth cookies will only be send to ``(help|store).steampowered.com`` and ``steamcommunity.com`` domains

        .. note::
            The session is valid only while :class:`.SteamClient` instance is logged on.

        :param language: localization language for steam pages
        :type language: :class:`str`
        :return: authenticated Session ready for use
        :rtype: :class:`requests.Session`, :class:`None`
        """
        if self._web_session:
            return self._web_session

        cookies = self.get_web_session_cookies()
        if cookies is None:
            return None

        self._web_session = session = make_requests_session()
        session_id = generate_session_id()
        client_session_id = hexlify(urandom(8)).decode('ascii')

        for domain in ['store.steampowered.com', 'help.steampowered.com', 'steamcommunity.com']:
            for name, val in cookies.items():
                secure = (name == 'steamLoginSecure')
                session.cookies.set(name, val, domain=domain, secure=secure)

            session.cookies.set('Steam_Language', language, domain=domain)
            session.cookies.set('birthtime', '-3333', domain=domain)
            session.cookies.set('sessionid', session_id, domain=domain)
            session.cookies.set('clientsessionid', client_session_id, domain=domain)

        return session
