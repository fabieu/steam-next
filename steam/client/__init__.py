"""
Implementation of Steam client based on ``gevent``

.. warning::
    ``steam.client`` no longer patches stdlib to make it gevent cooperative.
    This provides flexibility if you want to use :class:`.SteamClient` with async or other modules.
    If you want to monkey patch anyway use :meth:`steam.monkey.patch_minimal()`

.. note::
    Additional features are located in separate submodules. All functionality from :mod:`.builtins` is inherited by default.

.. note::
    Optional features are available as :mod:`.mixins`. This allows the client to remain light yet flexible.

"""
import hashlib
import json
import logging
import os
import socket
import sys
from base64 import urlsafe_b64decode
from getpass import getpass
from io import open
from random import random
from time import time

import gevent

from steam.client.builtins import BuiltinBase
from steam.core.cm import CMClient
from steam.core.crypto import sha1_hash, rsa_encrypt_password
from steam.core.msg import MsgProto
from steam.core.msg.unified import get_um
from steam.enums import EResult, EOSType, EType, ETransport
from steam.enums.emsg import EMsg
from steam.enums.proto import EAuthSessionGuardType, EAuthTokenPlatformType, ESessionPersistence, ETokenRenewalType
from steam.steamid import SteamID
from steam.utils import ip4_from_int
from steam.utils.proto import proto_fill_from_dict

PROTOCOL_VERSION = 65580
_GUARD_NONE = EAuthSessionGuardType['None']


def _spoofed_hostname():
    """Spoofed ``DESKTOP-XXXXXXX`` device name derived from the real hostname."""
    digest = hashlib.sha1((socket.gethostname() or '').encode('utf-8')).digest()
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return 'DESKTOP-' + ''.join(chars[b % len(chars)] for b in digest[:7])


def _make_machine_id(account_name):
    """Binary KV ``MessageObject`` with ``BB3``/``FF2``/``3B3`` hashes derived from the account name."""

    def sha1_hex(text):
        return hashlib.sha1(text.encode('utf-8')).hexdigest().encode('ascii')

    def cstring(value):
        return value + b'\x00'

    return (b'\x00' + cstring(b'MessageObject')
            + b'\x01' + cstring(b'BB3') + cstring(sha1_hex('SteamUser Hash BB3 %s' % account_name))
            + b'\x01' + cstring(b'FF2') + cstring(sha1_hex('SteamUser Hash FF2 %s' % account_name))
            + b'\x01' + cstring(b'3B3') + cstring(sha1_hex('SteamUser Hash 3B3 %s' % account_name))
            + b'\x08\x08')


def _detect_os_type():
    """OS type reported in ``CMsgClientLogon``, as an unsigned 32bit value.

    ``client_os_type`` is a ``uint32``, while the macOS and Linux :class:`.EOSType` values
    are negative, so they go on the wire as their two's complement.
    """
    if sys.platform == 'win32':
        os_type = EOSType.Windows10
    elif sys.platform == 'darwin':
        os_type = EOSType.MacOSUnknown
    else:
        os_type = EOSType.LinuxUnknown

    return int(os_type) & 0xFFFFFFFF


def _decode_jwt(token):
    """Return the payload claims of a JWT. Raises :class:`ValueError` when malformed."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    payload = parts[1] + '=' * (-len(parts[1]) % 4)  # restore base64url padding
    try:
        return json.loads(urlsafe_b64decode(payload))
    except Exception:
        raise ValueError("Invalid JWT")


def _jwt_has_audience(token, audience):
    try:
        return audience in (_decode_jwt(token).get('aud') or [])
    except ValueError:
        return False


class SteamClient(CMClient, BuiltinBase):
    EVENT_LOGGED_ON = 'logged_on'
    """After successful login"""

    EVENT_AUTH_CODE_REQUIRED = 'auth_code_required'
    """When either email or 2FA code is needed for login"""

    EVENT_REFRESH_TOKEN = 'refresh_token'
    """When a new refresh token is obtained; persist it to log in later via ``login(access_token=...)``

    :param refresh_token: JWT refresh token
    :type refresh_token: :class:`str`
    """

    EVENT_MACHINE_AUTH_TOKEN = 'machine_auth_token'
    """When Steam issues a new Steam Guard machine auth token; persist it to skip the guard code on
    the next password login. Stored automatically when :attr:`credential_location` is set.

    :param machine_auth_token: JWT machine auth token
    :type machine_auth_token: :class:`str`
    """

    EVENT_WEB_SESSION = 'web_session'
    """After each user logon, once a web session has been negotiated (see :meth:`get_web_session`)

    :param session: authenticated session
    :type session: :class:`requests.Session`
    """

    LOGON_TIMEOUT = 5  #: seconds to wait for ``ClientLogOnResponse`` before retrying

    _LOG = logging.getLogger("SteamClient")
    _reconnect_backoff_c = 0
    current_jobid = 0
    credential_location = None  #: location for sentry
    username = None  #: username when logged on
    refresh_token = None  #: JWT refresh token, acquired on login and usable via :meth:`relogin`
    machine_auth_token = None  #: Steam Guard machine auth token (JWT) for :attr:`username`, sent as ``guard_data``
    chat_mode = 2  #: chat mode (0=old chat, 2=new chat)
    renew_refresh_tokens = False  #: renew :attr:`refresh_token` after each logon
    _last_session_id = 0
    _client_instance_id = 0

    def __init__(self, protocol=ETransport.WebSocket):
        # Steam only serves the pre-logon credential auth flow over the WebSocket CM
        # endpoints, so the client defaults to WebSocket. Pass ``ETransport.TCP`` for a
        # token/anonymous-only session that should use the raw TCP CMs instead.
        CMClient.__init__(self, protocol)

        # register listeners
        self.on(self.EVENT_DISCONNECTED, self._handle_disconnect)
        self.on(self.EVENT_RECONNECT, self._handle_disconnect)
        self.on(EMsg.ClientUpdateMachineAuth, self._handle_update_machine_auth)

        #: indicates logged on status. Listen to ``logged_on`` when change to ``True``
        self.logged_on = False

        #: friendly name reported to Steam during the auth session
        self.device_friendly_name = _spoofed_hostname()

        BuiltinBase.__init__(self)

    def __repr__(self):
        return "<%s(%s) %s>" % (self.__class__.__name__,
                                repr(self.current_server_addr),
                                'online' if self.connected else 'offline',
                                )

    def set_credential_location(self, path):
        """
        Sets folder location for sentry files

        Needs to be set explicitly for sentries to be created.
        """
        self.credential_location = path

    def connect(self, *args, **kwargs):
        """Attempt to establish connection, see :meth:`.CMClient.connect`"""
        self._bootstrap_cm_list_from_file()
        return CMClient.connect(self, *args, **kwargs)

    def disconnect(self, *args, **kwargs):
        """Close connection, see :meth:`.CMClient.disconnect`"""
        self.logged_on = False
        CMClient.disconnect(self, *args, **kwargs)

    def _parse_message(self, message):
        result = CMClient._parse_message(self, message)

        if result is None:
            return

        emsg, msg = result

        # emit job events
        if msg.proto:
            jobid = msg.header.jobid_target
        else:
            jobid = msg.header.targetJobID

        if jobid not in (-1, 18446744073709551615):
            jobid = "job_%d" % jobid
            if msg.body is None and self.count_listeners(jobid):
                msg.parse()
            self.emit(jobid, msg)

        # emit UMs
        if emsg in (EMsg.ServiceMethod, EMsg.ServiceMethodResponse, EMsg.ServiceMethodSendToClient):
            if msg.body is None and self.count_listeners(msg.header.target_job_name):
                msg.parse()
            self.emit(msg.header.target_job_name, msg)

    def _bootstrap_cm_list_from_file(self):
        if not self.credential_location or self.cm_servers.last_updated > 0:
            return

        filepath = os.path.join(self.credential_location, 'cm_servers.json')

        if not os.path.isfile(filepath):
            return

        self._LOG.debug("Reading CM servers from %s" % repr(filepath))

        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
        except ValueError:
            self._LOG.error("Failed parsing %s", repr(filepath))
        except IOError as e:
            self._LOG.error("Failed reading %s (%s)", repr(filepath), str(e))
        else:
            # The cache is transport agnostic: each transport's server list is stored
            # under its own key so switching transports doesn't discard the other's cache.
            transport = self.protocol.name
            transport_data = data.get(transport)

            if not transport_data:
                self._LOG.debug("No cached CM server list for %s transport", transport)
                return

            self.cm_servers.clear()
            self.cm_servers.merge_list(transport_data['servers'])
            self.cm_servers.last_updated = transport_data.get('last_updated', 0)
            self.cell_id = self.cm_servers.cell_id = transport_data.get('cell_id', 0)

    def _handle_cm_list(self, msg):
        if (self.cm_servers.last_updated + 3600 * 24 > time()
                and self.cm_servers.cell_id != 0):
            return

        CMClient._handle_cm_list(self, msg)  # clear and merge

        if self.credential_location:
            filepath = os.path.join(self.credential_location, 'cm_servers.json')
            transport = self.protocol.name
            data = {}

            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                except ValueError:
                    self._LOG.error("Failed parsing %s", repr(filepath))
                    data = {}
                except IOError as e:
                    self._LOG.error("Failed reading %s (%s)", repr(filepath), str(e))
                    data = {}
                else:
                    if data.get(transport, {}).get('last_updated', 0) + 3600 * 24 > time():
                        return

                self._LOG.debug("Persisted CM server list is stale")

            # Only this transport's section is replaced, so the other transport's
            # cached list survives.
            data[transport] = {
                'cell_id': self.cm_servers.cell_id,
                'last_updated': self.cm_servers.last_updated,
                'servers': list(zip(map(ip4_from_int, msg.body.cm_addresses), msg.body.cm_ports)),
            }
            try:
                with open(filepath, 'wb') as f:
                    f.write(json.dumps(data, indent=True).encode('ascii'))
                self._LOG.debug("Saved CM servers to %s" % repr(filepath))
            except IOError as e:
                self._LOG.error("saving %s: %s" % (filepath, str(e)))

    def _handle_disconnect(self, *args):
        self.logged_on = False
        self.current_jobid = 0

    def _handle_logon(self, msg):
        CMClient._handle_logon(self, msg)

        result = self._eresult(msg.body.eresult)

        if result == EResult.OK:
            self._reconnect_backoff_c = 0
            # remembered for the next logon of this session
            self._last_session_id = self.session_id
            self._client_instance_id = msg.body.client_instance_id
            self.logged_on = True
            self.emit(self.EVENT_LOGGED_ON)

            if self.steam_id and self.steam_id.type == EType.Individual:
                gevent.spawn(self._post_logon)
            return

        # CM kills the connection on error anyway
        self.disconnect()

        if result in (EResult.InvalidPassword, EResult.AccessDenied, EResult.Expired, EResult.Revoked):
            self.refresh_token = None

        if result in (EResult.AccountLogonDenied,
                      EResult.InvalidLoginAuthCode,
                      EResult.AccountLoginDeniedNeedTwoFactor,
                      EResult.TwoFactorCodeMismatch,
                      ):

            is_2fa = (result in (EResult.AccountLoginDeniedNeedTwoFactor,
                                 EResult.TwoFactorCodeMismatch,
                                 ))

            if is_2fa:
                code_mismatch = (result == EResult.TwoFactorCodeMismatch)
            else:
                code_mismatch = (result == EResult.InvalidLoginAuthCode)

            self.emit(self.EVENT_AUTH_CODE_REQUIRED, is_2fa, code_mismatch)

    def _handle_update_machine_auth(self, message):
        ok = self.store_sentry(self.username, message.body.bytes)

        if ok:
            resp = MsgProto(EMsg.ClientUpdateMachineAuthResponse)

            resp.header.jobid_target = message.header.jobid_source

            resp.body.filename = message.body.filename
            resp.body.eresult = EResult.OK
            resp.body.sha_file = sha1_hash(message.body.bytes)
            resp.body.getlasterror = 0
            resp.body.offset = message.body.offset
            resp.body.cubwrote = message.body.cubtowrite

            self.send(resp)

    def reconnect(self, maxdelay=30, retry=0):
        """Implements explonential backoff delay before attempting to connect.
        It is otherwise identical to calling :meth:`.CMClient.connect`.
        The delay is reset upon a successful login.

        :param maxdelay: maximum delay in seconds before connect (0-120s)
        :type maxdelay: :class:`int`
        :param retry: see :meth:`.CMClient.connect`
        :type retry: :class:`int`
        :return: successful connection
        :rtype: :class:`bool`
        """
        delay_seconds = 2 ** self._reconnect_backoff_c - 1

        if delay_seconds < maxdelay:
            self._reconnect_backoff_c = min(7, self._reconnect_backoff_c + 1)

        delay_seconds = int(delay_seconds * 0.5 + delay_seconds * 0.5 * random())

        return self.connect(delay=delay_seconds, retry=retry)

    def wait_msg(self, event, timeout=None, raises=None):
        """Wait for a message, similiar to :meth:`.wait_event`

        :param event: event id
        :type  event: :class:`.EMsg` or :class:`str`
        :param timeout: seconds to wait before timeout
        :type  timeout: :class:`int`
        :param raises: On timeout when ``False`` returns :class:`None`, else raise :class:`gevent.Timeout`
        :type  raises: :class:`bool`
        :return: returns a message or :class:`None`
        :rtype: :class:`None`, or `proto message`
        :raises: :class:`gevent.Timeout`
        """
        resp = self.wait_event(event, timeout, raises)

        if resp is not None:
            return resp[0]

    def send(self, message, body_params=None):
        """Send a message to CM

        :param message: a message instance
        :type message: :class:`.Msg`, :class:`.MsgProto`
        :param body_params: a dict with params to the body (only :class:`.MsgProto`)
        :type body_params: dict
        """
        if not self.connected:
            self._LOG.debug("Trying to send message when not connected. (discarded)")
        elif not self.logged_on and message.msg not in self._PRELOGON_MSGS:
            self._LOG.debug("Dropping outgoing message %r because we're not logged on.", message.msg)
        else:
            if body_params and isinstance(message, MsgProto):
                proto_fill_from_dict(message.body, body_params)

            CMClient.send(self, message)

    #: the only messages that may go out before logon
    _PRELOGON_MSGS = (EMsg.ChannelEncryptResponse,
                      EMsg.ClientLogon,
                      EMsg.ClientHello,
                      EMsg.ServiceMethodCallFromClientNonAuthed,
                      )

    def send_job(self, message, body_params=None):
        """Send a message as a job

        .. note::
            Not all messages are jobs, you'll have to find out which are which

        :param message: a message instance
        :type message: :class:`.Msg`, :class:`.MsgProto`
        :param body_params: a dict with params to the body (only :class:`.MsgProto`)
        :type body_params: dict
        :return: ``jobid`` event identifier
        :rtype: :class:`str`

        To catch the response just listen for the ``jobid`` event.

        .. code:: python

            jobid = steamclient.send_job(my_message)

            resp = steamclient.wait_event(jobid, timeout=15)
            if resp:
                (message,) = resp

        """
        jobid = self.current_jobid = ((self.current_jobid + 1) % 10000) or 1
        self.remove_all_listeners('job_%d' % jobid)

        if message.proto:
            message.header.jobid_source = jobid
        else:
            message.header.sourceJobID = jobid

        self.send(message, body_params)

        return "job_%d" % jobid

    def send_job_and_wait(self, message, body_params=None, timeout=None, raises=False):
        """Send a message as a job and wait for the response.

        .. note::
            Not all messages are jobs, you'll have to find out which are which

        :param message: a message instance
        :type  message: :class:`.Msg`, :class:`.MsgProto`
        :param body_params: a dict with params to the body (only :class:`.MsgProto`)
        :type  body_params: dict
        :param timeout: (optional) seconds to wait
        :type  timeout: :class:`int`
        :param raises: (optional) On timeout if ``False`` return ``None``, else raise :class:`gevent.Timeout`
        :type  raises: :class:`bool`
        :return: response proto message
        :rtype: :class:`.Msg`, :class:`.MsgProto`
        :raises: :class:`gevent.Timeout`
        """
        job_id = self.send_job(message, body_params)
        response = self.wait_event(job_id, timeout, raises=raises)
        if response is None:
            return None
        return response[0].body

    def send_message_and_wait(self, message, response_emsg, body_params=None, timeout=None, raises=False):
        """Send a message to CM and wait for a defined answer.

        :param message: a message instance
        :type  message: :class:`.Msg`, :class:`.MsgProto`
        :param response_emsg: emsg to wait for
        :type  response_emsg: :class:`.EMsg`,:class:`int`
        :param body_params: a dict with params to the body (only :class:`.MsgProto`)
        :type  body_params: dict
        :param timeout: (optional) seconds to wait
        :type  timeout: :class:`int`
        :param raises: (optional) On timeout if ``False`` return ``None``, else raise :class:`gevent.Timeout`
        :type  raises: :class:`bool`
        :return: response proto message
        :rtype: :class:`.Msg`, :class:`.MsgProto`
        :raises: :class:`gevent.Timeout`
        """
        self.send(message, body_params)
        response = self.wait_event(response_emsg, timeout, raises=raises)
        if response is None:
            return None
        return response[0].body

    def _get_sentry_path(self, username):
        if self.credential_location:
            return os.path.join(self.credential_location,
                                "%s_sentry.bin" % username
                                )
        return None

    def get_sentry(self, username):
        """Returns contents of sentry file for the given username

        .. note::
            returns ``None`` if :attr:`credential_location` is not set, or file is not found/inaccessible

        :param username: username
        :type  username: str
        :return: sentry file contents, or ``None``
        :rtype: :class:`bytes`, :class:`None`
        """
        filepath = self._get_sentry_path(username)

        if filepath and os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as f:
                    return f.read()
            except IOError as e:
                self._LOG.error("get_sentry: %s" % str(e))

        return None

    def store_sentry(self, username, sentry_bytes):
        """Store sentry bytes under a username

        :param username: username
        :type  username: str
        :return: Whenver the operation succeed
        :rtype: :class:`bool`
        """
        filepath = self._get_sentry_path(username)
        if filepath:
            try:
                with open(filepath, 'wb') as f:
                    f.write(sentry_bytes)
                return True
            except IOError as e:
                self._LOG.error("store_sentry: %s" % str(e))

        return False

    def _pre_login(self):
        if self.logged_on:
            self._LOG.debug("Trying to login while logged on???")
            raise RuntimeError("Already logged on")

        self.steam_id = None

        if not self.connected and not self._connecting:
            if not self.connect():
                return EResult.Fail

        if not self.channel_secured:
            resp = self.wait_event(self.EVENT_CHANNEL_SECURED, timeout=10)

            # some CMs will not send hello
            if resp is None:
                if self.connected:
                    self.wait_event(self.EVENT_DISCONNECTED)
                return EResult.TryAnotherCM

        return EResult.OK

    @property
    def relogin_available(self):
        """``True`` when the client has the nessesary data for :meth:`relogin`"""
        return bool(self.username) and bool(self.refresh_token)

    def relogin(self):
        """Login without needing credentials, using the stored :attr:`refresh_token`.
        The token is acquired automatically after a successful :meth:`login`.

        .. note::
            Only works when :attr:`relogin_available` is ``True``.

        .. code:: python

            if client.relogin_available: client.relogin()
            else:
                client.login(user, pass)

        :returns: login result
        :rtype: :class:`.EResult`
        """
        if self.relogin_available:
            return self.login(self.username, access_token=self.refresh_token)
        return EResult.Fail

    def login(self, username, password='', auth_code=None, two_factor_code=None,
              login_id=None, access_token=None, machine_auth_token=None):
        """Login as a specific user

        Steam no longer accepts plaintext passwords at the CM. When a ``password`` is supplied
        this method first runs the ``IAuthenticationService`` credential flow (over the CM) to
        obtain a refresh token, then logs on with it. Alternatively a previously obtained
        refresh token can be passed directly via ``access_token``.

        :param username: username
        :type  username: :class:`str`
        :param password: password
        :type  password: :class:`str`
        :param auth_code: email authentication code
        :type  auth_code: :class:`str`
        :param two_factor_code: 2FA authentication code
        :type  two_factor_code: :class:`str`
        :param login_id: number used for identifying logon session
        :type  login_id: :class:`int`
        :param access_token: refresh token (JWT), instead of a password
        :type  access_token: :class:`str`
        :param machine_auth_token: Steam Guard machine auth token from a previous login (see
            :attr:`EVENT_MACHINE_AUTH_TOKEN`); read from :attr:`credential_location` when omitted
        :type  machine_auth_token: :class:`str`
        :return: logon result, see `CMsgClientLogonResponse.eresult <https://github.com/fabieu/steam-next/blob/513c68ca081dc9409df932ad86c66100164380a6/protobufs/steammessages_clientserver.proto#L95-L118>`_
        :rtype: :class:`.EResult`
        :raises RuntimeError: already logged on
        :raises ValueError: ``access_token`` is malformed or not a refresh token minted for the Steam client

        .. note::
            Any failure drops the connection; the next :meth:`login` call reconnects. The ``error``
            event is fired for failures other than a required Steam Guard code or a transient CM error.

        With Steam Guard enabled the ``auth_code_required`` event is fired and the login has to be
        repeated with the code:

        .. code:: python

            @steamclient.on(steamclient.EVENT_AUTH_CODE_REQUIRED)
            def auth_code_prompt(is_2fa, code_mismatch):
                if is_2fa:
                    code = input("Enter 2FA Code: ")
                    steamclient.login(username, password, two_factor_code=code)
                else:
                    code = input("Enter Email Code: ")
                    steamclient.login(username, password, auth_code=code)
        """
        self._LOG.debug("Attempting login")

        eresult = self._pre_login()

        if eresult != EResult.OK:
            return eresult

        if username != self.username:
            # A stored refresh_token / machine auth token belongs to the previous account. Drop
            # them so a failed credential login can't leave a mismatched (username, refresh_token)
            # pair that relogin() would use to log on as the wrong account.
            self.refresh_token = None
            self.machine_auth_token = None

        self.username = username

        if machine_auth_token:
            self.machine_auth_token = machine_auth_token

        token = access_token

        if not token:
            eresult, token, steam_id = self._get_refresh_token(username, password,
                                                               auth_code, two_factor_code)
            if eresult != EResult.OK:
                self.disconnect()
                if eresult not in self._GUARD_CODE_RESULTS + self._TRANSIENT_RESULTS:
                    self.emit(self.EVENT_ERROR, eresult)
                return eresult
        else:
            # A token supplied directly (relogin) carries the account's SteamID in its payload;
            # the logon header needs it, and self.steam_id is empty on a freshly created client.
            steam_id = self._steamid_from_refresh_token(token)

        return self._send_logon(username,
                                access_token=token,
                                login_id=login_id,
                                steam_id=steam_id)

    _GUARD_CODE_RESULTS = (EResult.AccountLogonDenied,
                           EResult.InvalidLoginAuthCode,
                           EResult.AccountLoginDeniedNeedTwoFactor,
                           EResult.TwoFactorCodeMismatch,
                           )
    _TRANSIENT_RESULTS = (EResult.Fail, EResult.ServiceUnavailable, EResult.TryAnotherCM)

    @staticmethod
    def _steamid_from_refresh_token(token):
        """Validate a refresh token and return the :class:`.SteamID` from its ``sub`` claim.

        :raises ValueError: malformed token, not a Steam refresh token (``iss``), or not minted for
            the Steam client (``aud``) -- the CM only accepts client refresh tokens
        """
        claims = _decode_jwt(token)
        if claims.get('iss') != 'steam':
            raise ValueError("Not a Steam refresh token (iss=%r)" % claims.get('iss'))
        if 'client' not in (claims.get('aud') or []):
            raise ValueError("Refresh token is not valid for the Steam client (aud=%r)" % claims.get('aud'))
        return SteamID(claims['sub'])

    def _machine_auth_token_path(self, username):
        if self.credential_location:
            return os.path.join(self.credential_location, "machineAuthToken.%s.txt" % username.lower())
        return None

    def _read_machine_auth_token(self, username):
        """Returns the stored machine auth token for ``username``, or ``None``"""
        filepath = self._machine_auth_token_path(username)

        if filepath and os.path.isfile(filepath):
            try:
                with open(filepath, 'r') as f:
                    return f.read().strip() or None
            except IOError as e:
                self._LOG.error("read machine auth token: %s" % str(e))

        return None

    def _handle_new_machine_auth_token(self, username, token):
        """Remember a machine auth token issued by Steam, persist it and emit :attr:`EVENT_MACHINE_AUTH_TOKEN`"""
        self.machine_auth_token = token
        self.emit(self.EVENT_MACHINE_AUTH_TOKEN, token)

        filepath = self._machine_auth_token_path(username)
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    f.write(token)
            except IOError as e:
                self._LOG.error("store machine auth token: %s" % str(e))

    @staticmethod
    def _eresult(value):
        """Coerce a raw eresult int to :class:`.EResult`, tolerating values our vendored
        enum does not know (Steam occasionally introduces new ones) instead of raising.
        """
        try:
            return EResult(value)
        except ValueError:
            return EResult.Fail

    def _send_auth_um(self, method_name, params):
        """Send an ``IAuthenticationService`` Unified Message and wait for the response.

        Uses ``ServiceMethodCallFromClientNonAuthed`` before logon (``ServiceMethodCallFromClient``
        once logged on), with ``realm`` set to the public universe. Returns ``None`` on timeout
        or if the response body could not be resolved.
        """
        emsg = EMsg.ServiceMethodCallFromClient if self.logged_on else EMsg.ServiceMethodCallFromClientNonAuthed
        message = MsgProto(emsg)
        message.header.target_job_name = method_name
        message.header.realm = 1
        message.body = get_um(method_name)()
        proto_fill_from_dict(message.body, params)

        resp = self.wait_msg(self.send_job(message), timeout=10)

        # A body that failed to resolve to a proto is left as an error string by MsgProto.parse.
        if resp is None or isinstance(resp.body, str):
            return None
        return resp

    def _begin_auth_session(self, username, password):
        """Start a credential auth session.

        Returns the session ``dict`` on success, or an :class:`.EResult` on failure.
        """
        # a ClientHello precedes the credential auth session
        hello = MsgProto(EMsg.ClientHello)
        hello.body.protocol_version = PROTOCOL_VERSION
        self.send(hello)

        rsa = self._send_auth_um('Authentication.GetPasswordRSAPublicKey#1',
                                 {'account_name': username})
        if rsa is None or not rsa.body.publickey_mod:
            return EResult.ServiceUnavailable

        encrypted_password = rsa_encrypt_password(rsa.body.publickey_mod, rsa.body.publickey_exp, password)

        params = {
            'account_name': username,
            'encrypted_password': encrypted_password,
            'encryption_timestamp': rsa.body.timestamp,
            'remember_login': True,
            'persistence': ESessionPersistence.Persistent,
            'website_id': 'Unknown',
            'device_details': {
                'device_friendly_name': self.device_friendly_name,
                'platform_type': EAuthTokenPlatformType.SteamClient,
                'os_type': int(EOSType.Windows11),
                'gaming_device_type': 1,  # desktop PC
                'machine_id': _make_machine_id(username),
            },
        }

        # A machine auth token from a previous login lets Steam skip the guard code; only a
        # token minted for the 'machine' audience is accepted, anything else is left out.
        guard_data = self.machine_auth_token or self._read_machine_auth_token(username)
        if guard_data and _jwt_has_audience(guard_data, 'machine'):
            params['guard_data'] = guard_data

        begin = self._send_auth_um('Authentication.BeginAuthSessionViaCredentials#1', params)
        if begin is None:
            return EResult.ServiceUnavailable
        if not begin.body.client_id:
            # Surface the server's actual verdict (e.g. RateLimitExceeded) rather than
            # blaming the password; fall back to InvalidPassword when it gave none or one
            # our vendored enum does not know.
            try:
                eresult = EResult(begin.header.eresult)
            except ValueError:
                return EResult.InvalidPassword
            return eresult if eresult != EResult.OK else EResult.InvalidPassword

        # Keep the raw guard-type ints; they compare equal to the enum members and an
        # unrecognised type (e.g. a newly added one) must not blow up the login.
        return {
            'username': username,
            'client_id': begin.body.client_id,
            'request_id': begin.body.request_id,
            'steam_id': SteamID(begin.body.steamid),
            'interval': begin.body.interval or 5,
            'allowed_confirmations': [c.confirmation_type for c in begin.body.allowed_confirmations],
        }

    def _get_refresh_token(self, username, password, auth_code=None, two_factor_code=None):
        """Run the credential auth session flow and return ``(EResult, refresh_token, SteamID)``.

        Every call starts a fresh auth session. The allowed confirmations are handled in the
        order the server lists them: no guard, or an accepted code, leads straight to polling
        for the token. A required (or rejected) code fires ``auth_code_required``, the session
        is abandoned and the caller retries with a code. Transport failures, timeouts and
        unknown guard types surface as :attr:`.EResult.ServiceUnavailable`.
        """
        session = self._begin_auth_session(username, password)
        if isinstance(session, EResult):
            return session, None, None

        allowed_confirmations = session['allowed_confirmations']
        code = two_factor_code or auth_code
        poll = False
        actions = []

        for guard_type in allowed_confirmations:
            if guard_type == _GUARD_NONE:
                poll = True
                break
            elif guard_type in (EAuthSessionGuardType.EmailCode, EAuthSessionGuardType.DeviceCode):
                if code:
                    eresult = self._submit_guard_code(session, code)
                    if eresult == EResult.OK:
                        poll = True
                        break
                    if eresult not in (EResult.InvalidLoginAuthCode, EResult.TwoFactorCodeMismatch):
                        return eresult, None, None
                actions.append(guard_type)
            elif guard_type in (EAuthSessionGuardType.DeviceConfirmation,
                                EAuthSessionGuardType.EmailConfirmation):
                actions.append(guard_type)
            elif guard_type == EAuthSessionGuardType.MachineToken:
                pass
            else:
                self._LOG.error("Unknown auth session guard type %r", guard_type)
                return EResult.ServiceUnavailable, None, None

        if not poll:
            if not actions:
                self._LOG.error("Login requires action, but the offered guard types allow none")
                return EResult.ServiceUnavailable, None, None
            return self._auth_code_result(actions, bool(two_factor_code)), None, None

        eresult, token = self._poll_for_refresh_token(session, timeout=30)

        if token:
            return EResult.OK, token, session['steam_id']
        return eresult, None, None

    def _auth_code_result(self, actions, had_two_factor_code):
        """Emit ``auth_code_required`` for the pending guard actions and map them to an :class:`.EResult`.

        An email code is reported as :attr:`.EResult.AccountLogonDenied`; otherwise a rejected
        2FA code as :attr:`.EResult.TwoFactorCodeMismatch` and a missing one as
        :attr:`.EResult.AccountLoginDeniedNeedTwoFactor`.
        """
        if EAuthSessionGuardType.EmailCode in actions:
            result = EResult.AccountLogonDenied
        elif had_two_factor_code:
            result = EResult.TwoFactorCodeMismatch
        else:
            result = EResult.AccountLoginDeniedNeedTwoFactor

        is_2fa = result != EResult.AccountLogonDenied
        code_mismatch = result == EResult.TwoFactorCodeMismatch

        self.emit(self.EVENT_AUTH_CODE_REQUIRED, is_2fa, code_mismatch)
        return result

    def _submit_guard_code(self, session, code):
        """Submit a Steam Guard code to the auth session and return the server's :class:`.EResult`.

        The code type follows the session's allowed confirmations: an email code when the
        session offers one, a device (authenticator) code otherwise.
        """
        if EAuthSessionGuardType.EmailCode in session['allowed_confirmations']:
            code_type = EAuthSessionGuardType.EmailCode
        else:
            code_type = EAuthSessionGuardType.DeviceCode

        update = self._send_auth_um(
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1',
            {'client_id': session['client_id'], 'steamid': session['steam_id'].as_64,
             'code': code, 'code_type': code_type})

        if update is None:
            return EResult.ServiceUnavailable
        return self._eresult(update.header.eresult)

    def _poll_for_refresh_token(self, session, timeout):
        """Poll ``PollAuthSessionStatus`` until a refresh token is minted or ``timeout`` passes.

        Returns ``(EResult, refresh_token)``; the token is ``None`` and the result
        :attr:`.EResult.ServiceUnavailable` on timeout or any poll failure.
        """
        deadline = time() + timeout

        while True:
            poll = self._send_auth_um('Authentication.PollAuthSessionStatus#1',
                                      {'client_id': session['client_id'],
                                       'request_id': session['request_id']})
            if poll is None or poll.header.eresult != EResult.OK:
                self._LOG.debug("PollAuthSessionStatus failed: %r",
                                None if poll is None else self._eresult(poll.header.eresult))
                return EResult.ServiceUnavailable, None
            # Steam can rotate the client_id mid-session; keep polling with the new one.
            if poll.body.new_client_id:
                session['client_id'] = poll.body.new_client_id
            if poll.body.new_guard_data:
                self._handle_new_machine_auth_token(session['username'], poll.body.new_guard_data)
            if poll.body.refresh_token:
                self.emit(self.EVENT_REFRESH_TOKEN, poll.body.refresh_token)
                return EResult.OK, poll.body.refresh_token
            remaining = deadline - time()
            if remaining <= 0:
                return EResult.ServiceUnavailable, None
            # Honour the server interval, but never sleep past the deadline (guards against a
            # bogus/huge interval hanging the login).
            self.sleep(min(session['interval'], remaining))

    def _fill_logon_session_fields(self, message):
        """Add the cell id and the ids remembered from the previous logon to a ``CMsgClientLogon``"""
        if self.cell_id:
            message.body.cell_id = self.cell_id
        if self._last_session_id:
            message.body.last_session_id = self._last_session_id
        if self._client_instance_id:
            message.body.client_instance_id = self._client_instance_id

    def _wait_logon_response(self):
        """Wait for ``ClientLogOnResponse``; the CM occasionally never answers, in which case the
        connection is dropped and :attr:`.EResult.ServiceUnavailable` returned so the caller retries.
        """
        resp = self.wait_msg(EMsg.ClientLogOnResponse, timeout=self.LOGON_TIMEOUT)

        if resp is None:
            self._LOG.debug("Logon message timeout elapsed")
            self.disconnect()
            return EResult.ServiceUnavailable

        eresult = self._eresult(resp.body.eresult)
        if eresult == EResult.OK:
            self.sleep(0.5)
        return eresult

    def _send_logon(self, username, access_token, login_id=None, steam_id=None):
        """Build and send ``CMsgClientLogon`` with a refresh token, waiting for the response.

        The body carries the token in ``access_token`` and an account-derived ``machine_id``;
        no ``account_name`` / password / sentry.
        """
        message = MsgProto(EMsg.ClientLogon)
        message.header.steamid = steam_id if steam_id else SteamID(type='Individual', universe='Public')
        message.body.protocol_version = PROTOCOL_VERSION
        message.body.access_token = access_token
        message.body.should_remember_password = True
        message.body.supports_rate_limit_response = True
        message.body.client_os_type = _detect_os_type()
        message.body.client_language = "english"
        message.body.machine_name = ''
        message.body.chat_mode = self.chat_mode
        message.body.machine_id = _make_machine_id(username)
        message.body.obfuscated_private_ip.v4 = login_id or 0
        self._fill_logon_session_fields(message)

        # The token stays valid whatever the logon result (a rejected token is cleared by
        # _handle_logon), so remember it up front for relogin() and the post-logon tasks.
        self.refresh_token = access_token

        self.send(message)

        return self._wait_logon_response()

    def anonymous_login(self):
        """Login as anonymous user

        :return: logon result, see `CMsgClientLogonResponse.eresult <https://github.com/fabieu/steam-next/blob/513c68ca081dc9409df932ad86c66100164380a6/protobufs/steammessages_clientserver.proto#L95-L118>`_
        :rtype: :class:`.EResult`
        """
        self._LOG.debug("Attempting Anonymous login")

        eresult = self._pre_login()

        if eresult != EResult.OK:
            return eresult

        self.username = None
        self.refresh_token = None

        message = MsgProto(EMsg.ClientLogon)
        message.header.steamid = SteamID(type='AnonUser', universe='Public')
        message.body.protocol_version = PROTOCOL_VERSION
        message.body.anon_user_target_account_name = 'anonymous'
        message.body.should_remember_password = False
        message.body.supports_rate_limit_response = False
        message.body.client_os_type = _detect_os_type()
        message.body.client_language = ''
        message.body.machine_name = ''
        message.body.chat_mode = self.chat_mode
        message.body.obfuscated_private_ip.v4 = 0
        self._fill_logon_session_fields(message)
        self.send(message)

        return self._wait_logon_response()

    def _post_logon(self):
        """After a user logon: renew the refresh token when enabled, then negotiate a web session"""
        if self.renew_refresh_tokens and self.refresh_token:
            self._renew_refresh_token()

        session = self.get_web_session()
        if session is not None:
            self.emit(self.EVENT_WEB_SESSION, session)

    def _renew_refresh_token(self):
        """Ask Steam for a fresh refresh token; on success it replaces :attr:`refresh_token` and
        :attr:`EVENT_REFRESH_TOKEN` is emitted.
        """
        resp = self.send_um_and_wait('Authentication.GenerateAccessTokenForApp#1',
                                     {'refresh_token': self.refresh_token,
                                      'steamid': self.steam_id.as_64,
                                      'renewal_type': ETokenRenewalType.Allow})

        renewed = (resp is not None and resp.header.eresult == EResult.OK
                   and bool(resp.body.refresh_token))
        self._LOG.debug("Attempted to renew refresh token, success = %s", renewed)

        if renewed:
            self.refresh_token = resp.body.refresh_token
            self.emit(self.EVENT_REFRESH_TOKEN, self.refresh_token)

    def logout(self):
        """
        Logout from steam. Doesn't nothing if not logged on.

        .. note::
            The server will drop the connection immediatelly upon logout.
        """
        if self.logged_on:
            self.send(MsgProto(EMsg.ClientLogOff))
            self.logged_on = False
            try:
                self.wait_event(self.EVENT_DISCONNECTED, timeout=5, raises=True)
            except:
                self.disconnect()
            self.idle()

    def run_forever(self):
        """
        Transfer control the gevent event loop

        This is useful when the application is setup and ment to run for a long time
        """
        while True:
            self.sleep(300)

    def cli_login(self, username='', password=''):
        """Generates CLI prompts to complete the login process

        :param username: optionally provide username
        :type  username: :class:`str`
        :param password: optionally provide password
        :type  password: :class:`str`
        :return: logon result, see `CMsgClientLogonResponse.eresult <https://github.com/fabieu/steam-next/blob/513c68ca081dc9409df932ad86c66100164380a6/protobufs/steammessages_clientserver.proto#L95-L118>`_
        :rtype: :class:`.EResult`

        Example console output after calling :meth:`cli_login`

        .. code:: python

            In [5]: client.cli_login()
            Steam username: myusername
            Password:
            Steam is down. Keep retrying? [y/n]: y
            Invalid password for 'myusername'. Enter password:
            Enter email code: 123
            Enter email code: K6VKF
            Out[5]: <EResult.OK: 1>
        """
        if not username:
            username = input("Username: ")
        if not password:
            password = getpass()

        auth_code = two_factor_code = None
        prompt_for_unavailable = True

        result = self.login(username, password)

        while result in self._GUARD_CODE_RESULTS + (EResult.TryAnotherCM,
                                                    EResult.ServiceUnavailable,
                                                    EResult.InvalidPassword,
                                                    ):
            self.sleep(0.1)

            if result == EResult.InvalidPassword:
                password = getpass("Invalid password for %s. Enter password: " % repr(username))

            elif result in (EResult.TryAnotherCM, EResult.ServiceUnavailable):
                keep_going, prompt_for_unavailable = self._cli_handle_unavailable(
                    result, prompt_for_unavailable)
                if not keep_going:
                    break

            else:
                auth_code, two_factor_code = self._cli_prompt_guard_code(result)

            result = self.login(username, password, auth_code, two_factor_code)

        return result

    def _cli_prompt_guard_code(self, result):
        """Prompt for a Steam Guard code for :meth:`cli_login`.

        :return: ``(auth_code, two_factor_code)``; exactly one carries the value entered
        """
        if result in (EResult.AccountLogonDenied, EResult.InvalidLoginAuthCode):
            prompt = ("Enter email code: " if result == EResult.AccountLogonDenied else
                      "Incorrect code. Enter email code: ")
            return input(prompt), None

        prompt = ("Enter 2FA code: " if result == EResult.AccountLoginDeniedNeedTwoFactor else
                  "Incorrect code. Enter 2FA code: ")
        return None, input(prompt)

    def _cli_handle_unavailable(self, result, prompt_for_unavailable):
        """Handle a transient CM error for :meth:`cli_login` by reconnecting.

        On the first :attr:`EResult.ServiceUnavailable` the user is asked once whether
        to keep retrying.

        :return: ``(keep_going, prompt_for_unavailable)`` where ``keep_going`` is
            :class:`False` when the user declined to keep retrying.
        """
        if prompt_for_unavailable and result == EResult.ServiceUnavailable:
            while True:
                answer = input("Steam is down. Keep retrying? [y/n]: ").lower()
                if answer in ('y', 'n'): break

            prompt_for_unavailable = False
            if answer == 'n':
                return False, prompt_for_unavailable

        self.reconnect(maxdelay=15)  # implements reconnect throttling
        return True, prompt_for_unavailable
