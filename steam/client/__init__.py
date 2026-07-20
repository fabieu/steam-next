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
import json
import logging
import os
import socket
from base64 import urlsafe_b64decode
from getpass import getpass
from io import open
from random import random
from time import time

import gevent

from steam import __appname__
from steam.client.builtins import BuiltinBase
from steam.core.cm import CMClient
from steam.core.crypto import sha1_hash, rsa_encrypt_password
from steam.core.msg import MsgProto
from steam.enums import EResult, EOSType, ETransport
from steam.enums.emsg import EMsg
from steam.enums.proto import EAuthSessionGuardType, EAuthTokenPlatformType
from steam.steamid import SteamID
from steam.utils import ip4_from_int, ip4_to_int
from steam.utils.proto import proto_fill_from_dict


class SteamClient(CMClient, BuiltinBase):
    EVENT_LOGGED_ON = 'logged_on'
    """After successful login"""

    EVENT_AUTH_CODE_REQUIRED = 'auth_code_required'
    """When either email or 2FA code is needed for login"""

    _LOG = logging.getLogger("SteamClient")
    _reconnect_backoff_c = 0
    current_jobid = 0
    credential_location = None  #: location for sentry
    username = None  #: username when logged on
    refresh_token = None  #: JWT refresh token, acquired on login and usable via :meth:`relogin`
    chat_mode = 2  #: chat mode (0=old chat, 2=new chat)
    confirmation_timeout = 60  #: seconds to wait for a device/email confirmation approval

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

        #: pending credential auth session, reused across login() calls while a guard code
        #: is being collected (see :meth:`_get_refresh_token`)
        self._auth_session = None

        #: greenlet polling for an out-of-band confirmation while a code is being collected
        self._confirm_greenlet = None

        #: friendly name reported to Steam during the auth session
        hostname = socket.gethostname() or __appname__
        self.device_friendly_name = "%s (%s)" % (hostname, __appname__)

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
        self._cancel_confirmation()

    def _handle_logon(self, msg):
        CMClient._handle_logon(self, msg)

        result = self._eresult(msg.body.eresult)

        if result == EResult.OK:
            self._reconnect_backoff_c = 0
            self.logged_on = True
            self.emit(self.EVENT_LOGGED_ON)
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
        else:
            if body_params and isinstance(message, MsgProto):
                proto_fill_from_dict(message.body, body_params)

            CMClient.send(self, message)

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
              login_id=None, access_token=None):
        """Login as a specific user

        Steam no longer accepts plaintext passwords at the CM. When a ``password`` is supplied
        this method first runs the ``IAuthenticationService`` credential flow (over the CM) to
        obtain a refresh token, then logs on with it. Alternatively a previously obtained
        refresh token can be passed directly via ``access_token``.

        When the account can be approved out-of-band (Steam mobile app / email link), the flow
        waits up to :attr:`confirmation_timeout` seconds for that approval before falling back
        to asking for a Steam Guard code.

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
        :return: logon result, see `CMsgClientLogonResponse.eresult <https://github.com/fabieu/steam-next/blob/513c68ca081dc9409df932ad86c66100164380a6/protobufs/steammessages_clientserver.proto#L95-L118>`_
        :rtype: :class:`.EResult`

        .. note::
            Failure to login will result in the server dropping the connection, ``error`` event is fired

        With Steam Guard enabled, first call ``login(username, password)`` and approve the login
        in your Steam mobile app; it blocks up to :attr:`confirmation_timeout` seconds. If you
        don't approve in time, the ``auth_code_required`` event is fired so you can supply a code.

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

        # A background confirmation poll may already have logged us on for this account.
        # A login for a different account must still fall through to _pre_login (which
        # rejects logging in while already logged on).
        if self.logged_on and username == self.username:
            return EResult.OK

        # This attempt supersedes any background confirmation poll from a previous one.
        self._cancel_confirmation()

        eresult = self._pre_login()

        if eresult != EResult.OK:
            return eresult

        if username != self.username:
            # A stored refresh_token / pending auth session belongs to the previous account.
            # Drop both so a failed credential login can't leave a mismatched
            # (username, refresh_token) pair that relogin() would use to log on as the wrong
            # account, and so we never reuse a stale auth session across an account switch.
            self.refresh_token = None
            self._auth_session = None

        self.username = username

        token = access_token

        if not token:
            eresult, token, steam_id = self._get_refresh_token(username, password,
                                                               auth_code, two_factor_code,
                                                               login_id)
            if eresult != EResult.OK:
                return eresult
        else:
            # A token supplied directly (relogin) carries the account's SteamID in its payload;
            # the logon header needs it, and self.steam_id is empty on a freshly created client.
            steam_id = self._steamid_from_access_token(token)

        return self._send_logon(username,
                                access_token=token,
                                login_id=login_id,
                                steam_id=steam_id)

    @staticmethod
    def _steamid_from_access_token(token):
        """Extract the :class:`.SteamID` from the ``sub`` claim of a Steam JWT access token.

        Returns ``None`` if the token cannot be parsed, letting :meth:`_send_logon` fall back to
        a generic SteamID.
        """
        try:
            payload = token.split('.')[1]
            payload += '=' * (-len(payload) % 4)  # restore base64url padding
            claims = json.loads(urlsafe_b64decode(payload))
            return SteamID(claims['sub'])
        except Exception:
            return None

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
        """Send a pre-logon ``IAuthenticationService`` Unified Message and wait for the response.

        Returns ``None`` on timeout or if the response body could not be resolved to a proto.
        """
        resp = self.send_um_and_wait(method_name, params,
                                     emsg=EMsg.ServiceMethodCallFromClientNonAuthed)

        # A body that failed to resolve to a proto is left as an error string by MsgProto.parse.
        if resp is None or isinstance(resp.body, str):
            return None
        return resp

    def _auth_code_result(self, allowed_confirmations, code_mismatch):
        """Emit ``auth_code_required`` and map the pending guard type to an :class:`.EResult`.

        Only reached when a code-based guard is offered, so the choice is purely between an
        authenticator code (:attr:`.EAuthSessionGuardType.DeviceCode`) and an email code.
        """
        is_2fa = EAuthSessionGuardType.DeviceCode in allowed_confirmations

        self.emit(self.EVENT_AUTH_CODE_REQUIRED, is_2fa, code_mismatch)

        if is_2fa:
            return EResult.TwoFactorCodeMismatch if code_mismatch else EResult.AccountLoginDeniedNeedTwoFactor
        return EResult.InvalidLoginAuthCode if code_mismatch else EResult.AccountLogonDenied

    def _begin_auth_session(self, username, password):
        """Start a fresh credential auth session and cache it on :attr:`_auth_session`.

        Returns the session ``dict`` on success, or an :class:`.EResult` on failure.
        """
        rsa = self._send_auth_um('Authentication.GetPasswordRSAPublicKey#1',
                                 {'account_name': username})
        if rsa is None or not rsa.body.publickey_mod:
            return EResult.Fail

        encrypted_password = rsa_encrypt_password(rsa.body.publickey_mod, rsa.body.publickey_exp, password)

        begin = self._send_auth_um('Authentication.BeginAuthSessionViaCredentials#1', {
            'device_friendly_name': self.device_friendly_name,
            'account_name': username,
            'encrypted_password': encrypted_password,
            'encryption_timestamp': rsa.body.timestamp,
            'remember_login': True,
            'platform_type': EAuthTokenPlatformType.SteamClient,
            'website_id': 'Client',
            'device_details': {
                'device_friendly_name': self.device_friendly_name,
                'platform_type': EAuthTokenPlatformType.SteamClient,
                'os_type': int(EOSType.Windows10),
            },
        })
        if begin is None:
            return EResult.Fail
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
        self._auth_session = {
            'username': username,
            'password': password,
            'client_id': begin.body.client_id,
            'request_id': begin.body.request_id,
            'steam_id': SteamID(begin.body.steamid),
            'interval': begin.body.interval or 5,
            'allowed_confirmations': [c.confirmation_type for c in begin.body.allowed_confirmations],
        }
        return self._auth_session

    def _get_refresh_token(self, username, password, auth_code=None, two_factor_code=None,
                           login_id=None):
        """Run the credential auth session flow and return ``(EResult, refresh_token, SteamID)``.

        The refresh token is minted for the ``SteamClient`` platform so it is valid for a full
        CM logon. When a Steam Guard code is needed the ``auth_code_required`` event is emitted
        and a matching :class:`.EResult` is returned; if the account can *also* be approved
        out-of-band, a background greenlet keeps polling so the user can just tap *Approve* in
        the Steam mobile app instead of entering a code, in which case it completes the logon.
        """
        code = two_factor_code or auth_code

        # Reuse the session opened by a previous login() attempt for this user, so retries and
        # code submissions hit the same session instead of triggering a fresh email / push.
        # A changed password can't be applied to an already-open session, so that also forces
        # a fresh one.
        session = self._auth_session
        if not (session and session['username'] == username and session['password'] == password):
            session = self._begin_auth_session(username, password)
            if isinstance(session, EResult):
                return session, None, None

        allowed_confirmations = session['allowed_confirmations']

        # A rejected code is surfaced immediately; keep the session so the caller can retry
        # with a new code without opening a new one (which would send another email).
        if code and not self._submit_guard_code(session, code, is_2fa=bool(two_factor_code)):
            return self._auth_code_result(allowed_confirmations, code_mismatch=True), None, None

        needs_code = (EAuthSessionGuardType.DeviceCode in allowed_confirmations
                      or EAuthSessionGuardType.EmailCode in allowed_confirmations)
        can_confirm = (EAuthSessionGuardType.DeviceConfirmation in allowed_confirmations
                       or EAuthSessionGuardType.EmailConfirmation in allowed_confirmations)

        if not code and needs_code:
            return self._request_guard_code(session, username, login_id,
                                            allowed_confirmations, can_confirm)

        # Poll for the token: a confirmation-only guard gets the full approval window; a supplied
        # code / no guard just needs the (near-instant) mint.
        timeout = self.confirmation_timeout if (not code and can_confirm) else 30
        token = self._poll_for_refresh_token(session, timeout=timeout)

        if token:
            self._auth_session = None
            return EResult.OK, token, session['steam_id']

        # Timed out without a token: a transient issue (or an un-approved confirmation) the
        # caller can retry — not a wrong code.
        return EResult.Fail, None, None

    def _request_guard_code(self, session, username, login_id, allowed_confirmations, can_confirm):
        """Ask the caller for a Steam Guard code.

        If the account can also be approved out-of-band, keep polling for that approval in the
        background so the user can just tap *Approve* instead of entering a code.
        """
        if can_confirm:
            self._start_confirmation(session, username, login_id)
        return self._auth_code_result(allowed_confirmations, code_mismatch=False), None, None

    def _start_confirmation(self, session, username, login_id):
        """Spawn a background poll that completes the logon if the login is approved out-of-band."""
        self._cancel_confirmation()
        self._confirm_greenlet = gevent.spawn(self._background_confirmation,
                                              session, username, login_id)

    def _cancel_confirmation(self):
        """Stop any running background confirmation poll."""
        if self._confirm_greenlet is not None:
            self._confirm_greenlet.kill()
            self._confirm_greenlet = None

    def _background_confirmation(self, session, username, login_id):
        """Poll for an out-of-band approval and, if it arrives, complete the CM logon."""
        try:
            token = self._poll_for_refresh_token(session, timeout=self.confirmation_timeout)
            if token and not self.logged_on:
                self._auth_session = None
                self._send_logon(username, access_token=token, login_id=login_id,
                                 steam_id=session['steam_id'])
        finally:
            # Only clear the handle if it still points at us; a newer login() may have
            # already replaced it with a fresh poll that must not be orphaned.
            if self._confirm_greenlet is gevent.getcurrent():
                self._confirm_greenlet = None

    def _await_confirmation(self):
        """Block until a pending out-of-band approval completes the logon.

        While a background confirmation poll started by a previous :meth:`login` call is
        running (the account can be approved via the Steam Mobile app / email link), this
        leaves the gevent hub free so that poll can finish. Returns ``True`` if the logon
        completed, ``False`` if there was nothing to wait for or the approval did not
        arrive within :attr:`confirmation_timeout`.
        """
        if self.logged_on:
            return True
        if self._confirm_greenlet is None:
            return False
        self.wait_event(self.EVENT_LOGGED_ON, timeout=self.confirmation_timeout + 30)
        return self.logged_on

    def _submit_guard_code(self, session, code, is_2fa):
        """Submit a Steam Guard code to the auth session.

        Returns ``True`` when the code was accepted, ``False`` when it was rejected or the
        submission could not be confirmed (e.g. the request timed out).
        """
        code_type = EAuthSessionGuardType.DeviceCode if is_2fa else EAuthSessionGuardType.EmailCode
        update = self._send_auth_um(
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1',
            {'client_id': session['client_id'], 'steamid': session['steam_id'].as_64,
             'code': code, 'code_type': code_type})

        return update is not None and update.header.eresult == EResult.OK

    def _poll_for_refresh_token(self, session, timeout):
        """Poll ``PollAuthSessionStatus`` until a refresh token is minted or ``timeout`` passes.

        Returns the refresh token, or ``None`` on timeout / failure.
        """
        deadline = time() + timeout

        while True:
            poll = self._send_auth_um('Authentication.PollAuthSessionStatus#1',
                                      {'client_id': session['client_id'],
                                       'request_id': session['request_id']})
            if poll is None:
                return None
            if poll.body.refresh_token:
                return poll.body.refresh_token
            # Steam can rotate the client_id mid-session; keep polling with the new one.
            if poll.body.new_client_id:
                session['client_id'] = poll.body.new_client_id
            remaining = deadline - time()
            if remaining <= 0:
                return None
            # Honour the server interval, but never sleep past the deadline (guards against a
            # bogus/huge interval hanging the login).
            self.sleep(min(session['interval'], remaining))

    def _send_logon(self, username, access_token, login_id=None, steam_id=None):
        """Build and send ``CMsgClientLogon``, waiting for the response."""
        message = MsgProto(EMsg.ClientLogon)
        message.header.steamid = steam_id if steam_id else SteamID(type='Individual', universe='Public')
        message.body.protocol_version = 65580
        message.body.client_package_version = 1561159470
        message.body.client_os_type = EOSType.Windows10
        message.body.client_language = "english"
        message.body.should_remember_password = True
        message.body.supports_rate_limit_response = True
        message.body.chat_mode = self.chat_mode

        if login_id is None:
            message.body.obfuscated_private_ip.v4 = ip4_to_int(self.connection.local_address) ^ 0xF00DBAAD
        else:
            message.body.obfuscated_private_ip.v4 = login_id

        message.body.account_name = username
        message.body.access_token = access_token

        sentry = self.get_sentry(username)
        if sentry is None:
            message.body.eresult_sentryfile = EResult.FileNotFound
        else:
            message.body.eresult_sentryfile = EResult.OK
            message.body.sha_sentryfile = sha1_hash(sentry)

        self.send(message)

        resp = self.wait_msg(EMsg.ClientLogOnResponse, timeout=30)

        if resp and resp.body.eresult == EResult.OK:
            self.refresh_token = access_token
            self._auth_session = None
            self.sleep(0.5)

        return self._eresult(resp.body.eresult) if resp else EResult.Fail

    def anonymous_login(self):
        """Login as anonymous user

        :return: logon result, see `CMsgClientLogonResponse.eresult <https://github.com/fabieu/steam-next/blob/513c68ca081dc9409df932ad86c66100164380a6/protobufs/steammessages_clientserver.proto#L95-L118>`_
        :rtype: :class:`.EResult`
        """
        self._LOG.debug("Attempting Anonymous login")

        self._cancel_confirmation()

        eresult = self._pre_login()

        if eresult != EResult.OK:
            return eresult

        self.username = None
        self.refresh_token = None

        message = MsgProto(EMsg.ClientLogon)
        message.header.steamid = SteamID(type='AnonUser', universe='Public')
        message.body.client_package_version = 1561159470
        message.body.protocol_version = 65580
        self.send(message)

        resp = self.wait_msg(EMsg.ClientLogOnResponse, timeout=30)
        return self._eresult(resp.body.eresult) if resp else EResult.Fail

    def logout(self):
        """
        Logout from steam. Doesn't nothing if not logged on.

        .. note::
            The server will drop the connection immediatelly upon logout.
        """
        if self.logged_on:
            self.logged_on = False
            self.send(MsgProto(EMsg.ClientLogOff))
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

    def cli_login(self, username='', password='', wait_for_confirmation=True):
        """Generates CLI prompts to complete the login process

        :param username: optionally provide username
        :type  username: :class:`str`
        :param password: optionally provide password
        :type  password: :class:`str`
        :param wait_for_confirmation: when the account can be approved out-of-band (Steam
            Mobile app / email link), wait up to :attr:`confirmation_timeout` seconds for
            that approval before prompting for a Steam Guard code. Set to :class:`False`
            to always prompt for a code immediately.
        :type  wait_for_confirmation: :class:`bool`
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
            Incorrect code. Enter email code: K6VKF
            Out[5]: <EResult.OK: 1>
        """
        if not username:
            username = input("Username: ")
        if not password:
            password = getpass()

        auth_code = two_factor_code = None
        prompt_for_unavailable = True

        result = self.login(username, password)

        while result in (EResult.AccountLogonDenied, EResult.InvalidLoginAuthCode,
                         EResult.AccountLoginDeniedNeedTwoFactor, EResult.TwoFactorCodeMismatch,
                         EResult.TryAnotherCM, EResult.ServiceUnavailable,
                         EResult.InvalidPassword,
                         ):
            self.sleep(0.1)

            # A background out-of-band confirmation may have completed the logon while we
            # yielded above; don't prompt for a code we no longer need.
            if self.logged_on:
                return EResult.OK

            if result == EResult.InvalidPassword:
                password = getpass("Invalid password for %s. Enter password: " % repr(username))

            elif result in (EResult.TryAnotherCM, EResult.ServiceUnavailable):
                keep_going, prompt_for_unavailable = self._cli_handle_unavailable(
                    result, prompt_for_unavailable)
                if not keep_going:
                    break

            else:
                confirmed, auth_code, two_factor_code = self._cli_prompt_guard_code(
                    result, wait_for_confirmation)
                if confirmed:
                    return EResult.OK

            result = self.login(username, password, auth_code, two_factor_code)

        return result

    def _cli_prompt_guard_code(self, result, wait_for_confirmation):
        """Confirm the sign in out-of-band or prompt for a Steam Guard code.

        Handles the email-code and Steam Mobile 2FA cases for :meth:`cli_login`.

        :return: ``(confirmed, auth_code, two_factor_code)`` where ``confirmed`` is
            :class:`True` when the login was approved out-of-band; otherwise exactly
            one of the codes carries the value entered at the prompt.
        """
        email = result in (EResult.AccountLogonDenied, EResult.InvalidLoginAuthCode)

        message = ("Approve the sign in via the link in your Steam email, or wait to enter a code..."
                   if email else
                   "Approve the sign in on your Steam Mobile app, or wait to enter a code...")
        if wait_for_confirmation and self._confirm_greenlet is not None:
            print(message)
            if self._await_confirmation():
                return True, None, None

        if email:
            prompt = ("Enter email code: " if result == EResult.AccountLogonDenied else
                      "Incorrect code. Enter email code: ")
            return False, input(prompt), None

        prompt = ("Enter 2FA code: " if result == EResult.AccountLoginDeniedNeedTwoFactor else
                  "Incorrect code. Enter 2FA code: ")
        return False, None, input(prompt)

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
