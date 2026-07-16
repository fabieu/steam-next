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
from getpass import getpass
from io import open
from random import random
from time import time

from steam import __appname__
from steam.client.builtins import BuiltinBase
from steam.core.cm import CMClient
from steam.core.crypto import sha1_hash, rsa_encrypt_password
from steam.core.msg import MsgProto
from steam.enums import EResult, EOSType
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

    def __init__(self):
        CMClient.__init__(self)

        # register listeners
        self.on(self.EVENT_DISCONNECTED, self._handle_disconnect)
        self.on(self.EVENT_RECONNECT, self._handle_disconnect)
        self.on(EMsg.ClientUpdateMachineAuth, self._handle_update_machine_auth)

        #: indicates logged on status. Listen to ``logged_on`` when change to ``True``
        self.logged_on = False

        #: pending credential auth session, reused across login() calls while a guard code
        #: is being collected (see :meth:`_get_refresh_token`)
        self._auth_session = None

        #: friendly name reported to Steam during the auth session
        try:
            hostname = socket.gethostname() or __appname__
        except Exception:
            hostname = __appname__
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
            self.cm_servers.clear()
            self.cm_servers.merge_list(data['servers'])
            self.cm_servers.last_updated = data.get('last_updated', 0)
            self.cell_id = self.cm_servers.cell_id = data.get('cell_id', 0)

    def _handle_cm_list(self, msg):
        if (self.cm_servers.last_updated + 3600 * 24 > time()
                and self.cm_servers.cell_id != 0):
            return

        CMClient._handle_cm_list(self, msg)  # clear and merge

        if self.credential_location:
            filepath = os.path.join(self.credential_location, 'cm_servers.json')

            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                except ValueError:
                    self._LOG.error("Failed parsing %s", repr(filepath))
                except IOError as e:
                    self._LOG.error("Failed reading %s (%s)", repr(filepath), str(e))
                else:
                    if data.get('last_updated', 0) + 3600 * 24 > time():
                        return

                self._LOG.debug("Persisted CM server list is stale")

            data = {
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

        result = EResult(msg.body.eresult)

        if result == EResult.OK:
            self._reconnect_backoff_c = 0
            self.logged_on = True
            self.emit(self.EVENT_LOGGED_ON)
            return

        # CM kills the connection on error anyway
        self.disconnect()

        if result == EResult.InvalidPassword:
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

        ``auth_code_required`` event is fired when 2FA or Email code is needed.
        Here is example code of how to handle the situation.

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

        self.username = username

        token = access_token
        steam_id = None

        if not token:
            eresult, token, steam_id = self._get_refresh_token(username, password,
                                                               auth_code, two_factor_code)
            if eresult != EResult.OK:
                return eresult

        return self._send_logon(username,
                                access_token=token,
                                login_id=login_id,
                                steam_id=steam_id)

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
        if begin is None or not begin.body.client_id:
            return EResult.InvalidPassword

        # Keep the raw guard-type ints; they compare equal to the enum members and an
        # unrecognised type (e.g. a newly added one) must not blow up the login.
        self._auth_session = {
            'username': username,
            'client_id': begin.body.client_id,
            'request_id': begin.body.request_id,
            'steam_id': SteamID(begin.body.steamid),
            'interval': begin.body.interval or 5,
            'allowed_confirmations': [c.confirmation_type for c in begin.body.allowed_confirmations],
        }
        return self._auth_session

    def _get_refresh_token(self, username, password, auth_code=None, two_factor_code=None):
        """Run the credential auth session flow and return ``(EResult, refresh_token, SteamID)``.

        The refresh token is minted for the ``SteamClient`` platform so it is valid for a full
        CM logon. When a Steam Guard code is required but not provided (or rejected) the
        ``auth_code_required`` event is emitted and a matching :class:`.EResult` is returned.
        """
        code = two_factor_code or auth_code

        # Reuse the session opened by a previous login() attempt when the caller is now
        # supplying the guard code we asked for. Beginning a new session would (for email
        # guard) send a fresh code and invalidate the one the user just entered.
        session = self._auth_session
        if not (code and session and session['username'] == username):
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

        # A guard code is required and none was supplied: ask for it immediately instead of
        # blocking on an out-of-band confirmation the caller may not be able to complete.
        if needs_code and not code:
            return self._auth_code_result(allowed_confirmations, code_mismatch=False), None, None

        # Poll for the refresh token. When the only option is out-of-band confirmation (mobile
        # app), keep polling for a while so the user has time to approve the login. A supplied
        # code is validated synchronously above, so a comfortable window keeps a slow token
        # mint from being mistaken for a bad code.
        wait_for_confirmation = can_confirm and not code
        token = self._poll_for_refresh_token(session, timeout=60 if wait_for_confirmation else 30)

        if token:
            self._auth_session = None
            return EResult.OK, token, session['steam_id']

        # Timed out without a token: a transient issue (or an un-approved confirmation) the
        # caller can retry — not a wrong code.
        return EResult.Fail, None, None

    def _submit_guard_code(self, session, code, is_2fa):
        """Submit a Steam Guard code to the auth session.

        Returns ``True`` when the code was accepted (or the server gave no verdict), ``False``
        when it was rejected.
        """
        code_type = EAuthSessionGuardType.DeviceCode if is_2fa else EAuthSessionGuardType.EmailCode
        update = self._send_auth_um(
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1',
            {'client_id': session['client_id'], 'steamid': session['steam_id'].as_64,
             'code': code, 'code_type': code_type})

        return update is None or update.header.eresult == EResult.OK

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

        return EResult(resp.body.eresult) if resp else EResult.Fail

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
        message.body.client_package_version = 1561159470
        message.body.protocol_version = 65580
        self.send(message)

        resp = self.wait_msg(EMsg.ClientLogOnResponse, timeout=30)
        return EResult(resp.body.eresult) if resp else EResult.Fail

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

            if result == EResult.InvalidPassword:
                password = getpass("Invalid password for %s. Enter password: " % repr(username))

            elif result in (EResult.AccountLogonDenied, EResult.InvalidLoginAuthCode):
                prompt = ("Enter email code: " if result == EResult.AccountLogonDenied else
                          "Incorrect code. Enter email code: ")
                auth_code, two_factor_code = input(prompt), None

            elif result in (EResult.AccountLoginDeniedNeedTwoFactor, EResult.TwoFactorCodeMismatch):
                prompt = ("Enter 2FA code: " if result == EResult.AccountLoginDeniedNeedTwoFactor else
                          "Incorrect code. Enter 2FA code: ")
                auth_code, two_factor_code = None, input(prompt)

            elif result in (EResult.TryAnotherCM, EResult.ServiceUnavailable):
                if prompt_for_unavailable and result == EResult.ServiceUnavailable:
                    while True:
                        answer = input("Steam is down. Keep retrying? [y/n]: ").lower()
                        if answer in 'yn': break

                    prompt_for_unavailable = False
                    if answer == 'n': break

                self.reconnect(maxdelay=15)  # implements reconnect throttling

            result = self.login(username, password, auth_code, two_factor_code)

        return result
