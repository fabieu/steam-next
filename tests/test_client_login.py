import unittest
from types import SimpleNamespace

from mock import patch, MagicMock

from steam.client import SteamClient
from steam.enums import EResult
from steam.enums.emsg import EMsg
from steam.enums.proto import EAuthSessionGuardType
from steam.steamid import SteamID

DEVICE_CODE = EAuthSessionGuardType.DeviceCode
EMAIL_CODE = EAuthSessionGuardType.EmailCode
DEVICE_CONFIRMATION = EAuthSessionGuardType.DeviceConfirmation

STEAMID64 = SteamID('76561197960287930').as_64


def resp(eresult=EResult.OK, **body):
    return SimpleNamespace(header=SimpleNamespace(eresult=int(eresult)),
                           body=SimpleNamespace(**body))


def confirmations(*types):
    return [SimpleNamespace(confirmation_type=int(t)) for t in types]


def rsa_resp():
    return resp(publickey_mod='ab', publickey_exp='11', timestamp=123)


def begin_resp(allowed, client_id=5):
    return resp(client_id=client_id, request_id=b'req', steamid=STEAMID64,
                allowed_confirmations=allowed, interval=5)


def poll_resp(refresh_token='', new_client_id=0):
    return resp(refresh_token=refresh_token, new_client_id=new_client_id)


class RefreshTokenFlow(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        # avoid real crypto and real sleeps
        p = patch('steam.client.rsa_encrypt_password', return_value='ENCPW')
        self.addCleanup(p.stop); p.start()
        self.client.sleep = MagicMock()
        self.client.emit = MagicMock()

    def assertAuthCodeEvent(self, is_2fa, code_mismatch):
        self.client.emit.assert_called_once_with(
            self.client.EVENT_AUTH_CODE_REQUIRED, is_2fa, code_mismatch)

    def assertNoAuthCodeEvent(self):
        self.client.emit.assert_not_called()

    def stub(self, responses):
        def dispatch(method_name, params):
            return responses[method_name].pop(0)
        self.client._send_auth_um = MagicMock(side_effect=dispatch)

    def test_success_without_guard(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations())],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })

        result, token, steam_id = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')
        self.assertEqual(steam_id.as_64, STEAMID64)
        self.assertNoAuthCodeEvent()

    def test_invalid_password(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(), client_id=0)],
        })

        result, token, _ = self.client._get_refresh_token('user', 'bad')

        self.assertEqual(result, EResult.InvalidPassword)
        self.assertIsNone(token)

    def test_needs_2fa_code(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='')],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.AccountLoginDeniedNeedTwoFactor)
        self.assertIsNone(token)
        self.assertAuthCodeEvent(True, False)

    def test_needs_email_code(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(EMAIL_CODE))],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='')],
        })

        result, _, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.AccountLogonDenied)
        self.assertAuthCodeEvent(False, False)

    def test_2fa_code_accepted(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.OK)],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='ABCDE')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')
        self.assertNoAuthCodeEvent()

    def test_2fa_code_rejected(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.TwoFactorCodeMismatch)],
        })

        result, _, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='WRONG')

        self.assertEqual(result, EResult.TwoFactorCodeMismatch)
        self.assertAuthCodeEvent(True, True)

    def test_device_confirmation_polls_until_approved(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CONFIRMATION))],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token=''), poll_resp(refresh_token='TOK')],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')
        self.client.sleep.assert_called()

    def called_methods(self):
        return [c.args[0] for c in self.client._send_auth_um.call_args_list]

    def test_authenticator_asks_for_code_and_polls_in_background(self):
        # Account with the mobile authenticator offers both a code and app-confirmation:
        # ask for a code immediately, and start a background poll for the phone approval.
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [
                begin_resp(confirmations(DEVICE_CODE, DEVICE_CONFIRMATION))],
        })
        self.client._start_confirmation = MagicMock()

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.AccountLoginDeniedNeedTwoFactor)
        self.assertIsNone(token)
        self.assertAuthCodeEvent(True, False)
        self.client._start_confirmation.assert_called_once()

    def test_background_confirmation_completes_logon_on_approval(self):
        session = {'username': 'user', 'client_id': 5, 'request_id': b'req',
                   'steam_id': SteamID(STEAMID64), 'interval': 5,
                   'allowed_confirmations': confirmations(DEVICE_CONFIRMATION)}
        self.stub({'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')]})
        self.client._send_logon = MagicMock()

        self.client._background_confirmation(session, 'user', login_id=0)

        self.client._send_logon.assert_called_once()
        self.assertEqual(self.client._send_logon.call_args.kwargs['access_token'], 'TOK')
        self.assertIsNone(self.client._auth_session)

    def test_background_confirmation_noop_when_not_approved(self):
        session = {'username': 'user', 'client_id': 5, 'request_id': b'req',
                   'steam_id': SteamID(STEAMID64), 'interval': 5,
                   'allowed_confirmations': confirmations(DEVICE_CONFIRMATION)}
        self.stub({'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='')]})
        self.client._send_logon = MagicMock()

        with patch('steam.client.time', side_effect=[1000.0, 1000.0 + self.client.confirmation_timeout + 1]):
            self.client._background_confirmation(session, 'user', login_id=0)

        self.client._send_logon.assert_not_called()

    def test_background_confirmation_does_not_clobber_newer_greenlet(self):
        # A newer login() may have replaced _confirm_greenlet with a fresh poll; a finishing
        # older poll must not null it out (which would orphan the newer one).
        session = {'username': 'user', 'client_id': 5, 'request_id': b'req',
                   'steam_id': SteamID(STEAMID64), 'interval': 5,
                   'allowed_confirmations': confirmations(DEVICE_CONFIRMATION)}
        self.stub({'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='')]})
        self.client._send_logon = MagicMock()
        newer = object()  # stands in for a greenlet spawned by a later login()
        self.client._confirm_greenlet = newer

        with patch('steam.client.time', side_effect=[1000.0, 1000.0 + self.client.confirmation_timeout + 1]):
            self.client._background_confirmation(session, 'user', login_id=0)

        self.assertIs(self.client._confirm_greenlet, newer)

    def test_unknown_confirmation_type_does_not_crash(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(99))],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')

    def test_guard_code_reuses_session_without_new_begin(self):
        # First attempt with no code: a session is opened and the caller is asked for a code.
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(EMAIL_CODE))],
        })
        result, _, _ = self.client._get_refresh_token('user', 'pass')
        self.assertEqual(result, EResult.AccountLogonDenied)

        # Second attempt supplies the emailed code: it must reuse the same session and NOT call
        # Begin again (which would send a fresh email and invalidate the code just entered).
        self.stub({
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.OK)],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })
        result, token, _ = self.client._get_refresh_token('user', 'pass', auth_code='12345')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')
        self.assertNotIn('Authentication.BeginAuthSessionViaCredentials#1', self.called_methods())

    def test_guard_code_rejected_keeps_session_for_retry(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.TwoFactorCodeMismatch)],
        })
        result, _, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='WRONG')
        self.assertEqual(result, EResult.TwoFactorCodeMismatch)

        # A rejected code must not discard the session; the next code retries the same one.
        self.stub({
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.OK)],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })
        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='RIGHT')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')
        self.assertNotIn('Authentication.BeginAuthSessionViaCredentials#1', self.called_methods())

    def test_accepted_code_survives_slow_token_mint(self):
        # Code accepted, but the token is not minted on the first poll. It must not be reported
        # as a mismatch just because the first poll came back empty.
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.OK)],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token=''),
                                                       poll_resp(refresh_token='TOK')],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='ABCDE')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')
        self.assertNoAuthCodeEvent()

    def test_no_guard_poll_timeout_returns_fail(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations())],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='')],
        })

        # Drive the poll deadline past without real waiting.
        with patch('steam.client.time', side_effect=[1000.0, 1031.0]):
            result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.Fail)
        self.assertIsNone(token)
        self.assertNoAuthCodeEvent()

    def test_begin_error_surfaces_real_eresult(self):
        # A rate-limited Begin (no client_id) must not be reported as a wrong password.
        rate_limited = resp(EResult.RateLimitExceeded, client_id=0, request_id=b'',
                            steamid=0, allowed_confirmations=confirmations(), interval=5)
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [rate_limited],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.RateLimitExceeded)
        self.assertIsNone(token)

    def test_begin_unknown_eresult_falls_back_to_invalid_password(self):
        # An eresult our vendored enum does not know must not crash the login.
        unknown = resp(client_id=0, request_id=b'', steamid=0,
                       allowed_confirmations=confirmations(), interval=5)
        unknown.header.eresult = 991337
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [unknown],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.InvalidPassword)
        self.assertIsNone(token)

    def test_guard_code_submit_timeout_not_accepted(self):
        # A timed-out code submission (None) must be treated as unconfirmed, not accepted:
        # it must not fall through to polling (no PollAuthSessionStatus is stubbed).
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [None],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='ABCDE')

        self.assertEqual(result, EResult.TwoFactorCodeMismatch)
        self.assertIsNone(token)
        self.assertNotIn('Authentication.PollAuthSessionStatus#1', self.called_methods())


class SendLogon(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.get_sentry = MagicMock(return_value=None)
        self.client.sleep = MagicMock()
        self.captured = {}
        self.client.send = lambda msg: self.captured.__setitem__('msg', msg)
        self.client.wait_msg = MagicMock(
            return_value=SimpleNamespace(body=SimpleNamespace(eresult=int(EResult.OK))))

    def test_access_token_sets_field_and_omits_password(self):
        result = self.client._send_logon('user', access_token='TOK', login_id=0)

        msg = self.captured['msg']
        self.assertEqual(msg.body.access_token, 'TOK')
        self.assertEqual(msg.body.password, '')
        self.assertEqual(msg.body.account_name, 'user')
        self.assertEqual(result, EResult.OK)
        self.assertEqual(self.client.refresh_token, 'TOK')

    def test_header_uses_supplied_steamid(self):
        self.client._send_logon('user', access_token='TOK', login_id=0, steam_id=SteamID(STEAMID64))

        self.assertEqual(self.captured['msg'].header.steamid, STEAMID64)

    def test_unknown_eresult_returns_fail(self):
        # A logon eresult our vendored enum does not know must not crash _send_logon.
        self.client.wait_msg = MagicMock(
            return_value=SimpleNamespace(body=SimpleNamespace(eresult=991337)))

        result = self.client._send_logon('user', access_token='TOK', login_id=0)

        self.assertEqual(result, EResult.Fail)
        self.assertIsNone(self.client.refresh_token)


class NonAuthedServiceMethod(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()

    def test_send_um_honours_emsg_override(self):
        captured = {}
        self.client.send_job = MagicMock(side_effect=lambda m: captured.__setitem__('msg', m) or 'job_1')

        jobid = self.client.send_um('Authentication.GetPasswordRSAPublicKey#1',
                                    {'account_name': 'user'},
                                    emsg=EMsg.ServiceMethodCallFromClientNonAuthed)

        msg = captured['msg']
        self.assertEqual(msg.msg, EMsg.ServiceMethodCallFromClientNonAuthed)
        self.assertEqual(msg.header.target_job_name, 'Authentication.GetPasswordRSAPublicKey#1')
        self.assertEqual(msg.body.account_name, 'user')
        self.assertEqual(jobid, 'job_1')

    def test_send_um_defaults_to_authed_emsg(self):
        captured = {}
        self.client.send_job = MagicMock(side_effect=lambda m: captured.__setitem__('msg', m) or 'job_1')

        self.client.send_um('Player.GetGameBadgeLevels#1', {})

        self.assertEqual(captured['msg'].msg, EMsg.ServiceMethodCallFromClient)

    def test_auth_um_uses_nonauthed_emsg(self):
        response = SimpleNamespace(body=SimpleNamespace())
        self.client.send_um_and_wait = MagicMock(return_value=response)

        out = self.client._send_auth_um('Authentication.GetPasswordRSAPublicKey#1', {'account_name': 'user'})

        self.assertIs(out, response)
        self.client.send_um_and_wait.assert_called_once_with(
            'Authentication.GetPasswordRSAPublicKey#1', {'account_name': 'user'},
            emsg=EMsg.ServiceMethodCallFromClientNonAuthed)

    def test_auth_um_returns_none_on_unresolved_body(self):
        self.client.send_um_and_wait = MagicMock(
            return_value=SimpleNamespace(body='!!! Failed to resolve message !!!'))

        out = self.client._send_auth_um('Authentication.GetPasswordRSAPublicKey#1', {'account_name': 'user'})

        self.assertIsNone(out)


def make_token(steamid64):
    """Build a minimal Steam-style JWT access token with ``sub`` = steamid64."""
    from base64 import urlsafe_b64encode
    import json as _json

    def seg(d):
        return urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b'=').decode()

    return "%s.%s.sig" % (seg({'alg': 'EdDSA'}), seg({'sub': str(steamid64)}))


class TokenLogin(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client._pre_login = MagicMock(return_value=EResult.OK)
        self.captured = {}
        self.client._send_logon = MagicMock(
            side_effect=lambda *a, **kw: self.captured.update(kw) or EResult.OK)
        self.client._get_refresh_token = MagicMock()

    def test_direct_token_derives_steamid_from_jwt(self):
        token = make_token(STEAMID64)

        self.client.login('user', access_token=token)

        self.client._get_refresh_token.assert_not_called()
        self.assertEqual(self.captured['access_token'], token)
        self.assertEqual(self.captured['steam_id'].as_64, STEAMID64)

    def test_unparseable_token_falls_back_to_no_steamid(self):
        self.client.login('user', access_token='not-a-jwt')

        self.assertIsNone(self.captured['steam_id'])


class HandleLogon(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.disconnect = MagicMock()
        self.client.emit = MagicMock()

    def _logon(self, eresult, patch_base=True):
        from steam.core.cm import CMClient
        self.client.refresh_token = 'TOK'
        msg = SimpleNamespace(body=SimpleNamespace(eresult=int(eresult)))
        if patch_base:
            with patch.object(CMClient, '_handle_logon'):
                self.client._handle_logon(msg)
        else:
            self.client._handle_logon(msg)

    def test_expired_token_is_cleared(self):
        for eresult in (EResult.InvalidPassword, EResult.AccessDenied,
                        EResult.Expired, EResult.Revoked):
            self._logon(eresult)
            self.assertIsNone(self.client.refresh_token, "%r should clear the token" % eresult)

    def test_transient_failure_keeps_token(self):
        self._logon(EResult.TryAnotherCM)
        self.assertEqual(self.client.refresh_token, 'TOK')

    def test_unknown_eresult_does_not_crash(self):
        # An eresult not in our vendored enum must not raise (Steam may add new ones).
        # Exercise the real base CMClient._handle_logon -- that is where the raw eresult
        # is coerced, so patching it out would hide a crash there.
        self._logon(991337, patch_base=False)
        self.client.disconnect.assert_called()
        self.assertFalse(self.client.logged_on)


class PreLogin(unittest.TestCase):
    def test_resets_stale_steamid(self):
        client = SteamClient()
        client.steam_id = SteamID(STEAMID64)
        client.logged_on = False
        client.connected = True
        client.channel_secured = True

        self.assertEqual(client._pre_login(), EResult.OK)
        self.assertIsNone(client.steam_id)


class LoginGuards(unittest.TestCase):
    def test_logged_on_short_circuits_only_for_same_user(self):
        client = SteamClient()
        client.logged_on = True
        client.username = 'A'
        client._send_logon = MagicMock()

        self.assertEqual(client.login('A'), EResult.OK)
        client._send_logon.assert_not_called()

    def test_login_for_different_user_while_logged_on_raises(self):
        # Must not silently return OK for a different account (_pre_login rejects it).
        client = SteamClient()
        client.logged_on = True
        client.username = 'A'

        with self.assertRaises(RuntimeError):
            client.login('B', 'pass')

    def test_failed_login_for_new_user_clears_stale_token(self):
        # Logged in as A with A's token, then a failed credential login for B must not
        # leave B paired with A's token (relogin() would log on as the wrong account).
        client = SteamClient()
        client._pre_login = MagicMock(return_value=EResult.OK)
        client.username = 'A'
        client.refresh_token = 'tokenA'
        client._auth_session = {'username': 'A'}
        client._get_refresh_token = MagicMock(
            return_value=(EResult.InvalidPassword, None, None))

        result = client.login('B', 'wrong')

        self.assertEqual(result, EResult.InvalidPassword)
        self.assertIsNone(client.refresh_token)
        self.assertIsNone(client._auth_session)
        self.assertFalse(client.relogin_available)


class AwaitConfirmation(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()

    def test_true_when_already_logged_on(self):
        self.client.logged_on = True
        self.assertTrue(self.client._await_confirmation())

    def test_false_when_nothing_pending(self):
        self.client.logged_on = False
        self.client._confirm_greenlet = None
        self.assertFalse(self.client._await_confirmation())

    def test_waits_for_logged_on_event(self):
        self.client.logged_on = False
        self.client._confirm_greenlet = object()  # pretend a poll is running

        def approve(*a, **kw):
            self.client.logged_on = True
        self.client.wait_event = MagicMock(side_effect=approve)

        self.assertTrue(self.client._await_confirmation())
        self.client.wait_event.assert_called_once_with(
            self.client.EVENT_LOGGED_ON, timeout=self.client.confirmation_timeout)


class CliLogin(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.sleep = MagicMock()

    def test_waits_for_out_of_band_approval(self):
        # login() reports a code is needed but a background confirmation poll is active;
        # with wait_for_confirmation the approval completes the logon and no code is asked.
        self.client.login = MagicMock(return_value=EResult.AccountLoginDeniedNeedTwoFactor)
        self.client._confirm_greenlet = object()
        self.client._await_confirmation = MagicMock(return_value=True)

        with patch('builtins.input', side_effect=AssertionError("should not prompt")), \
                patch('builtins.print'):
            result = self.client.cli_login('user', 'pass')

        self.assertEqual(result, EResult.OK)
        self.client._await_confirmation.assert_called_once()
        self.client.login.assert_called_once_with('user', 'pass')

    def test_no_wait_prompts_for_code_immediately(self):
        self.client.login = MagicMock(side_effect=[EResult.AccountLoginDeniedNeedTwoFactor,
                                                   EResult.OK])
        self.client._confirm_greenlet = object()
        self.client._await_confirmation = MagicMock()

        with patch('builtins.input', return_value='12345'):
            result = self.client.cli_login('user', 'pass', wait_for_confirmation=False)

        self.assertEqual(result, EResult.OK)
        self.client._await_confirmation.assert_not_called()
        self.client.login.assert_called_with('user', 'pass', None, '12345')

    def test_logon_completed_in_background_skips_prompt(self):
        # The out-of-band poll completes the logon while cli_login sleeps between attempts;
        # it must notice and not prompt for a code it no longer needs.
        self.client.login = MagicMock(return_value=EResult.AccountLoginDeniedNeedTwoFactor)
        self.client._confirm_greenlet = object()

        def approve(_):
            self.client.logged_on = True
        self.client.sleep = MagicMock(side_effect=approve)

        with patch('builtins.input', side_effect=AssertionError("should not prompt")), \
                patch('builtins.print'):
            result = self.client.cli_login('user', 'pass')

        self.assertEqual(result, EResult.OK)

    def test_wait_skipped_when_no_confirmation_pending(self):
        # wait_for_confirmation is on, but the account offers no out-of-band approval
        # (no background poll), so it prompts for a code without waiting.
        self.client.login = MagicMock(side_effect=[EResult.AccountLoginDeniedNeedTwoFactor,
                                                   EResult.OK])
        self.client._confirm_greenlet = None
        self.client._await_confirmation = MagicMock()

        with patch('builtins.input', return_value='12345'):
            result = self.client.cli_login('user', 'pass')

        self.assertEqual(result, EResult.OK)
        self.client._await_confirmation.assert_not_called()

    def test_unavailable_empty_answer_reprompts(self):
        # Pressing Enter (empty input) must not be taken as "keep retrying"; it reprompts
        # until a clear y/n is given.
        self.client.reconnect = MagicMock()

        with patch('builtins.input', side_effect=['', 'n']):
            keep_going, prompt_for_unavailable = self.client._cli_handle_unavailable(
                EResult.ServiceUnavailable, True)

        self.assertFalse(keep_going)
        self.client.reconnect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
