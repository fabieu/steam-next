import os
import tempfile
import unittest
from types import SimpleNamespace

from mock import patch, MagicMock

from steam.client import SteamClient
from steam.enums import EResult, EOSType
from steam.enums.emsg import EMsg
from steam.enums.proto import (EAuthSessionGuardType, EAuthTokenPlatformType, ESessionPersistence,
                               ETokenRenewalType)
from steam.steamid import SteamID

NO_GUARD = EAuthSessionGuardType['None']
DEVICE_CODE = EAuthSessionGuardType.DeviceCode
EMAIL_CODE = EAuthSessionGuardType.EmailCode
DEVICE_CONFIRMATION = EAuthSessionGuardType.DeviceConfirmation
EMAIL_CONFIRMATION = EAuthSessionGuardType.EmailConfirmation
MACHINE_TOKEN_GUARD = EAuthSessionGuardType.MachineToken

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


def poll_resp(refresh_token='', new_client_id=0, new_guard_data=''):
    return resp(refresh_token=refresh_token, new_client_id=new_client_id, new_guard_data=new_guard_data)


def make_token(steamid64, iss='steam', aud=('client', 'derive')):
    """Build a minimal Steam-style JWT with the given ``sub`` / ``iss`` / ``aud`` claims."""
    from base64 import urlsafe_b64encode
    import json as _json

    def seg(d):
        return urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b'=').decode()

    claims = {'sub': str(steamid64)}
    if iss is not None:
        claims['iss'] = iss
    if aud is not None:
        claims['aud'] = list(aud)
    return "%s.%s.sig" % (seg({'alg': 'EdDSA'}), seg(claims))


MACHINE_TOKEN = make_token(STEAMID64, aud=('machine',))


class RefreshTokenFlow(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        # avoid real crypto and real sleeps
        p = patch('steam.client.rsa_encrypt_password', return_value='ENCPW')
        self.addCleanup(p.stop); p.start()
        self.client.sleep = MagicMock()
        self.client.emit = MagicMock()
        self.client.send = MagicMock()  # swallows the ClientHello

    def auth_code_events(self):
        return [c.args[1:] for c in self.client.emit.call_args_list
                if c.args[0] == self.client.EVENT_AUTH_CODE_REQUIRED]

    def assertAuthCodeEvent(self, is_2fa, code_mismatch):
        self.assertEqual(self.auth_code_events(), [(is_2fa, code_mismatch)])

    def assertNoAuthCodeEvent(self):
        self.assertEqual(self.auth_code_events(), [])

    def stub(self, responses):
        def dispatch(method_name, params):
            return responses[method_name].pop(0)
        self.client._send_auth_um = MagicMock(side_effect=dispatch)

    def called_methods(self):
        return [c.args[0] for c in self.client._send_auth_um.call_args_list]

    def params_of(self, method_name):
        return [c.args[1] for c in self.client._send_auth_um.call_args_list
                if c.args[0] == method_name][0]

    def begin_params(self):
        return self.params_of('Authentication.BeginAuthSessionViaCredentials#1')

    def stub_no_guard(self, *polls):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(NO_GUARD))],
            'Authentication.PollAuthSessionStatus#1': list(polls) or [poll_resp(refresh_token='TOK')],
        })

    # -- request shapes ---------------------------------------------------------------------

    def test_client_hello_sent_before_begin(self):
        self.stub_no_guard()

        self.client._get_refresh_token('user', 'pass')

        self.client.send.assert_called_once()
        hello = self.client.send.call_args.args[0]
        self.assertEqual(hello.msg, EMsg.ClientHello)
        self.assertEqual(hello.body.protocol_version, 65580)

    def test_begin_request_fields(self):
        self.stub_no_guard()

        self.client._get_refresh_token('user', 'pass')

        params = self.begin_params()
        self.assertEqual(params['account_name'], 'user')
        self.assertEqual(params['encrypted_password'], 'ENCPW')
        self.assertEqual(params['encryption_timestamp'], 123)
        self.assertTrue(params['remember_login'])
        self.assertEqual(params['persistence'], ESessionPersistence.Persistent)
        self.assertEqual(params['website_id'], 'Unknown')
        self.assertNotIn('platform_type', params)
        self.assertNotIn('guard_data', params)  # no machine auth token known

        details = params['device_details']
        self.assertRegex(details['device_friendly_name'], r'^DESKTOP-[A-Z]{7}$')
        self.assertEqual(details['platform_type'], EAuthTokenPlatformType.SteamClient)
        self.assertEqual(details['os_type'], int(EOSType.Windows11))
        self.assertEqual(details['gaming_device_type'], 1)
        self.assertTrue(details['machine_id'].startswith(b'\x00MessageObject\x00\x01BB3\x00'))
        self.assertTrue(details['machine_id'].endswith(b'\x08\x08'))

    def test_machine_auth_token_sent_as_guard_data(self):
        self.client.machine_auth_token = MACHINE_TOKEN
        self.stub_no_guard()

        self.client._get_refresh_token('user', 'pass')

        self.assertEqual(self.begin_params()['guard_data'], MACHINE_TOKEN)

    def test_machine_auth_token_with_wrong_audience_not_sent(self):
        self.client.machine_auth_token = make_token(STEAMID64, aud=('client',))
        self.stub_no_guard()

        self.client._get_refresh_token('user', 'pass')

        self.assertNotIn('guard_data', self.begin_params())

    def test_machine_auth_token_read_from_credential_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.client.set_credential_location(tmp)
            with open(os.path.join(tmp, 'machineAuthToken.user.txt'), 'w') as f:
                f.write(MACHINE_TOKEN + '\n')
            self.stub_no_guard()

            self.client._get_refresh_token('User', 'pass')  # file name is lower-cased

            self.assertEqual(self.begin_params()['guard_data'], MACHINE_TOKEN)

    def test_new_guard_data_is_stored_and_emitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.client.set_credential_location(tmp)
            self.stub_no_guard(poll_resp(refresh_token='TOK', new_guard_data='NEWGUARD'))

            result, token, _ = self.client._get_refresh_token('user', 'pass')

            self.assertEqual((result, token), (EResult.OK, 'TOK'))
            self.assertEqual(self.client.machine_auth_token, 'NEWGUARD')
            self.client.emit.assert_any_call(self.client.EVENT_MACHINE_AUTH_TOKEN, 'NEWGUARD')
            with open(os.path.join(tmp, 'machineAuthToken.user.txt')) as f:
                self.assertEqual(f.read(), 'NEWGUARD')

    # -- no guard -----------------------------------------------------------------------------

    def test_success_without_guard(self):
        self.stub_no_guard()

        result, token, steam_id = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(token, 'TOK')
        self.assertEqual(steam_id.as_64, STEAMID64)
        self.assertNoAuthCodeEvent()
        self.client.emit.assert_any_call(self.client.EVENT_REFRESH_TOKEN, 'TOK')

    def test_token_minted_on_later_poll(self):
        self.stub_no_guard(poll_resp(refresh_token='', new_client_id=6), poll_resp(refresh_token='TOK'))

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual((result, token), (EResult.OK, 'TOK'))
        self.client.sleep.assert_called_once_with(5)
        # the rotated client_id is used for the next poll
        polls = [c.args[1] for c in self.client._send_auth_um.call_args_list
                 if c.args[0] == 'Authentication.PollAuthSessionStatus#1']
        self.assertEqual([p['client_id'] for p in polls], [5, 6])

    def test_poll_timeout_is_service_unavailable(self):
        self.stub_no_guard(poll_resp(refresh_token=''))

        # Drive the poll deadline past without real waiting.
        with patch('steam.client.time', side_effect=[1000.0, 1031.0]):
            result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.ServiceUnavailable)
        self.assertIsNone(token)
        self.assertNoAuthCodeEvent()

    def test_poll_error_is_service_unavailable(self):
        self.stub_no_guard(resp(EResult.Expired, refresh_token='', new_client_id=0, new_guard_data=''))

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.ServiceUnavailable)
        self.assertIsNone(token)
        self.assertEqual(self.called_methods().count('Authentication.PollAuthSessionStatus#1'), 1)

    def test_poll_transport_failure_is_service_unavailable(self):
        self.stub_no_guard(None)

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.ServiceUnavailable)

    # -- begin failures ------------------------------------------------------------------------

    def test_invalid_password(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [
                resp(EResult.InvalidPassword, client_id=0, request_id=b'', steamid=0,
                     allowed_confirmations=confirmations(), interval=5)],
        })

        result, token, _ = self.client._get_refresh_token('user', 'wrong')

        self.assertEqual(result, EResult.InvalidPassword)
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

    def test_rsa_or_begin_transport_failure_is_service_unavailable(self):
        self.stub({'Authentication.GetPasswordRSAPublicKey#1': [None]})
        result, _, _ = self.client._get_refresh_token('user', 'pass')
        self.assertEqual(result, EResult.ServiceUnavailable)

        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [None],
        })
        result, _, _ = self.client._get_refresh_token('user', 'pass')
        self.assertEqual(result, EResult.ServiceUnavailable)

    # -- guard codes -------------------------------------------------------------------------

    def test_needs_2fa_code(self):
        # Authenticator accounts offer both app confirmation and a code; a code is always
        # requested, the confirmation is never awaited.
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [
                begin_resp(confirmations(DEVICE_CONFIRMATION, DEVICE_CODE))],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.AccountLoginDeniedNeedTwoFactor)
        self.assertIsNone(token)
        self.assertAuthCodeEvent(True, False)
        self.assertNotIn('Authentication.PollAuthSessionStatus#1', self.called_methods())

    def test_needs_email_code(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [
                begin_resp(confirmations(EMAIL_CODE, EMAIL_CONFIRMATION))],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.AccountLogonDenied)
        self.assertIsNone(token)
        self.assertAuthCodeEvent(False, False)

    def test_2fa_code_accepted(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [
                begin_resp(confirmations(DEVICE_CONFIRMATION, DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.OK)],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='ABCDE')

        self.assertEqual((result, token), (EResult.OK, 'TOK'))
        self.assertNoAuthCodeEvent()
        update = self.params_of('Authentication.UpdateAuthSessionWithSteamGuardCode#1')
        self.assertEqual(update, {'client_id': 5, 'steamid': STEAMID64, 'code': 'ABCDE',
                                  'code_type': DEVICE_CODE})

    def test_code_type_follows_session_not_argument(self):
        # The code type is derived from the guard the session offers, whichever argument
        # carried the code.
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(EMAIL_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.OK)],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })

        result, _, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='K6VKF')

        self.assertEqual(result, EResult.OK)
        update = self.params_of('Authentication.UpdateAuthSessionWithSteamGuardCode#1')
        self.assertEqual(update['code_type'], EMAIL_CODE)

    def test_2fa_code_rejected(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.TwoFactorCodeMismatch)],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='WRONG')

        self.assertEqual(result, EResult.TwoFactorCodeMismatch)
        self.assertIsNone(token)
        self.assertAuthCodeEvent(True, True)
        self.assertNotIn('Authentication.PollAuthSessionStatus#1', self.called_methods())

    def test_email_code_rejected_reported_as_logon_denied(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(EMAIL_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.InvalidLoginAuthCode)],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', auth_code='WRONG')

        self.assertEqual(result, EResult.AccountLogonDenied)
        self.assertIsNone(token)
        self.assertAuthCodeEvent(False, False)

    def test_every_attempt_starts_a_fresh_session(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp(), rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [
                begin_resp(confirmations(DEVICE_CODE)), begin_resp(confirmations(DEVICE_CODE), client_id=9)],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.OK)],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })

        self.client._get_refresh_token('user', 'pass')
        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='ABCDE')

        self.assertEqual((result, token), (EResult.OK, 'TOK'))
        self.assertEqual(self.called_methods().count('Authentication.BeginAuthSessionViaCredentials#1'), 2)
        self.assertEqual(self.params_of('Authentication.UpdateAuthSessionWithSteamGuardCode#1')['client_id'], 9)

    def test_guard_code_other_error_surfaces(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [resp(EResult.Expired)],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='ABCDE')

        self.assertEqual(result, EResult.Expired)
        self.assertIsNone(token)
        self.assertNoAuthCodeEvent()

    def test_guard_code_submit_timeout_is_service_unavailable(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CODE))],
            'Authentication.UpdateAuthSessionWithSteamGuardCode#1': [None],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass', two_factor_code='ABCDE')

        self.assertEqual(result, EResult.ServiceUnavailable)
        self.assertNotIn('Authentication.PollAuthSessionStatus#1', self.called_methods())

    def test_confirmation_only_guard_still_asks_for_2fa_code(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(DEVICE_CONFIRMATION))],
        })

        result, _, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.AccountLoginDeniedNeedTwoFactor)
        self.assertAuthCodeEvent(True, False)

    def test_machine_token_guard_alone_is_service_unavailable(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(MACHINE_TOKEN_GUARD))],
        })

        result, _, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.ServiceUnavailable)
        self.assertNoAuthCodeEvent()

    def test_unknown_confirmation_type_is_service_unavailable(self):
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [begin_resp(confirmations(99))],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.ServiceUnavailable)
        self.assertIsNone(token)


class SendLogon(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.sleep = MagicMock()
        self.client.disconnect = MagicMock()
        self.captured = {}
        self.client.send = lambda msg: self.captured.__setitem__('msg', msg)
        self.client.wait_msg = MagicMock(
            return_value=SimpleNamespace(body=SimpleNamespace(eresult=int(EResult.OK))))

    def test_access_token_sets_field_and_omits_password(self):
        result = self.client._send_logon('user', access_token='TOK', login_id=0)

        msg = self.captured['msg']
        self.assertEqual(msg.body.access_token, 'TOK')
        self.assertFalse(msg.body.HasField('password'))
        self.assertFalse(msg.body.HasField('account_name'))  # not sent alongside a token
        self.assertEqual(result, EResult.OK)
        self.assertEqual(self.client.refresh_token, 'TOK')

    def test_body_fields(self):
        self.client.cell_id = 42
        self.client._last_session_id = 77
        self.client._client_instance_id = 123456789

        self.client._send_logon('user', access_token='TOK')

        body = self.captured['msg'].body
        self.assertEqual(body.protocol_version, 65580)
        self.assertTrue(body.should_remember_password)
        self.assertTrue(body.supports_rate_limit_response)
        self.assertEqual(body.client_language, 'english')
        self.assertTrue(body.HasField('machine_name'))
        self.assertEqual(body.machine_name, '')
        self.assertEqual(body.chat_mode, 2)
        self.assertEqual(body.cell_id, 42)
        self.assertEqual(body.last_session_id, 77)
        self.assertEqual(body.client_instance_id, 123456789)
        self.assertEqual(body.obfuscated_private_ip.v4, 0)
        self.assertTrue(body.machine_id.startswith(b'\x00MessageObject\x00'))
        self.assertFalse(body.HasField('client_package_version'))
        self.assertFalse(body.HasField('eresult_sentryfile'))
        self.assertFalse(body.HasField('sha_sentryfile'))

    def test_os_type_is_sent_unsigned_on_every_platform(self):
        for platform, os_type in (('win32', EOSType.Windows10),
                                  ('darwin', EOSType.MacOSUnknown),
                                  ('linux', EOSType.LinuxUnknown)):
            with self.subTest(platform=platform):
                with patch('steam.client.sys.platform', platform):
                    self.client._send_logon('user', access_token='TOK')

                body = self.captured['msg'].body
                self.assertEqual(body.client_os_type, int(os_type) & 0xFFFFFFFF)

    def test_session_fields_omitted_when_unknown(self):
        self.client._send_logon('user', access_token='TOK')

        body = self.captured['msg'].body
        self.assertFalse(body.HasField('cell_id'))
        self.assertFalse(body.HasField('last_session_id'))
        self.assertFalse(body.HasField('client_instance_id'))

    def test_login_id_sets_obfuscated_ip(self):
        self.client._send_logon('user', access_token='TOK', login_id=1234)

        self.assertEqual(self.captured['msg'].body.obfuscated_private_ip.v4, 1234)

    def test_header_uses_supplied_steamid(self):
        self.client._send_logon('user', access_token='TOK', login_id=0, steam_id=SteamID(STEAMID64))

        self.assertEqual(self.captured['msg'].header.steamid, STEAMID64)

    def test_unknown_eresult_returns_fail(self):
        # A logon eresult our vendored enum does not know must not crash _send_logon.
        self.client.wait_msg = MagicMock(
            return_value=SimpleNamespace(body=SimpleNamespace(eresult=991337)))

        result = self.client._send_logon('user', access_token='TOK', login_id=0)

        self.assertEqual(result, EResult.Fail)

    def test_no_response_drops_connection_and_retries(self):
        self.client.wait_msg = MagicMock(return_value=None)

        result = self.client._send_logon('user', access_token='TOK')

        self.assertEqual(result, EResult.ServiceUnavailable)
        self.client.wait_msg.assert_called_once_with(EMsg.ClientLogOnResponse, timeout=5)
        self.client.disconnect.assert_called_once()

    def test_anonymous_body_fields(self):
        self.client._pre_login = MagicMock(return_value=EResult.OK)

        self.client.anonymous_login()

        msg = self.captured['msg']
        self.assertEqual(msg.header.steamid, SteamID(type='AnonUser', universe='Public'))
        body = msg.body
        self.assertEqual(body.protocol_version, 65580)
        self.assertEqual(body.anon_user_target_account_name, 'anonymous')
        self.assertFalse(body.should_remember_password)
        self.assertTrue(body.HasField('should_remember_password'))
        self.assertFalse(body.supports_rate_limit_response)
        self.assertEqual(body.client_language, '')
        self.assertEqual(body.machine_name, '')
        self.assertEqual(body.chat_mode, 2)
        self.assertEqual(body.obfuscated_private_ip.v4, 0)
        self.assertFalse(body.HasField('machine_id'))
        self.assertFalse(body.HasField('access_token'))


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

    def test_auth_um_uses_nonauthed_emsg_and_realm(self):
        captured = {}
        self.client.send_job = MagicMock(side_effect=lambda m: captured.__setitem__('msg', m) or 'job_1')
        response = SimpleNamespace(body=SimpleNamespace())
        self.client.wait_msg = MagicMock(return_value=response)

        out = self.client._send_auth_um('Authentication.GetPasswordRSAPublicKey#1', {'account_name': 'user'})

        self.assertIs(out, response)
        msg = captured['msg']
        self.assertEqual(msg.msg, EMsg.ServiceMethodCallFromClientNonAuthed)
        self.assertEqual(msg.header.target_job_name, 'Authentication.GetPasswordRSAPublicKey#1')
        self.assertEqual(msg.header.realm, 1)
        self.assertEqual(msg.body.account_name, 'user')
        self.client.wait_msg.assert_called_once_with('job_1', timeout=10)

    def test_auth_um_uses_authed_emsg_once_logged_on(self):
        captured = {}
        self.client.send_job = MagicMock(side_effect=lambda m: captured.__setitem__('msg', m) or 'job_1')
        self.client.wait_msg = MagicMock(return_value=SimpleNamespace(body=SimpleNamespace()))
        self.client.logged_on = True

        self.client._send_auth_um('Authentication.GetPasswordRSAPublicKey#1', {'account_name': 'user'})

        self.assertEqual(captured['msg'].msg, EMsg.ServiceMethodCallFromClient)

    def test_auth_um_returns_none_on_unresolved_body(self):
        self.client.send_job = MagicMock(return_value='job_1')
        self.client.wait_msg = MagicMock(
            return_value=SimpleNamespace(body='!!! Failed to resolve message !!!'))

        out = self.client._send_auth_um('Authentication.GetPasswordRSAPublicKey#1', {'account_name': 'user'})

        self.assertIsNone(out)


class OutgoingMessageGuard(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.connected = True
        self.sent = []
        p = patch('steam.client.CMClient.send', side_effect=lambda c, m: self.sent.append(m))
        self.addCleanup(p.stop); p.start()

    def test_prelogon_messages_allowed(self):
        from steam.core.msg import MsgProto, Msg

        for emsg in (EMsg.ClientHello, EMsg.ClientLogon, EMsg.ServiceMethodCallFromClientNonAuthed):
            self.client.send(MsgProto(emsg))
        self.client.send(Msg(EMsg.ChannelEncryptResponse))

        self.assertEqual([m.msg for m in self.sent],
                         [EMsg.ClientHello, EMsg.ClientLogon,
                          EMsg.ServiceMethodCallFromClientNonAuthed, EMsg.ChannelEncryptResponse])

    def test_other_messages_dropped_until_logged_on(self):
        from steam.core.msg import MsgProto

        self.client.send(MsgProto(EMsg.ClientHeartBeat))
        self.assertEqual(self.sent, [])

        self.client.logged_on = True
        self.client.send(MsgProto(EMsg.ClientHeartBeat))
        self.assertEqual([m.msg for m in self.sent], [EMsg.ClientHeartBeat])

    def test_logoff_is_sent_before_clearing_logged_on(self):
        self.client.logged_on = True
        self.client.wait_event = MagicMock()
        self.client.idle = MagicMock()

        self.client.logout()

        self.assertEqual([m.msg for m in self.sent], [EMsg.ClientLogOff])
        self.assertFalse(self.client.logged_on)


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

    def test_malformed_token_raises(self):
        with self.assertRaises(ValueError):
            self.client.login('user', access_token='not-a-jwt')

        self.client._send_logon.assert_not_called()

    def test_token_not_issued_by_steam_raises(self):
        with self.assertRaises(ValueError):
            self.client.login('user', access_token=make_token(STEAMID64, iss='other'))

    def test_token_without_client_audience_raises(self):
        # A web / mobile refresh token is rejected before it ever reaches the CM.
        with self.assertRaises(ValueError):
            self.client.login('user', access_token=make_token(STEAMID64, aud=('web', 'derive')))

        self.client._send_logon.assert_not_called()


class HandleLogon(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.disconnect = MagicMock()
        self.client.emit = MagicMock()

    def _logon(self, eresult, patch_base=True, **body):
        from steam.core.cm import CMClient
        self.client.refresh_token = 'TOK'
        msg = SimpleNamespace(body=SimpleNamespace(eresult=int(eresult), **body))
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

    def test_ok_remembers_session_ids_and_runs_post_logon_for_users(self):
        self.client.steam_id = SteamID(STEAMID64)
        self.client.session_id = 77

        with patch('steam.client.gevent.spawn') as spawn:
            self._logon(EResult.OK, client_instance_id=123456789)

        self.assertTrue(self.client.logged_on)
        self.assertEqual(self.client._last_session_id, 77)
        self.assertEqual(self.client._client_instance_id, 123456789)
        self.client.emit.assert_called_once_with(self.client.EVENT_LOGGED_ON)
        spawn.assert_called_once_with(self.client._post_logon)

    def test_ok_skips_post_logon_for_anonymous(self):
        self.client.steam_id = SteamID(type='AnonUser', universe='Public', id=1)

        with patch('steam.client.gevent.spawn') as spawn:
            self._logon(EResult.OK, client_instance_id=1)

        spawn.assert_not_called()


class PostLogon(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.emit = MagicMock()
        self.client.refresh_token = 'OLD'
        self.client.steam_id = SteamID(STEAMID64)
        self.client.logged_on = True

    def test_web_session_emitted(self):
        session = object()
        self.client.get_web_session = MagicMock(return_value=session)

        self.client._post_logon()

        self.client.emit.assert_called_once_with(self.client.EVENT_WEB_SESSION, session)

    def test_no_event_without_web_session(self):
        self.client.get_web_session = MagicMock(return_value=None)

        self.client._post_logon()

        self.client.emit.assert_not_called()

    def test_renewal_off_by_default(self):
        self.client.get_web_session = MagicMock(return_value=None)
        self.client.send_um_and_wait = MagicMock()

        self.client._post_logon()

        self.client.send_um_and_wait.assert_not_called()

    def test_renewal_replaces_token(self):
        self.client.renew_refresh_tokens = True
        self.client.get_web_session = MagicMock(return_value=None)
        self.client.send_um_and_wait = MagicMock(return_value=resp(access_token='ACC', refresh_token='NEW'))

        self.client._post_logon()

        self.client.send_um_and_wait.assert_called_once_with(
            'Authentication.GenerateAccessTokenForApp#1',
            {'refresh_token': 'OLD', 'steamid': STEAMID64, 'renewal_type': ETokenRenewalType.Allow})
        self.assertEqual(self.client.refresh_token, 'NEW')
        self.client.emit.assert_called_once_with(self.client.EVENT_REFRESH_TOKEN, 'NEW')

    def test_renewal_failure_keeps_token(self):
        self.client.renew_refresh_tokens = True
        self.client.get_web_session = MagicMock(return_value=None)
        self.client.send_um_and_wait = MagicMock(return_value=resp(access_token='ACC', refresh_token=''))

        self.client._post_logon()

        self.assertEqual(self.client.refresh_token, 'OLD')
        self.client.emit.assert_not_called()


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
    def test_login_while_logged_on_raises(self):
        client = SteamClient()
        client.logged_on = True
        client.username = 'A'
        client._send_logon = MagicMock()

        for username in ('A', 'B'):
            with self.assertRaises(RuntimeError):
                client.login(username, 'pass')
        client._send_logon.assert_not_called()

    def test_failed_login_for_new_user_clears_stale_token(self):
        # Logged in as A with A's token, then a failed credential login for B must not
        # leave B paired with A's token (relogin() would log on as the wrong account).
        client = SteamClient()
        client._pre_login = MagicMock(return_value=EResult.OK)
        client.username = 'A'
        client.refresh_token = 'tokenA'
        client.machine_auth_token = 'machineA'
        client._get_refresh_token = MagicMock(
            return_value=(EResult.InvalidPassword, None, None))

        result = client.login('B', 'wrong')

        self.assertEqual(result, EResult.InvalidPassword)
        self.assertIsNone(client.refresh_token)
        self.assertIsNone(client.machine_auth_token)
        self.assertFalse(client.relogin_available)

    def test_failure_drops_connection_and_reports_error(self):
        client = SteamClient()
        client._pre_login = MagicMock(return_value=EResult.OK)
        client.disconnect = MagicMock()
        client.emit = MagicMock()
        client._get_refresh_token = MagicMock(return_value=(EResult.InvalidPassword, None, None))

        self.assertEqual(client.login('user', 'wrong'), EResult.InvalidPassword)

        client.disconnect.assert_called_once()
        client.emit.assert_called_once_with(client.EVENT_ERROR, EResult.InvalidPassword)

    def test_guard_and_transient_failures_do_not_report_error(self):
        client = SteamClient()
        client._pre_login = MagicMock(return_value=EResult.OK)
        client.disconnect = MagicMock()
        client.emit = MagicMock()

        for eresult in (EResult.AccountLogonDenied, EResult.AccountLoginDeniedNeedTwoFactor,
                        EResult.TwoFactorCodeMismatch, EResult.ServiceUnavailable):
            client._get_refresh_token = MagicMock(return_value=(eresult, None, None))
            self.assertEqual(client.login('user', 'pass'), eresult)

        self.assertEqual(client.disconnect.call_count, 4)
        client.emit.assert_not_called()


class CliLogin(unittest.TestCase):
    def setUp(self):
        self.client = SteamClient()
        self.client.sleep = MagicMock()

    def test_prompts_for_2fa_code(self):
        self.client.login = MagicMock(side_effect=[EResult.AccountLoginDeniedNeedTwoFactor,
                                                   EResult.OK])

        with patch('builtins.input', return_value='12345') as prompt:
            result = self.client.cli_login('user', 'pass')

        self.assertEqual(result, EResult.OK)
        prompt.assert_called_once_with("Enter 2FA code: ")
        self.client.login.assert_called_with('user', 'pass', None, '12345')

    def test_prompts_again_on_2fa_mismatch(self):
        self.client.login = MagicMock(side_effect=[EResult.AccountLoginDeniedNeedTwoFactor,
                                                   EResult.TwoFactorCodeMismatch,
                                                   EResult.OK])

        with patch('builtins.input', side_effect=['11111', '22222']) as prompt:
            result = self.client.cli_login('user', 'pass')

        self.assertEqual(result, EResult.OK)
        self.assertEqual(prompt.call_args.args, ("Incorrect code. Enter 2FA code: ",))
        self.client.login.assert_called_with('user', 'pass', None, '22222')

    def test_prompts_for_email_code(self):
        self.client.login = MagicMock(side_effect=[EResult.AccountLogonDenied, EResult.OK])

        with patch('builtins.input', return_value='K6VKF') as prompt:
            result = self.client.cli_login('user', 'pass')

        self.assertEqual(result, EResult.OK)
        prompt.assert_called_once_with("Enter email code: ")
        self.client.login.assert_called_with('user', 'pass', 'K6VKF', None)

    def test_invalid_password_reprompts(self):
        self.client.login = MagicMock(side_effect=[EResult.InvalidPassword, EResult.OK])

        with patch('steam.client.getpass', return_value='right'):
            result = self.client.cli_login('user', 'wrong')

        self.assertEqual(result, EResult.OK)
        self.client.login.assert_called_with('user', 'right', None, None)

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
