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

    def test_authenticator_asks_for_code_without_polling(self):
        # Account with the mobile authenticator offers both a code and app-confirmation.
        self.stub({
            'Authentication.GetPasswordRSAPublicKey#1': [rsa_resp()],
            'Authentication.BeginAuthSessionViaCredentials#1': [
                begin_resp(confirmations(DEVICE_CODE, DEVICE_CONFIRMATION))],
            'Authentication.PollAuthSessionStatus#1': [poll_resp(refresh_token='TOK')],
        })

        result, token, _ = self.client._get_refresh_token('user', 'pass')

        self.assertEqual(result, EResult.AccountLoginDeniedNeedTwoFactor)
        self.assertIsNone(token)
        self.assertAuthCodeEvent(True, False)
        # It must not block polling / sleeping when a code can be entered instead.
        self.assertNotIn('Authentication.PollAuthSessionStatus#1', self.called_methods())
        self.client.sleep.assert_not_called()

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


if __name__ == '__main__':
    unittest.main()
