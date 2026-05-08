######################################################
####
#### NOT TO BE RAN WITHOUT GENERATING A VCR FIRST
#### use make webauth_gen
####
######################################################
import unittest

import mock
import requests
import vcr

from steam import webauth as wa


class WACase(unittest.TestCase):
    @mock.patch("steam.webauth.make_requests_session")
    def test_http_error(self, mrs_mock):
        mm = mrs_mock.return_value = mock.MagicMock()

        mm.get.side_effect = requests.exceptions.ConnectTimeout('test')

        with self.assertRaises(wa.HTTPError):
            wa.WebAuth('a', 'b').login()

        mm.get.reset_mock()
        mm.get.side_effect = requests.exceptions.ReadTimeout('test')

        with self.assertRaises(wa.HTTPError):
            wa.WebAuth('c', 'd').login()

    @vcr.use_cassette('vcr/webauth_user_pass_only_success.yaml',
                      mode='none',
                      serializer='yaml',
                      match_on=['method', 'scheme', 'host', 'port', 'path'])
    def test_login_user_and_pass_only_ok(self):
        user = wa.WebAuth('testuser', 'testpass')
        s = user.login()

        self.assertTrue(user.logged_on)
        self.assertIsInstance(s, requests.Session)
        self.assertEqual(s, user.login())

    @vcr.use_cassette('vcr/webauth_user_pass_only_fail.yaml',
                      mode='none',
                      serializer='yaml',
                      match_on=['method', 'scheme', 'host', 'port', 'path'])
    def test_login_user_and_pass_only_fail(self):
        with self.assertRaises(wa.LoginIncorrect):
            wa.WebAuth('testuser', 'testpass').login()
            wa.WebAuth('testuser').login('testpass')

    @mock.patch("steam.webauth.make_requests_session")
    def test_login_with_2fa_reuses_existing_session(self, mrs_mock):
        """Test that login() does not start a new session when 2FA code is provided
        and a session already exists (client_id is set)."""
        mm = mrs_mock.return_value = mock.MagicMock()

        user = wa.WebAuth('testuser', 'testpass')

        # Simulate that a session was already started (first login call set these)
        user.client_id = '12345'
        user.request_id = b'req123'
        user.steam_id = mock.MagicMock()
        user.allowed_confirmations = []

        # Mock API responses for both POST calls (update token + poll status)
        poll_response = {
            'response': {
                'refresh_token': 'refresh_tok',
                'access_token': 'access_tok',
            }
        }
        mm.post.return_value = mock.MagicMock()
        mm.post.return_value.json.side_effect = [{'response': {}}, poll_response]

        user.login(code='ABC123')

        # Verify _start_login_session was NOT called (no GET for RSA key)
        mm.get.assert_not_called()

        # Verify _update_login_token was called (POST for UpdateAuthSessionWithSteamGuardCode)
        # and _poll_login_status was called (POST for PollAuthSessionStatus)
        self.assertEqual(mm.post.call_count, 2)
        self.assertTrue(user.logged_on)

    @mock.patch("steam.webauth.make_requests_session")
    def test_login_without_code_starts_new_session(self, _mrs_mock):
        """Test that login() starts a new session when client_id is None."""
        user = wa.WebAuth('testuser', 'testpass')

        # Mock _start_login_session and _poll_login_status at method level
        with mock.patch.object(user, '_start_login_session') as mock_start, \
                mock.patch.object(user, '_poll_login_status') as mock_poll, \
                mock.patch.object(user, '_finalize_login'):
            user.login()

            # Verify _start_login_session was called
            mock_start.assert_called_once()
            # Verify _poll_login_status was called
            mock_poll.assert_called_once()

    @mock.patch("steam.webauth.make_requests_session")
    def test_login_2fa_flow_first_raises_then_succeeds_with_code(self, _mrs_mock):
        """Test the typical 2FA flow: first call raises TwoFactorAuthNotProvided,
        second call with code succeeds without starting a new session."""
        user = wa.WebAuth('testuser', 'testpass')

        with mock.patch.object(user, '_start_login_session') as mock_start:
            # Set up the session state that _start_login_session would set
            def fake_start():
                user.client_id = '67890'
                user.request_id = b'req456'
                user.steam_id = mock.MagicMock()
                user.allowed_confirmations = [wa.EAuthSessionGuardType.DeviceCode]

            mock_start.side_effect = fake_start

            # First poll: no tokens (2FA not provided yet)
            with mock.patch.object(user, '_poll_login_status',
                                   side_effect=wa.TwoFactorAuthNotProvided('need 2fa')):
                with self.assertRaises(wa.TwoFactorAuthNotProvided):
                    user.login()

            # Verify session was started
            mock_start.assert_called_once()
            self.assertEqual(user.client_id, '67890')

            # Reset for second call
            mock_start.reset_mock()

            # Second call: poll succeeds, update_login_token is called
            with mock.patch.object(user, '_poll_login_status') as mock_poll, \
                    mock.patch.object(user, '_update_login_token') as mock_update:
                user.login(code='ABC123')

                # Verify NO new session was started
                mock_start.assert_not_called()
                # Verify 2FA code was submitted
                mock_update.assert_called_once_with('ABC123')
                # Verify poll was called
                mock_poll.assert_called_once()
                self.assertTrue(user.logged_on)

    @mock.patch("steam.webauth.make_requests_session")
    def test_login_clears_client_id_when_code_rejected(self, _mrs_mock):
        """If a 2FA code is submitted but poll still raises TwoFactorAuthNotProvided,
        client_id must be cleared so the next login() starts a fresh session
        """
        user = wa.WebAuth('testuser', 'testpass')
        user.client_id = '67890'
        user.request_id = b'req456'
        user.steam_id = mock.MagicMock()
        user.allowed_confirmations = [wa.EAuthSessionGuardType.DeviceCode]

        with mock.patch.object(user, '_start_login_session') as mock_start, \
                mock.patch.object(user, '_update_login_token'), \
                mock.patch.object(user, '_poll_login_status',
                                  side_effect=wa.TwoFactorAuthNotProvided('rejected')):
            with self.assertRaises(wa.TwoFactorAuthNotProvided):
                user.login(code='STALE')

            mock_start.assert_not_called()

        self.assertIsNone(user.client_id)
        self.assertFalse(user.logged_on)
