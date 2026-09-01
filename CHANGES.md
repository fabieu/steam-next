# Change notes

## Unreleased

This release brings breaking changes

### steam.client

- `SteamClient`/`CMClient` default to the WebSocket CM transport (`protocol=ETransport.WebSocket`); pass `protocol=ETransport.TCP` to keep the previous behavior. `CMClient.PROTOCOL_TCP`/`PROTOCOL_UDP` are removed in favor of `steam.enums.ETransport`
- The WebSocket transport requires cooperative sockets outside a fully gevent app; call `steam.monkey.patch_minimal()` first
- `CMServerList.bootstrap_from_dns()` returns no servers for the WebSocket transport
- `SteamClient.login()` no longer accepts `login_key`; password logins run the `IAuthenticationService` credential flow. New arguments `access_token` (refresh token, instead of a password) and `machine_auth_token`. Raises `RuntimeError` when already logged on and `ValueError` for an `access_token` that is not a Steam client refresh token
- Removed `SteamClient.login_key` and the `new_login_key` event; added `SteamClient.refresh_token` (used by `relogin()`) and the `refresh_token` event
- Added `SteamClient.machine_auth_token` and the `machine_auth_token` event; the token is persisted under `credential_location` as `machineAuthToken.<username>.txt`
- Added the `web_session` event, emitted after each user logon, and `SteamClient.renew_refresh_tokens` (default `False`)
- `get_web_session_cookies()` no longer returns a `steamLogin` cookie; `steamLoginSecure` is derived from an access token
- A Steam Guard code is always requested via `auth_code_required`; a rejected email code is reported as `AccountLogonDenied`. Transport failures and timeouts during login are reported as `ServiceUnavailable`, and any login failure drops the connection
- `SteamClient.send()` drops messages while not logged on, except those needed for logon
- `cli_login()` no longer accepts `wait_for_confirmation`
- Added `EOSType.Windows11`

### steam.webauth

- Removed `MobileWebAuth`

### steam.guard

- `SteamAuthenticator.backend` no longer accepts a `MobileWebAuth` instance; only a logged in `SteamClient` is supported

## 2.0.0

This release brings breaking changes

### steam.client

- Add `steam.monkey` module for applying gevent monkey patches
- Removed monkey patching by default. See `steam.monkey` for details

## 1.0.0

This release brings breaking changes

### General

- Added steam.utils.appcache methods for parsing appcache files
- Replaced `cryptography` library with `pycryptodomex`
- Updated all enums
- Removed imports from 'steam' namespace
- Renamed `steam.util` to `steam.utils`
- Moved proto utils to `steam.utils.proto`
- Moved SteamClient dependecies to `client` extras

### steam.steamid

- Added support for invite codes in SteamID
- Updated `SteamID.is_valid`

### steam.guard

- Renamed `medium` param to `backend` on `SteamAuthenticator`
- Fixed `create_emergency_codes()` not returning codes
- Fixed `validate_phone_number()` returning no data

### steam.webauth

- Added `WebAuth.cli_login()`, handles all steps of the login process
- Updated `password` param to be optional on `WebAuth`

### steam.client

- Replaced builtin CM server list with automatic discovery via WebAPI or DNS
- UM/ServiceMethods are now handled in the `SteamClient` instance. See `SteamClient.send_um()`
- Messages now have a `payload` property set when the body cannot be parsed
- `get_product_info()` now replaces invalid unicode chars
- `get_product_info()` includes `_missing_token` key with every result
- Added `CDNClient` for downloading connect from SteamPipe
- Added `rich_presence` property to `SteamUser`
- Added block/unblock methods for `SteamUser`
- Added jitter to reconnect delay in `SteamClient`
- Updated protocol version to 65580
- Updated `SteamClient` to use new chat mode, with option to fallback
- Updated `get_product_info()` to include `_missing_token` variable
- Updated protobufs
- Removed `SteamClient.unifed_messages`
- Removed `steam.client.mixins` package
- Removed `Account` builtin as all methods have been deprecated
- Removed `SteamClient.change_email()`
- Removed `SteamClient.create_account()`
