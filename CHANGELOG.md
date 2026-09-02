# Changelog

## [3.0.1](https://github.com/fabieu/steam-next/compare/3.0.0...3.0.1) (2026-09-02)


### Dependencies

* bump websocket-client from 1.9.0 to 1.9.2 in the minor-updates group ([#32](https://github.com/fabieu/steam-next/issues/32)) ([827c923](https://github.com/fabieu/steam-next/commit/827c923be95582c870efcad2d857195116899329))

## [3.0.0](https://github.com/fabieu/steam-next/compare/2.2.1...3.0.0) (2026-09-02)


### ⚠ BREAKING CHANGES

* **client:** `SteamClient`/`CMClient` default to the WebSocket CM transport; pass `protocol=ETransport.TCP` for the previous behavior and replace `CMClient.PROTOCOL_TCP`/`PROTOCOL_UDP` with `steam.enums.ETransport`
* **client:** the WebSocket transport needs cooperative sockets outside a fully gevent app; call `steam.monkey.patch_minimal()` first
* **client:** `CMServerList.bootstrap_from_dns()` returns no servers for the WebSocket transport
* **client:** `SteamClient.login()` no longer accepts `login_key`; password logins run the `IAuthenticationService` credential flow behind the new `access_token` and `machine_auth_token` arguments
* **client:** replace `SteamClient.login_key` and the `new_login_key` event with `SteamClient.refresh_token` and the `refresh_token` event
* **client:** `get_web_session_cookies()` no longer returns a `steamLogin` cookie; `steamLoginSecure` is derived from an access token
* **client:** always request a Steam Guard code via `auth_code_required`, report a rejected email code as `AccountLogonDenied`, report login transport failures and timeouts as `ServiceUnavailable`, and drop the connection on any login failure
* **client:** `SteamClient.send()` drops messages while not logged on, except those needed for logon
* **client:** `cli_login()` no longer accepts `wait_for_confirmation`
* **webauth:** remove `MobileWebAuth`
* **guard:** `SteamAuthenticator.backend` only accepts a logged in `SteamClient`


### Features

* **client:** password login via IAuthenticationService over WebSocket CM ([#25](https://github.com/fabieu/steam-next/issues/25)) ([f4795f4](https://github.com/fabieu/steam-next/commit/f4795f43e1fd0f0662b345cd857390326e4127cc))
* **client:** add `SteamClient.machine_auth_token` and the `machine_auth_token` event, persisted as `machineAuthToken.<username>.txt` under `credential_location` ([f4795f4](https://github.com/fabieu/steam-next/commit/f4795f43e1fd0f0662b345cd857390326e4127cc))
* **client:** add the `web_session` event and `SteamClient.renew_refresh_tokens` ([f4795f4](https://github.com/fabieu/steam-next/commit/f4795f43e1fd0f0662b345cd857390326e4127cc))
* **enums:** add `EOSType.Windows11` ([f4795f4](https://github.com/fabieu/steam-next/commit/f4795f43e1fd0f0662b345cd857390326e4127cc))

## [2.2.1](https://github.com/fabieu/steam-next/compare/2.2.0...2.2.1) (2026-07-15)


### Documentation

* update README to reflect Python 3.10+ support ([933461b](https://github.com/fabieu/steam-next/commit/933461b4b289411e7ba1879155d292e39bebac38))
* add AGENTS.md with project guidance for AI coding agents ([9cfdc77](https://github.com/fabieu/steam-next/commit/9cfdc775e3845a2cb9f4be42a065a80f5cf83957))


### Dependencies

* update locked dependencies ([120ee09](https://github.com/fabieu/steam-next/commit/120ee09ebedb52c5631a02ebc6c57f3cce5c5014))

## [2.2.0](https://github.com/fabieu/steam-next/compare/2.1.1...2.2.0) (2026-05-15)


### Features

* **appcache:** support V29 appinfo.vdf with string table compression ([#17](https://github.com/fabieu/steam-next/issues/17)) ([fd6f120](https://github.com/fabieu/steam-next/commit/fd6f120b1e3c616c43553acd3b6b82e1d8b0955c))
* drop Python 3.9 support ([#15](https://github.com/fabieu/steam-next/issues/15)) ([76e6359](https://github.com/fabieu/steam-next/commit/76e6359bd821a336f7b24633aed2d46b7752c37d))
* update protobufs from SteamDatabase/SteamTracking ([1f08d9a](https://github.com/fabieu/steam-next/commit/1f08d9a76b376c3e5c1d7761a8678ee64d67c50a))


### Bug Fixes

* **client:** guard the missing `supports_package_tokens` field on `CMsgClientPICSProductInfoRequest` ([#16](https://github.com/fabieu/steam-next/issues/16)) ([04ab05f](https://github.com/fabieu/steam-next/commit/04ab05f31c391f54a15e671440effd8bbbc0cf69))

## [2.1.1](https://github.com/fabieu/steam-next/compare/2.1.0...2.1.1) (2026-05-08)


### Bug Fixes

* **webauth:** keep the session when `login()` is called again with a 2FA code ([#8](https://github.com/fabieu/steam-next/issues/8)) ([945e428](https://github.com/fabieu/steam-next/commit/945e428dffbb2b7ecd72e6202cabef2ddd5fb961))


### Dependencies

* bump the major-updates group across 1 directory with 3 updates ([#10](https://github.com/fabieu/steam-next/issues/10)) ([a8714a1](https://github.com/fabieu/steam-next/commit/a8714a1462938fc0ea7fd6df3029e61e2a6c300f))

## [2.1.0](https://github.com/fabieu/steam-next/compare/2.0.0...2.1.0) (2026-01-01)


### Features

* **client:** add a `timeout` parameter to `Apps.get_changes_since()` ([abbf04a](https://github.com/fabieu/steam-next/commit/abbf04aff60d1af8bdcb65568610c24f68ec116f))
* **webauth:** rework session handling and add regression tests ([#5](https://github.com/fabieu/steam-next/issues/5)) ([68071cc](https://github.com/fabieu/steam-next/commit/68071cc923e3411e1156a2afb51cf5bf9bd778b2))
* regenerate proto files with an up-to-date protobuf compiler ([#6](https://github.com/fabieu/steam-next/issues/6)) ([026f404](https://github.com/fabieu/steam-next/commit/026f4040f1aa76fd96556ac5b4c65a3399c71d8b))


### Bug Fixes

* **cdn:** read the gid from the branch dict when it is not encrypted ([922c018](https://github.com/fabieu/steam-next/commit/922c018e48630cff6f23aba5993a52373c119757))


### Reverts

* fix for decoding content in request responses ([c5e6766](https://github.com/fabieu/steam-next/commit/c5e6766d7fbf6dbe96a76d96702772b0340167cb))

## 2.0.0 (2025-12-28)


### ⚠ BREAKING CHANGES

* **client:** no monkey patching on import; apply the gevent patches yourself via `steam.monkey`
* migrate the project to Poetry, Python 3.9+ and updated tooling


### Features

* **client:** add the `steam.monkey` module for applying gevent monkey patches
* modernize the project layout and packaging ([#3](https://github.com/fabieu/steam-next/issues/3)) ([383529f](https://github.com/fabieu/steam-next/commit/383529f04c459410f82525bc79e5aedec19ba82f))

## 1.0.0 (2020-05-02)


### ⚠ BREAKING CHANGES

* rename `steam.util` to `steam.utils` and move the proto helpers to `steam.utils.proto`
* remove the imports from the `steam` namespace
* replace the `cryptography` library with `pycryptodomex`
* move the `SteamClient` dependencies to the `client` extras
* **guard:** rename the `medium` param to `backend` on `SteamAuthenticator`
* **client:** replace the builtin CM server list with automatic discovery via WebAPI or DNS
* **client:** handle UM/ServiceMethods on the `SteamClient` instance, see `SteamClient.send_um()`
* **client:** remove `SteamClient.unifed_messages`, the `steam.client.mixins` package, the `Account` builtin, `change_email()` and `create_account()`


### Features

* add `steam.utils.appcache` methods for parsing appcache files
* **steamid:** support invite codes and update `SteamID.is_valid`
* **webauth:** add `WebAuth.cli_login()` handling all steps of the login process, and make `password` optional
* **client:** add `CDNClient` for downloading content from SteamPipe
* **client:** add a `rich_presence` property and block/unblock methods to `SteamUser`
* **client:** set a `payload` property on messages whose body cannot be parsed
* **client:** replace invalid unicode chars and include `_missing_token` in every `get_product_info()` result
* **client:** add jitter to the reconnect delay and use the new chat mode with a fallback option
* update all enums and protobufs, and raise the protocol version to 65580


### Bug Fixes

* **guard:** `create_emergency_codes()` not returning codes
* **guard:** `validate_phone_number()` returning no data
