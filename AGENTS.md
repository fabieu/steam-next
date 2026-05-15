# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Codex, Cursor, Aider, etc.) when working with code in this
repository.

## Project overview

`steam-next` is a Python library for interacting with Steam (CM servers, WebAPI, CDN/depots, Web auth, 2FA, SteamID,
master server queries). It is a maintained fork of the original `ValvePython/steam` project. The `SteamClient` stack is
`gevent`-based; everything else works without gevent. Public installation extra `client` pulls in `gevent`,
`gevent-eventemitter`, and `protobuf`.

Supported Python: 3.10–3.14.

## Common commands

Dependencies are managed by Poetry (version pinned to `2.4.1` in `.github/actions/setup-poetry/action.yml`).

```bash
poetry install --extras client --with dev   # full dev install (matches CI)
poetry run pytest                           # full test suite
poetry run pytest tests/test_steamid.py     # single file
poetry run pytest tests/test_steamid.py -k SteamID  # filtered by name
poetry run pytest --cov=steam               # with coverage (what `make test` does)
poetry build                                # build sdist + wheel into dist/
```

`Makefile` exposes the same as `make init`, `make test`, `make build`. The Makefile is bash/Linux-only — on Windows,
call `poetry` directly.

Vermin checks minimum-Python compatibility; config lives in `vermin.conf`.

### Regenerating protobuf bindings

Hand-edited Python is not used for protobufs — `steam/protobufs/*_pb2.py` is generated from `protobufs/*.proto`. Run the
pipeline only when updating upstream protos; never edit a `_pb2.py` file directly.

Prerequisites: `wget`, GNU `sed`, and `protoc` on `PATH`. All `pb_*` targets assume a Unix shell — on Windows use WSL or
Git Bash.

End-to-end refresh:

```bash
make pb_update    # = pb_clear + pb_fetch + pb_compile + pb_services + pb_gen_enums
```

Individual targets, in pipeline order:

| Target              | What it does                                                                                                                                                                                                                                                                                           |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `make pb_clear`     | Deletes `protobufs/*.proto` and `steam/protobufs/*_pb2.py`. Run first to drop stale outputs.                                                                                                                                                                                                           |
| `make pb_fetch`     | `wget`s every URL in `protobuf_list.txt` into `protobufs/`. Renames `*.steamclient.proto` → `*.proto`, prepends `syntax = "proto2";`, swaps `cc_generic_services` → `py_generic_services`, rewrites cross-proto imports to match the renames.                                                          |
| `make pb_compile`   | Runs `protoc --python_out=steam/protobufs/ --proto_path=protobufs` over every `.proto` in `protobufs/` and `protobufs/tests/`, then rewrites the resulting `_pb2.py` imports (anything other than `import sys`) to `import steam.protobufs.<name>` so generated modules are importable when installed. |
| `make pb_services`  | Regenerates the Unified Message service registry inside `steam/core/msg/unified.py`, between the `MARK_SERVICE_START` and `MARK_SERVICE_END` sentinels, by scanning `service` declarations across all proto files. Do not remove those sentinels.                                                      |
| `make pb_gen_enums` | Runs `generate_enums_from_proto.py`, which imports the proto modules listed at the top of that script and dumps every enum it finds into `steam/enums/proto.py`. If a new proto file with enums is added you must also add its `_pb2` name to `_proto_modules` in `generate_enums_from_proto.py`.      |

Adding a new proto source: append the upstream URL to `protobuf_list.txt`, then run `make pb_update`. If the new proto
defines enums, edit `generate_enums_from_proto.py:_proto_modules` to include it before the `pb_gen_enums` step.

After regeneration, commit the generated `steam/protobufs/*_pb2.py`, the updated `steam/core/msg/unified.py`, and the
updated `steam/enums/proto.py` together with the `protobufs/*.proto` and `protobuf_list.txt` changes — they are
intentionally vendored.

### Regenerating VCR cassettes

Webauth tests use VCR.py cassettes under `vcr/`. To regenerate (requires real Steam credentials):

```bash
make webauth_gen   # runs tests/generete_webauth_vcr.py
```

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for all commits in this repo.

- Format: `<type>(<optional scope>): <description>`
- Common types: `feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `build`, `ci`, `chore`.
- Use `!` after the type/scope or a `BREAKING CHANGE:` footer for breaking changes.
- Scope examples already used in history: `appcache`, `ci`.
- Keep the subject in the imperative mood and under ~72 chars.

## Architecture

### Layers

- **`steam.core`** — low-level CM (Connection Manager) protocol. `CMClient` (`core/cm.py`) is an `EventEmitter` that
  owns a `TCPConnection` (`core/connection.py`), handles handshake/crypto (`core/crypto.py`), and emits each incoming
  message as an event keyed by its `EMsg`. `core/msg/` defines `Msg`/`MsgProto` and the `unified.py` service registry
  that maps Unified Message service names to their `_pb2` modules. `core/manifest.py` parses CDN depot manifests.

- **`steam.client`** — high-level `SteamClient` extends `CMClient + BuiltinBase`. Features are composed via mixins in
  `client/builtins/` (`apps`, `friends`, `gameservers`, `leaderboards`, `unified_messages`, `user`, `web`).
  `client/cdn.py` (`CDNClient`) is the SteamPipe downloader, `client/user.py` models `SteamUser`, `client/gc.py` wraps
  the GameCoordinator channel.

- **`steam.webapi`**, **`steam.webauth`**, **`steam.guard`**, **`steam.steamid`**, **`steam.game_servers`** —
  independent, gevent-free modules. `webauth` handles `store.steampowered.com` / `steamcommunity.com` login; `guard` is
  the 2FA / mobile authenticator implementation; `steamid` handles all SteamID/SteamID64/invite-code conversions.

- **`steam.protobufs`** — generated `_pb2.py` modules. Do not edit by hand. The import rewrite step in `pb_compile`
  makes every cross-proto import resolve as `steam.protobufs.<module>` so the package is importable when installed.

- **`steam.enums`** — hand-written core enums plus generated `proto.py` (mirrors proto enum values) and `emsg.py` (
  EMsg → name).

- **`steam.utils`** — helpers including `appcache.py` / `appcache_readers.py` (V28/V29 `appinfo.vdf` parsers, V29 added
  string-table compression in 2.2.0), `proto.py` (proto<->dict helpers), `binary.py`, `throttle.py`, `web.py`.

- **`steam.monkey`** — opt-in gevent monkey-patching helper. Since 2.0.0 the library no longer monkey-patches stdlib on
  import; consumers using `SteamClient` outside a fully-gevent app should call `steam.monkey.patch_minimal()`
  themselves.

### Gevent boundary

Anything that touches `steam.client.SteamClient`, `steam.core.cm`, or `steam.client.cdn.CDNClient` runs cooperatively
under gevent and depends on `gevent.socket`. The rest of the package is plain blocking Python and works under asyncio /
threads. Keep this split in mind when adding features — putting blocking I/O into the client side will hang the gevent
hub.

### Tests

- `tests/test_data/` holds binary fixtures (appcache VDF blobs, manifest payloads).
- `vcr/*.yaml` cassettes drive `test_webapi.py` and `test_webauth.py` (no network needed at test time).
- `test_appcache.py` is the canary for V28/V29 `appinfo.vdf` format changes — re-run after touching
  `steam/utils/appcache*`.

## CI

- `.github/workflows/test.yml` — matrix of 3 OS × 5 Python (3.10–3.14), uses the local composite action
  `./.github/actions/setup-poetry` (Python + Poetry + `.venv` cache). Triggers on PR and is reusable via
  `workflow_call`.
- `.github/workflows/build.yml` — `workflow_dispatch` only. Runs the reusable test workflow, builds the dist, publishes
  to PyPI via **OIDC trusted publishing** (`pypa/gh-action-pypi-publish`, environment `pypi`), then creates a GitHub
  release. There is no `PYPI_TOKEN` — trusted publishing is configured PyPI-side.
- Third-party actions are SHA-pinned with version comments; first-party `actions/*` use major-version tags.
