[![PyPI](https://img.shields.io/pypi/v/steam-next.svg?label=pypi)](https://pypi.python.org/pypi/steam-next)
[![Python Versions](https://img.shields.io/pypi/pyversions/steam-next.svg?label=%20&logo=python&logoColor=white)](https://pypi.python.org/pypi/steam-next)
[![License](https://img.shields.io/pypi/l/steam-next.svg?style=flat&label=license)](https://pypi.python.org/pypi/steam-next)
[![Docs](https://readthedocs.org/projects/steam-next/badge/?version=latest)](https://steam-next.readthedocs.io/latest/)

A python module for interacting with various parts of [Steam](https://store.steampowered.com/) supporting python `3.9+`.

> [!NOTE]
> This project builds upon an earlier fork that is no longer maintained.
> While preserving the original intent, this version introduces modern improvements, fixes, and long-term
> maintainability.

**Documentation:** https://steam-next.readthedocs.io/latest/

## Features

- [`SteamClient`](https://steam-next.readthedocs.io/latest/api/steam.client.html) – communication with the steam
  network based on `gevent`
- [`CDNClient`](https://steam-next.readthedocs.io/latest/api/steam.client.cdn.html) – access to Steam content depots
- [`WebAuth`](https://steam-next.readthedocs.io/latest/api/steam.webauth.html) – authentication for access to
  `store.steampowered.com` and `steamcommunity.com`
- [`WebAPI`](https://steam-next.readthedocs.io/latest/api/steam.webapi.html) – simple API for Steam's Web API with
  automatic population of interfaces
- [`SteamAuthenticator`](https://steam-next.readthedocs.io/latest/api/steam.guard.html) – enable/disable/manage two
  factor authentication for Steam accounts
- [`SteamID`](https://steam-next.readthedocs.io/latest/api/steam.steamid.html) – convert between the various ID
  representations with ease
- [`Master Server Query Protocol`](https://steam-next.readthedocs.io/latest/api/steam.game_servers.html) – query
  master servers directly or via `SteamClient`

Checkout the [User guide](https://steam-next.readthedocs.io/latest/user_guide.html) for examples,
or the [API Reference](https://steam-next.readthedocs.io/latest/api/steam.html) for details.

For questions, issues or general curiosity visit the repo at
https://github.com/fabieu/steam-next

---

## Install

For system specific details, see
[Installation Details](https://steam-next.readthedocs.io/latest/install.html).

Install latest release version from PyPI:

```bash
# with SteamClient dependencies
pip install -U "steam-next[client]"

# without (only when using parts that do not rely on gevent and protobuf)
pip install -U steam-next
```
