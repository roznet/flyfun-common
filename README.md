# flyfun-common

Shared code for [flyfun](https://flyfun.aero) services.

This repository hosts both the Python library (FastAPI auth, database models, OAuth) and the Swift library (auth client, rolling Bearer sessions, login UI) used across the flyfun apps and servers.

## Layout

- [`python/`](./python/) — `flyfun-common` Python package (FastAPI shared code). See [`python/README.md`](./python/README.md).
- `Sources/FlyFunCommon/` — `FlyFunCommon` Swift package (iOS / macOS shared code). See [`Package.swift`](./Package.swift).

## License

MIT
