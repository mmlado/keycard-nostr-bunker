# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `connection.authorized_clients` admits known client pubkeys without the secret
- The permissions a client requests in `connect` are stored with it and enforced, on top of the signing policy
- `tools/nip46_client.py`, a minimal NIP-46 client for trying a bunker by hand

### Changed

- `[approval] mode = "policy" | "always"` is now `[signing] policy = "allowed_kinds" | "all"`
- Every request event is verified (signature, id, age) before it is served, and served ids are kept across restarts
- `clients revoke` rotates the generated secret; `clients pending` shows when and through which relay a client asked
- The config loader rejects unknown keys and wrong types, validates `key_path` and `ca_public_keys`, and refuses a world-readable config that holds a PIN or secret
- The bunker URL is printed only on a terminal; `keycard-nostr-bunker url` prints it on demand
- State files are written atomically with mode 0600 in a 0700 directory

### Fixed

- A request whose body was not a JSON object, or whose reply exceeded the NIP-44 size limit, dropped the relay connection
- A dead card session was not reopened until a physical reinsert; the per-peer ECDH cache outlived the card
- The wrong-PIN guard did not survive a restart, and the card's identity was checked only after the PIN
- Deleting the `clients` file revoked nobody in a running bunker
- A closing relay could tear down a healthy one during reply fan-out
- The terminal approval prompt could be answered by stale input and blocked all other requests
- `service install` wrote unquoted paths into the unit

## [0.1.0] - 2026-10-16

### Added

- NIP-46 bunker with `connect`, `get_public_key`, `sign_event`, `ping`, `nip44_encrypt`, `nip44_decrypt`, `nip04_encrypt` and `nip04_decrypt`
- Keycard applet 4.x: BIP-340 Schnorr signing and ECDH on the card over Secure Channel V2; older applets are ignored
- Runs without the card and picks it up on insertion
- Clients are admitted by `connect` with the secret from the bunker URL and remembered; the secret is generated when the config has none
- Optional secret rotation after each admission and optional approval of new clients, from a prompt or `clients approve`; `clients revoke` and `clients pending`
- Approval policy by event kind, multiple relays with reconnect
- `service install` sets the bunker up as a systemd user service

[unreleased]: https://github.com/mmlado/keycard-nostr-bunker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mmlado/keycard-nostr-bunker/releases/tag/v0.1.0
