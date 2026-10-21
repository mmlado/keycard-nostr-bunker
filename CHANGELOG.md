# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-16

### Added

- NIP-46 bunker with `connect`, `get_public_key`, `sign_event`, `ping`, `nip44_encrypt`, `nip44_decrypt`, `nip04_encrypt` and `nip04_decrypt`; NIP-44 for the transport, NIP-04 for older clients
- Keycard applet 4.x: BIP-340 Schnorr signing and ECDH on the card over Secure Channel V2, with the card's identity certificate checked against trusted Keycard CAs; older applets are refused
- Runs without the card and picks it up when it is inserted; reopens a session another program disturbed; refuses a card whose key UID is not the remembered one before any PIN is sent; a wrong PIN is tried once and remembered across restarts, and the last PIN attempt is never spent
- Clients are admitted by `connect` with the secret from the bunker URL, generated when the config has none; optional rotation of the secret after each use, and optional approval at a terminal prompt or with `clients approve`
- `clients list`, `pending`, `approve` and `revoke`; revoking rotates the secret, and approval admits only a client that asked, with the permissions it requested
- `connection.authorized_clients` for client pubkeys admitted without the secret
- The permissions a client requests in `connect` are stored with it and enforced, on top of the signing policy, `[signing] policy = "allowed_kinds" | "all"`
- Every request event is verified, its signature, id and age, before it is served, and served ids are kept across restarts
- A strict config loader: unknown keys and wrong types are errors, `key_path` and `ca_public_keys` are validated, and a config that holds a PIN or secret must be private
- The bunker URL is printed only on a terminal; `keycard-nostr-bunker url` prints it on demand
- State files are written atomically with mode 0600 in a 0700 directory, and the bunker and the `clients` commands take turns through a lock file
- Several relays, with reconnect
- `service install` and `service uninstall` set the bunker up as a systemd user service
- `tools/nip46_client.py`, a minimal NIP-46 client for trying a bunker by hand

[unreleased]: https://github.com/mmlado/keycard-nostr-bunker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mmlado/keycard-nostr-bunker/releases/tag/v0.1.0
