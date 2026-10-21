# keycard-nostr-bunker

[![Build status](https://github.com/mmlado/keycard-nostr-bunker/actions/workflows/test.yml/badge.svg)](https://github.com/mmlado/keycard-nostr-bunker/actions/workflows/test.yml) [![PyPI version](https://img.shields.io/pypi/v/keycard-nostr-bunker.svg)](https://pypi.org/project/keycard-nostr-bunker/) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A NIP-46 remote signer (bunker) that keeps your Nostr key on a [Keycard](https://keycard.tech).

With a Keycard running applet 4.x, every signature and every ECDH shared secret is computed on the card. The private key never leaves the secure element. Any NIP-46 client (Coracle, noStrudel, Snort, Amethyst) connects to the bunker with a `bunker://` URL.

```
Nostr client ──NIP-46──▶ relay ──NIP-46──▶ keycard-nostr-bunker ──PC/SC──▶ Keycard
```

1. The bunker subscribes to the configured relays for kind:24133 events addressed to its bunker key.
2. Each request is checked (signature, age), decrypted with NIP-44 (or NIP-04 for older clients) and dispatched.
3. `sign_event` sends the event hash to the card, which returns a BIP-340 Schnorr signature. `nip44_*` and `nip04_*` ask the card for the ECDH shared secret with the peer and do the symmetric part on the host.
4. The reply is encrypted and published back to the relays.

## Three keys

- **Your identity** is the key on the card at `key_path`. The bunker never has it. It learns the public key from the card and remembers it in `user.pubkey`, together with the card's key UID, so another card is refused before any PIN is sent.
- **The bunker key** in `signer.key` is a software key used only for the NIP-46 transport. Clients address it; it signs replies. It never signs anything as you.
- **A client** is whatever keypair the Nostr app generated for itself. The bunker knows it only as a pubkey and admits it by the secret in the bunker URL, see below.

## Requirements

- Python 3.11 or later
- A Keycard **development card** with applet 4.0.1 or later. Keycards sold in stores still ship applet 3.x, which has no Schnorr and no ECDH, so the bunker refuses them. [Get a development card](https://keycard.tech/6cd6gk).
- A PC/SC reader and `pcscd` running: `sudo systemctl enable --now pcscd.socket`
- To build `pyscard`, which has no Linux wheels on PyPI: a C compiler, `swig`, Python headers and pcsc-lite headers. Fedora: `sudo dnf install gcc swig python3-devel pcsc-lite-devel`. Debian and Ubuntu: `sudo apt install build-essential swig python3-dev libpcsclite-dev`.

> **Advertisement:** the development card link above is an affiliate link. The developer earns a
> commission on purchases made through it. Nothing in keycard-nostr-bunker depends on buying through it.

## Installation

```sh
pipx install keycard-nostr-bunker
```

Or from source:

```sh
git clone https://github.com/mmlado/keycard-nostr-bunker
cd keycard-nostr-bunker
python -m venv .venv && source .venv/bin/activate
pip install .
```

## Keycard setup

A development card needs the 4.x applet and an identity certificate first:

1. Build and install the applet from [keycard-tech/status-keycard](https://github.com/keycard-tech/status-keycard) at tag `4.0.1`: `./gradlew convertJavacard`, then `./gradlew install` with only the card's reader connected. This needs OpenJDK 11, and works as is because development cards come with the Keycard development keys.
2. Load an identity certificate from the Test CA: `keycard-cli load-ident --test`, or `python tools/load_test_identity.py` from a keycard-py checkout.
3. Set `trust_test_ca = true` in the config.

Then the card needs a PIN and a key. With [keycard-py](https://github.com/mmlado/keycard-py) (`pip install keycard mnemonic`):

```python
from keycard import KeyCard, constants
from keycard.constants import LoadKeyType
from mnemonic import Mnemonic

# A development card's certificate comes from the Test CA, so trust it here too.
card = KeyCard(ca_public_keys=[constants.OFFICIAL_CA_PUBLIC_KEY, constants.TEST_CA_PUBLIC_KEY])
card.transport.connect()
card.select()
card.init('123456', '987654321098')          # PIN, PUK; opens the secure channel
card.verify_pin('123456')
card.generate_key()                          # a fresh key that lives only on the card
# or, to keep an identity you already have as a mnemonic:
# card.load_key(LoadKeyType.BIP39_SEED, bip39_seed=Mnemonic.to_seed('your twelve words'))
```

[keycard-cli](https://github.com/keycard-tech/keycard-cli) does the same with `keycard init` and `keycard shell`.

**Can I keep my npub?** Only if your identity exists as a mnemonic (NIP-06) and you load that seed: with `key_path = "m/44'/1237'/0'/0/0"` the card derives the same key as any NIP-06 wallet. A bare `nsec` cannot be loaded as a derived key, so an nsec-only identity means a new npub.

**Certificates.** Applet 4.x cards prove they are genuine with an Identity Certificate. Store-bought 4.x cards, once they exist, will carry one from the official CA, trusted by default. A development card carries one from the Test CA (`trust_test_ca = true`) or from your own CA (`ca_public_keys`). Trust the Test CA only on machines you control, since anyone can sign with it.

## Configuration

Copy `config.example.toml` to `~/.config/keycard-nostr-bunker/config.toml` and edit. The loader is strict: an unknown key or a value of the wrong type is an error, and a config that holds a PIN or secret must be mode 0600.

| Section | Key | Meaning |
|---|---|---|
| `relay` | `urls` | Relays to listen on and publish replies to; two is a good number |
| `keycard` | `pin` | Card PIN; see the PIN sources below |
| | `reader` | Part of the PC/SC reader name to use; empty means any |
| | `key_path` | Derivation path of the Nostr key, under `m/44'/1237'` or `m/43'/60'/1581'` |
| | `trust_test_ca`, `ca_public_keys` | Extra Keycard CAs to trust |
| `signer` | `key_file` | Bunker keypair file; the other state files live next to it |
| `signing` | `policy` | `allowed_kinds` signs only the listed kinds; `all` signs everything |
| | `allowed_kinds` | Event kinds to sign; the example config lists the usual ones |
| `connection` | `secret` | Secret in the bunker URL that admits a client; generated if empty |
| | `rotate_secret` | Replace the secret once a client has used it, so a URL serves one client |
| | `approve_clients` | Ask before admitting a client |
| | `authorized_clients` | Client pubkeys admitted without the secret |

The key path decides the public key. The default is the EIP-1581 subtree, which the Nim predecessor used, so existing users keep their npub. `m/44'/1237'/0'/0/0` gives the same npub as any NIP-06 wallet seeded from the same mnemonic.

### State files

Everything the bunker remembers sits next to `signer.key`, mode 0600 in a 0700 directory:

| File | Holds |
|---|---|
| `signer.key` | the bunker's transport key |
| `secret` | the generated admission secret; `clients revoke` and `rotate_secret` replace it |
| `clients` | admitted client pubkeys, with when and through which relay they came |
| `pending` | clients waiting for approval, with the permissions they asked for |
| `admission.lock` | lets the bunker and the `clients` commands take turns changing `clients`, `pending` and `secret` |
| `seen` | ids of recent requests, so a restart does not serve them twice |
| `user.pubkey` | your public key and the card's key UID |
| `pin.rejected` | present after a wrong PIN; removed by a successful one |

## Running

```sh
keycard-nostr-bunker
```

That reads `config.toml` from the current directory, or `~/.config/keycard-nostr-bunker/config.toml` if there is none. `-c FILE` picks another; it goes before or after the subcommand.

```
11:02:04 [INFO] Config: /home/me/.config/keycard-nostr-bunker/config.toml
11:02:04 [INFO] State: /home/me/.config/keycard-nostr-bunker
11:02:04 [INFO] Bunker pubkey: 4f6915de49dbfe3457bcedaf217a25ac188222f96e1a17aa518eb57e5ccf0c89
11:02:04 [INFO] Keycard: applet 4.0 in Generic USB2.0-CRW [Smart Card Reader Interface] 00 00
11:02:05 [INFO] Keycard: PIN verified
11:02:05 [INFO] Keycard: ready
11:02:05 [INFO] User pubkey: 1ed7d46f37d4f0f5f35538679bf77fd9b0a839041acf3a1dbbae5a3e0fd347e1
11:02:05 [INFO] Signing policy: allowed_kinds [0, 1, 3, 5, 6, 7, 10002]
11:02:05 [INFO] Admitted clients: 0

bunker://4f6915de49dbfe3457bcedaf217a25ac188222f96e1a17aa518eb57e5ccf0c89?relay=wss://relay.damus.io&relay=wss://nos.lol&secret=X0dxuE2zI2BAOcGKqWTbsg

11:02:05 [INFO] Connected to relay: wss://relay.damus.io
11:02:10 [INFO] NIP-46 admitted client 8f1f3a2c...
11:02:11 [INFO] NIP-46 sign_event -> ok
```

Paste the `bunker://` URL into the client's remote signer field. The URL carries the secret, so it is printed only when the bunker runs in a terminal; a service logs a hint instead, and `keycard-nostr-bunker url` prints it on demand.

| Command | |
|---|---|
| `keycard-nostr-bunker` or `keycard-nostr-bunker run` | start the bunker |
| `keycard-nostr-bunker run --no-card` | sign with the bunker key instead of a card, to test the relay side |
| `keycard-nostr-bunker url` | print the bunker URL, secret included, without starting anything |
| `keycard-nostr-bunker readers` | list PC/SC readers, for the `reader` setting |
| `keycard-nostr-bunker service install` / `uninstall` | systemd user service, see below |
| `keycard-nostr-bunker clients list` / `pending` | admitted clients, clients waiting for approval |
| `keycard-nostr-bunker clients approve <pubkey>` / `revoke <pubkey>` | admit or remove a client |

`-v` turns on debug logging.

### Admitting clients

Clients are admitted by the secret in the `bunker://` URL: the first `connect` with it enrolls the client's pubkey in `clients`, and every other request from a pubkey not in that file is refused with `unauthorized`. The URL is therefore a bearer credential: whoever has it can enroll one client. Treat it like a password and paste it only into apps you trust.

`keycard-nostr-bunker clients revoke <pubkey>` removes a client, drops its request from `pending` if it has one, and rotates the secret at the same time, since the client still knows the old one; the running bunker picks both changes up at once. If the secret is fixed in the config, change it there. The same command is the answer to a leaked URL: revoke anything you do not recognise, and the old URL admits nobody.

Two options tighten admission:

- `rotate_secret = true` replaces the secret as soon as a client presents it, whether or not you then approve that client, and prints the new URL. A URL you already used admits nobody else.
- `approve_clients = true` makes the bunker ask you before admitting. In a terminal it prompts, with a minute to answer, and the answer is the first four characters of the pubkey shown, so a stray keystroke cannot approve anyone. As a service it parks the client in `pending`, logs the pubkey, and the client gets `pending approval` until you run `keycard-nostr-bunker clients approve <pubkey>` and it connects again. `clients pending` lists who is waiting, with the time, the relay and the permissions asked for. Only a client that asked can be approved: `clients approve` refuses a key that is not in `pending`, and admits a waiting one with exactly the permissions it requested. A waiting client that connects again gets `pending approval` without being asked for the secret again, which matters with `rotate_secret`, since the secret in its URL is already gone. `pending` keeps the 64 most recent requests; a client pushed out has to connect again with a current URL. Approve only a client you have just set up yourself, right after pasting the URL, and refuse anything you did not expect. A hacker with the URL then still needs your approval, on your machine.

To admit a client whose pubkey you already know, without any URL, list it in `connection.authorized_clients`. Those clients skip the secret and the approval and show up in `clients list` as coming from the config. The list is read when the bunker starts. To revoke one, run `clients revoke <pubkey>`, which also removes any record the key got at runtime, then delete it from the config and restart the bunker.

For a desktop, `approve_clients` with the prompt is the comfortable choice. For a headless service, `rotate_secret` keeps a leaked URL harmless and `clients approve` over SSH works when you need it.

A client can also say what it needs. NIP-46 lets `connect` carry a permission list such as `sign_event:1,nip44_encrypt`, and the bunker holds the client to it: it is stored with the client, shown in the approval prompt and in `clients pending`, and anything outside it is refused, for example `sign_event for kind 3 is not among the permissions this client requested`. `ping` and `get_public_key` are always allowed. A client that sends no list is unrestricted, as before. The list is fixed at admission; reconnecting cannot widen it, so revoke the client to start over. Clients from `authorized_clients` are unrestricted.

What an admitted client can do is also bounded by `signing`: with `policy = "allowed_kinds"` the bunker signs only those kinds, and a rejected request says so in the log and to the client (`kind 7 is not in signing.allowed_kinds`). Encryption and decryption requests are not filtered.

### Running without the card

The bunker starts whether or not the card is inserted and watches the readers. While the card is out, `connect`, `ping` and `get_public_key` work, the last one from the public key remembered in `user.pubkey`, and signing and ECDH requests get the error `Keycard not present`. Insert the card and the session opens; remove it and the session closes, together with any cached ECDH secrets. A card whose key UID is not the remembered one is refused before any PIN is sent, so the identity cannot change under a running bunker. Delete `user.pubkey` after changing `key_path` or loading a new key.

If another program uses the card while the bunker runs, the session is reopened on the next request. The PIN is sent at most once per card and per PIN: a wrong PIN is remembered in `pin.rejected` across restarts, and when the card reports a single attempt left the bunker does not spend it. A refused card shows up in the log with the reason, and clients get `Keycard refused: ...`.

The PIN comes from the first of: `keycard.pin` in the config, the `KEYCARD_NOSTR_BUNKER_PIN` environment variable, a systemd credential named `pin`, a prompt when running in a terminal.

### As a service

```sh
keycard-nostr-bunker service install -c ~/.config/keycard-nostr-bunker/config.toml
```

This writes a systemd user unit for that config, pointing at the `keycard-nostr-bunker` command you ran, then enables and starts it. A service cannot prompt for the PIN, so the install refuses unless `keycard.pin` is set or a file named `pin` sits next to the config; that file is passed to the service as a systemd credential and the PIN stays out of the config. Create it with:

```sh
(umask 077 && echo 123456 > ~/.config/keycard-nostr-bunker/pin)
```

Useful afterwards:

```sh
keycard-nostr-bunker url                         # the bunker URL; it is not in the journal
journalctl --user -u keycard-nostr-bunker -f     # logs
loginctl enable-linger                     # keep running while logged out
keycard-nostr-bunker service uninstall
```

`pcscd` must be running. The bunker stops cleanly on SIGTERM.

## Supported NIP-46 methods

| Method | Card operation |
|---|---|
| `connect` | none; enrolls the client when the secret matches |
| `get_public_key` | EXPORT KEY (public) at `key_path`, cached |
| `sign_event` | SIGN, BIP-340 Schnorr, after the signing policy |
| `nip44_encrypt`, `nip44_decrypt` | ECDH on the card, NIP-44 v2 on the host |
| `nip04_encrypt`, `nip04_decrypt` | ECDH on the card, AES-256-CBC on the host |
| `ping` | none |

Every method but `connect` requires an admitted client. Every request must be signed by its pubkey, carry a matching id, and be no more than a minute old; the bunker checks this itself and does not trust the relay.

## Relays

The relay is only a mailbox for signer traffic. It must accept kind 24133 events without NIP-42 AUTH and be reachable from the bunker and from every client; it does not have to be a relay you post to. `wss://relay.nsec.app` exists for NIP-46 traffic; `wss://relay.damus.io` and `wss://nos.lol` work too. Use two. Both the bunker and the clients only make outbound connections, so NAT and firewalls need no configuration.

## Tests

```sh
pip install -e '.[dev]'
pytest
```

The suite covers BIP-340 and NIP-44 against the official vectors, the NIP-46 dispatcher, and the Keycard signer against a fake card. No card is needed.

## Limitations

- No per-request approval; the signing policy is static.
- No NFC transport.
- Relay AUTH (NIP-42) and the `nostrconnect://` flow are not supported.

## License

MIT
