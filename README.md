**English** · [Español](README.es.md)

# kazna

A small Nostr key keeper and **NIP-46 remote signer** in Python, built to log in to
[Stacker News](https://stacker.news) without handing the site your secret key.

You create (or import) a Nostr identity, run `kazna bunker <name>`, and paste the
`bunker://` link it prints into Stacker News. The site asks kazna to sign its login
challenge over Nostr relays, kazna shows you the request, and signs it only if you approve.

## Demo

https://github.com/user-attachments/assets/66412f93-1f4a-44ce-80fc-e57e506ea856

## Setup

Requires Docker with Compose. Everything runs in containers.

```sh
docker compose build
alias kazna='docker compose run --rm kazna'      # bash/zsh
alias kazna 'docker compose run --rm kazna'      # fish
```

Run the alias from the project directory, where `docker-compose.yml` lives.

## Logging in to Stacker News

```sh
kazna create vavilov        # or: kazna import vavilov  (paste an nsec1… or hex secret)
kazna bunker vavilov
```

`bunker` prints a one-time link and waits:

```
signing as  vavilov  npub1…
signer key  65ec0cb4…  (new for this session)

paste this link into the app; it works for one connection:

bunker://65ec0cb4…?relay=wss%3A%2F%2Fnos.lol&relay=wss%3A%2F%2Frelay.primal.net&secret=3685…
```

1. Open <https://stacker.news/signup?callbackUrl=https%3A%2F%2Fstacker.news%2F&type=nostr>.
2. Choose the token / NIP-05 option, paste the `bunker://` link and submit.
3. kazna shows the event Stacker News wants signed:

   ```
   client 04092e30…7e2f asks to sign:
     kind     27235
     content  'Stacker News Authentication'
     tag      challenge a3ff237b…
     tag      u https://stacker.news
     tag      method GET
   sign it? [y/N]
   ```

4. Answer `y`. Stacker News verifies the signature and logs you in. A new pubkey gets a new
   account, which Stacker News only creates from the `/signup` page.

Each link works for one connection. After a client connects, kazna prints a fresh link for
the next login.

## Other commands

```sh
kazna show vavilov                         # npub, hex pubkey and a profile link
kazna post vavilov -m "marri marri mapu"   # sign and publish a kind 1 text note
```

`post` prints each relay's answer and an njump.me link to the note. Notes on public relays are
public and effectively permanent.

## How it works

```
Stacker News page (NDK, in your browser)        relays               kazna bunker
  connect [ "", secret ]          ── kind 24133, encrypted ──►   check one-time secret → "ack"
  get_public_key                  ──────────────────────────►   your identity's pubkey
  sign_event {kind 27235, challenge}  ──────────────────────►   ask y/N → sign with your key
  ◄──────────────────────── signed event ─────────────────────
  → Stacker News's server checks id, Schnorr signature and challenge → session
```

- **Two keys.** Your identity key (stored on disk) only signs the events you approve. Each
  `bunker` session creates a separate *signer key*; the client talks to that one and learns
  your identity through `get_public_key`, as NIP-46 describes.
- **Encryption.** Requests are decrypted with NIP-44 or NIP-04, detected per message, and the
  reply uses the same scheme. Stacker News's client (NDK 2.12.2) sends NIP-04 by default.
- **Methods.** `connect`, `get_public_key`, `sign_event`, `ping` and `logout`. Everything else
  gets an `unsupported method` error. Requests from clients that haven't connected are refused.
- **Envelopes are verified.** Incoming events with a bad id or signature are dropped. Relays
  reconnect with backoff, and an event seen on several relays is handled once.

## Storage

Each identity is a directory `identities/<name>/` with `key.json` (name, pubkey, npub, nsec,
created_at), mode `0600` inside a `0700` directory. `identities/` is mounted at `/data`
(`KAZNA_HOME`) and ignored by git.

## Testing

```sh
docker compose run --rm --entrypoint pytest kazna
```

The unit tests include the official NIP-44 test vectors, the NIP-19 examples, NIP-04 checked
against OpenSSL, and the signer's protocol rules.

The login itself is tested against **Stacker News's own client code**:
`tests/sn-client/login.mjs` reproduces its login (same NDK 2.12.2, same URL patch, same
kind 27235 event) and then applies the checks its server runs. It runs against a local relay:

```sh
docker compose --profile dev up -d relay
kazna bunker vavilov --relay ws://relay:8080          # in one terminal
docker compose --profile dev run --rm sn-client "<bunker://…>" [--nip44]
docker compose --profile dev down
```

## Assumptions and tradeoffs

- **Stacker News is the target client.** Where its client (NDK 2.12.2) differs from the
  current NIP-46 text, kazna accepts both. It accepts an empty first `connect` param and
  replies `"ack"` rather than echoing the secret.
- **Only the `bunker://` flow.** Stacker News doesn't offer `nostrconnect://`, so it isn't
  implemented. Neither are `auth_url` challenges or `switch_relays`.
- **No encrypt/decrypt methods.** `nip04_*` and `nip44_*` would let a connected client read
  your DMs, and login doesn't need them, so they are refused.
- **Sessions live in memory.** The signer key and connected clients are lost when `bunker`
  stops. Stacker News makes a new client key for every login anyway.
- **A yes/no prompt instead of permission policies.** `--yes` auto-approves, for automated
  tests only.
- **The secret key is stored in plaintext**, protected only by file permissions.
  Password-based encryption (NIP-49) is planned.
- **Default relays** are `nos.lol` and `relay.primal.net`, the ones that worked in testing.
  Use `--relay` to choose others; Stacker News's page connects to whatever the link lists.
- **Low-level libraries instead of a Nostr SDK.** Events, NIP-19, NIP-04, NIP-44 and NIP-46 are
  implemented here on top of `coincurve`, `cryptography`, `bech32` and `websockets`.

## Layout

```
kazna/
  identity.py  Identity (keypair, ECDH) and IdentityStore (one directory per identity)
  event.py     Event: NIP-01 serialization, id, sign, verify, parsing untrusted JSON
  nip19.py     bech32 encodings: npub, nsec, nevent
  cipher.py    Cipher base class
  nip04.py     Nip04Cipher (AES-256-CBC)
  nip44.py     Nip44Cipher (v2: ChaCha20 + HMAC-SHA256)
  relay.py     RelayConnection (reconnecting websocket) and RelayPool
  nip46.py     RemoteSigner (methods) and Bunker (relay transport), BunkerUrl
  approval.py  PromptApprover (y/N on the terminal) and AutoApprover
  cli.py       argparse commands
tests/
  test_*.py    unit tests, vectors/ holds the NIP-44 vectors
  sn-client/   Stacker News's login client (Node, NDK 2.12.2) for local end-to-end tests
```
