from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import sys
from pathlib import Path

from . import nip19
from .approval import AutoApprover, PromptApprover
from .event import Event
from .identity import Identity, IdentityError, IdentityStore, short_key
from .nip46 import Bunker, BunkerUrl, RemoteSigner
from .relay import PublishResult, RelayPool

VIEWER_URL = "https://njump.me/"


class KaznaCLI:
    def __init__(self, store: IdentityStore):
        self.store = store
        self.parser = self._build_parser()

    def run(self, argv: list[str] | None = None) -> int:
        args = self.parser.parse_args(argv)
        try:
            return args.handler(args)
        except IdentityError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="kazna", description="Minimal Nostr identity tool.")
        commands = parser.add_subparsers(required=True, metavar="command")

        create = commands.add_parser("create", help="generate a new identity")
        create.add_argument("name")
        create.set_defaults(handler=self.create)

        import_ = commands.add_parser("import", help="store an existing secret key (nsec or hex)")
        import_.add_argument("name")
        import_.set_defaults(handler=self.import_)

        show = commands.add_parser("show", help="print an identity's public key")
        show.add_argument("name")
        show.set_defaults(handler=self.show)

        post = commands.add_parser("post", help="publish a text note (kind 1)")
        post.add_argument("name")
        post.add_argument("-m", "--message", required=True)
        post.add_argument("--relay", action="append", dest="relays", metavar="URL",
                          help="relay to publish to (repeatable, replaces the defaults)")
        post.set_defaults(handler=self.post)

        bunker = commands.add_parser("bunker", help="run a NIP-46 remote signer for an identity")
        bunker.add_argument("name")
        bunker.add_argument("--relay", action="append", dest="relays", metavar="URL",
                            help="relay to listen on (repeatable, replaces the defaults)")
        bunker.add_argument("--yes", action="store_true",
                            help="sign without asking (for automated tests only)")
        bunker.set_defaults(handler=self.bunker)

        return parser

    def create(self, args: argparse.Namespace) -> int:
        identity = Identity.generate()
        self.store.save(args.name, identity)
        print(f"created identity {args.name!r}")
        self._print_public(identity)
        return 0

    def import_(self, args: argparse.Namespace) -> int:
        if sys.stdin.isatty():
            secret = getpass.getpass("secret key (nsec1… or hex): ")
        else:
            secret = sys.stdin.readline()
        identity = Identity.from_secret(secret)
        self.store.save(args.name, identity)
        print(f"imported identity {args.name!r}")
        self._print_public(identity)
        return 0

    def show(self, args: argparse.Namespace) -> int:
        self._print_public(self.store.load(args.name))
        return 0

    def post(self, args: argparse.Namespace) -> int:
        if not args.message.strip():
            self.parser.error("message is empty")
        identity = self.store.load(args.name)
        event = Event.text_note(args.message).sign(identity)
        results = asyncio.run(self._publish(args.relays or RelayPool.DEFAULT_RELAYS, event))

        print(f"event   {event.id}")
        for result in results:
            status = "OK  " if result.accepted else "FAIL"
            detail = f"  ({result.message})" if result.message else ""
            print(f"  {status}  {result.relay}{detail}")

        accepted = [r.relay for r in results if r.accepted]
        if not accepted:
            print("no relay accepted the event", file=sys.stderr)
            return 1
        nevent = nip19.encode_nevent(event.id, accepted, event.pubkey, event.kind)
        print(f"view    {VIEWER_URL}{nevent}")
        return 0

    def bunker(self, args: argparse.Namespace) -> int:
        identity = self.store.load(args.name)
        logging.basicConfig(format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
        logging.getLogger("kazna").setLevel(logging.INFO)

        signer = RemoteSigner(identity, AutoApprover() if args.yes else PromptApprover())
        bunker = Bunker(signer, args.relays or Bunker.DEFAULT_RELAYS, on_connect=self._print_next_link)
        print(f"signing as  {args.name}  {identity.npub}")
        print(f"signer key  {signer.signer_key.pubkey}  (new for this session)")
        if args.yes:
            print("warning: --yes signs every request without asking")
        print("\npaste this link into the app; it works for one connection:\n")
        print(f"{bunker.url}\n")
        print("waiting for requests, Ctrl+C to stop")
        try:
            asyncio.run(bunker.serve())
        except KeyboardInterrupt:
            print("\nstopped")
        return 0

    @staticmethod
    async def _publish(urls, event: Event) -> list[PublishResult]:
        async with RelayPool(urls) as pool:
            return await pool.publish(event)

    @staticmethod
    def _print_next_link(client: str, url: BunkerUrl) -> None:
        print(f"\nclient {short_key(client)} connected. Link for another login:\n\n{url}\n")

    @staticmethod
    def _print_public(identity: Identity) -> None:
        print(f"npub    {identity.npub}")
        print(f"pubkey  {identity.pubkey}")
        print(f"profile {VIEWER_URL}{identity.npub}")


def main(argv: list[str] | None = None) -> int:
    store = IdentityStore(Path(os.environ.get("KAZNA_HOME", "identities")))
    return KaznaCLI(store).run(argv)
