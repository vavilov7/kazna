from __future__ import annotations

import asyncio
import sys
import threading
from abc import ABC, abstractmethod

from .event import Event
from .identity import short_key


class Approver(ABC):
    """Decides whether the signer may sign an event a client asked for."""

    @abstractmethod
    async def approve(self, client: str, event: Event) -> bool: ...


class AutoApprover(Approver):
    """Signs everything. Meant for automated tests, not for real use."""

    async def approve(self, client: str, event: Event) -> bool:
        return True


class PromptApprover(Approver):
    """Shows the event on the terminal and waits for y/N; anything but yes rejects."""

    CONTENT_PREVIEW = 200

    def __init__(self):
        self._lines: asyncio.Queue[str | None] | None = None
        self._eof = False

    async def approve(self, client: str, event: Event) -> bool:
        print(self.describe(client, event))
        print("sign it? [y/N] ", end="", flush=True)
        answer = await self._read_line()
        approved = answer.strip().lower() in {"y", "yes"}
        print("approved" if approved else "rejected")
        return approved

    @classmethod
    def describe(cls, client: str, event: Event) -> str:
        content = event.content
        if len(content) > cls.CONTENT_PREVIEW:
            content = content[:cls.CONTENT_PREVIEW] + "…"
        lines = [
            f"\nclient {short_key(client)} asks to sign:",
            f"  kind     {event.kind}",
            f"  content  {content!r}",
        ]
        lines += [f"  tag      {' '.join(tag)}" for tag in event.tags]
        return "\n".join(lines)

    async def _read_line(self) -> str:
        if self._lines is None:
            self._lines = asyncio.Queue()
            # Daemon thread instead of input() in an executor, so a pending prompt never blocks exit.
            threading.Thread(target=self._pump_stdin, args=(asyncio.get_running_loop(), self._lines),
                             daemon=True).start()
        while not self._lines.empty():  # discard anything typed before the prompt appeared
            if self._lines.get_nowait() is None:
                self._eof = True
        if self._eof:
            return ""
        line = await self._lines.get()
        if line is None:
            self._eof = True
            return ""
        return line

    @staticmethod
    def _pump_stdin(loop: asyncio.AbstractEventLoop, lines: asyncio.Queue) -> None:
        for line in sys.stdin:
            loop.call_soon_threadsafe(lines.put_nowait, line)
        loop.call_soon_threadsafe(lines.put_nowait, None)
