"""stdio transport for the native MCP server.

Newline-delimited JSON-RPC on stdin/stdout, exactly as the MCP spec
requires: stdout carries protocol messages only, logs go to stderr.

Because a single stray ``print()`` from a handler or a library would corrupt
the stream, :func:`run_stdio_async` (with ``protect_stdout=True``, the
default when serving the real process stdio) duplicates the original stdout
file descriptor for the protocol and then points both ``sys.stdout`` and file
descriptor 1 at stderr for the rest of the process.

Reading uses a daemon thread (portable across POSIX and Windows consoles and
pipes); writing goes through a single writer task so messages are never
interleaved. Requests other than ``initialize`` run concurrently so
``notifications/cancelled`` and ``ping`` work while a long tool call is in
flight.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sys
import threading
from typing import IO, Any

from cloudg.mcp.context import Principal
from cloudg.mcp.native.jsonrpc import PARSE_ERROR, dumps, error_response, is_request
from cloudg.mcp.native.protocol import NativeMCPServer

logger = logging.getLogger("cloudg.mcp.native")

__all__ = ["protected_stdout", "run_stdio_async"]

_EOF = object()


@contextlib.contextmanager
def protected_stdout() -> Any:
    """Yield a binary stream bound to the *original* stdout while redirecting
    ``sys.stdout`` and fd 1 to stderr. Restores everything on exit."""
    sys.stdout.flush()
    try:
        out_fd = sys.stdout.fileno()
        err_fd = sys.stderr.fileno()
    except (AttributeError, OSError, ValueError):  # not a real file (tests, IDEs)
        yield sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
        return
    proto_fd = os.dup(out_fd)
    saved_fd = os.dup(out_fd)
    saved_stdout = sys.stdout
    os.dup2(err_fd, out_fd)
    sys.stdout = sys.stderr
    stream = os.fdopen(proto_fd, "wb", buffering=0)
    try:
        yield stream
    finally:
        with contextlib.suppress(Exception):
            stream.close()
        with contextlib.suppress(Exception):
            sys.stderr.flush()
            os.dup2(saved_fd, out_fd)
        with contextlib.suppress(Exception):
            os.close(saved_fd)
        sys.stdout = saved_stdout


async def run_stdio_async(
    server: NativeMCPServer,
    *,
    stdin: IO[bytes] | None = None,
    stdout: IO[bytes] | None = None,
    principal: Principal | None = None,
    protect_stdout: bool = True,
    shutdown_grace: float = 5.0,
) -> None:
    """Serve one MCP client over stdio until stdin reaches EOF.

    Args:
        server: The protocol engine.
        stdin / stdout: Binary streams; default to the process stdio.
        principal: Caller identity (default: the local user).
        protect_stdout: Redirect stray stdout writes to stderr (only applies
            when ``stdout`` is not given).
        shutdown_grace: Seconds to let in-flight requests finish after EOF.
    """
    if stdout is None and protect_stdout:
        with protected_stdout() as proto_out:
            await _serve(server, stdin or sys.stdin.buffer, proto_out, principal, shutdown_grace)
        return
    await _serve(
        server,
        stdin or sys.stdin.buffer,
        stdout or sys.stdout.buffer,
        principal,
        shutdown_grace,
    )


async def _serve(
    server: NativeMCPServer,
    stdin: IO[bytes],
    stdout: IO[bytes],
    principal: Principal | None,
    grace: float,
) -> None:
    await _StdioLoop(server, stdin, stdout, principal, grace).serve()


class _StdioLoop:
    """One stdio connection: a reader thread feeding an inbox, a single
    writer task draining an outbox, and the session in between."""

    def __init__(
        self,
        server: NativeMCPServer,
        stdin: IO[bytes],
        stdout: IO[bytes],
        principal: Principal | None,
        grace: float,
    ) -> None:
        self.server = server
        self.stdin = stdin
        self.stdout = stdout
        self.grace = grace
        self.loop = asyncio.get_running_loop()
        self.inbox: asyncio.Queue[Any] = asyncio.Queue()
        self.outbox: asyncio.Queue[Any] = asyncio.Queue()
        self.pending: set[asyncio.Task[Any]] = set()
        self.session = server.create_session(
            transport="stdio", send=self.send, principal=principal or Principal.local()
        )

    # -- I/O ---------------------------------------------------------------

    def _read(self) -> None:
        try:
            for line in iter(self.stdin.readline, b""):
                self.loop.call_soon_threadsafe(self.inbox.put_nowait, line)
        except Exception:  # closed / broken pipe
            logger.debug("stdin reader stopped", exc_info=True)
        finally:
            with contextlib.suppress(RuntimeError):
                self.loop.call_soon_threadsafe(self.inbox.put_nowait, _EOF)

    def _write(self, data: bytes) -> None:
        self.stdout.write(data)
        flush = getattr(self.stdout, "flush", None)
        if flush:
            flush()

    async def _writer(self) -> None:
        while True:
            item = await self.outbox.get()
            if item is _EOF:
                return
            try:
                await asyncio.to_thread(self._write, (dumps(item) + "\n").encode("utf-8"))
            except (BrokenPipeError, ValueError, OSError):
                logger.debug("stdout closed; dropping message")

    async def send(self, message: dict[str, Any]) -> None:
        await self.outbox.put(message)

    # -- messages ------------------------------------------------------------

    async def _run(self, msg: Any) -> None:
        response = await self.session.handle(msg)
        if response is not None:
            await self.send(response)  # type: ignore[arg-type]

    async def _accept(self, line: bytes) -> None:
        text = line.strip()
        if not text:
            return
        try:
            msg = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            await self.send(error_response(None, PARSE_ERROR, "Parse error"))
            return
        if isinstance(msg, list) or (is_request(msg) and msg.get("method") != "initialize"):
            task = asyncio.create_task(self._run(msg))
            self.pending.add(task)
            task.add_done_callback(self.pending.discard)
        else:  # initialize, notifications, responses: in order
            await self._run(msg)

    async def serve(self) -> None:
        writer_task = asyncio.create_task(self._writer())
        threading.Thread(target=self._read, name="cloudg-mcp-stdin", daemon=True).start()
        try:
            while True:
                line = await self.inbox.get()
                if line is _EOF:
                    break
                await self._accept(line)
        finally:
            await self._shutdown(writer_task)

    async def _shutdown(self, writer_task: asyncio.Task[Any]) -> None:
        self.server.close_listens()
        if self.pending:
            _, still = await asyncio.wait(self.pending, timeout=self.grace)
            for task in still:
                task.cancel()
            if still:
                await asyncio.gather(*still, return_exceptions=True)
        self.session.close()
        await self.server.aclose()
        await self.outbox.put(_EOF)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer_task, timeout=self.grace)
