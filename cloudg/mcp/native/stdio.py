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
    loop = asyncio.get_running_loop()
    inbox: asyncio.Queue[Any] = asyncio.Queue()
    outbox: asyncio.Queue[Any] = asyncio.Queue()

    def reader() -> None:
        try:
            for line in iter(stdin.readline, b""):
                loop.call_soon_threadsafe(inbox.put_nowait, line)
        except Exception:  # closed / broken pipe
            logger.debug("stdin reader stopped", exc_info=True)
        finally:
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(inbox.put_nowait, _EOF)

    def write(data: bytes) -> None:
        stdout.write(data)
        flush = getattr(stdout, "flush", None)
        if flush:
            flush()

    async def writer() -> None:
        while True:
            item = await outbox.get()
            if item is _EOF:
                return
            try:
                await asyncio.to_thread(write, (dumps(item) + "\n").encode("utf-8"))
            except (BrokenPipeError, ValueError, OSError):
                logger.debug("stdout closed; dropping message")

    async def send(message: dict[str, Any]) -> None:
        await outbox.put(message)

    session = server.create_session(
        transport="stdio", send=send, principal=principal or Principal.local()
    )
    writer_task = asyncio.create_task(writer())
    threading.Thread(target=reader, name="cloudg-mcp-stdin", daemon=True).start()
    pending: set[asyncio.Task[Any]] = set()

    async def run(msg: Any) -> None:
        response = await session.handle(msg)
        if response is not None:
            await send(response)  # type: ignore[arg-type]

    try:
        while True:
            line = await inbox.get()
            if line is _EOF:
                break
            text = line.strip()
            if not text:
                continue
            try:
                msg = json.loads(text)
            except (ValueError, UnicodeDecodeError):
                await send(error_response(None, PARSE_ERROR, "Parse error"))
                continue
            concurrent = isinstance(msg, list) or (
                is_request(msg) and msg.get("method") != "initialize"
            )
            if concurrent:
                task = asyncio.create_task(run(msg))
                pending.add(task)
                task.add_done_callback(pending.discard)
            else:  # initialize, notifications, responses: in order
                await run(msg)
    finally:
        server.close_listens()
        if pending:
            _, still = await asyncio.wait(pending, timeout=grace)
            for task in still:
                task.cancel()
            if still:
                await asyncio.gather(*still, return_exceptions=True)
        session.close()
        await server.aclose()
        await outbox.put(_EOF)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer_task, timeout=grace)
