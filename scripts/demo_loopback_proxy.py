#!/usr/bin/env python3
"""Expose a Compose service on recorder loopback for the live VHS demo."""

from __future__ import annotations

import argparse
import asyncio


async def copy_stream(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        while data := await reader.read(64 * 1024):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()
    except (ConnectionError, OSError):
        pass


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstream_host: str,
    upstream_port: int,
) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            upstream_host, upstream_port
        )
    except (ConnectionError, OSError):
        writer.close()
        await writer.wait_closed()
        return

    await asyncio.gather(
        copy_stream(reader, upstream_writer),
        copy_stream(upstream_reader, writer),
    )
    upstream_writer.close()
    writer.close()
    await asyncio.gather(
        upstream_writer.wait_closed(),
        writer.wait_closed(),
        return_exceptions=True,
    )


async def serve(args: argparse.Namespace) -> None:
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(
            reader,
            writer,
            args.upstream_host,
            args.upstream_port,
        ),
        args.listen_host,
        args.listen_port,
    )
    async with server:
        await server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=18087)
    parser.add_argument("--upstream-host", default="codeigniter")
    parser.add_argument("--upstream-port", type=int, default=80)
    return parser.parse_args()


if __name__ == "__main__":
    asyncio.run(serve(parse_args()))
