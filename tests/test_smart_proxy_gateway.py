"""PC smart proxy routing and configuration contracts."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from smart_proxy_gateway import (
    ConfigError,
    DecisionCache,
    ProxyConfig,
    Route,
    SmartProxyGateway,
    parse_request_head,
)


def config(tmp_path: Path) -> ProxyConfig:
    path = tmp_path / "proxy.json"
    path.write_text(
        json.dumps(
            {
                "listen": "127.0.0.1:18081",
                "upstream_proxy": "http://user:upstream@127.0.0.1:7890",
                "default_route": "auto",
                "direct_domains": ["dragon.tools.huawei.com"],
                "proxy_domains": ["example.com"],
                "direct_cidrs": ["10.0.0.0/8"],
                "host_overrides": {"inside.huawei.com": "7.1.2.3"},
                "allowed_clients": ["127.0.0.1/32", "7.242.106.192/32"],
                "connect_timeout_seconds": 0.2,
            }
        ),
        encoding="utf-8",
    )
    return ProxyConfig.load(path)


def test_configuration_and_route_rules(tmp_path: Path) -> None:
    gateway = SmartProxyGateway(config(tmp_path))

    assert gateway.configured_route("api.dragon.tools.huawei.com") is Route.DIRECT
    assert gateway.configured_route("dragon.tools.huawei.com") is Route.DIRECT
    assert gateway.configured_route("www.example.com") is Route.UPSTREAM
    assert gateway.configured_route("10.3.4.5") is Route.DIRECT
    assert gateway.configured_route("unknown.test") is Route.AUTO
    assert gateway.client_allowed("7.242.106.192") is True
    assert gateway.client_allowed("7.242.106.193") is False


def test_parse_connect_request() -> None:
    request = parse_request_head(
        b"CONNECT rnd-idea-api.huawei.com:443 HTTP/1.1\r\n"
        b"Host: rnd-idea-api.huawei.com:443\r\n\r\n"
    )
    assert request.method == "CONNECT"
    assert request.target == "rnd-idea-api.huawei.com:443"


def test_missing_client_allowlist_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "proxy.json"
    path.write_text(
        json.dumps({"upstream_proxy": "http://127.0.0.1:7890"}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="allowed_clients"):
        ProxyConfig.load(path)


def test_removed_auth_configuration_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "proxy.json"
    path.write_text(
        json.dumps(
            {
                "upstream_proxy": "http://127.0.0.1:7890",
                "allowed_clients": ["127.0.0.1/32"],
                "auth": {"username": "legacy", "password": "secret"},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="auth is no longer supported"):
        ProxyConfig.load(path)


def test_auto_route_falls_back_and_caches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gateway = SmartProxyGateway(config(tmp_path))
    calls: list[str] = []

    async def direct(host: str, port: int):
        calls.append("direct")
        raise OSError("direct unavailable")

    async def upstream(host: str, port: int):
        calls.append("upstream")
        return object(), object()

    monkeypatch.setattr(gateway, "_open_direct", direct)
    monkeypatch.setattr(gateway, "_open_upstream", upstream)

    _, _, first_route = asyncio.run(gateway.open_target("unknown.test", 443))
    _, _, second_route = asyncio.run(gateway.open_target("unknown.test", 443))

    assert first_route is Route.UPSTREAM
    assert second_route is Route.UPSTREAM
    assert calls == ["direct", "upstream", "upstream"]


def test_decision_cache_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = iter((10.0, 10.5, 12.0))
    monkeypatch.setattr("smart_proxy_gateway.time.monotonic", lambda: next(clock))
    cache = DecisionCache(1.0)
    cache.put("example.com", 443, Route.UPSTREAM)
    assert cache.get("example.com", 443) is Route.UPSTREAM
    assert cache.get("example.com", 443) is None


def test_connect_tunnel_reaches_direct_host(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            data = await reader.read(64)
            writer.write(data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        origin = await asyncio.start_server(echo, "127.0.0.1", 0)
        origin_port = origin.sockets[0].getsockname()[1]
        runtime = replace(
            config(tmp_path),
            direct_domains=("inside.test",),
            host_overrides={"inside.test": "127.0.0.1"},
        )
        gateway = SmartProxyGateway(runtime)
        proxy = await asyncio.start_server(gateway.handle_client, "127.0.0.1", 0)
        proxy_port = proxy.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(
                f"CONNECT inside.test:{origin_port} HTTP/1.1\r\n"
                f"Host: inside.test:{origin_port}\r\n\r\n".encode("ascii")
            )
            await writer.drain()
            response = await reader.readuntil(b"\r\n\r\n")
            assert response.startswith(b"HTTP/1.1 200")
            writer.write(b"round-trip")
            await writer.drain()
            assert await reader.readexactly(len(b"round-trip")) == b"round-trip"
            writer.close()
            await writer.wait_closed()
        finally:
            proxy.close()
            origin.close()
            await proxy.wait_closed()
            await origin.wait_closed()

    asyncio.run(scenario())


class RelayWriter:
    """In-memory sink for controlled EOF, failure, and cancellation tests."""
    def __init__(self):
        self.data = bytearray()
        self.eof = asyncio.Event()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof.set()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def test_upstream_half_close_allows_remaining_upload(tmp_path: Path) -> None:
    async def scenario():
        gateway = SmartProxyGateway(config(tmp_path))
        client_reader, upstream_reader = asyncio.StreamReader(), asyncio.StreamReader()
        client_writer, upstream_writer = RelayWriter(), RelayWriter()
        upstream_reader.feed_data(b"early response")
        upstream_reader.feed_eof()
        relay = asyncio.create_task(gateway._relay(client_reader, client_writer, upstream_reader, upstream_writer))
        try:
            await asyncio.wait_for(client_writer.eof.wait(), 1)
            assert not relay.done()
            upload = b"late upload" * 100000
            client_reader.feed_data(upload)
            client_reader.feed_eof()
            await asyncio.wait_for(relay, 1)
            assert bytes(upstream_writer.data) == upload
            assert bytes(client_writer.data) == b"early response"
            assert client_writer.closed and upstream_writer.closed
        finally:
            relay.cancel()
            await asyncio.gather(relay, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel", [False, True])
def test_relay_failure_or_cancellation_cleans_up(tmp_path: Path, caplog, cancel: bool) -> None:
    async def scenario():
        gateway = SmartProxyGateway(config(tmp_path))
        client_reader, upstream_reader = asyncio.StreamReader(), asyncio.StreamReader()
        client_writer, upstream_writer = RelayWriter(), RelayWriter()
        before = asyncio.all_tasks()
        relay = asyncio.create_task(gateway._relay(
            client_reader, client_writer, upstream_reader, upstream_writer,
            context="target=downloads.test:443 route=upstream",
        ))
        await asyncio.sleep(0)
        if cancel:
            relay.cancel()
            with pytest.raises(asyncio.CancelledError):
                await relay
        else:
            upstream_reader.set_exception(ConnectionResetError("upstream reset"))
            await asyncio.wait_for(relay, 1)
            assert "direction=download" in caplog.text
            assert "ConnectionResetError" in caplog.text
            assert "target=downloads.test:443" in caplog.text
        assert client_writer.closed and upstream_writer.closed
        assert not client_writer.data  # Never insert a 502 inside a started tunnel.
        assert asyncio.all_tasks() == before

    asyncio.run(scenario())


def test_upstream_connect_timeout_has_context_and_closes_socket(tmp_path: Path, monkeypatch) -> None:
    async def scenario():
        gateway = SmartProxyGateway(replace(
            config(tmp_path), default_route=Route.UPSTREAM, header_timeout_seconds=0.01,
        ))
        upstream_reader, upstream_writer = asyncio.StreamReader(), RelayWriter()

        async def connect(*args):
            return upstream_reader, upstream_writer

        monkeypatch.setattr(gateway, "_connect_tcp", connect)
        with pytest.raises(TimeoutError, match="upstream CONNECT response.*downloads.test:443.*0.01s"):
            await gateway.open_target("downloads.test", 443)
        assert upstream_writer.closed

    asyncio.run(scenario())


def test_disallowed_client_is_rejected_before_proxying(tmp_path: Path) -> None:
    async def scenario() -> None:
        runtime = replace(
            config(tmp_path),
            allowed_clients=(ipaddress.ip_network("192.0.2.1/32"),),
        )
        gateway = SmartProxyGateway(runtime)
        proxy = await asyncio.start_server(gateway.handle_client, "127.0.0.1", 0)
        proxy_port = proxy.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            response = await reader.read()
            assert response.startswith(b"HTTP/1.1 403")
            writer.close()
            await writer.wait_closed()
        finally:
            proxy.close()
            await proxy.wait_closed()

    asyncio.run(scenario())


@pytest.mark.parametrize("route", [Route.DIRECT, Route.UPSTREAM])
@pytest.mark.parametrize("method", ["CONNECT", "GET"])
@pytest.mark.parametrize("half_close", [False, True])
def test_concurrent_large_downloads(
    tmp_path: Path, route: Route, method: str, half_close: bool,
) -> None:
    """Finishing an upload must not truncate a slow, multi-buffer response."""
    async def scenario() -> None:
        payload = bytes(range(256)) * (16 * 1024)  # 4 MiB per client
        expected = hashlib.sha256(payload).digest()
        handlers: list[asyncio.Task] = []
        failures: list[Exception] = []

        def tracked(handler):
            async def run(reader, writer):
                handlers.append(asyncio.current_task())
                try:
                    await handler(reader, writer)
                except Exception as error:
                    failures.append(error)
                finally:
                    writer.close()
                    await writer.wait_closed()
            return run

        async def origin_handler(reader, writer):
            request = await reader.readuntil(b"\r\n\r\n")
            assert request.startswith(b"GET /large HTTP/1.1\r\n")
            if half_close:
                assert await reader.read() == b""
            # With half_close, respond only after FIN has passed through the proxy.
            await asyncio.sleep(0.02)
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n\r\n".encode())
            for offset in range(0, len(payload), 32768):
                writer.write(payload[offset:offset + 32768])
                await writer.drain()
                await asyncio.sleep(0)

        origin = await asyncio.start_server(tracked(origin_handler), "127.0.0.1", 0)
        origin_port = origin.sockets[0].getsockname()[1]

        async def upstream_handler(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            assert head.startswith(f"CONNECT downloads.test:{origin_port} HTTP/1.1\r\n".encode())
            remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", origin_port)
            try:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()

                async def copy(source, destination):
                    while chunk := await source.read(32768):
                        destination.write(chunk)
                        await destination.drain()
                    destination.write_eof()
                    await destination.drain()

                await asyncio.gather(copy(reader, remote_writer), copy(remote_reader, writer))
            finally:
                remote_writer.close()
                await remote_writer.wait_closed()

        upstream = await asyncio.start_server(tracked(upstream_handler), "127.0.0.1", 0)
        runtime = replace(
            config(tmp_path), default_route=route,
            upstream=urlsplit(f"http://127.0.0.1:{upstream.sockets[0].getsockname()[1]}"),
            host_overrides={"downloads.test": "127.0.0.1"},
        )
        gateway = SmartProxyGateway(runtime)
        proxy = await asyncio.start_server(tracked(gateway.handle_client), "127.0.0.1", 0)

        async def download():
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy.sockets[0].getsockname()[1])
            try:
                if method == "CONNECT":
                    writer.write(f"CONNECT downloads.test:{origin_port} HTTP/1.1\r\n\r\n".encode())
                    await writer.drain()
                    assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
                    target = "/large"
                else:
                    target = f"http://downloads.test:{origin_port}/large"
                writer.write(f"GET {target} HTTP/1.1\r\nHost: downloads.test\r\n\r\n".encode())
                await writer.drain()
                if half_close:
                    writer.write_eof()
                head = await reader.readuntil(b"\r\n\r\n")
                assert f"Content-Length: {len(payload)}".encode() in head
                digest = hashlib.sha256()
                received = 0
                while chunk := await reader.read(16384):
                    received += len(chunk)
                    digest.update(chunk)
                    await asyncio.sleep(0.001)  # Exercise downstream backpressure.
                assert received == len(payload)
                assert digest.digest() == expected
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            await asyncio.wait_for(asyncio.gather(*(download() for _ in range(4))), 30)
            await asyncio.wait_for(asyncio.gather(*handlers), 5)
            assert failures == []
        finally:
            for server in (proxy, upstream, origin):
                server.close()
                await server.wait_closed()
            for task in handlers:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*handlers, return_exceptions=True)

    asyncio.run(scenario())
