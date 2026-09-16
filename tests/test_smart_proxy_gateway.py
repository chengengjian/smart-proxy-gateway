"""PC smart proxy routing and configuration contracts."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

from smart_proxy_gateway import (
    ConfigError,
    DecisionCache,
    GatewayAuth,
    ProxyConfig,
    Route,
    SmartProxyGateway,
    parse_request_head,
)


def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ProxyConfig:
    monkeypatch.setenv("SMART_PROXY_PASSWORD", "secret")
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
                "auth": {"username": "ouroboros", "password_env": "SMART_PROXY_PASSWORD"},
                "connect_timeout_seconds": 0.2,
            }
        ),
        encoding="utf-8",
    )
    return ProxyConfig.load(path)


def test_configuration_and_route_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gateway = SmartProxyGateway(config(tmp_path, monkeypatch))

    assert gateway.configured_route("api.dragon.tools.huawei.com") is Route.DIRECT
    assert gateway.configured_route("dragon.tools.huawei.com") is Route.DIRECT
    assert gateway.configured_route("www.example.com") is Route.UPSTREAM
    assert gateway.configured_route("10.3.4.5") is Route.DIRECT
    assert gateway.configured_route("unknown.test") is Route.AUTO
    assert gateway.client_allowed("7.242.106.192") is True
    assert gateway.client_allowed("7.242.106.193") is False


def test_gateway_basic_auth_uses_constant_time_value_check() -> None:
    auth = GatewayAuth("agent", "s3cret")
    import base64

    accepted = "Basic " + base64.b64encode(b"agent:s3cret").decode("ascii")
    rejected = "Basic " + base64.b64encode(b"agent:wrong").decode("ascii")
    assert auth.accepts(accepted) is True
    assert auth.accepts(rejected) is False
    assert auth.accepts(None) is False


def test_parse_connect_request() -> None:
    request = parse_request_head(
        b"CONNECT rnd-idea-api.huawei.com:443 HTTP/1.1\r\n"
        b"Host: rnd-idea-api.huawei.com:443\r\n"
        b"Proxy-Authorization: Basic abc\r\n\r\n"
    )
    assert request.method == "CONNECT"
    assert request.target == "rnd-idea-api.huawei.com:443"
    assert request.header("proxy-authorization") == "Basic abc"


def test_missing_client_allowlist_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "proxy.json"
    path.write_text(
        json.dumps({"upstream_proxy": "http://127.0.0.1:7890"}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="allowed_clients"):
        ProxyConfig.load(path)


def test_auto_route_falls_back_and_caches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gateway = SmartProxyGateway(config(tmp_path, monkeypatch))
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
    monkeypatch: pytest.MonkeyPatch,
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
            config(tmp_path, monkeypatch),
            auth=None,
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
