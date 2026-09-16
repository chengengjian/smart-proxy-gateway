#!/usr/bin/env python3
"""Rule-based PC forward proxy for split corporate/external egress.

The gateway does not intercept TLS. HTTPS clients use CONNECT and retain
end-to-end TLS with the destination. Known corporate hosts go DIRECT from the
PC; external hosts are chained through an existing HTTP proxy. AUTO mode tries
DIRECT before the upstream proxy and caches the successful route.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hmac
import ipaddress
import json
import logging
import os
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import SplitResult, urlsplit


LOGGER = logging.getLogger("smart-proxy")
MAX_HEADER_BYTES = 64 * 1024
BUFFER_SIZE = 64 * 1024


class ConfigError(ValueError):
    """The gateway configuration is invalid."""


class ProxyProtocolError(RuntimeError):
    """A client or upstream proxy sent an invalid HTTP proxy message."""


class Route(str, Enum):
    DIRECT = "direct"
    UPSTREAM = "upstream"
    AUTO = "auto"


def _normalized_host(host: str) -> str:
    value = host.strip().rstrip(".").lower()
    if not value:
        raise ProxyProtocolError("empty target host")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ProxyProtocolError("invalid target host") from error


def _split_host_port(authority: str, default_port: int) -> tuple[str, int]:
    parsed = urlsplit("//" + authority)
    if parsed.hostname is None:
        raise ProxyProtocolError("target authority has no host")
    try:
        port = parsed.port or default_port
    except ValueError as error:
        raise ProxyProtocolError("invalid target port") from error
    if not 1 <= port <= 65535:
        raise ProxyProtocolError("target port is out of range")
    return _normalized_host(parsed.hostname), port


def _parse_list(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{field_name} must be an array of strings")
    return tuple(item.strip() for item in value if item.strip())


@dataclass(frozen=True)
class GatewayAuth:
    username: str
    password: str

    @classmethod
    def from_mapping(cls, raw: object) -> GatewayAuth | None:
        if raw is None:
            return None
        if not isinstance(raw, Mapping):
            raise ConfigError("auth must be an object")
        username = str(raw.get("username", "")).strip()
        password = str(raw.get("password", ""))
        password_env = str(raw.get("password_env", "")).strip()
        if password and password_env:
            raise ConfigError("auth may use password or password_env, not both")
        if password_env:
            password = os.environ.get(password_env, "")
            if not password:
                raise ConfigError(f"environment variable {password_env!r} is empty")
        if not username or not password:
            raise ConfigError("auth requires a username and password")
        return cls(username=username, password=password)

    def accepts(self, header: str | None) -> bool:
        if header is None or not header.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        expected = f"{self.username}:{self.password}"
        return hmac.compare_digest(decoded, expected)


@dataclass(frozen=True)
class ProxyConfig:
    listen_host: str
    listen_port: int
    upstream: SplitResult
    default_route: Route
    direct_domains: tuple[str, ...]
    proxy_domains: tuple[str, ...]
    direct_networks: tuple[ipaddress._BaseNetwork, ...]
    host_overrides: Mapping[str, str]
    allowed_clients: tuple[ipaddress._BaseNetwork, ...]
    auth: GatewayAuth | None
    connect_timeout_seconds: float
    header_timeout_seconds: float
    decision_cache_seconds: float

    @classmethod
    def load(cls, path: Path) -> ProxyConfig:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if not isinstance(raw, Mapping):
            raise ConfigError("configuration root must be an object")

        listen_host, listen_port = _split_host_port(str(raw.get("listen", "127.0.0.1:18081")), 18081)
        upstream = urlsplit(str(raw.get("upstream_proxy", "")))
        if upstream.scheme != "http" or upstream.hostname is None:
            raise ConfigError("upstream_proxy must be an http:// URL")
        if upstream.path not in {"", "/"} or upstream.query or upstream.fragment:
            raise ConfigError("upstream_proxy must not contain a path, query, or fragment")
        try:
            if upstream.port is not None and not 1 <= upstream.port <= 65535:
                raise ConfigError("upstream_proxy port is out of range")
        except ValueError as error:
            raise ConfigError("upstream_proxy has an invalid port") from error

        try:
            default_route = Route(str(raw.get("default_route", Route.AUTO.value)).lower())
        except ValueError as error:
            raise ConfigError("default_route must be direct, upstream, or auto") from error

        direct_domains = tuple(_normalized_host(item.lstrip(".")) for item in _parse_list(raw.get("direct_domains"), "direct_domains"))
        proxy_domains = tuple(_normalized_host(item.lstrip(".")) for item in _parse_list(raw.get("proxy_domains"), "proxy_domains"))

        try:
            direct_networks = tuple(
                ipaddress.ip_network(item, strict=False)
                for item in _parse_list(raw.get("direct_cidrs"), "direct_cidrs")
            )
            allowed_clients = tuple(
                ipaddress.ip_network(item, strict=False)
                for item in _parse_list(raw.get("allowed_clients"), "allowed_clients")
            )
        except ValueError as error:
            raise ConfigError(f"invalid CIDR: {error}") from error
        if not allowed_clients:
            raise ConfigError("allowed_clients must contain at least one CIDR")

        overrides_raw = raw.get("host_overrides", {})
        if not isinstance(overrides_raw, Mapping):
            raise ConfigError("host_overrides must be an object")
        overrides: dict[str, str] = {}
        for host, address in overrides_raw.items():
            normalized = _normalized_host(str(host))
            try:
                overrides[normalized] = str(ipaddress.ip_address(str(address)))
            except ValueError as error:
                raise ConfigError(f"host_overrides[{host!r}] must be an IP address") from error

        def positive_float(name: str, default: float) -> float:
            try:
                value = float(raw.get(name, default))
            except (TypeError, ValueError) as error:
                raise ConfigError(f"{name} must be a number") from error
            if value <= 0:
                raise ConfigError(f"{name} must be positive")
            return value

        return cls(
            listen_host=listen_host,
            listen_port=listen_port,
            upstream=upstream,
            default_route=default_route,
            direct_domains=direct_domains,
            proxy_domains=proxy_domains,
            direct_networks=direct_networks,
            host_overrides=overrides,
            allowed_clients=allowed_clients,
            auth=GatewayAuth.from_mapping(raw.get("auth")),
            connect_timeout_seconds=positive_float("connect_timeout_seconds", 1.0),
            header_timeout_seconds=positive_float("header_timeout_seconds", 10.0),
            decision_cache_seconds=positive_float("decision_cache_seconds", 600.0),
        )


@dataclass
class DecisionCache:
    ttl_seconds: float
    _items: dict[tuple[str, int], tuple[Route, float]] = field(default_factory=dict)

    def get(self, host: str, port: int) -> Route | None:
        item = self._items.get((host, port))
        if item is None:
            return None
        route, expires_at = item
        if time.monotonic() >= expires_at:
            self._items.pop((host, port), None)
            return None
        return route

    def put(self, host: str, port: int, route: Route) -> None:
        self._items[(host, port)] = (route, time.monotonic() + self.ttl_seconds)

    def discard(self, host: str, port: int) -> None:
        self._items.pop((host, port), None)


@dataclass(frozen=True)
class ParsedRequest:
    method: str
    target: str
    version: str
    headers: tuple[tuple[str, str], ...]
    raw_head: bytes

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None


def parse_request_head(raw: bytes) -> ParsedRequest:
    try:
        text = raw.decode("iso-8859-1")
    except UnicodeDecodeError as error:
        raise ProxyProtocolError("request headers are not ISO-8859-1") from error
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise ProxyProtocolError("invalid HTTP request line")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            raise ProxyProtocolError("invalid HTTP header")
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return ParsedRequest(parts[0].upper(), parts[1], parts[2], tuple(headers), raw)


def _domain_matches(host: str, rules: Sequence[str]) -> bool:
    return any(host == rule or host.endswith("." + rule) for rule in rules)


class SmartProxyGateway:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.cache = DecisionCache(config.decision_cache_seconds)

    def client_allowed(self, address: str) -> bool:
        try:
            client = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(client in network for network in self.config.allowed_clients)

    def configured_route(self, host: str) -> Route:
        normalized = _normalized_host(host)
        if _domain_matches(normalized, self.config.direct_domains):
            return Route.DIRECT
        if _domain_matches(normalized, self.config.proxy_domains):
            return Route.UPSTREAM
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            address = None
        if address is not None and any(address in network for network in self.config.direct_networks):
            return Route.DIRECT
        return self.config.default_route

    async def open_target(
        self,
        host: str,
        port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, Route]:
        normalized = _normalized_host(host)
        configured = self.configured_route(normalized)
        if configured is Route.DIRECT:
            reader, writer = await self._open_direct(normalized, port)
            return reader, writer, Route.DIRECT
        if configured is Route.UPSTREAM:
            reader, writer = await self._open_upstream(normalized, port)
            return reader, writer, Route.UPSTREAM

        cached = self.cache.get(normalized, port)
        attempts = [cached] if cached is not None else []
        attempts.extend(route for route in (Route.DIRECT, Route.UPSTREAM) if route is not cached)
        errors: list[str] = []
        for route in attempts:
            try:
                if route is Route.DIRECT:
                    reader, writer = await self._open_direct(normalized, port)
                else:
                    reader, writer = await self._open_upstream(normalized, port)
                self.cache.put(normalized, port, route)
                return reader, writer, route
            except (OSError, asyncio.TimeoutError, ProxyProtocolError) as error:
                errors.append(f"{route.value}: {error}")
                self.cache.discard(normalized, port)
        raise OSError("; ".join(errors))

    async def _open_direct(
        self,
        host: str,
        port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        connect_host = self.config.host_overrides.get(host, host)
        return await asyncio.wait_for(
            asyncio.open_connection(connect_host, port),
            timeout=self.config.connect_timeout_seconds,
        )

    async def _open_upstream(
        self,
        host: str,
        port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        proxy_host = self.config.upstream.hostname
        assert proxy_host is not None
        proxy_port = self.config.upstream.port or 80
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port),
            timeout=self.config.connect_timeout_seconds,
        )
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        lines = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
            "Proxy-Connection: Keep-Alive",
        ]
        if self.config.upstream.username is not None:
            password = self.config.upstream.password or ""
            token = base64.b64encode(
                f"{self.config.upstream.username}:{password}".encode("utf-8")
            ).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        try:
            response = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self.config.header_timeout_seconds,
            )
            first_line = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
            parts = first_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit() or not 200 <= int(parts[1]) < 300:
                raise ProxyProtocolError(f"upstream CONNECT failed: {first_line}")
            return reader, writer
        except BaseException:
            writer.close()
            await writer.wait_closed()
            raise

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = str(peer[0]) if isinstance(peer, tuple) and peer else "unknown"
        if not self.client_allowed(client_ip):
            await self._send_error(writer, 403, "client is not allowed")
            return
        try:
            raw = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self.config.header_timeout_seconds,
            )
            if len(raw) > MAX_HEADER_BYTES:
                raise ProxyProtocolError("request headers are too large")
            request = parse_request_head(raw)
            if self.config.auth is not None and not self.config.auth.accepts(
                request.header("Proxy-Authorization")
            ):
                await self._send_proxy_auth_required(writer)
                return
            if request.method == "GET" and urlsplit(request.target).path == "/healthz":
                await self._send_health(writer)
                return
            if request.method == "CONNECT":
                await self._handle_connect(request, reader, writer, client_ip)
            else:
                await self._handle_http(request, reader, writer, client_ip)
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError, ProxyProtocolError) as error:
            LOGGER.warning("client=%s request failed: %s", client_ip, error)
            await self._send_error(writer, 502, str(error))
        except Exception:
            LOGGER.exception("client=%s unexpected proxy failure", client_ip)
            await self._send_error(writer, 500, "internal proxy error")

    async def _handle_connect(
        self,
        request: ParsedRequest,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        client_ip: str,
    ) -> None:
        host, port = _split_host_port(request.target, 443)
        upstream_reader, upstream_writer, route = await self.open_target(host, port)
        LOGGER.info("client=%s CONNECT %s:%d route=%s", client_ip, host, port, route.value)
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        await self._relay(client_reader, client_writer, upstream_reader, upstream_writer)

    async def _handle_http(
        self,
        request: ParsedRequest,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        client_ip: str,
    ) -> None:
        parsed = urlsplit(request.target)
        if parsed.hostname is not None:
            host = _normalized_host(parsed.hostname)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            origin_target = parsed.path or "/"
            if parsed.query:
                origin_target += "?" + parsed.query
        else:
            host_header = request.header("Host")
            if host_header is None:
                raise ProxyProtocolError("HTTP proxy request has no Host header")
            host, port = _split_host_port(host_header, 80)
            origin_target = request.target

        upstream_reader, upstream_writer, route = await self.open_target(host, port)
        LOGGER.info("client=%s %s %s:%d route=%s", client_ip, request.method, host, port, route.value)
        # open_target() gives us a tunnel all the way to the origin for both
        # routes (the upstream route has already completed CONNECT). The origin
        # therefore receives origin-form, never another proxy request.
        head = self._rewrite_request_head(request, origin_target)
        upstream_writer.write(head)
        await upstream_writer.drain()
        await self._relay(client_reader, client_writer, upstream_reader, upstream_writer)

    def _rewrite_request_head(self, request: ParsedRequest, target: str) -> bytes:
        lines = [f"{request.method} {target} {request.version}"]
        for name, value in request.headers:
            if name.lower() in {"proxy-authorization", "proxy-connection"}:
                continue
            lines.append(f"{name}: {value}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        async def pump(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            try:
                while data := await source.read(BUFFER_SIZE):
                    destination.write(data)
                    await destination.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                try:
                    destination.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    pass

        tasks = [
            asyncio.create_task(pump(client_reader, upstream_writer)),
            asyncio.create_task(pump(upstream_reader, client_writer)),
        ]
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        upstream_writer.close()
        client_writer.close()
        await asyncio.gather(
            upstream_writer.wait_closed(),
            client_writer.wait_closed(),
            return_exceptions=True,
        )

    @staticmethod
    async def _send_error(writer: asyncio.StreamWriter, status: int, message: str) -> None:
        safe = message.replace("\r", " ").replace("\n", " ")[:512]
        body = (safe + "\n").encode("utf-8")
        writer.write(
            f"HTTP/1.1 {status} Proxy Error\r\nContent-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    @staticmethod
    async def _send_proxy_auth_required(writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Basic realm="smart-proxy"\r\n'
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    @staticmethod
    async def _send_health(writer: asyncio.StreamWriter) -> None:
        body = b'{"status":"ok"}\n'
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()


async def run(config: ProxyConfig) -> None:
    gateway = SmartProxyGateway(config)
    server = await asyncio.start_server(
        gateway.handle_client,
        config.listen_host,
        config.listen_port,
        limit=MAX_HEADER_BYTES + 1,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or ())
    LOGGER.info("smart proxy listening on %s", sockets)
    LOGGER.info(
        "upstream=http://%s:%d default_route=%s",
        config.upstream.hostname,
        config.upstream.port or 80,
        config.default_route.value,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signame in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, signame, None)
        if signum is None:
            continue
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:
            pass
    async with server:
        await stop.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="JSON configuration path")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = ProxyConfig.load(args.config)
        asyncio.run(run(config))
    except (ConfigError, OSError, json.JSONDecodeError) as error:
        LOGGER.error("startup failed: %s", error)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
