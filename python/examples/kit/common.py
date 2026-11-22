"""Shared helpers for the bundled offline extension kit."""

from __future__ import annotations

import json
import re
from collections import OrderedDict, deque
from typing import Any, Iterable

HEADER_LINE = re.compile(r"^([^:\s]+):\s*(.*)$")


def text(data: bytes | str | None) -> str:
    if isinstance(data, bytes):
        return data.decode("latin-1", "replace")
    return str(data or "")


def raw_split(message: bytes | str) -> tuple[bytes, bytes, bytes]:
    """Split an HTTP message into head bytes, separator and body bytes."""
    raw = message.encode("latin-1") if isinstance(message, str) else bytes(message or b"")
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body = raw.partition(b"\n\n")
    return head, separator, body


def split_message(message: bytes | str) -> tuple[str, list[str], bytes]:
    """Return start line, headers and raw body from an HTTP message."""
    head, separator, body = raw_split(message)
    line_separator = b"\r\n" if separator == b"\r\n\r\n" else b"\n"
    lines = head.decode("latin-1", "replace").split(line_separator.decode("ascii"))
    if not lines:
        return "", [], body
    return lines[0], [line for line in lines[1:] if line], body


def header_value(headers: Iterable[str], name: str) -> str:
    wanted = name.lower()
    for header in headers:
        match = HEADER_LINE.match(header)
        if match and match.group(1).lower() == wanted:
            return match.group(2).strip()
    return ""


def is_chunked(message: bytes | str) -> bool:
    """Return whether a message declares chunked transfer encoding."""
    _, headers, _ = split_message(message)
    return "chunked" in header_value(headers, "Transfer-Encoding").lower()


def status_code(response: bytes | str) -> int:
    start, _, _ = split_message(response)
    parts = start.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0


def body_of(message: bytes | str) -> bytes:
    _, _, body = split_message(message)
    return body


def replace_body(message: bytes, body: bytes) -> bytes:
    head, separator, _ = raw_split(message)
    if not separator:
        return message
    return head + separator + body


def set_content_length(message: bytes, length: int) -> bytes:
    """Rewrite ``Content-Length`` while preserving the original line endings."""
    head, separator, body = raw_split(message)
    if not separator:
        return message
    line_separator = b"\r\n" if separator == b"\r\n\r\n" else b"\n"
    lines = head.split(line_separator)
    replacement = b"Content-Length: " + str(length).encode("ascii")
    kept = []
    replaced = False
    for line in lines:
        lowered = line.lower()
        if lowered.startswith(b"content-length:"):
            kept.append(replacement)
            replaced = True
        elif lowered.startswith(b"transfer-encoding:"):
            # A rewritten body must never keep CL and TE at the same time.
            continue
        else:
            kept.append(line)
    if not replaced:
        kept.append(replacement)
    return line_separator.join(kept) + separator + body


def url_of(request: bytes, service: Any = None) -> str:
    start, headers, _ = split_message(request)
    parts = start.split()
    target = parts[1] if len(parts) > 1 else "/"
    if target.startswith("http://") or target.startswith("https://"):
        return target
    host = ""
    if service is not None and getattr(service, "getHost", None):
        host = service.getHost()
        port = service.getPort()
        protocol = service.getProtocol()
    else:
        host = header_value(headers, "Host")
        protocol = "https" if host.endswith(":443") else "http"
        port = 443 if protocol == "https" else 80
    if host.startswith("[") and "]" in host:
        end = host.index("]")
        tail = host[end + 1:]
        if tail.startswith(":") and tail[1:].isdigit():
            port = int(tail[1:])
        host = host[:end + 1]
    elif ":" in host:
        if host.count(":") == 1:
            host, _, port_text = host.rpartition(":")
            if port_text.isdigit():
                port = int(port_text)
        if ":" in host:
            host = "[" + host + "]"
    return f"{protocol}://{host}:{port}{target}"


def setting(callbacks, name: str, default: str) -> str:
    """Read ``name`` from extension settings or ``--extension-arg name=value``."""
    key = "blurp.kit." + name
    value = callbacks.loadExtensionSetting(key)
    if value is None:
        for argument in callbacks.getCommandLineArguments():
            argument = str(argument)
            if argument.startswith(key + "="):
                value = argument[len(key) + 1:]
                break
    return default if value is None else str(value)


def set_setting(callbacks, name: str, value: str) -> None:
    callbacks.saveExtensionSetting("blurp.kit." + name, str(value))


def parse_args(callbacks, flag: str) -> list[str]:
    """Read ``flag=value`` values from extension command-line arguments."""
    values = []
    for argument in callbacks.getCommandLineArguments():
        argument = str(argument)
        if argument.startswith(flag + "="):
            values.append(argument[len(flag) + 1:])
    return values


def int_setting(callbacks, name: str, default: int) -> int:
    """Read an integer setting, falling back to ``default`` on bad input."""
    try:
        return int(setting(callbacks, name, str(default)))
    except (TypeError, ValueError):
        return default


def enabled(callbacks, name: str, default: bool = True) -> bool:
    value = setting(callbacks, name + ".enabled", "true" if default else "false")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def report(callbacks, tag: str, message: str) -> None:
    callbacks.printOutput(f"[{tag}] {message}")


def bounded(items: deque, item, size: int = 500) -> None:
    items.append(item)
    while len(items) > size:
        items.popleft()


def bounded_add(items: OrderedDict, item, size: int = 2000) -> bool:
    """Add ``item`` unless already present; evict the oldest entry on overflow."""
    if item in items:
        return False
    items[item] = None
    if len(items) > size:
        items.popitem(last=False)
    return True


def bounded_put(items: OrderedDict, key, value, size: int = 2000) -> None:
    """Store ``key`` in a FIFO-bounded mapping."""
    items.pop(key, None)
    items[key] = value
    if len(items) > size:
        items.popitem(last=False)


def json_preview(body: bytes, limit: int = 2000) -> str:
    try:
        parsed = json.loads(body.decode("utf-8", "replace"))
        result = json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False)
    except Exception:
        result = text(body)
    return result[:limit]
