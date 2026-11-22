"""Exports the Burp-compatible API objects to the bridge package.

The implementation lives in :mod:`burp.api` so extensions can import it under
the familiar package name.  This module simply re-exports it for
``python -m blurp.bridge``.
"""

from burp.api import (  # noqa: F401
    BurpExtenderCallbacks,
    Cookie,
    Helpers,
    HttpHeader,
    HttpRequestResponse,
    HttpService,
    InterceptedProxyMessage,
    Parameter,
    RequestInfo,
    ResponseInfo,
    decode,
    encode,
)

__all__ = [
    "BurpExtenderCallbacks",
    "Cookie",
    "Helpers",
    "HttpHeader",
    "HttpRequestResponse",
    "HttpService",
    "InterceptedProxyMessage",
    "Parameter",
    "RequestInfo",
    "ResponseInfo",
    "decode",
    "encode",
]
