from __future__ import annotations

import gzip
import json
import zlib

import brotli


def decode_body(body: bytes, encoding: str) -> bytes:
    encoding = encoding.strip().lower()
    if not body or not encoding:
        return body
    if encoding == "gzip":
        try:
            return gzip.decompress(body)
        except (EOFError, gzip.BadGzipFile):
            return body
    if encoding == "br":
        try:
            return brotli.decompress(body)
        except brotli.error:
            return body
    if encoding == "deflate":
        try:
            return zlib.decompress(body, -zlib.MAX_WBITS)
        except zlib.error:
            return body
    return body


def try_parse_json(body: bytes) -> object | None:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
