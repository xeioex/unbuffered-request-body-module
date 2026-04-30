#!/usr/bin/env python3

import argparse
import hashlib
import socket
import time
from urllib.parse import urlparse


UNITS = {
    "k": 1024,
    "m": 1024 ** 2,
    "g": 1024 ** 3,
}


def parse_size(value):
    value = value.strip().lower()

    if value[-1:] in UNITS:
        return int(float(value[:-1]) * UNITS[value[-1]])

    return int(value)


def body_block(offset, size):
    return bytes(((offset + i) & 0xff for i in range(size)))


def read_response(sock):
    data = bytearray()

    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed before response headers")

        data.extend(chunk)

    head, rest = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    headers = {}

    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.lower()] = value.strip()

    body = bytearray(rest)

    if "content-length" in headers:
        length = int(headers["content-length"])

        while len(body) < length:
            chunk = sock.recv(65536)
            if not chunk:
                break

            body.extend(chunk)

        body = body[:length]

    else:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break

            body.extend(chunk)

    return lines[0], headers, bytes(body)


def send_body(sock, total, chunk_size, mode, rate, chunk_delay):
    sha1 = hashlib.sha1()
    sent = 0
    started = time.monotonic()

    while sent < total:
        size = min(chunk_size, total - sent)
        data = body_block(sent, size)

        sha1.update(data)
        sock.sendall(data)
        sent += size

        if mode == "rate":
            target = sent / rate
            elapsed = time.monotonic() - started

            if target > elapsed:
                time.sleep(target - elapsed)

        elif mode == "chunks" and chunk_delay > 0:
            time.sleep(chunk_delay)

    return sha1.hexdigest()


def verify(expect, status, headers, body, digest, size):
    text = body.decode("utf-8", "replace")

    if not status.startswith("HTTP/1.1 200"):
        raise AssertionError(status)

    if expect == "consume_content":
        expected = f"sha1={digest} size={size}\n"

        if text != expected:
            raise AssertionError(f"bad body: {text!r}, expected {expected!r}")

        verify_no_unbuffered_headers(headers)
        return

    if expect in ("consume_access", "view"):
        if text != "backend ok\n":
            raise AssertionError(f"bad backend body: {text!r}")

        verify_unbuffered_headers(headers, digest, size)
        return

    if expect == "off":
        if text != "backend ok\n":
            raise AssertionError(f"bad backend body: {text!r}")

        verify_no_unbuffered_headers(headers)
        return

    raise AssertionError(f"unknown expectation: {expect}")


def verify_unbuffered_headers(headers, digest, size):
    checks = {
        "x-unbuffered-body-sha1": digest,
        "x-unbuffered-body-size": str(size),
        "x-unbuffered-body-state": "done",
    }

    for name, expected in checks.items():
        actual = headers.get(name)

        if actual != expected:
            raise AssertionError(
                f"bad {name}: {actual!r}, expected {expected!r}"
            )


def verify_no_unbuffered_headers(headers):
    for name in headers:
        if name.startswith("x-unbuffered-"):
            raise AssertionError(f"unexpected header: {name}")


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--url", required=True)
    parser.add_argument("--size", required=True, type=parse_size)
    parser.add_argument("--mode", choices=("fast", "rate", "chunks"),
                        default="fast")
    parser.add_argument("--rate", type=parse_size)
    parser.add_argument("--chunk-size", type=parse_size, default=65536)
    parser.add_argument("--chunk-delay", type=float, default=0.0)
    parser.add_argument("--expect",
                        choices=("consume_content", "consume_access", "view",
                                 "off"),
                        required=True)

    args = parser.parse_args()

    if args.mode == "rate" and args.rate is None:
        parser.error("--mode rate requires --rate")

    return args


def main():
    args = parse_args()
    url = urlparse(args.url)

    if url.scheme != "http":
        raise SystemExit("only http:// URLs are supported")

    host = url.hostname
    port = url.port or 80
    path = url.path or "/"

    if url.query:
        path += "?" + url.query

    sock = socket.create_connection((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"Content-Length: {args.size}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
    ).encode("ascii")

    started = time.monotonic()

    sock.sendall(request)
    digest = send_body(sock, args.size, args.chunk_size, args.mode,
                       args.rate, args.chunk_delay)

    status, headers, body = read_response(sock)
    elapsed = time.monotonic() - started

    verify(args.expect, status, headers, body, digest, args.size)

    mib = args.size / 1024 / 1024

    print(f"ok sha1={digest} size={args.size}")
    print(f"elapsed={elapsed:.3f}s throughput={mib / elapsed:.2f} MiB/s")


if __name__ == "__main__":
    main()
