"""Minimal educational VPN-like protocol implementation.

This module defines a simple encrypted framing protocol that can be used
on top of any reliable byte stream (e.g. TCP). It is **not** meant to be
cryptographically strong, but it demonstrates key ideas:

- shared secret key
- per-frame nonces
- authenticated encryption (ciphertext + MAC)
- length-prefixed frames over a stream

Do NOT use this in production.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import zlib
from typing import BinaryIO, Optional


# --- Symmetric crypto primitives -------------------------------------------------


KEY_LEN = 32  # bytes
NONCE_LEN = 16  # bytes
MAC_LEN = 32  # HMAC-SHA256
FLAG_COMPRESSED = 0x01


class ProtocolError(Exception):
    pass


def _derive_keystream_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Derive a pseudo-random keystream block from key, nonce, and counter.

    This is *not* a standard construction; it's purely for educational purposes.
    """

    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 16 bytes")

    ctr_bytes = counter.to_bytes(8, "big")
    data = key + nonce + ctr_bytes
    return hashlib.sha256(data).digest()


def _xor_bytes(data: bytes, keystream: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(data, keystream))


def encrypt_payload(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt `plaintext` with a stream cipher-like construction and HMAC.

    Returns (ciphertext, mac).
    """

    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 16 bytes")

    ciphertext_parts = []
    mac = hmac.new(key, nonce, hashlib.sha256)

    block_index = 0
    offset = 0
    while offset < len(plaintext):
        block = _derive_keystream_block(key, nonce, block_index)
        chunk = plaintext[offset : offset + len(block)]
        ks = block[: len(chunk)]
        cipher_chunk = _xor_bytes(chunk, ks)
        ciphertext_parts.append(cipher_chunk)
        mac.update(cipher_chunk)

        offset += len(chunk)
        block_index += 1

    ciphertext = b"".join(ciphertext_parts)
    tag = mac.digest()
    return ciphertext, tag


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 16 bytes")
    if len(tag) != MAC_LEN:
        raise ValueError("tag must be 32 bytes")

    mac = hmac.new(key, nonce, hashlib.sha256)
    mac.update(ciphertext)
    if not hmac.compare_digest(mac.digest(), tag):
        raise ProtocolError("MAC verification failed")

    plaintext_parts = []
    block_index = 0
    offset = 0
    while offset < len(ciphertext):
        block = _derive_keystream_block(key, nonce, block_index)
        chunk = ciphertext[offset : offset + len(block)]
        ks = block[: len(chunk)]
        plain_chunk = _xor_bytes(chunk, ks)
        plaintext_parts.append(plain_chunk)

        offset += len(chunk)
        block_index += 1

    return b"".join(plaintext_parts)


# --- Framing over a stream -------------------------------------------------------


# Frame format:
# [length: uint32 big-endian] [nonce: 16 bytes] [ciphertext: length bytes] [mac: 32 bytes]


def send_encrypted_frame(stream: BinaryIO, key: bytes, plaintext: bytes) -> None:
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")

    nonce = os.urandom(NONCE_LEN)
    ciphertext, tag = encrypt_payload(key, nonce, plaintext)
    length = len(ciphertext)
    header = struct.pack("!I", length)
    stream.write(header + nonce + ciphertext + tag)
    stream.flush()


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError("unexpected EOF while reading frame")
        buf.extend(chunk)
    return bytes(buf)


def recv_encrypted_frame(stream: BinaryIO, key: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")

    header = _read_exact(stream, 4)
    (length,) = struct.unpack("!I", header)
    nonce = _read_exact(stream, NONCE_LEN)
    ciphertext = _read_exact(stream, length)
    tag = _read_exact(stream, MAC_LEN)
    return decrypt_payload(key, nonce, ciphertext, tag)


# --- Simple VPN-like tunnel ------------------------------------------------------


def _key_from_passphrase(passphrase: str, salt: str = "", iterations: int = 100_000) -> bytes:
    """Derive a key from a passphrase using PBKDF2-HMAC-SHA256."""

    if iterations <= 0:
        raise ValueError("iterations must be positive")
    salt_bytes = salt.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt_bytes, iterations, KEY_LEN)


def _ratchet_key(current_key: bytes, label: bytes = b"rekey") -> bytes:
    """Derive the next session key using an HMAC-based ratchet."""

    return hmac.new(current_key, label, hashlib.sha256).digest()


class SessionCrypto:
    """Stateful helper that adds compression and key rotation on top of the framing helpers."""

    def __init__(
        self,
        base_key: bytes,
        compress: bool = False,
        rekey_interval: Optional[int] = None,
    ) -> None:
        if len(base_key) != KEY_LEN:
            raise ValueError("base_key must be 32 bytes")
        if rekey_interval is not None and rekey_interval <= 0:
            raise ValueError("rekey_interval must be positive when provided")

        self._current_key = base_key
        self._compress = compress
        self._rekey_interval = rekey_interval
        self._frames_since_rekey = 0

    def _bump_key_if_needed(self) -> None:
        if self._rekey_interval is None:
            return
        self._frames_since_rekey += 1
        if self._frames_since_rekey >= self._rekey_interval:
            self._current_key = _ratchet_key(self._current_key)
            self._frames_since_rekey = 0

    def _encode_payload(self, payload: bytes) -> bytes:
        if not self._compress:
            return b"\x00" + payload

        compressed = zlib.compress(payload)
        # Only use compression if it meaningfully shrinks the payload.
        if len(compressed) < len(payload):
            return bytes([FLAG_COMPRESSED]) + compressed
        return b"\x00" + payload

    def _decode_payload(self, framed_payload: bytes) -> bytes:
        if not framed_payload:
            return b""
        flag = framed_payload[0]
        body = framed_payload[1:]
        if flag & FLAG_COMPRESSED:
            return zlib.decompress(body)
        return body

    def send_frame(self, stream: BinaryIO, payload: bytes) -> None:
        framed = self._encode_payload(payload)
        send_encrypted_frame(stream, self._current_key, framed)
        self._bump_key_if_needed()

    def recv_frame(self, stream: BinaryIO) -> bytes:
        framed = recv_encrypted_frame(stream, self._current_key)
        self._bump_key_if_needed()
        return self._decode_payload(framed)


class StreamWrapper:
    """Wrap a socket to present a file-like binary interface for framing helpers."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._file = sock.makefile("rwb")

    def write(self, data: bytes) -> int:  # type: ignore[override]
        return self._file.write(data)

    def flush(self) -> None:
        self._file.flush()

    def read(self, n: int) -> bytes:  # type: ignore[override]
        return self._file.read(n)

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            self._sock.close()


def run_server(
    listen_host: str,
    listen_port: int,
    target_host: str,
    target_port: int,
    passphrase: str,
    *,
    salt: str = "",
    iterations: int = 100_000,
    compress: bool = False,
    rekey_interval: Optional[int] = None,
) -> None:
    """Run a single-connection VPN server.

    - Accepts one client connection
    - Forwards plaintext to `target_host:target_port`
    - Uses the framing/encryption helpers over the client socket
    """

    key = _key_from_passphrase(passphrase, salt=salt, iterations=iterations)
    session = SessionCrypto(key, compress=compress, rekey_interval=rekey_interval)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((listen_host, listen_port))
        server_sock.listen(1)
        client_sock, _ = server_sock.accept()

    client_stream = StreamWrapper(client_sock)
    target_sock = socket.create_connection((target_host, target_port))

    try:
        target_stream = target_sock.makefile("rwb")

        # Simple loop: client -> target, then target -> client (request/response style)
        while True:
            try:
                payload = session.recv_frame(client_stream)
            except EOFError:
                break

            if not payload:
                break

            # First byte = direction: 0x01 client->target, 0x02 target->client request for more data
            direction = payload[:1]
            body = payload[1:]

            if direction == b"\x01":
                # Write body to target and read response
                target_stream.write(body)
                target_stream.flush()
                response = target_stream.read(4096)
                if not response:
                    break
                session.send_frame(client_stream, b"\x02" + response)
            else:
                # Unknown direction; ignore
                break
    finally:
        client_stream.close()
        target_sock.close()


def run_client(
    listen_host: str,
    listen_port: int,
    server_host: str,
    server_port: int,
    passphrase: str,
    *,
    salt: str = "",
    iterations: int = 100_000,
    compress: bool = False,
    rekey_interval: Optional[int] = None,
) -> None:
    """Run a local client that exposes a TCP port and forwards via encrypted tunnel.

    Any connection to (listen_host, listen_port) will be proxied to the VPN server,
    which then forwards to its configured target.
    """

    key = _key_from_passphrase(passphrase, salt=salt, iterations=iterations)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, listen_port))
        listener.listen(1)

        local_sock, _ = listener.accept()

    server_sock = socket.create_connection((server_host, server_port))
    server_stream = StreamWrapper(server_sock)
    local_stream = local_sock.makefile("rwb")
    session = SessionCrypto(key, compress=compress, rekey_interval=rekey_interval)

    try:
        while True:
            chunk = local_stream.read(4096)
            if not chunk:
                break
            session.send_frame(server_stream, b"\x01" + chunk)

            # Read single response frame
            try:
                payload = session.recv_frame(server_stream)
            except EOFError:
                break
            if not payload or payload[:1] != b"\x02":
                break
            local_stream.write(payload[1:])
            local_stream.flush()
    finally:
        server_stream.close()
        local_stream.close()
