import io
import os

from vpn_protocol import (
    KEY_LEN,
    NONCE_LEN,
    MAC_LEN,
    encrypt_payload,
    decrypt_payload,
    send_encrypted_frame,
    recv_encrypted_frame,
    ProtocolError,
    SessionCrypto,
)


def test_roundtrip_payload_random():
    key = os.urandom(KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    plaintext = os.urandom(1024)

    ciphertext, tag = encrypt_payload(key, nonce, plaintext)
    assert len(ciphertext) == len(plaintext)
    assert len(tag) == MAC_LEN

    recovered = decrypt_payload(key, nonce, ciphertext, tag)
    assert recovered == plaintext


def test_mac_mismatch_raises():
    key = os.urandom(KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    plaintext = b"hello world"

    ciphertext, tag = encrypt_payload(key, nonce, plaintext)
    # Flip one bit
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01

    try:
        decrypt_payload(key, nonce, ciphertext, bytes(bad_tag))
        raised = False
    except ProtocolError:
        raised = True

    assert raised


def test_frame_roundtrip_in_memory():
    key = os.urandom(KEY_LEN)
    plaintext = b"frame payload test" * 50

    fake_stream = io.BytesIO()
    send_encrypted_frame(fake_stream, key, plaintext)

    # reset cursor to the beginning to simulate reading
    fake_stream.seek(0)
    recovered = recv_encrypted_frame(fake_stream, key)
    assert recovered == plaintext


def test_session_compression_roundtrip():
    key = os.urandom(KEY_LEN)
    sender = SessionCrypto(key, compress=True)
    receiver = SessionCrypto(key, compress=True)
    payload = b"\x01" + (b"hello world" * 50)

    fake_stream = io.BytesIO()
    sender.send_frame(fake_stream, payload)

    fake_stream.seek(0)
    recovered = receiver.recv_frame(fake_stream)
    assert recovered == payload


def test_session_rekeys_after_interval():
    key = os.urandom(KEY_LEN)
    sender = SessionCrypto(key, rekey_interval=2)
    receiver = SessionCrypto(key, rekey_interval=2)

    fake_stream = io.BytesIO()
    sender.send_frame(fake_stream, b"\x01first")
    sender.send_frame(fake_stream, b"\x01second")

    fake_stream.seek(0)
    receiver.recv_frame(fake_stream)
    receiver.recv_frame(fake_stream)

    assert receiver._current_key != key
