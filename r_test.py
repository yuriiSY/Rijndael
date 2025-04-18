import os
import ctypes
import pytest
from aes.aes import (
    AES,
    bytes2matrix,
    matrix2bytes,
    sub_bytes as py_sub,
    inv_sub_bytes as py_inv_sub,
    shift_rows as py_shift,
    inv_shift_rows as py_inv_shift,
    mix_columns as py_mix,
    inv_mix_columns as py_inv_mix,
    add_round_key as py_xor_key,
)

# Load the C impl
lib = ctypes.CDLL('./rijndael.so')

# Helpers
def flat(mat):
    return [b for row in mat for b in row]


def ptr_to_bytes(ptr, length=16):
    return bytes((ptr[i] for i in range(length)))


def make_buffers():
    data = os.urandom(16)
    c_buf = ctypes.create_string_buffer(data)
    py_state = bytes2matrix(data)
    original = ctypes.create_string_buffer(data)
    return c_buf, py_state, original


def make_key():
    raw = os.urandom(16)
    return ctypes.create_string_buffer(raw), bytes2matrix(raw)


# Test Cases

@pytest.mark.parametrize("rounds", [1, 2, 3])
def test_bytes_substitution(rounds):
    c_buf, py_state, original = make_buffers()
    lib.sub_bytes(c_buf)
    py_sub(py_state)
    assert flat(py_state) == list(c_buf.raw[:16])
    assert c_buf.raw != original.raw


@pytest.mark.parametrize("rounds", [1, 2, 3])
def test_inverse_sub(rounds):
    c_buf, py_state, original = make_buffers()
    lib.sub_bytes(c_buf)
    py_sub(py_state)
    lib.invert_sub_bytes(c_buf)
    py_inv_sub(py_state)
    assert flat(py_state) == list(c_buf.raw[:16])
    assert c_buf.raw == original.raw


@pytest.mark.parametrize("rounds", [1, 2, 3])
def test_shift_variants(rounds):
    c_buf, py_state, original = make_buffers()
    lib.shift_rows(c_buf)
    py_shift(py_state)
    assert flat(py_state) == list(c_buf.raw[:16])
    assert c_buf.raw != original.raw

    lib.invert_shift_rows(c_buf)
    py_inv_shift(py_state)
    assert flat(py_state) == list(c_buf.raw[:16])
    assert c_buf.raw == original.raw


@pytest.mark.parametrize("rounds", [1, 2, 3])
def test_mix_variants(rounds):
    c_buf, py_state, original = make_buffers()
    lib.mix_columns(c_buf)
    py_mix(py_state)
    assert flat(py_state) == list(c_buf.raw[:16])
    assert c_buf.raw != original.raw

    lib.invert_mix_columns(c_buf)
    py_inv_mix(py_state)
    assert flat(py_state) == list(c_buf.raw[:16])
    assert c_buf.raw == original.raw


@pytest.mark.parametrize("rounds", [1, 2, 3])
def test_key_xoring(rounds):
    c_buf, py_state, orig = make_buffers()
    c_key, py_key = make_key()
    lib.add_round_key(c_buf, c_key)
    py_xor_key(py_state, bytes2matrix(c_key.raw))
    assert flat(py_state) == list(c_buf.raw[:16])
    assert c_buf.raw != orig.raw


def test_end_to_end_encrypt_decrypt():
    c_state, py_state, orig = make_buffers()
    c_key, py_key = make_key()
    aes = AES(matrix2bytes(py_key))

    # Encryption
    lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
    enc_ptr = lib.aes_encrypt_block(c_state, c_key)
    c_cipher = ptr_to_bytes(enc_ptr)
    py_cipher = aes.encrypt_block(matrix2bytes(py_state))
    assert c_cipher == py_cipher
    # ensure change
    assert c_cipher != orig.raw[:16]

    # Decryption
    lib.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
    dec_ptr = lib.aes_decrypt_block(c_cipher, c_key)
    c_plain = ptr_to_bytes(dec_ptr)
    py_plain = aes.decrypt_block(py_cipher)
    assert c_plain == py_plain
    assert c_plain == orig.raw[:16]

    # Wrong key should fail
    wrong_key, _ = make_key()
    bad_ptr = lib.aes_decrypt_block(c_cipher, wrong_key)
    bad_plain = ptr_to_bytes(bad_ptr)
    assert bad_plain != orig.raw[:16]
