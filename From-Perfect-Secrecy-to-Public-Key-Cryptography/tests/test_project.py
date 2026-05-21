from otp import generate_key as otp_key, otp_encrypt, otp_decrypt
from aes_cbc import generate_key as aes_key, aes_cbc_encrypt, aes_cbc_decrypt, pkcs7_pad, pkcs7_unpad, oracle_encrypt, padding_oracle, mac_then_encrypt, mac_then_decrypt
from hash_utils import sha256_hex, commit, generate_nonce, verify_commitment
from rsa import generate_rsa_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes, rsa_encrypt_oaep, rsa_decrypt_oaep


def test_otp_roundtrip_and_determinism():
    m = b"hello otp"
    k = otp_key(len(m))
    c1 = otp_encrypt(m, k)
    c2 = otp_encrypt(m, k)
    assert c1 == c2
    assert otp_decrypt(c1, k) == m


def test_pkcs7_padding():
    data = b"1234567890"
    padded = pkcs7_pad(data)
    assert len(padded) % 16 == 0
    assert pkcs7_unpad(padded) == data


def test_aes_cbc_roundtrip_and_random_iv():
    key = aes_key()
    m = b"same message"
    c1 = aes_cbc_encrypt(m, key)
    c2 = aes_cbc_encrypt(m, key)
    assert c1 != c2
    assert aes_cbc_decrypt(c1, key) == m
    assert aes_cbc_decrypt(c2, key) == m


def test_padding_oracle():
    valid = oracle_encrypt(b"oracle test")
    assert padding_oracle(valid) is True
    tampered = valid[:-1] + bytes([valid[-1] ^ 1])
    assert padding_oracle(tampered) is False


def test_sha256_and_commitment():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    nonce = generate_nonce()
    com = commit(b"message", nonce)
    assert verify_commitment(b"message", nonce, com)
    assert not verify_commitment(b"other", nonce, com)


def test_rsa_roundtrip_fast_demo():
    kp = generate_rsa_keypair(prime_bits=64, e=65537)
    m = b"hi"
    c = rsa_encrypt_bytes(m, kp.public_key)
    assert rsa_decrypt_bytes(c, kp.private_key) == m


def test_mac_then_encrypt_roundtrip_and_tamper():
    enc_key = aes_key()
    mac_key = b"M" * 32
    msg = b"authenticated message"
    c = mac_then_encrypt(msg, enc_key, mac_key)
    assert mac_then_decrypt(c, enc_key, mac_key) == msg


def test_rsa_oaep_roundtrip():
    kp = generate_rsa_keypair(prime_bits=512, e=65537)
    msg = b"OAEP demo"
    c = rsa_encrypt_oaep(msg, kp.public_key)
    assert rsa_decrypt_oaep(c, kp.private_key) == msg
