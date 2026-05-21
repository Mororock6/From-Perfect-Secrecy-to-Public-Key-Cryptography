import secrets
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def generate_aes_key(length: int = 32) -> bytes:
    if length not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")
    return secrets.token_bytes(length)


def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes) -> bytes:
    if not padded or len(padded) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data.")

    pad_len = padded[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length.")

    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")

    return padded[:-pad_len]


def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = secrets.token_bytes(BLOCK_SIZE)
    padded = pkcs7_pad(plaintext)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext


def aes_cbc_decrypt(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    if len(iv_and_ciphertext) < 32 or len(iv_and_ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must contain IV + at least one block.")

    iv = iv_and_ciphertext[:BLOCK_SIZE]
    ciphertext = iv_and_ciphertext[BLOCK_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    return pkcs7_unpad(padded_plaintext)


# Fixed oracle key for Group B padding-oracle testing
ORACLE_KEY = generate_aes_key()


def oracle_encrypt(plaintext: bytes) -> bytes:
    return aes_cbc_encrypt(plaintext, ORACLE_KEY)


def padding_oracle(ciphertext: bytes) -> bool:
    try:
        aes_cbc_decrypt(ciphertext, ORACLE_KEY)
        return True
    except ValueError:
        return False


def aes_demo() -> None:
    print("\n========== AES-CBC ==========")

    plaintext = b"Amer AES Demo"
    key = generate_aes_key()

    ciphertext1 = aes_cbc_encrypt(plaintext, key)
    ciphertext2 = aes_cbc_encrypt(plaintext, key)

    recovered1 = aes_cbc_decrypt(ciphertext1, key)
    recovered2 = aes_cbc_decrypt(ciphertext2, key)

    print("INPUT plaintext:", plaintext)
    print("INPUT AES key hex:", key.hex())

    print("OUTPUT ciphertext 1 hex:", ciphertext1.hex())
    print("OUTPUT ciphertext 2 hex:", ciphertext2.hex())

    print("Same plaintext encrypted twice gives different ciphertexts:", ciphertext1 != ciphertext2)

    print("OUTPUT decrypted 1:", recovered1)
    print("OUTPUT decrypted 2:", recovered2)

    valid_ciphertext = oracle_encrypt(b"valid padding test")
    print("Padding oracle on valid ciphertext:", padding_oracle(valid_ciphertext))


if __name__ == "__main__":
    aes_demo()