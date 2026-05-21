import secrets


def generate_otp_key(length: int) -> bytes:
    return secrets.token_bytes(length)


def otp_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) != len(key):
        raise ValueError("OTP key must be the same length as plaintext.")
    return bytes(p ^ k for p, k in zip(plaintext, key))


def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) != len(key):
        raise ValueError("OTP key must be the same length as ciphertext.")
    return bytes(c ^ k for c, k in zip(ciphertext, key))


def otp_demo() -> None:
    print("\n========== OTP ==========")

    plaintext = b"HELLO"
    key = generate_otp_key(len(plaintext))

    ciphertext = otp_encrypt(plaintext, key)
    recovered = otp_decrypt(ciphertext, key) # USING THE SAME KEY

    print("INPUT plaintext:", plaintext)
    print("INPUT key hex:", key.hex())
    print("OUTPUT ciphertext hex:", ciphertext.hex())
    print("OUTPUT decrypted:", recovered)

    print("\nPerfect secrecy demo:")
    target_ciphertext = secrets.token_bytes(3)
    possible_messages = [b"YES", b"NO!", b"PAY"]

    print("Observed ciphertext:", target_ciphertext.hex())

    for msg in possible_messages:
        possible_key = otp_encrypt(msg, target_ciphertext)
        print(f"If message is {msg!r}, possible key is:", possible_key.hex())


if __name__ == "__main__":
    otp_demo()