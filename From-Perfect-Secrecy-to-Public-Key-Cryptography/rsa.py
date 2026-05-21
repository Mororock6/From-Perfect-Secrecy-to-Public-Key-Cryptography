import math
import secrets
import sympy


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def int_to_bytes(number: int) -> bytes:
    length = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(length, "big")


def generate_prime(bits: int = 512) -> int:
    while True:
        candidate = secrets.randbits(bits)

        # Force exact bit size
        candidate |= (1 << (bits - 1))

        # Force odd number
        candidate |= 1

        if sympy.isprime(candidate):
            return candidate


def generate_rsa_keypair(prime_bits: int = 512, e: int = 65537):
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) == 1:
            d = pow(e, -1, phi)

            public_key = (e, n)
            private_key = (d, n)

            return public_key, private_key, p, q, phi


def generate_vulnerable_rsa():
    return generate_rsa_keypair(prime_bits=512, e=3)


def rsa_encrypt_int(message_int: int, public_key: tuple[int, int]) -> int:
    e, n = public_key

    if not 0 <= message_int < n:
        raise ValueError("Message integer must be smaller than n.")

    return pow(message_int, e, n)


def rsa_decrypt_int(ciphertext_int: int, private_key: tuple[int, int]) -> int:
    d, n = private_key

    if not 0 <= ciphertext_int < n:
        raise ValueError("Ciphertext integer must be smaller than n.")

    return pow(ciphertext_int, d, n)


def rsa_encrypt_bytes(message: bytes, public_key: tuple[int, int]) -> int:
    message_int = bytes_to_int(message)
    return rsa_encrypt_int(message_int, public_key)


def rsa_decrypt_bytes(ciphertext_int: int, private_key: tuple[int, int]) -> bytes:
    recovered_int = rsa_decrypt_int(ciphertext_int, private_key)
    return int_to_bytes(recovered_int)


def rsa_demo() -> None:
    print("\n========== RSA ==========")

    message = b"Amer RSA Demo"

    # Small primes for fast demo only
    public_key, private_key, p, q, phi = generate_rsa_keypair(prime_bits=128)

    ciphertext = rsa_encrypt_bytes(message, public_key)
    recovered = rsa_decrypt_bytes(ciphertext, private_key)

    e, n = public_key
    d, _ = private_key

    print("INPUT plaintext:", message)
    print("INPUT p:", p)
    print("INPUT q:", q)
    print("INPUT n = p * q:", n)
    print("INPUT phi = (p-1)*(q-1):", phi)
    print("INPUT public key (e, n):", public_key)
    print("INPUT private key d:", d)

    print("OUTPUT ciphertext integer:", ciphertext)
    print("OUTPUT decrypted:", recovered)
    print("OUTPUT decryption ok:", recovered == message)

    print("\nVulnerable RSA example:")
    vulnerable_public, vulnerable_private, _, _, _ = generate_rsa_keypair(prime_bits=128, e=3)
    print("Vulnerable public e:", vulnerable_public[0])
    print("Vulnerable modulus bits:", vulnerable_public[1].bit_length())


if __name__ == "__main__":
    rsa_demo()