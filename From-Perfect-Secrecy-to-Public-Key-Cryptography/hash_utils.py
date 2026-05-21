import secrets
import time
from Crypto.Hash import SHA256


def sha256_digest(data: bytes) -> bytes:
    return SHA256.new(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256_digest(data).hex()


def generate_nonce(length: int = 32) -> bytes:
    return secrets.token_bytes(length)


def commit(message: bytes, nonce: bytes) -> bytes:
    return sha256_digest(message + nonce)


def verify_commitment(message: bytes, nonce: bytes, commitment: bytes) -> bool:
    return commit(message, nonce) == commitment


def benchmark_sha256() -> list[dict]:
    sizes = [64, 1024, 65536]
    rounds = 10
    results = []

    for size in sizes:
        data = secrets.token_bytes(size)

        start = time.perf_counter()

        for _ in range(rounds):
            sha256_digest(data)

        total_time = time.perf_counter() - start
        avg_time = total_time / rounds

        results.append({
            "input_size_bytes": size,
            "rounds": rounds,
            "total_seconds": total_time,
            "average_seconds": avg_time,
        })

    return results


def hash_demo() -> None:
    print("\n========== HASH + COMMITMENT ==========")

    message = b"Amer Ashoush"
    nonce = generate_nonce()

    digest = sha256_hex(message)
    commitment = commit(message, nonce)
    verified = verify_commitment(message, nonce, commitment)

    print("INPUT message:", message)
    print("INPUT nonce hex:", nonce.hex())

    print("OUTPUT SHA-256(message):", digest)
    print("OUTPUT commitment SHA-256(message || nonce):", commitment.hex())
    print("OUTPUT verify:", verified)

    print("OUTPUT benchmarks:")
    for row in benchmark_sha256():
        print(row)


if __name__ == "__main__":
    hash_demo()