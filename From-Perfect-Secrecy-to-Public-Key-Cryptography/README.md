# Advanced Cryptography Project - Group A

Project theme: **From Perfect Secrecy to Public Key**.

## Files

- `otp.py` - One-Time Pad XOR encryption/decryption and perfect secrecy demo.
- `aes_cbc.py` - AES-CBC using random IV, PKCS#7 padding/unpadding, and a padding oracle API for Group B.
- `hash_utils.py` - SHA-256 wrapper, Merkle-Damgard explanation, hash commitment, and timing benchmarks.
- `rsa.py` - RSA prime generation using `sympy.isprime()`, textbook encryption/decryption, JSON public key export, and vulnerable `e=3` key generation.
- `demo.py` - Runs all demonstrations.
- `tests/` - Unit tests.
- `GroupA_report.pdf` - Written report.

## Setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

The AES and SHA-256 modules prefer `pycryptodome`. A fallback is included for environments where `pycryptodome` is not installed, but for submission install the requirements.

## Run the demo

```bash
python demo.py
```

## Run unit tests

```bash
pytest -q
```

## Export vulnerable RSA public key for Group B

```bash
python rsa.py
```

This creates `groupB_public_key.json` with:

```json
{
  "e": "3",
  "n": "..."
}
```

## Notes

- OTP is secure only with a truly random key, same length as the message, used once.
- AES-CBC uses a fresh random IV per encryption. The padding oracle is intentionally exposed for the assignment and must not be exposed in real applications.
- Plain textbook RSA and `e=3` are intentionally vulnerable for Group B. Use OAEP in real systems.
