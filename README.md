# From-Perfect-Secrecy-to-Public-Key-Cryptography
A practical Python implementation of core cryptographic concepts, demonstrating the progression from theoretically perfect secrecy to practical symmetric encryption and finally public-key cryptography.

This project was developed as part of an Advanced Cryptography academic project, focusing on both secure implementations and intentionally vulnerable configurations for educational security analysis.

---

## Project Overview

This project implements:

- One-Time Pad (OTP)
- AES-CBC symmetric encryption
- PKCS#7 padding
- SHA-256 hashing
- Hash-based commitment scheme
- RSA public-key cryptography
- Vulnerable RSA (`e = 3`) for attack demonstration
- CBC padding oracle exposure for security analysis

The objective was to move beyond theory and implement core cryptographic mechanisms from scratch to understand both how they work and how implementation choices affect security.

---

## Features

### One-Time Pad (OTP)
- XOR-based encryption and decryption
- Cryptographically secure random key generation
- Perfect secrecy demonstration
- Demonstrates why ciphertext alone reveals no plaintext information under OTP assumptions

Formula:

```text
Ciphertext = Plaintext XOR Key
```

---

### AES-CBC
- AES encryption using CBC mode
- AES-128 / AES-192 / AES-256 support
- Random IV generation
- PKCS#7 padding implementation
- Encryption/decryption demonstrations
- Padding oracle exposure for attack demonstration
- Demonstrates CPA security through randomized encryption

Encryption flow:

```text
Plaintext
→ PKCS#7 Padding
→ Random IV Generation
→ AES-CBC Encryption
→ IV + Ciphertext
```

Decryption flow:

```text
IV + Ciphertext
→ Extract IV
→ AES-CBC Decryption
→ Remove Padding
→ Original Plaintext
```

---

### SHA-256 & Commitment Scheme
- SHA-256 hashing
- Human-readable hexadecimal digest output
- Secure random nonce generation
- Commitment creation and verification
- SHA-256 performance benchmarking

Commitment formula:

```text
Commitment = SHA256(message || nonce)
```

Security properties:
- Integrity
- Binding
- Hiding

---

### RSA
- Random prime generation
- RSA keypair generation
- Public/private key creation
- Integer and byte encryption/decryption
- Modular inverse computation
- Standard RSA using `e = 65537`
- Vulnerable RSA example using `e = 3`

RSA formulas:

```text
n = p × q
φ(n) = (p - 1)(q - 1)
```

Encryption:

```text
c = m^e mod n
```

Decryption:

```text
m = c^d mod n
```

---

## Project Structure

```text
From-Perfect-Secrecy-to-Public-Key-Cryptography/
│
├── otp.py
├── aes_cbc.py
├── hash_utils.py
├── rsa.py
├── demo.py
├── requirements.txt
└── README.md
```

### File Descriptions

| File | Description |
|------|-------------|
| `otp.py` | One-Time Pad implementation and perfect secrecy demonstration |
| `aes_cbc.py` | AES-CBC encryption/decryption, padding, and padding oracle |
| `hash_utils.py` | SHA-256 hashing, commitment scheme, benchmarking |
| `rsa.py` | RSA implementation and vulnerable RSA example |
| `demo.py` | Runs demonstrations for all cryptographic modules |

---

## Security Demonstrations

This project intentionally includes insecure configurations for educational purposes.

### Padding Oracle
The AES-CBC module exposes a padding oracle:

```python
padding_oracle(ciphertext)
```

Returns:

```python
True
```

if padding is valid, and:

```python
False
```

if padding is invalid.

This demonstrates how seemingly small implementation mistakes can create exploitable vulnerabilities.

---

### Vulnerable RSA
A vulnerable RSA configuration is included:

```text
e = 3
```

This demonstrates low public exponent attacks when secure padding is absent.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Mororock6/From-Perfect-Secrecy-to-Public-Key-Cryptography.git
cd From-Perfect-Secrecy-to-Public-Key-Cryptography
```

Create a virtual environment.

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If activation is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then:

```powershell
.\.venv\Scripts\Activate.ps1
```

---

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Requirements

```text
pycryptodome
sympy
pytest
```

Install manually if needed:

```bash
pip install pycryptodome sympy pytest
```

---

## Usage

Run the full demonstration:

```bash
python demo.py
```

This demonstrates:

- OTP encryption/decryption
- Perfect secrecy
- AES-CBC encryption/decryption
- Random IV behavior
- Padding oracle behavior
- SHA-256 hashing
- Commitment creation and verification
- SHA-256 benchmarking
- RSA encryption/decryption
- Vulnerable RSA example

---

## Example Output

### OTP

```text
INPUT plaintext: b'HELLO'
INPUT key hex: 6767c6d24a
OUTPUT ciphertext hex: 2f228a9e05
OUTPUT decrypted: b'HELLO'
```

---

### AES-CBC

```text
INPUT plaintext: b'Amer AES Demo'
OUTPUT decrypted: b'Amer AES Demo'
```

---

### Hash

```text
OUTPUT SHA-256(message): ...
OUTPUT commitment: ...
OUTPUT verify: True
```

---

### RSA

```text
OUTPUT decrypted: b'Amer RSA Demo'
OUTPUT decryption ok: True
```

---

## Educational Disclaimer

This project was developed for academic and educational purposes.

The intentionally vulnerable components included in this repository (padding oracle exposure and low-exponent RSA) are meant to demonstrate real-world cryptographic weaknesses and attack surfaces.

These implementations should **not** be used in production environments.

---

## Author

**Amer Ashoush**

Cybersecurity Student | Blue Team | Offensive Security | Cryptography

GitHub: https://github.com/Mororock6
LinkedIn: https://linkedin.com/in/amerashoush2468
