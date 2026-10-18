#!/usr/bin/env python3
"""
keyguard - password-based file encryption for personal use.

Encryption: AES-256-GCM (authenticated, so tampering or a wrong password is detected)
Key derivation: scrypt (slow on purpose, to resist password guessing)

Usage:
    python keyguard.py encrypt secret.pdf          -> secret.pdf.enc
    python keyguard.py decrypt secret.pdf.enc      -> secret.pdf
    python keyguard.py encrypt notes.txt -o out.enc

Install dependency:
    pip install cryptography
"""

import argparse
import getpass
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FCRYPT1"          # file signature + format version
SALT_LEN = 16
NONCE_LEN = 12
# scrypt cost parameters (stored in the file so they can be raised later)
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
# header = magic | salt | nonce | N (u32) | r (u16) | p (u16)
HEADER_FMT = f">{len(MAGIC)}s{SALT_LEN}s{NONCE_LEN}sIHH"
HEADER_LEN = struct.calcsize(HEADER_FMT)


def derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    header = struct.pack(HEADER_FMT, MAGIC, salt, nonce, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    plaintext = src.read_bytes()
    # The header is passed as associated data, so it is authenticated too.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)

    dst.write_bytes(header + ciphertext)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    data = src.read_bytes()
    if len(data) < HEADER_LEN or not data.startswith(MAGIC):
        raise ValueError("Not a keyguard file (or the file is corrupted).")

    header, ciphertext = data[:HEADER_LEN], data[HEADER_LEN:]
    _, salt, nonce, n, r, p = struct.unpack(HEADER_FMT, header)
    key = derive_key(password, salt, n, r, p)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise ValueError("Decryption failed: wrong password or the file was modified.")

    dst.write_bytes(plaintext)


def read_password(confirm: bool) -> str:
    password = getpass.getpass("Password: ")
    if not password:
        sys.exit("Password cannot be empty.")
    if confirm and getpass.getpass("Confirm password: ") != password:
        sys.exit("Passwords do not match.")
    return password


def main() -> None:
    parser = argparse.ArgumentParser(description="Password-based file encryption (AES-256-GCM).")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("file", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="output path (default: add/remove .enc)")
    parser.add_argument("-f", "--force", action="store_true", help="overwrite the output if it exists")
    args = parser.parse_args()

    src: Path = args.file
    if not src.is_file():
        sys.exit(f"File not found: {src}")

    if args.output:
        dst = args.output
    elif args.mode == "encrypt":
        dst = src.with_name(src.name + ".enc")
    else:
        dst = src.with_suffix("") if src.suffix == ".enc" else src.with_name(src.name + ".dec")

    if dst.exists() and not args.force:
        sys.exit(f"{dst} already exists. Use --force to overwrite.")

    try:
        if args.mode == "encrypt":
            encrypt_file(src, dst, read_password(confirm=True))
        else:
            decrypt_file(src, dst, read_password(confirm=False))
    except ValueError as e:
        sys.exit(str(e))

    print(f"Done: {dst}")


if __name__ == "__main__":
    main()
