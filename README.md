# KeyGuard

**A simple command-line tool that locks and unlocks your files with a password, using AES-256-GCM encryption.**

KeyGuard is built in Python for personal privacy. Pick a file, enter a password, and get an encrypted copy that nobody can read without that password.

## Features

- AES-256-GCM authenticated encryption (detects wrong passwords and tampering)
- scrypt key derivation to resist password guessing
- Unique random salt and nonce for every file
- Password prompt hidden while typing, with confirmation on encryption
- Refuses to overwrite existing files unless you pass `--force`

## Requirements

- Python 3.9 or newer
- The `cryptography` library (installed from `requirements.txt`)

## Installation

### 1. Get the code

```bash
git clone https://github.com/Sheeraz-122/keyguard.git
cd keyguard
```

Or just download `keyguard.py` and `requirements.txt` into a folder.

### 2. Create a virtual environment (recommended)

**Linux / macOS**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell)**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

Encrypt a file (creates `secret.pdf.enc`):
```bash
python keyguard.py encrypt secret.pdf
```

Decrypt it (restores `secret.pdf`):
```bash
python keyguard.py decrypt secret.pdf.enc
```

Choose your own output name:
```bash
python keyguard.py encrypt notes.txt -o notes.locked
python keyguard.py decrypt notes.locked -o notes.txt
```

Overwrite an existing output file:
```bash
python keyguard.py decrypt secret.pdf.enc --force
```

### Options

| Option | Description |
|---|---|
| `-o`, `--output` | Output file path |
| `-f`, `--force` | Overwrite the output file if it exists |
| `-h`, `--help` | Show help |

## Important notes

- **Forgotten passwords cannot be recovered.** There is no backdoor.
- The original file is **not** deleted after encryption. Confirm that decryption works, then remove the original yourself.
- The whole file is loaded into memory, so KeyGuard suits documents, images and archives rather than multi-gigabyte files.
- Use a long, unique password (a passphrase of 4+ random words works well).

## How it works

1. A random 16-byte salt is generated.
2. scrypt (N=2^15, r=8, p=1) turns your password and the salt into a 256-bit key.
3. The file is encrypted with AES-256-GCM using a random 12-byte nonce.
4. The output stores a small header (format marker, salt, nonce, scrypt settings) followed by the ciphertext and authentication tag.

## Roadmap

- [ ] Chunked encryption for large files
- [ ] Folder encryption
- [ ] Optional secure deletion of the original
- [ ] Simple GUI

## Author

Sheeraz ([`Sheeraz-122`](https://github.com/Sheeraz-122))

## License

Released under the [MIT License](LICENSE).

## Disclaimer

KeyGuard is a personal project and has not been independently audited. Keep backups of important files.
