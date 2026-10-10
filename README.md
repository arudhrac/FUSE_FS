# FUSE_FS — Encrypted Userspace Filesystem

FUSE_FS is a Linux userspace filesystem built using **FUSE (Filesystem in Userspace)** that transparently encrypts and decrypts files using **AES-256-GCM** and OpenSSL. It demonstrates Linux VFS integration, cryptography, and userspace-kernel communication.

## Features

- **AES-256-GCM:** Authenticated encryption with tamper detection.
- **PBKDF2-SHA256:** Password-based key derivation with 200,000 iterations.
- **Random IVs:** Generates a fresh 96-bit IV for each encryption operation.
- **Transparent File Access:** Supports standard operations such as `open`, `read`, `write`, and `readdir`.
- **File Integrity:** Rejects corrupted or tampered ciphertext.
- **Correct Metadata:** Reports plaintext file sizes through `getattr()`.

## Architecture

```text
Application
    |
Linux VFS
    |
FUSE Kernel Module
    |
/dev/fuse
    |
FUSE_FS (Userspace)
    |
AES-256-GCM Encryption
    |
Backing Filesystem
```

## Encrypted File Format

Each encrypted file is stored as:

```text
[ IV: 12 bytes ][ Authentication Tag: 16 bytes ][ Ciphertext ]
```

A fresh random IV is generated for every encryption operation. The authentication tag ensures that modifications to the ciphertext are detected during decryption.

## Prerequisites

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install build-essential libfuse3-dev libssl-dev pkg-config
```

## Build

```bash
git clone https://github.com/<your-username>/FUSE_FS.git
cd FUSE_FS
make
```

## Key Design Decisions

- **AES-256-GCM:** Provides confidentiality and integrity.
- **PBKDF2-SHA256:** Derives a 256-bit key from a password.
- **Whole-file encryption:** Simplifies authenticated writes at arbitrary offsets.
- **FUSE integration:** Enables transparent encryption without modifying applications.

## Skills Demonstrated

C • Linux Systems Programming • FUSE • VFS • OpenSSL • Cryptography • File I/O • Userspace-Kernel Interface

## Future Improvements

- Automated testing and CI integration.
- Atomic writes and crash recovery.
- Improved concurrent access and large-file performance.

**Note:** This project is intended for learning and demonstration. Production use requires additional security hardening.
