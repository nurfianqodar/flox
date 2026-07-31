# flox

![Flox Logo](assets/logo.png)

**Your files should stay yours.**

Whether you're storing documents in the cloud, sharing
backups, or archiving sensitive data, there are times when
you don't want anyone else including the storage
provider to be able to read your files.

**flox** is a fast, secure, password-based file encryption
tool. Protect files with a password you can remember,
then upload or share the encrypted file with confidence.
Without the correct password, the file remains unreadable.

## Features

- 🔒 Secure by default
- 🔑 Password-based encryption
- ✨ Simple and easy to use
- ⚡ Fast, small, and lightweight
- ⚙️ Configurable encryption parameters
- 📦 Supports very large files
- 🌍 Cross-platform
- 📖 Open source

## Installation

### Build from source

1. Clone the repository.

```bash
git clone https://codeberg.org/nurfianqodar/flox.git
cd flox
```

2. Build the project.

```bash
zig build
```

3. Install the executable.

Install to the default prefix:

```bash
zig build install -Doptimize=ReleaseSafe
```

Or install to a custom directory:

```bash
zig build install \
    -Doptimize=ReleaseSafe \
    --prefix-exe-dir "$HOME/.local/bin"
```

## Usage

### Encrypt File

#### Command

```bash
flox e
```

or

```
flox encrypt
```

#### Options

| Flag                  | Type      | Description                                     | Default             |
| --------------------- | --------- | ----------------------------------------------- | ------------------- |
| `--input`, `-i`       | `PATH`    | **Required.** Input file path.                  | —                   |
| `--output`, `-o`      | `PATH`    | Output file path. Required unless `-f` is used. | Input file path     |
| `--password`, `-P`    | `string`  | Encryption password.                            | Prompted if omitted |
| `--chunk-size`, `-c`  | `float32` | Chunk size (MiB).                               | `0.5`               |
| `--memory-cost`, `-m` | `float32` | Argon2 memory cost (MiB).                       | `64.0`              |
| `--time-cost`, `-t`   | `uint32`  | Argon2 time cost.                               | `1`                 |
| `--parallelism`, `-p` | `uint32`  | Argon2 parallelism.                             | `1`                 |
| `--force`, `-f`       | —         | Overwrite the output file if it exists.         | `false`             |

#### Examples

- Encrypt a file (password will be prompted)

  ```bash
  flox encrypt -i document.pdf -o document.pdf.flox
  ```

- Encrypt using the short command

  ```bash
  flox e -i document.pdf -o document.pdf.flox
  ```

- Encrypt with a password from the command line

  ```bash
  flox e -i document.pdf -o document.pdf.flox -P "my-secret-password"
  ```

- Encrypt and overwrite the input file

  ```bash
  flox e -i document.pdf -f
  ```

- Encrypt with a larger chunk size

  ```bash
  flox e -i backup.tar -o backup.tar.flox -c 1024
  ```

- Encrypt using custom Argon2 parameters

  ```bash
  flox e \
    -i backup.tar \
    -o backup.tar.flox \
    -m 128 \
    -t 3 \
    -p 4
  ```

- Encrypt with all options
  ```bash
  flox e \
    -i archive.zip \
    -o archive.zip.flox \
    -P "my-secret-password" \
    -c 1.5 \
    -m 128 \
    -t 2 \
    -p 2
  ```

> [!WARNING]
> Avoid passing passwords via `--password` (`-P`).
> Command-line arguments may be stored in shell history.
> Use the interactive password prompt instead.

### Decrypt File

#### Command

```bash
flox d
```

or

```
flox decrypt
```

#### Options

| Flag               | Type     | Description                                     | Default             |
| ------------------ | -------- | ----------------------------------------------- | ------------------- |
| `--input`, `-i`    | `PATH`   | **Required.** Input file path.                  | —                   |
| `--output`, `-o`   | `PATH`   | Output file path. Required unless `-f` is used. | Input file path     |
| `--password`, `-P` | `string` | Encryption password.                            | Prompted if omitted |
| `--force`, `-f`    | —        | Overwrite the output file if it exists.         | `false`             |

#### Examples

- Decrypt a file

  ```bash
  flox decrypt -i archive.tar.flox -o archive.tar
  ```

- Use the short command

  ```bash
  flox d -i archive.tar.flox -o archive.tar
  ```

- Enter the password interactively

  ```bash
  flox d -i archive.tar.flox -o archive.tar
  ```

  Since `--password` is omitted, `flox` prompts for the password.

- Provide the password from the command line

  ```bash
  flox d -i archive.tar.flox -o archive.tar -P "my-secret-password"
  ```

- Overwrite the output file if it already exists

  ```bash
  flox d -i archive.tar.flox -o archive.tar -f
  ```

- Decrypt in place
  ```bash
  flox d -i archive.tar.flox -f
  ```
  The decrypted file replaces the original encrypted file.

> [!WARNING]
> Avoid passing passwords via `--password` (`-P`).
> Command-line arguments may be stored in shell history.
> Use the interactive password prompt instead.

## Cryptography

**flox** uses modern, secure cryptographic primitives to
ensure your data remains private and tamper-proof:

- **Key Derivation:** Argon2 (Configurable memory, time,
  and parallelism costs to protect against brute-force attacks).
- **Encryption:** AES-256-GCM (Authenticated Encryption with
  Associated Data ensures both privacy and file integrity).
- **Streaming:** Files are processed in chunks, keeping
  memory usage low and constant even when encrypting multi-gigabyte files.

## License

Copyright (c) 2026 Nurfian Qodar

[MIT License](LICENSE)
