# flox: simple, secure, fast, lightweight file encryption tool

![Flox Logo](assets/logo-medium.svg)

**The Problem:**

- Some cloud storage providers use customer data to train
  their AI models.
- You want to encrypt files without installing large, feature-heavy
  encryption tools.
- You want to encrypt highly compressed archives, but archive
  formats often lack built-in encryption.
- Public key encryption requires managing keys and more complex
  commands, while all you want is to protect a file with a memorable
  password.

**The Solution:**

- Encrypt your files before uploading them to cloud storage.
- Use a tool dedicated solely to file encryption.
- Choose an encryption tool that efficiently handles large files.
- Use password-based encryption for a simple and convenient workflow.

**flox** is built to solve exactly these problems. It is a lightweight,
password-based file encryption tool designed to be simple, secure, and
efficient. It focuses on doing one thing well: encrypting and decrypting
files of any size with a memorable password.

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

> [!NOTE]
> Require zig 0.16.0 ([see downloads](https://ziglang.org/download/))

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
| `--password`, `-P`    | `string`  | Encryption password.                            | `FLOX_PASSWORD` env |
| `--interactive`, `-I` | —         | Prompt password interactively                   | `false`             |
| `--chunk-size`, `-c`  | `float32` | Chunk size (MiB).                               | `0.5`               |
| `--memory-cost`, `-m` | `float32` | Argon2 memory cost (MiB).                       | `64.0`              |
| `--time-cost`, `-t`   | `uint32`  | Argon2 time cost.                               | `1`                 |
| `--parallelism`, `-p` | `uint32`  | Argon2 parallelism.                             | `1`                 |
| `--force`, `-f`       | —         | Overwrite the output file if it exists.         | `false`             |

#### Examples

- Encrypt a file with prompted password

  ```bash
  flox encrypt -i document.pdf -o document.pdf.flox -I
  ```

- Encrypt with a password from the command line

  ```bash
  flox e -i document.pdf -o document.pdf.flox -P "my-secret-password"
  ```

- Encrypt with a password from environment variable

  ```bash
  export FLOX_PASSWORD="my-secret-password"
  flox e -i document.pdf -o document.pdf.flox
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

| Flag                  | Type     | Description                                     | Default             |
| --------------------- | -------- | ----------------------------------------------- | ------------------- |
| `--input`, `-i`       | `PATH`   | **Required.** Input file path.                  | —                   |
| `--output`, `-o`      | `PATH`   | Output file path. Required unless `-f` is used. | Input file path     |
| `--password`, `-P`    | `string` | Encryption password.                            | `FLOX_PASSWORD` env |
| `--interactive`, `-I` | —        | Prompt password interactively                   | `false`             |
| `--force`, `-f`       | —        | Overwrite the output file if it exists.         | `false`             |

#### Examples

- Enter the password interactively

  ```bash
  flox d -i archive.tar.flox -o archive.tar -I
  ```

- Provide the password from the command line

  ```bash
  flox d -i archive.tar.flox -o archive.tar -P "my-secret-password"
  ```

- Provide the password from environment variable

  ```bash
  export FLOX_PASSWORD="my-secret-password"
  flox d -i archive.tar.flox -o archive.tar
  ```

### Note

> [!NOTE]
> Password precedence:
>
> 1. `-I` (`--interactive`) and `-P` (`--password`) are mutually exclusive and cannot be used together.
> 2. If `-I` is provided, `flox` reads the password interactively.
> 3. If `-P` is provided, `flox` uses the password supplied on the command line.
> 4. If neither `-I` nor `-P` is provided, `flox` reads the password from the `FLOX_PASSWORD` environment variable.
> 5. If no password is available from any of the above sources, `flox` returns `PasswordNotProvided`.

### Security Note

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
