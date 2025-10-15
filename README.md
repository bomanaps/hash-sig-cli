# Hash-Sig CLI

A command-line interface for the [hash-sig](https://github.com/b-wagn/hash-sig) library - a prototype implementation of hash-based signatures for post-quantum cryptography.

## Overview

This CLI tool provides a user-friendly interface to work with hash-based signatures, keeping the main `hash-sig` repository focused on cryptography while providing practical tooling in a separate codebase.

## Prerequisites

- Rust >= 1.87
- Internet connection (to fetch the `hash-sig` dependency from GitHub)

## Installation

```bash
cargo build --release
```

## Usage

Generate cryptographic key pairs for hash-based signatures:

```bash
cargo run --release --bin hashsig -- --num-keys 5 --log-num-active-epochs 18 --output-dir ./generated_keys
```

**Parameters:**
- `--num-keys`: Number of key pairs to generate
- `--log-num-active-epochs`: Log2 of the number of active epochs (e.g., 18 for 2^18 = 262,144 active epochs)
- `--output-dir`: Directory where keys will be saved

**Output:**
The tool creates a directory with key pairs in JSON format:
```
generated_keys/
├── key_0_pk.json    # Public key
├── key_0_sk.json    # Secret key
├── key_1_pk.json
├── key_1_sk.json
└── ...
```

## Current Implementation

Currently uses the `SIGTopLevelTargetSumLifetime32Dim64Base8` scheme:
- **Hash Function**: Poseidon2 (ZK-friendly)
- **Encoding**: Target Sum 
- **Lifetime**: 2^32 epochs (4,294,967,296)


## References

- [Hash-Sig Repository](https://github.com/b-wagn/hash-sig)
- [Research Paper](https://eprint.iacr.org/2025/055.pdf)

## License

Apache Version 2.0 (same as hash-sig)

## Contributing

This is a separate codebase from the main `hash-sig` library to keep the cryptography-focused repository minimal and focused. Feel free to contribute CLI enhancements here.
