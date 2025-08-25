# Shamir Secret Sharing (SSS)

This crate provides a complete **randomized implementation** of the [Shamir Secret Sharing scheme](https://medium.com/data-science/how-to-share-a-secret-shamirs-secret-sharing-9a18a109a860) in cryptography.

## Overview

The scheme allows a secret to be split into multiple shares, such that only a **threshold number** of shares are required to reconstruct the original secret. Fewer than the threshold shares reveal nothing about it.

### Core Features

- Generate shares of a secret securely
- Reconstruct the secret from a threshold of shares
- Supports large prime sizes (256, 512, 1024 bits)
- Polynomial degrees up to 255 (max size of u8) tested
- Option to use fixed primes or generate them dynamically

## Installation

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
secretsharing-shamir = "0.1"
```

## Usage

Import the main types in your code:

```rust
use secretsharing_shamir::{SS, BitSize, Share, Error};
use num_bigint::BigUint;
```

Initialize `SS` with four parameters:

```rust
SS {
    prime_size: BitSize,     // One of 256, 512, 1024
    use_fixed_prime: bool,   // Choose fixed primes or generate new
    threshold: u8,           // Minimum number of shares needed
    secret: &BigUint,        // The secret to be shared
}
```

For a complete working example, see [`examples/usage.rs`](examples/usage.rs).

## Important Notes

- **Note 1:** This implementation has been stress-tested with fixed and generated primes of sizes **256, 512, and 1024 bits**, with polynomials of degree up to **20**.
- **Note 2:** Available prime sizes: **256, 512, 1024 bits** (choose fixed or generated).
- **Note 3:** The reconstruction is tested to work for threshold or more number of parties and fails when threshold is not reached.

## License

**MIT OR Apache-2.0**