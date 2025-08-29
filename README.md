# Shamir Secret Sharing

This crate provides a complete **randomized implementation** of the [Shamir Secret Sharing scheme](https://medium.com/data-science/how-to-share-a-secret-shamirs-secret-sharing-9a18a109a860) in cryptography.

## Overview

The scheme allows a secret to be split into multiple shares, such that only a **threshold number** of shares are required to reconstruct the original secret. Fewer than the threshold shares reveal nothing about it.

## New features

- Added support for circom prime BN254, for upcoming shares verification feature.

### Core Features

- Generate shares of a secret securely
- Reconstruct the secret from a threshold of shares
- Supports large prime sizes (BN254, 256, 512, 1024 bits)
- Polynomial degrees up to 255 (max size of u8) tested
- Option to use fixed primes or generate them dynamically

## Installation

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
secretsharing-shamir = "0.1"
```

## Usage

```rust
SS {
    prime_size: BitSize,     // One of BN254, Bit256, Bit512, Bit1024
    use_fixed_prime: bool,   // Choose fixed primes or generate new
    threshold: u8,           // Minimum number of shares needed
    secret: &BigUint,        // The secret to be shared
}
```

:
### Example showing how to use `secretsharing-shamir` with fixed 256 primes 

```rust
use num_bigint::BigUint;
use secretsharing_shamir::{BitSize, SS};

fn main() {
    /*SHARE GENERATION */

    // Init a bitsize from BN254, Bit256, Bit512, Bit1024 bits, for prime generation as well as random polynomial coefficients
    // Needed for fixed Primes, Not needed if primes are generated, (in SS init, set use_fixed_prime argument as false)
    let bitsize = BitSize::Bit256;
    // Secret to be shared

    let secret = BigUint::from(25u32);
    // Threshold no of parties for share reconstruction
    let threshol: u8 = 3;

    // points on which shares will be generated
    let points = vec![
        BigUint::from(4u16),
        BigUint::from(16u16),
        BigUint::from(13u16),
        BigUint::from(1u16),
        BigUint::from(12u16),
        BigUint::from(7u16),
    ];
    /*  Initializing SS, also ensure
         1. threshold >1,
         2. make instance mutable, because shares have to be generated
    */
    // Method 2: use unwrap()
    // SS takes 4 parameters {prime_size:BitSize, use_fixed_prime:bool, threshold:u8, secret:&BigUint}
    // also, note that it uses new generated prime; To use pre-fixed primes, set second argument as true
    let mut sss = SS::new(bitsize, true, threshol, &secret).unwrap();

    println!("{}", sss);
    // Generating shares on points
    let shares = sss.gen_shares(&points); // this is mut is required
    for i in 0..points.len() {
        println!("{}", shares[i as usize]);
    }

    /* RECONSTRUCTION */
    // retrieving prime in case of new_prime usage
    let prime = sss.get_prime();

    // randomly chosen shares for regen, if we use <=threshold no of shares, the secret is not reconstructed properly.
    let rshares = vec![
        shares[5].clone(),
        shares[0].clone(),
        shares[4].clone(),
        shares[1].clone(),
    ];
    // static regeneration method, with prime and chosen shares.
    let regen_secret = SS::reconstruct_secret(prime, &rshares);
    println!("{}", regen_secret);
}

```

Initialize `SS` with four parameters:

For more working examples, see [`docs.rs`](https://docs.rs/crate/secretsharing_shamir/latest/source/examples/).

## Important Notes

- The number of points you choose to generate shares is the total no. of parties and the threshold is the minimum no. of parties required to rebuild the secret.
- Ensure that **#points >= threshold** for correctness.  
- This implementation has been stress-tested with fixed and generated primes of sizes **BN254, 256, 512, and 1024 bits**, with polynomials of degree up to **254**.
- Available prime sizes: **256, 512, 1024 bits** (fixed or generated), along with BN254 prime.
- The reconstruction is tested to work for threhold or more no of parties and fails when threshold is not reached.

## Change Log

- 2025_08_29: Complete documentation and exmaple coverage
- 2025_08_29: Added support for BN254 curve scalar prime (base prime and scalar prime for BN254 are same) for upcoming shares verification feature. BN254 curve is used for circom proof generation and ethereum as well.

## License

**MIT OR Apache-2.0**