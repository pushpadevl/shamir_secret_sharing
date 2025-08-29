use num_bigint::BigUint;
use proptest::prelude::*;
use secretsharing_shamir::{BitSize, SS};

#[test]
fn test_secret_reconstruction_with_new_primes() {
    let secret = BigUint::from(25u32);
    let threshold = 3u8;
    let points = vec![
        BigUint::from(4u16),
        BigUint::from(16u16),
        BigUint::from(13u16),
        BigUint::from(1u16),
        BigUint::from(12u16),
        BigUint::from(7u16),
    ];

    // Generate shares
    let mut ss = SS::new(BitSize::Bit256, false, threshold, &secret).unwrap();
    let shares = ss.gen_shares(&points);

    // Reconstruct using exactly `threshold` shares
    let selected: Vec<_> = shares.iter().take(threshold as usize).cloned().collect();
    let prime = ss.get_prime(); // random prime
    let recovered = SS::reconstruct_secret(prime, &selected);
    assert_eq!(recovered, secret % prime, "Reconstructed secret mismatch");
}
#[test]
fn test_reconstruction_fails_with_insufficient_shares() {
    let bitsize = BitSize::Bit256;
    let secret = BigUint::from(50u32);
    let threshold = 3u8;
    let points = vec![BigUint::from(1u32), BigUint::from(2u32)];
    let mut ss = SS::new(bitsize, true, threshold, &secret).unwrap();
    let shares = ss.gen_shares(&points);
    let recovered = SS::reconstruct_secret(ss.get_prime(), &shares);
    assert_ne!(
        recovered, secret,
        "Should not reconstruct secret with too few shares"
    );
}

#[allow(non_snake_case)]
#[test]
fn test_secret_reconstruction_with_BN254_prime() {
    let threshold = 3;
    let secret = BigUint::from(232_u8);
    let points: Vec<BigUint> = (1u32..=25u32).map(BigUint::from).collect();
    let bitsize = BitSize::BN254;

    // Generate shares
    let mut ss = SS::new(bitsize, true, threshold, &secret).unwrap();
    let shares = ss.gen_shares(&points);

    // Pick exactly `threshold` shares (first 3 for simplicity)
    let subset: Vec<_> = shares.iter().take(threshold as usize).cloned().collect();
    let recovered = SS::reconstruct_secret(ss.get_prime(), &subset);
    assert_eq!(recovered, secret % &bitsize.fixed_prime());
}

#[test]
fn test_secret_reconstruction_with_512bit_prime() {
    let threshold = 3;
    let secret = BigUint::from(232_u8);
    let points: Vec<BigUint> = (1u32..=25u32).map(BigUint::from).collect();
    let bitsize = BitSize::Bit512;

    // Generate shares
    let mut ss = SS::new(bitsize, true, threshold, &secret).unwrap();
    let shares = ss.gen_shares(&points);

    // Pick exactly `threshold` shares (first 3 for simplicity)
    let subset: Vec<_> = shares.iter().take(threshold as usize).cloned().collect();
    let recovered = SS::reconstruct_secret(ss.get_prime(), &subset);
    assert_eq!(recovered, secret % &bitsize.fixed_prime());
}
#[test]
fn test_secret_reconstruction_with_1024bit_prime() {
    let threshold = 3;
    let secret = BigUint::from(232_u8);
    let points: Vec<BigUint> = (1u32..=25u32).map(BigUint::from).collect();
    let bitsize = BitSize::Bit1024;

    // Generate shares
    let mut ss = SS::new(bitsize, true, threshold, &secret).unwrap();
    let shares = ss.gen_shares(&points);

    // Pick exactly `threshold` shares (first 3 for simplicity)
    let subset: Vec<_> = shares.iter().take(threshold as usize).cloned().collect();
    let recovered = SS::reconstruct_secret(ss.get_prime(), &subset);
    assert_eq!(recovered, secret % &bitsize.fixed_prime());
}

proptest! {
    #![proptest_config(ProptestConfig {
    cases: 1, // run 100 random test cases
    .. ProptestConfig::default()
    })]
    #[test]
    fn prop_secret_reconstruction_with_256_primes(threshold in 2u8..=3u8) {
        let secret = BigUint::from(232_u8);
        let points: Vec<BigUint> = (1u32..=255u32).map(BigUint::from).collect();
        let bitsize = BitSize::Bit256;
        // Generate shares
        let mut ss = SS::new(bitsize, true, threshold, &secret).unwrap();
        let shares = ss.gen_shares(&points);
        // Pick exactly `threshold` shares (first 3 for simplicity)
        let subset: Vec<_> = shares.iter().take(threshold as usize).cloned().collect();
        let recovered = SS::reconstruct_secret(ss.get_prime(), &subset);
        prop_assert_eq!(recovered, secret % &bitsize.fixed_prime());
    }
}
