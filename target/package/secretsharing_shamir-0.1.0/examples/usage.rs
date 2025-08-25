//! Example showing how to use `secretsharing-shamir`
use num_bigint::BigUint;
use secretsharing_shamir::{BitSize, SS};

fn main() {
    /*SHARE GENERATION */

    // Init a bitsize from Bit256, Bit512, Bit1024 bits, for prime generation as well as random polynomial coefficients
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
    /* Method 1: Using  match,
    let instance_result = SS::new(bitsize,false, threshol, &secret);
    let mut sss = if let Ok(ins) = instance_result {
        println!("Created SS.");
        ins
        } else if let Err(e) = instance_result{
            eprintln!("Error creating SS. Reason: {:?}",e);
            return; // or handle the error
        } else {
            eprintln!("Some other error.");
            return;
        };
    */
    // Method 2: use unwrap()
    // SS takes 4 parameters {prime_size:BitSize, use_fixed_prime:bool, threshold:u8, secret:&BigUint}
    // also, note that it uses new generated prime; To use pre-fixed primes, set second argument as true
    let mut sss = SS::new(bitsize, false, threshol, &secret).unwrap();

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
