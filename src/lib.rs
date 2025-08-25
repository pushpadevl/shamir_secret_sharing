//! # Shamir Secret Sharing (SSS)
//!
//! This crate provides a complete **randomized implementation** of the
//! [Shamir Secret Sharing scheme](https://medium.com/data-science/how-to-share-a-secret-shamirs-secret-sharing-9a18a109a860)
//! in cryptography.
//!
//! ## Overview
//! The scheme allows a secret to be split into multiple shares, such that
//! only a **threshold number** of shares are required to reconstruct
//! the original secret. Fewer than the threshold shares reveal nothing about it.
//!
//! ### Core Features
//! - Generate shares of a secret securely
//! - Reconstruct the secret from a threshold of shares
//! - Supports large prime sizes (256, 512, 1024 bits)
//! - Polynomial degrees up to 255 (max size of u8) tested
//! - Option to use fixed primes or generate them dynamically
//!
//! ## Usage
//!
//! Add this crate to your `Cargo.toml`:
//!
//! ```toml
//! secretsharing-shamir = "0.1"
//! ```
//!
//! Import the main types in your code:
//!
//! ```rust
//! use secretsharing_shamir::{SS, BitSize, Share, Error};
//! use num_bigint::{BigUint};
//! ```
//!
//! Initialize `SS` with four parameters:
//!
//! ```ignore
//! SS {
//!     prime_size: BitSize,        // One of 256, 512, 1024
//!     use_fixed_prime: bool,      // Choose fixed primes or generate new
//!     threshold: u8,              // Minimum number of shares needed
//!     secret: &BigUint,           // The secret to be shared
//! }
//! ```
//!
//! For a complete working example, see [`examples/usage.rs`](examples/usage.rs).
//!
//! ## Notes
//! - **Note 1:** This implementation has been stress-tested with fixed and generated primes  
//!   of sizes **256, 512, and 1024 bits**, with polynomials of degree up to **20**.
//! - **Note 2:** Available prime sizes: **256, 512, 1024 bits** (choose fixed or generated).
//! - **Note 3:** The reconstruction is tested to work for threhold or more no of parties and fails when threshold is not reached.
//!
//! ---

use num_bigint::{BigUint ,RandBigInt};
use num_traits::{Zero,One,Num};
use rand::rngs::OsRng; // cryptographically secure RNG
use std::fmt;
use num_primes::Generator;


/// Enum for error handling
#[derive(Debug, PartialEq)]
pub enum Error{
    ThresholdTooSmall,
    ZeroInputGCD,
    NotCoprimes
}

/// BitSize enum for choosing bit sizes
#[derive(Clone, Copy, Debug)]
pub enum BitSize {
    Bit256,
    Bit512,
    Bit1024
}


impl BitSize {
    /// For fixed primes
    pub fn fixed_prime(&self) -> BigUint {
        match self {
            BitSize::Bit256 => BigUint::from_str_radix("D7F71B07B75BC19077A53B9B1BAEA33249C8CD5C132C7FA3E20E18AAF17F5A9B", 16).unwrap(),
            BitSize::Bit512 => BigUint::from_str_radix("EB3CFFA5DBAB1325022CE08399445F0E4B9B146B0BA3D17967D70616B2E33B62FCE08149C3D76FA8EAC2769B4DB5232DFF3416848ED598BA2470CEC3CB5DCD6B",16).unwrap(),
            BitSize::Bit1024 => BigUint::from_str_radix("DE97F71CFA25F986F6D07618C9EDB1378517A16101CEF67262AFBD3D703E94134F91757A03262A988C1A8DE361AAE62F96D7E2C70C10AFD647F718A628651C234225FE75F25FB1D6FB28596BEA5E2802B5B4E4BE3CE573192CC1E1F1DEB8CACAC9BC55AA8CB213945388C78271D5E500D34469A4108680E1AF56FA7C05D321DF",16).unwrap()
        }
    }
    /// For generating new primes
    pub fn new_prime(&self) -> BigUint {
        let prime = match self {
            BitSize::Bit256 => Generator::safe_prime(256),
            BitSize::Bit512 => Generator::safe_prime(512),
            BitSize::Bit1024 => Generator::safe_prime(1024)
        };
    // Note: Below conversion required becoz BigUint is part of two different crates, num-bigint and num-primes, 

        BigUint::from_bytes_be(&prime.to_bytes_be())
    }

    /// For generating random BigUint numbers based on the bit size chosen during intialization of SS
    pub fn n_bit_random(&self) -> BigUint {
        let mut rng = OsRng; // secure RNG
        let value: BigUint = match self{
            BitSize::Bit256 => rng.gen_biguint(256),
            BitSize::Bit512 => rng.gen_biguint(512),
            BitSize::Bit1024 => rng.gen_biguint(1024)
            
        };
        value
    }
}


/// Share struct for storing (x,y) pairs where y = polynomial(x) mod prime
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Share {
    X:BigUint,
    Y:BigUint
}
impl Share {
    // Share constructor
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self { X: x, Y: y }
    }
}
impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Share: (x = {}, y = {})", self.X, self.Y)
    }
}

/// SS struct for storing prime modulus(BigUint) and the polynomial()
#[derive(Clone, Debug)]
pub struct SS {
    prime: BigUint,
    polynomial: Vec<BigUint>
}
impl fmt::Display for SS {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Shamir Secret Sharing Instance:")?;
        writeln!(f, "  Prime: {}", self.prime)?;
        writeln!(f, "  Polynomial Coefficients:")?;
        for (i, coeff) in self.polynomial.iter().enumerate() {
            writeln!(f, "    a{} = {}", i, coeff)?;
        }
        Ok(())
    }
}
impl SS {
    /// SS constructor
    pub fn new( prime_size: BitSize, use_fixed_prime:bool,threshold: u8, secret: &BigUint) -> Result<Self, Error> {
        if threshold <= 1 {
            return Err(Error::ThresholdTooSmall);
        }
            let prim = if use_fixed_prime {
                                    prime_size.fixed_prime()
                                } else { 
                                    prime_size.new_prime()
                                };
            
            let mut instance = SS {
                prime: prim,
                polynomial:Vec::new(),
            };
            
            let secret_mod = secret % &instance.prime;
            instance.gen_polynomial(secret_mod,threshold-1, prime_size);
            
            Ok(instance)
    }
    
    /// Retrieves prime used in SS; Useful if prime is generated instead of usage of fixed prime
    pub fn get_prime(&self) -> &BigUint{ 
        &self.prime
    }

    /// Generates shares with given points and returns Vector of Shares
    pub fn gen_shares(&mut self, points:&Vec<BigUint>) -> Vec<Share> {
        let n:usize = points.len();
        let mut shares:Vec<Share> = Vec::with_capacity(n);

        for i in 0..(n) {
            shares.push(
                Share{
                    X:points[i].clone(),
                    Y:self.eval_px_at_xi(&points[i])
                }
            );
        }
        shares
    }

    fn eval_px_at_xi(&self, x:&BigUint)-> BigUint{ 
        let mut y:BigUint = (self.polynomial)[0].clone(); //init 
        let mut x_pow:BigUint = x.clone(); 
        for i in 1..(self.polynomial).len() {
            let tmp = (&x_pow * (self.polynomial)[i].clone() ) % &self.prime;
            y = (&y + &tmp) % &self.prime; 
            x_pow = ( &x_pow * x) % &self.prime; 
        } 
        y 
    }

    /// Builds polynomial using secret and pseudorandomly generated coefficients in modulo prime of degree = threshold -1 
    pub fn gen_polynomial(&mut self,secret:BigUint, degree:u8, prime_size: BitSize){

        let p = &self.prime;
        self.polynomial.push(secret % &self.prime); // secret consumed here

        for _ in 0..(degree -1) {
            let coeff:BigUint = prime_size.n_bit_random() % p; 
            self.polynomial.push(coeff);
        } 
        
        let mut leading_coeff;
        loop {
            leading_coeff = prime_size.n_bit_random() % p;
            if !leading_coeff.is_zero() {
                break;
            } 
        }
        self.polynomial.push(leading_coeff);
    }

    fn gcd(x:&BigUint,y:&BigUint) -> Result<BigUint,Error>{
         if x.is_zero() || y.is_zero() {
        return Err(Error::ZeroInputGCD);
        }

        let mut a = x.clone();
        let mut b = y.clone();

        while !b.is_zero() {
            let tmp = b.clone();
            b = a % &b;
            a = tmp;
        }

        Ok(a)
    }

    fn inv_modp(prime:&BigUint,a: &BigUint) -> Result<BigUint,Error>{ 
        let aa = (prime + a) % prime;
        if !SS::gcd(&aa,prime).unwrap().is_one() {
            return Err(Error::NotCoprimes);
        }   
        match aa.modinv(prime) {
            Some(inv) => Ok(inv),
            None => Err(Error::NotCoprimes)
        }
        // Suggestion 9: could use fermat's little theorem 
        // a.modpow(&(prime-2u32)).unwrap();
    }

    /// Reconstructs secret using given shares and returns secret (BigUint)
    pub fn reconstruct_secret(prime:&BigUint, shares:&Vec<Share>) -> BigUint{ 
        /* Comment: Does not have self,user should be able to try arbitrary share values to check if it matches.
           2. Also, it should work without an instance of SS, as that is majorly used for generating_shares.
        */ 
        let n = shares.len();
        let mut res:BigUint = BigUint::zero();
 
        for i in 0..n {
            let xi = &shares[i].X;
            let yi = &shares[i].Y;

            let mut num=BigUint::one();
            let mut den=BigUint::one();
            
            for j in 0..n {
                if i == j { continue; }
                let xj = &shares[j].X;

                // numerator term: (0 - xj) mod p == (p - xj) mod p
                let term_num = (prime - xj) % prime;
                num = (num * term_num) % prime;

                // denominator term: (xi - xj) mod p == (xi + (p - xj)) mod p
                let term_den = (xi + ((prime - xj) % prime)) % prime;
                // x's should not be equal, other inverse operation would panic
                den = (den * term_den) % prime;
            }

            // inv_modp should return the modular inverse of `den` modulo `p`
            let den_inv = SS::inv_modp(prime, &den).unwrap();
            let li0 = (num * den_inv) % prime; // lagrange interpolation

            // accumulate: y_i * lambda_i(0)
            res = (res + (yi * &li0) % prime) % prime;
        }
        
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prelude::*};
    #[test]
    fn test_inverse_exists() {
        let prime = BigUint::from(7_u32);
        let a = BigUint::from(3_u32);
        // 3 * 5 = 15 ≡ 1 (mod 7)
        let inv = SS::inv_modp(&prime, &a).unwrap();
        assert_eq!(inv, BigUint::from(5_u32));
    }
    #[test]
    fn test_inverse_is_correct_modular_identity() {
        let prime = BigUint::from(11_u32);
        let a = BigUint::from(7_u32);
        let inv = SS::inv_modp(&prime, &a).unwrap();
        // Check a * inv ≡ 1 (mod prime)
        assert_eq!((&a * &inv) % &prime, BigUint::one());
    }
    #[test]
    fn test_no_inverse_when_not_coprime() {
        let prime = BigUint::from(10_u32);
        let a = BigUint::from(4_u32);
        let result = SS::inv_modp(&prime, &a);
        assert_eq!(result, Err(Error::NotCoprimes));
    }
    
    proptest!{
        #![proptest_config(ProptestConfig {
        cases: 100, // run 100 random test cases
        .. ProptestConfig::default()
        })]
        #[test]
        fn test_modular_inverse_property(bits in 8u64..309u64) {
            use rand::thread_rng;
            let mut rng = thread_rng();
            let p = rng.gen_biguint(bits) | BigUint::one() | BigUint::from(3u32); 
            // (ORing with odd ensures it's not trivially even)
            // Generate random a
            let mut a = rng.gen_biguint(bits) % &p;
            if a.is_zero() {
                a = BigUint::one();
            }
            if SS::gcd(&a,&p).unwrap() == BigUint::one() {
                let inv = SS::inv_modp(&p, &a).unwrap();
                prop_assert_eq!((&a * &inv) % &p, BigUint::one());
            } else {
                // Should return error if not coprime
                let res = SS::inv_modp(&p, &a);
                    prop_assert!(res.is_err());
            }
            
        }
        
    }
}



    // Suggestion 7: Should we move secret to gen_share, so that one can gen_shares over any new secret with the same instance of SS? Not needed I guess.
    // Suggestion 6: could use FFT, should I just user the choce
    // Suggestion 8: Ger roots of unity for a generated prime
    