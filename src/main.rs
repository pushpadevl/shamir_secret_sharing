use secretsharing_shamir::{SS, BitSize };
use num_bigint::{BigUint};

fn main() {

    let bitsize = BitSize::Bit256;
    let secret:BigUint = BigUint::from(25u32);
    let threshol:u8 = 3;
    let points = vec![
        BigUint::from(4u16),
        BigUint::from(16u16),
        BigUint::from(13u16),
        BigUint::from(1u16),
        BigUint::from(12u16),
        BigUint::from(7u16)
        
        ];
        
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
    println!("{}",sss);
    
    let shares = sss.gen_shares(&points);
    for i in 0..points.len() {
        println!("{}",shares[i as usize]);
    } 
    let prime = sss.get_prime();
    let rshares = vec![shares[5].clone(), shares[0].clone(),shares[4].clone(),shares[1].clone()];
    
    let regen_secret = SS::reconstruct_secret(prime, &rshares);
    
    println!("{}",regen_secret);        
}

/* Example
  Prime: 105498447723574310168840203190333909102399981967910450718234073082555233249659
  Polynomial Coefficients:
    a0 = 12
    a1 = 73303190452245364377428588047816294810301457963035022897471903209948073790330
    a2 = 7510559186254739157107428912891612995364271437568929929602565713613562846765
    a3 = 12003836704041796216752897477066419453873817888187891123759984457314006170134

(x = 4, y = 21144332888414830038376418236108832088558718050253044483592865617598129851899)
(x = 16, y = 41537715503052824502326697314082721157243811328135365732837435337570083704791)
(x = 13, y = 4575884047428886908147823434728602160863613513669110029220394676420425504396)
(x = 1, y = 92817586342541899751288914437774327259539547288791843950834453380875642807241)
(x = 12, y = 21622372263373987400975974479170168334033770254275142069359730768957448732999)
(x = 7, y = 40028679770543293751018417754491245310879889338778198525502276415309249645796)

  Prime: 23
  Polynomial Coefficients:
    a0 = 12
    a1 = 12
    a2 = 20
    a3 = 14

(x = 4, y = 11)
(x = 16, y = 16)
(x = 13, y = 13)
(x = 1, y = 12)
(x = 12, y = 19)
(x = 7, y = 13)



  Polynomial Coefficients:
    a0 = 12
    a1 = 4
    a2 = 9
    a3 = 2

(x = 4, y = 11)
(x = 16, y = 15)
(x = 13, y = 12)
(x = 1, y = 10)
(x = 12, y = 1)
(x = 7, y = 11)

  Prime: 17
  Threshold: 3
  Polynomial Coefficients:
    a0 = 12
    a1 = 13
    a2 = 8
    a3 = 9
  Shares:
    Share 1 -> (x = 4, y = 3)
    Share 2 -> (x = 16, y = 15)
    Share 3 -> (x = 13, y = 5)
    Share 4 -> (x = 1, y = 8)
*/

/* Lesson 1:
Tuples and arrays implement Copy if all their elements do, but Vec doesn't
let t = (1, true); // (i32, bool) -> both Copy
let arr = [1, 2, 3]; // all i32 -> Copy

Vec<i32> is not Copy, even though i32 is Copy.

Why? Because Vec manages heap-allocated memory under the hood. Copying the struct blindly would duplicate only the pointer, not the heap data → leading to double frees.

Rust prevents this by not implementing Copy for heap-owning types like Vec, String, Box, etc.
*/
  
/* Lesson 2:
which is better, a tuple of 2 vectors or a vector of a tuple with two elements? "" shares:(Vec<BigUint>, Vec<BigUint>)  "" or  "" shares: Vec<(BigUint, BigUint)> ""?
When to choose which

Choose (Vec<T>, Vec<U>) (two vectors) if:

You almost always work on one component independently of the other.

You want batch operations on just one side (like summing all first components).

Example: working with x- and y-coordinates separately in geometry.

Choose Vec<(T, U)> (vector of tuples) if:

Each pair is conceptually one inseparable unit.

You usually work with both elements together (e.g., (x, y) points, (numerator, denominator), (share, modulus)).

You want safety: can’t forget to add/remove from both.
*/

/* Lesson 3:

Inside a struct "" pub struct SS { prime: BigUint, polynomial: Vec<BigUint>, threshold: u8, // the degree of the polynomial shares: Vec<(BigUint, BigUint)>, // (x,y) pairs }"", I know u8 implements copy trait, so while passing it as an argument, is the trait still applicable or because struct SS does not implement Copy trait, I should use &?
The fact that SS itself is not Copy does not affect the Copy behavior of its fields.
s.threshold (a u8) is still Copy, so you can pass it by value freely.
Use & only if you want a reference, not because you’re forced to.
 */

/* Lesson 4:

 For the constructor, I am using &mut self, is it fine?

 Ah, good catch 🚦 —
for a constructor (new function), you should not use &mut self.

Here’s why:

A constructor’s job is to create a new instance of your struct.

At that point, you don’t even have a self yet! (so you can’t have &mut self).

Instead, you make it an associated function (no self at all).

So the idiomatic way is:

impl SS {
    pub fn new(prime: BigUint, threshold: u8) -> Self {
        SS {
            prime,
            threshold,
            polynomial: Vec::new(),
            shares: Vec::new(),
        }
    }
}

  */

/* Lesson 5:
    1007  openssl prime --generate -safe -bits 512 -hex
 1008  openssl prime --generate -safe -bits 256 -hex

 */