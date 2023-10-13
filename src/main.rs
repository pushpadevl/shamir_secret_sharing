use rand::prelude::*;
/*

#[allow(dead_code)]
fn encoding(){
    
}
#[allow(dead_code)]
fn inverse(){

}
 */
fn gen_ran_in_fp(prime:i32)-> i32{
    let mut rng = rand::thread_rng(); //why thread_rng
    let y:i32 = rng.gen();
    (prime+y%prime)%(prime)
}

fn gen_poly(m:i32, prime:i32 , degree:u8) -> Vec<i32>{
    let mut vec:Vec<i32> = Vec::with_capacity((degree+1) as usize);
    vec.push(m);
    for _ in 0..(degree) {
        //let tmp = gen_ran_in_fp(prime);
        vec.push(gen_ran_in_fp(prime));
    } 
    vec
}

#[allow(dead_code)]
fn eval_px_at_xi(prime:i32, pn:&Vec<i32>, x:i32)-> i32{
    let mut y:i32 = (*pn)[0];
    let mut x_pow:i32 = x;

    for i in 1..(*pn).len() {
        let tmp = (x_pow*(*pn)[i])%prime;

        y = (y + tmp)%prime;
        x_pow = (x_pow*x)%prime;
        //println!("{} {}",xi,x_pow);
    }
    y
}   

#[allow(dead_code)]
fn gen_share(prime:i32, pn:&Vec<i32>, no_of_shares:i32) -> (Vec<i32>,Vec<i32>){
    let mut yi:Vec<i32> = Vec::with_capacity(no_of_shares as usize);
    let mut xi:Vec<i32> = Vec::with_capacity(no_of_shares as usize);

    // evaluating at 1,2,3,4 when Field over 5
    for i in 0..(no_of_shares as usize) {
        /* need to check for unique x's
        */
        let mut tmp:i32 = gen_ran_in_fp(prime);
        while tmp == 0 || xi.contains(&tmp) { // linear op on all Fp
            tmp = gen_ran_in_fp(prime);
        } 
        xi.push(tmp);
        yi.push(eval_px_at_xi(prime, &pn, xi[i]));
    }

    (xi,yi)
}

fn gcd(x:i32,y:i32) -> i32{
    if y==0 {
        x
    }else{
        gcd(y,x%y)
    }
}
fn inv_modp(a: i32,prime:i32) -> i32{ //change a to take -ve valeus, else sanitize inputs before
    if gcd(a,prime) != 1 {
        println!("Not coprime. Can't find inverse.");
        0
    }else { //without else it doesn't work
        let a = (prime+a)%prime; //defined antoher a
        let mut r:[i32;3] = [a,prime,0];
        let mut x:[i32;3] = [1,0,0];
        let mut y:[i32;3] = [0,1,0];
        //let mut q:i32=0;
        
        while r[1] != 1i32 {
            r[2] = (r[0] % r[1]) % prime;
            let q = (r[0] / r[1]) % prime;
            x[2] = (x[0] + (prime- q)*x[1]) % prime; // x[0] - q*x[1] in i32
            y[2] = (y[0] + (prime- q)*y[1]) % prime;

            r[0] = r[1]; r[1] = r[2];
            x[0] = x[1]; x[1] = x[2];
            y[0] = y[1]; y[1] = y[2];

        }
        x[1]
    }
}

#[allow(dead_code)]
fn reconstruct(shares:&(Vec<i32>,Vec<i32>),prime:i32) -> i32{
    /* Steps
        1. Lagrange interpolation
        2. Return m, the constant coefficient
     */
    let n = shares.0.len();
    let mut res:i32 = 0;

    for i in 0..n {
        let mut num:i32=1;
        let mut den:i32=1;
        for j in 0..n {
            if i == j {continue;}
            else {
                let tmpj:i32 = prime-shares.0[j];  
                num = (num * (tmpj)) % prime;
                den = (den * ((shares.0[i] + tmpj) % prime)) % prime; 
            }
        }
        res = (res + (shares.1[i] * (num * inv_modp(den, prime))%prime)%prime)%prime;
    }

    res
}

fn main() {
    let prime:i32 = 17; // starting  w prime field, later generalize if possible
    let m:i32 = 6;
    let degree = 7;
    let pn:Vec<i32> = gen_poly(m, prime, degree);
    
    print!("{} ",pn[0]);
    for i in 1..=(degree as usize) { 
        print!("+ {}x^{}",pn[i],i);
    }
    println!("\nxi -> yi");
    
    let no_of_shares:i32=9; // must be >degree, 
    // on trying w <=degree shares, v get random outputs
    // w > degree, we get m everytime
    let shares:(Vec<i32>, Vec<i32>) = gen_share(prime, &pn, no_of_shares);
    for i in 0..no_of_shares {
        println!("{} -> {}",shares.0[i as usize],shares.1[i as usize])
    }
    /*
     */
    //println!("{} ",inv_modp(4, 11));
    let mdash = reconstruct(&shares, prime);
    println!("{}",mdash);
    
    
}
