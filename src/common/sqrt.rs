use rand_core::RngCore;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use num_integer::Integer;

/// Find principal square root in a Blum modulus quotient ring.
///
/// Pre-requisites:
/// - x is a quadratic residue in Zn
/// - `n = pq`, p and q are Blum primes
///
/// If these don't hold, the result is a bogus number in Zn
pub fn blum_sqrt(x: &BigInt, p: &BigInt, q: &BigInt, n: &BigInt) -> BigInt {
    // Exponent in pq Blum modulus to obtain the principal square root.
    // Described in [Handbook of Applied cryptography, p. 75, Fact
    // 2.160](https://cacr.uwaterloo.ca/hac/about/chap2.pdf)
    let e = ((p - 1u8) * (q - 1u8) + 4) / 8;

    // e guaranteed to be non-negative by the prerequisite that p and q are blum primes
    #[allow(clippy::expect_used)]
    x.modpow(&e, n)
}

/// Find `(y' = (-1)^a w^b y, a, b)` such that y' is a quadratic residue in Zn.
///
/// a and b are treated as false = 0, true = 1
///
/// Pre-requisites:
/// - `n = pq`, p and q are Blum primes
/// - `jacobi(w, n) = -1`, that is w is quadratic non-residue in Zn with jacobi
///   symbol of -1
///
/// If these don't hold, the y' might not exist. In this case, returns `None`
pub fn find_residue(
    y: &BigInt,
    w: &BigInt,
    p: &BigInt,
    q: &BigInt,
    n: &BigInt,
) -> Option<(bool, bool, BigInt)> {
    let jp = y % p;
    let jq = y % q;
    let one = BigInt::from(1);
    let neg_one = BigInt::from(-1);
    
    match (jp, jq) {
        (ref jp, ref jq) if *jp == one && *jq == one => return Some((false, false, y.clone())),
        (ref jp, ref jq) if *jp == neg_one && *jq == neg_one => return Some((true, false, (n - y).clone())),
        _ => (),
    }

    let y_times_w = (y * w) % n;
    let jp = &y_times_w % p;
    let jq = &y_times_w % q;
    match (jp, jq) {
        (ref jp, ref jq) if *jp == one && *jq == one => Some((false, true, y_times_w)),
        (ref jp, ref jq) if *jp == neg_one && *jq == neg_one => Some((true, true, n - &y_times_w)),
        _ => None,
    }
}

/// Finds a element in Zn that has jacobi symbol of -1
pub fn sample_neg_jacobi<R: RngCore>(n: &BigInt, rng: &mut R) -> BigInt {
    loop {
        // Generate a random number below n
        let mut bytes = vec![0u8; (n.bits() as usize + 7) / 8];
        rng.fill_bytes(&mut bytes);
        let w = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes) % n;
        
        // Calculate Jacobi symbol
        if w.jacobi(n) == -1 {
            break w;
        }
    }
}

/// Calculate the Jacobi symbol (a/n)
/// 
/// This is an implementation of the Jacobi symbol for BigInt
/// since it's not provided in num-bigint
pub fn jacobi(a: &BigInt, n: &BigInt) -> i8 {
    if a.is_zero() {
        return 0;
    }

    if a == &BigInt::from(1) {
        return 1;
    }

    if a.is_even() {
        let result = jacobi(&(a >> 1), n);
        let n_mod_8 = n % 8;
        if n_mod_8 == BigInt::from(3) || n_mod_8 == BigInt::from(5) {
            return -result;
        } else {
            return result;
        }
    }

    if a < &BigInt::from(0) {
        let result = jacobi(&-a, n);
        let n_mod_4 = n % 4;
        if n_mod_4 == BigInt::from(3) {
            return -result;
        } else {
            return result;
        }
    }

    // Law of quadratic reciprocity
    // (a/n) = (n/a) * (-1)^((a-1)/2 * (n-1)/2) for a,n odd and a,n > 0
    let result = jacobi(&(n % a), a);
    
    let a_mod_4 = a % 4;
    let n_mod_4 = n % 4;
    
    if a_mod_4 == BigInt::from(3) && n_mod_4 == BigInt::from(3) {
        -result
    } else {
        result
    }
}

// Add jacobi method to BigInt through extension trait
pub trait BigIntJacobi {
    fn jacobi(&self, n: &BigInt) -> i8;
}

impl BigIntJacobi for BigInt {
    fn jacobi(&self, n: &BigInt) -> i8 {
        jacobi(self, n)
    }
}
