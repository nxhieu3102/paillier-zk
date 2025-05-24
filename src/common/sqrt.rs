use num_bigint::BigInt;
use num_bigint::RandBigInt;
use num_integer::Integer;
use num_traits::Zero;
use rand_core::RngCore;

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
    let jp = (y % p).jacobi(p);
    let jq = (y % q).jacobi(q);

    match (jp, jq) {
        (1, 1) => return Some((false, false, y.clone())),
        (-1, -1) => return Some((true, false, (n - y).clone())),
        _ => (),
    }

    let y_times_w = (y * w) % n;
    let jp = (&y_times_w % p).jacobi(p);
    let jq = (&y_times_w % q).jacobi(q);
    match (jp, jq) {
        (1, 1) => Some((false, true, y_times_w)),
        (-1, -1) => Some((true, true, n - &y_times_w)),
        _ => None,
    }
}

/// Finds a element in Zn that has jacobi symbol of -1
pub fn sample_neg_jacobi<R: RngCore>(n: &BigInt, rng: &mut R) -> BigInt {
    loop {
        // Generate a random number below n
        let w = rng.gen_bigint_range(&BigInt::zero(), n);

        // Calculate Jacobi symbol
        if w.jacobi(n) == -1 {
            break w;
        }
    }
}

use num_traits::{One, Signed};

/// Compute the Jacobi symbol (a/n)
pub fn jacobi(a: &BigInt, n: &BigInt) -> i8 {
    if n.is_zero() || n.is_even() || n.is_negative() {
        panic!("Jacobi symbol is undefined for non-positive or even denominator n");
    }

    let mut a = a.mod_floor(n); // a mod n
    let mut n = n.clone();
    let mut result = 1;

    while !a.is_zero() {
        // Remove factors of 2
        while a.is_even() {
            a >>= 1;
            let r = &n % 8;
            if r == 3.into() || r == 5.into() {
                result = -result;
            }
        }

        // Apply reciprocity
        std::mem::swap(&mut a, &mut n);
        if &a % 4 == 3.into() && &n % 4 == 3.into() {
            result = -result;
        }

        a = a.mod_floor(&n);
    }

    if n == One::one() {
        result
    } else {
        0
    }
}

// Add trait extension
pub trait BigIntJacobi {
    fn jacobi(&self, n: &BigInt) -> i8;
}

impl BigIntJacobi for BigInt {
    fn jacobi(&self, n: &BigInt) -> i8 {
        jacobi(self, n)
    }
}

#[cfg(test)]
mod tests {
    use super::{jacobi, BigIntJacobi};
    use num_bigint::BigInt;
    use num_traits::{One, Zero};

    #[test]
    fn test_basic_jacobi() {
        let a = BigInt::from(10);
        let n = BigInt::from(13);
        assert_eq!(jacobi(&a, &n), 1);
        assert_eq!(a.jacobi(&n), 1);

        let a = BigInt::from(10);
        let n = BigInt::from(15); // gcd(10,15) = 5
        assert_eq!(jacobi(&a, &n), 0);
        assert_eq!(a.jacobi(&n), 0);

        let a = BigInt::from(10);
        let n = BigInt::from(17);
        assert_eq!(jacobi(&a, &n), -1);
        assert_eq!(a.jacobi(&n), -1);
    }

    #[test]
    fn test_negative_a() {
        let a = BigInt::from(-3);
        let n = BigInt::from(11);
        assert_eq!(jacobi(&a, &n), -1);
    }

    #[test]
    fn test_multiplicativity() {
        let a = BigInt::from(3);
        let b = BigInt::from(5);
        let n = BigInt::from(7);

        let ab = &a * &b;
        let lhs = jacobi(&ab, &n);
        let rhs = jacobi(&a, &n) * jacobi(&b, &n);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_even_denominator_panics() {
        let a = BigInt::from(5);
        let n = BigInt::from(8);
        let result = std::panic::catch_unwind(|| jacobi(&a, &n));
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_a() {
        let a = BigInt::zero();
        let n = BigInt::from(17);
        assert_eq!(jacobi(&a, &n), 0);
    }

    #[test]
    fn test_one_a() {
        let a = BigInt::one();
        let n = BigInt::from(19);
        assert_eq!(jacobi(&a, &n), 1);
    }

    #[test]
    fn test_large_numbers() {
        let a = BigInt::parse_bytes(b"12345678901234567890", 10).unwrap();
        let n = BigInt::parse_bytes(b"9876543219876543211", 10).unwrap();

        let symbol = jacobi(&a, &n);
        assert!(symbol == 1 || symbol == -1 || symbol == 0);
    }
}
