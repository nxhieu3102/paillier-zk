use crate::integer_ext::mod_pow_int;
use core::cmp::Ordering;
use malachite::Integer;
use malachite_base::num::arithmetic::traits::Mod;
use malachite_base::num::arithmetic::traits::Parity;
use malachite_base::num::arithmetic::traits::Sign;
use malachite_base::num::basic::traits::One;
use malachite_base::num::basic::traits::Zero;
use rand_core::RngCore;
pub fn jacobi(a: &Integer, n: &Integer) -> i8 {
    if n.cmp(&Integer::ZERO) == Ordering::Equal || n.even() || n.sign() == Ordering::Less {
        panic!("Jacobi symbol is undefined for non-positive or even denominator n");
    }

    let mut a = a.mod_op(n); // a mod n
    let mut n = n.clone();
    let mut result = 1;

    while a.cmp(&Integer::ZERO) != Ordering::Equal {
        // Remove factors of 2
        while a.even() {
            a >>= 1;
            let r = n.clone().mod_op(&Integer::from(8));
            if r.cmp(&Integer::from(3)) == Ordering::Equal
                || r.cmp(&Integer::from(5)) == Ordering::Equal
            {
                result = -result;
            }
        }

        // Apply reciprocity
        std::mem::swap(&mut a, &mut n);
        if a.clone().mod_op(&Integer::from(4)).cmp(&Integer::from(3)) == Ordering::Equal
            && n.clone().mod_op(&Integer::from(4)).cmp(&Integer::from(3)) == Ordering::Equal
        {
            result = -result;
        }

        a = a.clone().mod_op(&n.clone());
    }

    if n.clone().cmp(&Integer::ONE) == Ordering::Equal {
        result
    } else {
        0
    }
}

// Add trait extension
pub trait IntegerJacobi {
    fn jacobi(&self, n: &Integer) -> i8;
}

impl IntegerJacobi for Integer {
    fn jacobi(&self, n: &Integer) -> i8 {
        jacobi(self, n)
    }
}

/// Find principal square root in a Blum modulus quotient ring.
///
/// Pre-requisites:
/// - x is a quadratic residue in Zn
/// - `n = pq`, p and q are Blum primes
///
/// If these don't hold, the result is a bogus number in Zn
pub fn blum_sqrt(x: &Integer, p: &Integer, q: &Integer, n: &Integer) -> Integer {
    // Exponent in pq Blum modulus to obtain the principal square root.
    // Described in [Handbook of Applied cryptography, p. 75, Fact
    // 2.160](https://cacr.uwaterloo.ca/hac/about/chap2.pdf)
    let e = ((p - Integer::ONE) * (q - Integer::ONE) + Integer::from(4)) / Integer::from(8);

    // e guaranteed to be non-negative by the prerequisite that p and q are blum primes
    #[allow(clippy::expect_used)]
    mod_pow_int(x, &e, n)
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
    y: &Integer,
    w: &Integer,
    p: &Integer,
    q: &Integer,
    n: &Integer,
) -> Option<(bool, bool, Integer)> {
    let jp = y.mod_op(p).jacobi(p);
    let jq = y.mod_op(q).jacobi(q);
    match (jp, jq) {
        (1, 1) => return Some((false, false, y.clone())),
        (-1, -1) => return Some((true, false, (n - y))),
        _ => (),
    }

    let y = (y.clone() * w).mod_op(n);
    let jp = y.clone().mod_op(p).jacobi(p);
    let jq = y.clone().mod_op(q).jacobi(q);
    match (jp, jq) {
        (1, 1) => Some((false, true, y)),
        (-1, -1) => Some((true, true, n - y)),
        _ => None,
    }
}

/// Finds a element in Zn that has jacobi symbol of -1
pub fn sample_neg_jacobi<R: RngCore>(n: &Integer, rng: &mut R) -> Integer {
    loop {
        let w = fast_paillier::utils::random_below(rng, n);
        if w.jacobi(n) == -1 {
            break w;
        }
    }
}


#[cfg(test)]
mod tests {
    use super::jacobi;
    use malachite::Integer;
    use crate::common::sqrt::IntegerJacobi;
    use malachite_base::num::basic::traits::Zero;
    use malachite_base::num::basic::traits::One;
    use malachite_base::num::conversion::traits::FromStringBase;
    #[test]
    fn test_basic_jacobi() {
        let a = Integer::from(10);
        let n = Integer::from(13);
        assert_eq!(jacobi(&a, &n), 1);
        assert_eq!(a.jacobi(&n), 1);

        let a = Integer::from(10);
        let n = Integer::from(15); // gcd(10,15) = 5
        assert_eq!(jacobi(&a, &n), 0);
        assert_eq!(a.jacobi(&n), 0);

        let a = Integer::from(10);
        let n = Integer::from(17);
        assert_eq!(jacobi(&a, &n), -1);
        assert_eq!(a.jacobi(&n), -1);
    }

    #[test]
    fn test_negative_a() {
        let a = Integer::from(-3);
        let n = Integer::from(11);
        assert_eq!(jacobi(&a, &n), -1);
    }

    #[test]
    fn test_multiplicativity() {
        let a = Integer::from(3);
        let b = Integer::from(5);
        let n = Integer::from(7);

        let ab = &a * &b;
        let lhs = jacobi(&ab, &n);
        let rhs = jacobi(&a, &n) * jacobi(&b, &n);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_even_denominator_panics() {
        let a = Integer::from(5);
        let n = Integer::from(8);
        let result = std::panic::catch_unwind(|| jacobi(&a, &n));
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_a() {
        let a = Integer::ZERO;
        let n = Integer::from(17);
        assert_eq!(jacobi(&a, &n), 0);
    }

    #[test]
    fn test_one_a() {
        let a = Integer::ONE;
        let n = Integer::from(19);
        assert_eq!(jacobi(&a, &n), 1);
    }

    #[test]
    fn test_large_numbers() {
        let a = Integer::from_string_base(10, "12345678901234567890").unwrap();
        let n = Integer::from_string_base(10, "9876543219876543211").unwrap();

        let symbol = jacobi(&a, &n);
        assert!(symbol == 1 || symbol == -1 || symbol == 0);
    }
}
