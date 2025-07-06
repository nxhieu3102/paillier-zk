// Helper utilities for working with malachite::Integer when the desired
// arithmetic trait is implemented only for Natural.
// All helpers live in this crate, so they avoid Rust's orphan-rule
// restrictions.
use malachite_base::num::random::random_primitive_ints;
use malachite::Integer;
use malachite_base::num::arithmetic::traits::{Mod, ModInverse, ModPow, UnsignedAbs};
use generic_ec::Scalar;
use malachite_base::num::basic::traits::Zero;
use core::cmp::Ordering;
use malachite_base::random::EXAMPLE_SEED;
use malachite_nz::integer::random::get_uniform_random_integer_from_inclusive_range;
use malachite_base::num::arithmetic::traits::Parity;
use crate::BadExponent;
use malachite_base::num::arithmetic::traits::FloorSqrt;
/// Modular exponentiation for `Integer`.
///
/// This delegates to the already-implemented `ModPow` for `Natural`.
/// `base`, `exp`, and `m` may be negative - the computation is carried
/// out on their absolute values and the result returned as a signed
/// `Integer` in the usual Paillier range (non-negative < m).
pub(crate) fn mod_pow_int(base: &Integer, exp: &Integer, m: &Integer) -> Integer {
    let base_red = base.mod_op(m).unsigned_abs();
    let exp_abs = exp.unsigned_abs_ref();
    let m_abs = m.unsigned_abs_ref();

    let res_nat = if exp < &Integer::from(0) {
        // Handle negative exponent by computing the modular inverse of the base
        base_red.mod_inverse(m_abs).map_or(malachite::Natural::from(0u32), |inv| inv.mod_pow(exp_abs, m_abs))
    } else {
        base_red.mod_pow(exp_abs, m_abs)
    };
    res_nat.into()
}

/// Modular inverse for `Integer` (`a^{-1} mod m`).
/// Returns `None` when the inverse does not exist.
pub(crate) fn mod_inverse_int(a: &Integer, m: &Integer) -> Option<Integer> {
    let a_red = a.mod_op(m).unsigned_abs();
    a_red
        .mod_inverse(m.unsigned_abs_ref())
        .map(Integer::from)
} 

pub trait IntegerExt: Sized {
    /// Generate element in Zm*. Does so by trial.
    fn gen_invertible<R: rand_core::RngCore>(modulo: &Self, rng: &mut R) -> Self;

    /// Compute l^le * r^re modulo self
    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Result<Self, BadExponent>;

    /// Embed BigInt into chosen scalar type
    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C>;

    /// Returns prime order of curve C
    // fn curve_order<C: generic_ec::Curve>() -> Self;

    /// Generates a random integer in interval `[-range; range]`
    fn from_rng_pm<R: rand_core::RngCore>(range: &Self, rng: &mut R) -> Self;

    /// Checks whether `self` is in interval `[-range; range]`
    fn is_in_pm(&self, range: &Self) -> bool;

    /// Returns `self smod n`
    ///
    /// For odd `n`, result is in `{-n/2, .., n/2}`. For even `n`, result is in
    /// `{-n/2, .., n/2 - 1}`
    fn signed_modulo(&self, n: &Self) -> Self;

    /// Returns `self` as a vector of bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Returns a random integer in the range `[0, self)`
    fn random_below(&self, rng: &mut impl rand_core::RngCore) -> Self;

    /// Returns a random integer in the range `[min, max)`
    fn rand_in_range(rng: &mut impl rand_core::RngCore, min: Integer, max: Integer) -> Self;

    /// Returns the order of the curve
    fn curve_order<C: generic_ec::Curve>() -> Self;

    /// Returns the square root of `self`
    fn sqrt(&self) -> Self;
}



impl IntegerExt for Integer {
    fn rand_in_range(rng: &mut impl rand_core::RngCore, min: Integer, max: Integer) -> Self {
        get_uniform_random_integer_from_inclusive_range(
            &mut random_primitive_ints(EXAMPLE_SEED),
            min,
            max,
        )
    }
    fn gen_invertible<R: rand_core::RngCore>(modulo: &Integer, rng: &mut R) -> Self {
        fast_paillier::utils::sample_in_mult_group(rng, modulo)
    }

    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Result<Self, BadExponent> {
        let l_to_le: Integer = crate::integer_ext::mod_pow_int(l, le, self);
        let r_to_re: Integer = crate::integer_ext::mod_pow_int(r, re, self);
        Ok((l_to_le * r_to_re) % self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let limbs = self.to_twos_complement_limbs_desc();
        let mut bytes = Vec::with_capacity(limbs.len() * 8);
        for &limb in limbs.iter().rev() {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }

        while let Some(&last) = bytes.last() {
            if last == 0 && bytes.len() > 1 {
                bytes.pop();
            } else {
                break;
            }
        }

        bytes
    }

    fn curve_order<C: generic_ec::Curve>() -> Self {
        let order_minus_one = -Scalar::<C>::one();
        let bytes = order_minus_one.to_be_bytes().to_vec();
        println!("order_minus_one bytes: {:?}", bytes);
        
        // Convert bytes to Integer directly
        let mut result = Integer::ZERO;
        for &byte in &bytes {
            result = (result << 8) + Integer::from(byte);
        }
        result = result + Integer::from(1);
        println!("calculated curve order: {result:?}");
        result
    }

    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C> {
        let curve_order = Self::curve_order::<C>();
        println!("self: {self:?}");
        println!("curve_order: {curve_order:?}");
        
        // Ensure the value is within [0, curve_order)
        let val = self.mod_op(&curve_order);
        println!("val after mod_op: {val:?}");
        
        // Convert directly to bytes using a different approach
        // Use the signed representation and convert to bytes
        let bytes = if val == Integer::ZERO {
            vec![0u8]
        } else {
            // Convert to bytes by repeatedly dividing by 256
            let mut temp = val.clone();
            let mut bytes = Vec::new();
            while temp > Integer::ZERO {
                let remainder = &temp % Integer::from(256u32);
                bytes.push(remainder.to_string().parse::<u8>().unwrap());
                temp = temp / Integer::from(256u32);
            }
            bytes.reverse(); // Convert to big-endian
            bytes
        };
        
        println!("final bytes: {:?}", bytes);
        
        let scalar = Scalar::<C>::from_be_bytes_mod_order(&bytes);
        println!("scalar: {scalar:?}");
        scalar
    }

    /// !TODO: need gen seed 
    fn from_rng_pm<R: rand_core::RngCore>(range: &Self, rng: &mut R) -> Self {
        get_uniform_random_integer_from_inclusive_range(
            &mut random_primitive_ints(EXAMPLE_SEED),
            -range.clone(),
            range.clone(),
        )
    }

    fn random_below(&self, rng: &mut impl rand_core::RngCore) -> Self {
        get_uniform_random_integer_from_inclusive_range(
            &mut random_primitive_ints(EXAMPLE_SEED),
            Integer::ZERO,
            self.clone(),
        )
    }

    fn is_in_pm(&self, range: &Self) -> bool {
        let minus_range = -range.clone();
        minus_range <= *self && self <= range
    }

    fn signed_modulo(&self, n: &Self) -> Self {
        let self_mod_n = self.mod_op(n);
        let half_n = (n >> 1_u32);
        if half_n.odd() && self_mod_n <= half_n || self_mod_n < half_n {
            self_mod_n
        } else {
            self_mod_n - n
        }
    }

    fn sqrt(&self) -> Self {
        self.floor_sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::{Scalar, curves::Secp256r1};
    use malachite_base::num::basic::traits::{Zero, One};

    #[test]
    fn test_to_scalar_positive() {
        let int_val = Integer::from(123456);
        let scalar: Scalar<Secp256r1> = int_val.to_scalar();
        // Scalar for Secp256r1 always returns 32 bytes, so we can't compare lengths directly
        // Instead, we can convert back to an Integer if needed, but for now, just ensure it's not zero
        assert!(!scalar.is_zero(), "Positive integer should not convert to zero scalar");
    }

    #[test]
    fn test_to_scalar_negative() {
        let int_val = Integer::from(-123456);
        let scalar: Scalar<Secp256r1> = int_val.to_scalar();
        let positive_scalar: Scalar<Secp256r1> = Integer::from(123456).to_scalar();
        let sum = scalar + positive_scalar;
        let curve_order = Integer::curve_order::<Secp256r1>();
        // println!("sum: {sum:?}");
        // println!("curve_order: {curve_order:?}");
        assert!(sum.is_zero(), "Negative and positive scalar of same magnitude should sum to zero");
    }

    #[test]
    fn test_to_scalar_zero() {
        let int_val = Integer::ZERO;
        let scalar: Scalar<Secp256r1> = int_val.to_scalar();
        assert!(scalar.is_zero(), "Zero integer should convert to zero scalar");
    }

    #[test]
    fn test_to_scalar_large_number() {
        let int_val = Integer::from(316819081939861044636107404782286008178u128); // A large number
        let scalar: Scalar<Secp256r1> = int_val.to_scalar();
        // We can't directly compare, but we can ensure it's not zero and operation is valid
        assert!(!scalar.is_zero(), "Large number should not convert to zero scalar");
    }
}

