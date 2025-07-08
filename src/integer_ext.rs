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
use generic_ec::{Curve};

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

    /// Converts `self` to a vector of bytes suitable for scalar representation 
    fn to_scalar_bytes(&self) -> Vec<u8>;

    /// Converts a scalar to an integer
    fn from_scalar<E: Curve>(scalar: impl AsRef<Scalar<E>>) -> Self;
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

        
        // Convert bytes to Integer directly
        let mut result = Integer::ZERO;
        for &byte in &bytes {
            result = (result << 8) + Integer::from(byte);
        }
        result = result + Integer::from(1);
        result
    }

    fn to_scalar_bytes(&self) -> Vec<u8> {
        let bytes = if self == &Integer::ZERO {
            vec![0u8]
        } else {
            // Convert to bytes by repeatedly dividing by 256
            let mut temp = self.clone();
            let mut bytes = Vec::new();
            while temp > Integer::ZERO {
                let remainder = &temp % Integer::from(256u32);
                bytes.push(remainder.to_string().parse::<u8>().unwrap());
                temp = temp / Integer::from(256u32);
            }
            bytes.reverse(); // Convert to big-endian
            bytes
        };
        bytes
    }

    fn from_scalar<E: Curve>(scalar: impl AsRef<Scalar<E>>) -> Self {
        let bytes = scalar.as_ref().to_be_bytes().to_vec();
        let mut result = Integer::ZERO;
        for &byte in bytes.iter() {
            result = (result << 8) + Integer::from(byte);
        }
        result
    }

    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C> {
        let curve_order = Self::curve_order::<C>();
        
        // Ensure the value is within [0, curve_order)
        let val = self.mod_op(&curve_order);
        
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
        
        let scalar = Scalar::<C>::from_be_bytes_mod_order(&bytes);
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

    #[test]
    fn test_from_scalar_zero() {
        let scalar: Scalar<Secp256r1> = Scalar::zero();
        let int_val = Integer::from_scalar(scalar);
        assert_eq!(int_val, Integer::ZERO, "Zero scalar should convert to zero integer");
    }

    #[test]
    fn test_from_scalar_one() {
        let scalar: Scalar<Secp256r1> = Scalar::one();
        let int_val = Integer::from_scalar(scalar);
        assert_eq!(int_val, Integer::ONE, "One scalar should convert to one integer");
    }

    #[test]
    fn test_from_scalar_positive() {
        // Create a scalar from a known integer value
        let original_int = Integer::from(123456);
        let scalar: Scalar<Secp256r1> = original_int.to_scalar();
        let converted_int = Integer::from_scalar(scalar);
        assert_eq!(converted_int, original_int, "Converting integer to scalar and back should preserve value");
    }
    use malachite_base::num::conversion::traits::FromStringBase;
    #[test]
    fn test_from_scalar_large_value() {
        // Test with a large value that's still within the curve order
        let original_int = Integer::from_string_base(10, "31681908193986104463610740478228600817831681908193986104463610740478228600817831681908193986104463610740478228600817831681908193986104463610740478228600817831681908193986104463610740478228600817831681908193986104463610740478228600817840478228600817831681908193986104463610740478228600817807404782286008178316819081939861044636107404782286008178316819081939861044636107404782286008178316819081939861044636107404782286008178316819081939861044636107404782286008178316819081939861044636107404782286008178404782286008178316819081939861044636107404782286008178").unwrap();
        let scalar: Scalar<Secp256r1> = original_int.to_scalar();
        let converted_int = Integer::from_scalar(scalar);
        
        // Since to_scalar applies modulo operation, we need to check against the modulo result
        let curve_order = Integer::curve_order::<Secp256r1>();
        let expected_int = original_int.mod_op(&curve_order);
        assert_eq!(converted_int, expected_int, "Large value conversion should be consistent with modulo operation");
    }

    #[test]
    fn test_from_scalar_round_trip() {
        // Test round-trip conversion: Integer -> Scalar -> Integer
        let test_values = vec![
            Integer::ZERO,
            Integer::ONE,
            Integer::from(42),
            Integer::from(255),
            Integer::from(256),
            Integer::from(65536),
            Integer::from(1000000),
        ];

        for original_int in test_values {
            let scalar: Scalar<Secp256r1> = original_int.to_scalar();
            let converted_int = Integer::from_scalar(scalar);
            assert_eq!(converted_int, original_int, "Round-trip conversion should preserve value for {}", original_int);
        }
    }

    #[test]
    fn test_from_scalar_byte_ordering() {
        // Test that from_scalar correctly handles big-endian byte ordering
        let scalar: Scalar<Secp256r1> = Scalar::one();
        let int_val = Integer::from_scalar(scalar);
        
        // Convert back to bytes to verify ordering
        let bytes = scalar.to_be_bytes();
        let mut expected_int = Integer::ZERO;
        for &byte in bytes.iter() {
            expected_int = (expected_int << 8) + Integer::from(byte);
        }
        
        assert_eq!(int_val, expected_int, "from_scalar should correctly handle big-endian byte ordering");
    }
}

