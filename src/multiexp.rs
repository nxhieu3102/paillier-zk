//! Optimized multiexponentiation with precomputations
//!
//! Many ZK proofs often require computing `s^x t^y mod N` with s, t, and N being known in advance.
//! This module provides [`MultiexpTable`] that can compute multiexponent faster.

#![allow(non_snake_case)]

use malachite::Integer;
use malachite_base::num::basic::traits::{One, Zero};
use malachite_base::num::arithmetic::traits::{Pow, ExtendedGcd};
use malachite_base::num::conversion::traits::Digits;
use malachite_base::num::logic::traits::SignificantBits;
use malachite_base::num::comparison::traits::PartialOrdAbs;
use malachite_nz::integer::random::{get_uniform_random_integer_from_inclusive_range};
use malachite_base::num::random::random_primitive_ints;
use malachite_base::random::EXAMPLE_SEED;
use fast_paillier::utils::{serializable_bigint, serializable_vec_bigint};
use fast_paillier::integer_ext::mod_pow_int;

/// Precomputed table for performing faster multiexponentiation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultiexpTable {
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    s: Vec<Integer>,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    ell_x: Integer,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    s_to_ell_x: Integer,
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    t: Vec<Integer>,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    ell_y: Integer,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    t_to_ell_y: Integer,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    N: Integer,
}

impl MultiexpTable {
    /// Builds a multiexponentiation table to perform `s^x t^y mod N` faster
    /// where `x` and `y` are up to `x_bits` and `y_bits`
    ///
    /// Returns `None` is `s` or `t` are non-positive or if any of them are not co-prime to `N` or
    /// if `N` is less than 2.
    pub fn build(s: &Integer, t: &Integer, x_bits: u32, y_bits: u32, N: Integer) -> Option<Self> {
        if s <= &Integer::ZERO
            || t <= &Integer::ZERO
            || N <= Integer::ONE
            || s.extended_gcd(&N).0 != malachite_nz::natural::Natural::ONE
            || t.extended_gcd(&N).0 != malachite_nz::natural::Natural::ONE
        {
            return None;
        }
        let k_x = x_bits / 8 + 1;
        let k_y = y_bits / 8 + 1;
        let mut s_table = Vec::with_capacity(k_x.try_into().ok()?);
        let mut t_table = Vec::with_capacity(k_y.try_into().ok()?);

        let B: u32 = 256;
        for i in 0..k_x {
            let B_to_i = Integer::from(B).pow(i as u64);
            s_table.push(mod_pow_int(s, &B_to_i, &N));
        }
        for i in 0..k_y {
            let B_to_i = Integer::from(B).pow(i as u64);
            t_table.push(mod_pow_int(t, &B_to_i, &N));
        }

        // smallest negative value possible for `x`
        let ell_x = -(Integer::ONE.clone() << (k_x * 8)) + Integer::ONE;
        let s_to_ell_x = mod_pow_int(s, &ell_x, &N);
        // smallest negative value possible for `y`
        let ell_y = -(Integer::ONE.clone() << (k_y * 8)) + Integer::ONE;
        let t_to_ell_y = mod_pow_int(t, &ell_y, &N);

        println!("s={s} t={t}");
        println!("ell_x={ell_x} ell_y={ell_y}");
        println!("s_to_ell_x={s_to_ell_x} t_to_ell_y={t_to_ell_y}");
        // println!("s_table={s_table:?} t_table={t_table:?}");
        println!("N={N}");
        Some(Self {
            s: s_table,
            ell_x,
            s_to_ell_x,
            t: t_table,
            ell_y,
            t_to_ell_y,
            N,
        })
    }

    /// Calculates `s^x t^y mod N`
    ///
    /// Returns `None` if either `x` or `y` do not fit into `x_bits` or `y_bits` provided in [`MultiexpTable::build`].
    pub fn prod_exp(&self, x: &Integer, y: &Integer) -> Option<Integer> {
        let x_is_neg = x < &Integer::ZERO;
        // `x_digits` correspond to digits of `x` is it's non-negative, and `x - ell_x` otherwise
        let x_digits = if !x_is_neg {
            x.unsigned_abs_ref().to_digits_asc(&256u16)
        } else {
            let x = x - &self.ell_x;
            if x < Integer::ZERO {
                // `x` is less than lower bound
                return None;
            }
            x.unsigned_abs_ref().to_digits_asc(&256u16)
        };

        let y_is_neg = y < &Integer::ZERO;
        // `y_digits` correspond to digits of `y` is it's non-negative, and `y - ell_y` otherwise
        let y_digits = if !y_is_neg {
            y.unsigned_abs_ref().to_digits_asc(&256u16)
        } else {
            let y = y - &self.ell_y;
            if y < Integer::ZERO {
                // `y` is less than lower bound
                return None;
            }
            y.unsigned_abs_ref().to_digits_asc(&256u16)
        };

        println!("x_digits={x_digits:?} y_digits={y_digits:?}");
        println!("s.len()={} t.len()={}", self.s.len(), self.t.len());

        if x_digits.len() > self.s.len() || y_digits.len() > self.t.len() {
            // `x` or `y` are higher than upper bound
            return None;
        }

        let mut digits_table = [(); 255].map(|_| None);
        build_digits_table(&mut digits_table, &self.s, &x_digits, &self.N);
        build_digits_table(&mut digits_table, &self.t, &y_digits, &self.N);

        let mut res = Integer::ONE.clone();
        let mut acc = Integer::ONE.clone();
        for d in digits_table.iter().rev() {
            if let Some(d) = d {
                acc = (acc * d) % &self.N;
            }
            res = (res * &acc) % &self.N;
        }
        

        if x_is_neg {
            res = (res * &self.s_to_ell_x) % &self.N;
        }
        if y_is_neg {
            res = (res * &self.t_to_ell_y) % &self.N;
        }

        println!("res={res}");

        Some(res)
    }

    /// Returns max size of exponents (in bits) that can be computed
    ///
    /// Max exponent size is guaranteed to be equal or greater than `x_bits` and `y_bits`
    /// provided in [MultiexpTable::build]
    pub fn max_exponents_size(&self) -> (usize, usize) {
        (self.s.len() * 8, self.t.len() * 8)
    }

    /// Estimates size of the table in RAM in bytes
    pub fn size_in_bytes(&self) -> usize {
        let Self {
            s,
            ell_x,
            s_to_ell_x,
            t,
            ell_y,
            t_to_ell_y,
            N,
        } = self;

        // A few bytes to encode length of Vec `s` and `t`
        let vec_len = 2 * (usize::BITS as usize / 8);
        // And a few bytes more to encode length of each integer
        let int_len = (5 + s.len() + t.len()) * (usize::BITS as usize / 8);

        type Limb = u64;
        let limb_bits = Limb::BITS as u64;
        let s: usize = s.iter().map(|s_i| ((s_i.significant_bits() + limb_bits - 1) / limb_bits) as usize).sum();
        let ell_x = ((ell_x.significant_bits() + limb_bits - 1) / limb_bits) as usize;
        let s_to_ell_x = ((s_to_ell_x.significant_bits() + limb_bits - 1) / limb_bits) as usize;
        let t: usize = t.iter().map(|t_i| ((t_i.significant_bits() + limb_bits - 1) / limb_bits) as usize).sum();
        let ell_y = ((ell_y.significant_bits() + limb_bits - 1) / limb_bits) as usize;
        let t_to_ell_y = ((t_to_ell_y.significant_bits() + limb_bits - 1) / limb_bits) as usize;
        let N = ((N.significant_bits() + limb_bits - 1) / limb_bits) as usize;

        let limbs_bytes =
            (limb_bits as usize / 8) * (s + ell_x + s_to_ell_x + t + ell_y + t_to_ell_y + N);

        vec_len + int_len + limbs_bytes
    }
}

fn build_digits_table(
    table: &mut [Option<Integer>; 255],
    base: &[Integer],
    digits: &[u16],
    N: &Integer,
) {
    for (i, digit) in digits.iter().copied().enumerate() {
        if digit != 0 {
            match &mut table[usize::from(digit - 1)] {
                Some(out) => {
                    *out *= &base[i];
                    *out %= N;
                }
                out @ None => *out = Some(base[i].clone()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use malachite::Integer;
    use malachite_base::num::random::random_primitive_ints;
    use malachite_base::random::EXAMPLE_SEED;
    use malachite_nz::integer::random::get_uniform_random_integer_from_inclusive_range;
    use fast_paillier::integer_ext::mod_pow_int;
    use malachite_base::num::basic::traits::{Zero, One};
    use super::MultiexpTable;

    #[test]
    fn multiexp_works() {
        let N = Integer::from(100000);
        let s = Integer::from(3);
        let t = Integer::from(7);

        let x_bits = 48;
        let y_bits = 32;

        let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();

        let mut rng: malachite_base::num::random::RandomPrimitiveInts<u64> = random_primitive_ints(EXAMPLE_SEED);

        for _ in 0..1 {
            let mut x = get_uniform_random_integer_from_inclusive_range(
                &mut rng,
                Integer::ZERO,
                Integer::from(1u64 << x_bits) - Integer::from(1)
            );
            if get_uniform_random_integer_from_inclusive_range(&mut rng, Integer::ZERO, Integer::ONE) == Integer::ONE {
                x = -x
            }

            let mut y = get_uniform_random_integer_from_inclusive_range(
                &mut rng,
                Integer::ZERO,
                Integer::from(1u64 << y_bits) - Integer::from(1)
            );
            if get_uniform_random_integer_from_inclusive_range(&mut rng, Integer::ZERO, Integer::ONE) == Integer::ONE {
                y = -y
            }
            println!("x={x} y={y}");

            let actual = table.prod_exp(&x, &y).unwrap();
            let expected =
                (mod_pow_int(&s, &x, &N) * mod_pow_int(&t, &y, &N)) % &N;
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn prod_exp_zero_exponents() {
        let N = Integer::from(100000);
        let s = Integer::from(3);
        let t = Integer::from(7);
        let x_bits = 48;
        let y_bits = 32;

        let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();
        let x = Integer::ZERO;
        let y = Integer::ZERO;

        let result = table.prod_exp(&x, &y).unwrap();
        assert_eq!(result, Integer::ONE);
    }

    #[test]
    fn prod_exp_max_exponents() {
        let N = Integer::from(100000);
        let s = Integer::from(3);
        let t = Integer::from(7);
        let x_bits = 16;
        let y_bits = 16;

        let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();
        let x = (Integer::ONE << x_bits) - Integer::ONE;
        let y = (Integer::ONE << y_bits) - Integer::ONE;

        let result = table.prod_exp(&x, &y).unwrap();
        let expected = (mod_pow_int(&s, &x, &N) * mod_pow_int(&t, &y, &N)) % &N;
        assert_eq!(result, expected);
    }

    #[test]
    fn prod_exp_min_exponents() {
        let N = Integer::from(100000);
        let s = Integer::from(3);
        let t = Integer::from(7);
        let x_bits = 16;
        let y_bits = 16;

        let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();
        let x = -(Integer::ONE << (x_bits)) + Integer::ONE;
        let y = -(Integer::ONE << (y_bits)) + Integer::ONE;

        println!("x={x} y={y}");

        let result = table.prod_exp(&x, &y);
        assert!(result.is_some(), "prod_exp should return a value for minimum exponents");
        let result = result.unwrap();
        let expected = (mod_pow_int(&s, &x, &N) * mod_pow_int(&t, &y, &N)) % &N;
        assert_eq!(result, expected, "Result for minimum exponents x={} y={} should match expected", x, y);
    }

    // #[test]
    // fn prod_exp_out_of_bounds() {
    //     let N = Integer::from(100000);
    //     let s = Integer::from(3);
    //     let t = Integer::from(7);
    //     let x_bits = 16;
    //     let y_bits = 16;

    //     let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();
    //     let x = Integer::ONE << (x_bits + 1);
    //     let y = Integer::ONE << y_bits;

    //     assert!(table.prod_exp(&x, &y).is_none());
    // }
}
