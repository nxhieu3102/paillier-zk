//! Optimized multiexponentiation with precomputations
//!
//! Many ZK proofs often require computing `s^x t^y mod N` with s, t, and N being known in advance.
//! This module provides [`MultiexpTable`] that can compute multiexponent faster.

#![allow(non_snake_case)]
use crate::common::BigIntExt;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Pow, Zero};

/// Precomputed table for performing faster multiexponentiation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultiexpTable {
    s: Vec<BigInt>,
    ell_x: BigInt,
    s_to_ell_x: BigInt,
    t: Vec<BigInt>,
    ell_y: BigInt,
    t_to_ell_y: BigInt,
    N: BigInt,
}

use num_traits::FromPrimitive;

impl MultiexpTable {
    /// Builds a multiexponentiation table to perform `s^x t^y mod N` faster
    /// where `x` and `y` are up to `x_bits` and `y_bits`
    ///
    /// Returns `None` is `s` or `t` are non-positive or if any of them are not co-prime to `N` or
    /// if `N` is less than 2.
    pub fn build(s: &BigInt, t: &BigInt, x_bits: u64, y_bits: u64, N: BigInt) -> Option<Self> {
        if *s <= Zero::zero()
            || *t <= Zero::zero()
            || N <= One::one()
            || !s.gcd(&N).is_one()
            || !t.gcd(&N).is_one()
        {
            return None;
        }

        let k_x = x_bits / 8 + 1;
        let k_y = y_bits / 8 + 1;
        let mut s_table = Vec::with_capacity(k_x.try_into().ok()?);
        let mut t_table = Vec::with_capacity(k_y.try_into().ok()?);

        let B: BigInt = BigInt::from(256);
        for i in 0..k_x {
            let B_to_i = B.clone().pow(i);
            s_table.push(s.clone().modpow(&B_to_i, &N));
        }
        for i in 0..k_y {
            let B_to_i = B.clone().pow(i);
            t_table.push(t.clone().modpow(&B_to_i, &N));
        }

        // smallest negative value possible for `x`
        let ell_x = -(BigInt::one() << (k_x * 8)) + 1;
        let s_to_ell_x = s.modpow_ext(&ell_x, &N)?;
        // smallest negative value possible for `y`
        let ell_y = -(BigInt::one() << (k_y * 8)) + 1;
        let t_to_ell_y = t.modpow_ext(&ell_y, &N)?;

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
    pub fn prod_exp(&self, x: &BigInt, y: &BigInt) -> Option<BigInt> {
        // let order = rug::integer::Order::Lsf;

        let x_is_neg = x < &Zero::zero();
        // `x_digits` correspond to digits of `x` is it's non-negative, and `x - ell_x` otherwise
        let x_digits = if !x_is_neg {
            x.to_bytes_le().1
        } else {
            let x = x - &self.ell_x;
            if x < Zero::zero() {
                // `x` is less than lower bound
                return None;
            }
            x.to_bytes_le().1
        };

        let y_is_neg = y < &Zero::zero();
        // `y_digits` correspond to digits of `y` is it's non-negative, and `y - ell_y` otherwise
        let y_digits = if !y_is_neg {
            y.to_bytes_le().1
        } else {
            let y = y - &self.ell_y;
            if y < Zero::zero() {
                // `y` is less than lower bound
                return None;
            }
            y.to_bytes_le().1
        };

        if x_digits.len() > self.s.len() || y_digits.len() > self.t.len() {
            // `x` or `y` are higher than upper bound
            return None;
        }

        let mut digits_table = [(); 255].map(|_| None);
        build_digits_table(&mut digits_table, &self.s, &x_digits, &self.N);
        build_digits_table(&mut digits_table, &self.t, &y_digits, &self.N);

        let mut res = BigInt::one();
        let mut acc = BigInt::one();
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

        let s: u64 = s.iter().map(|s_i| s_i.bits()).sum();
        let ell_x = ell_x.bits();
        let s_to_ell_x = s_to_ell_x.bits();
        let t: u64 = t.iter().map(|t_i| t_i.bits()).sum();
        let ell_y = ell_y.bits();
        let t_to_ell_y = t_to_ell_y.bits();
        let N = N.bits();

        let limbs_bytes =
            (u64::BITS as u64 / 8) * (s + ell_x + s_to_ell_x + t + ell_y + t_to_ell_y + N);

        vec_len + int_len + limbs_bytes as usize
    }
}

fn build_digits_table(
    table: &mut [Option<BigInt>; 255],
    base: &[BigInt],
    digits: &[u8],
    N: &BigInt,
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
    use crate::BigIntExt;
    use num_bigint::BigInt;

    use super::MultiexpTable;
    use num_bigint::RandBigInt;
    use num_traits::One;

    #[test]
    fn multiexp_works() {
        let N = BigInt::from(100000);
        let s = BigInt::from(3);
        let t = BigInt::from(7);

        let x_bits: u64 = 48;
        let y_bits: u64 = 32;

        let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();

        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let mut x = BigInt::from(rng.gen_bigint(x_bits));
            if rng.gen_bigint(1).is_one() {
                x = -x
            }

            let mut y = BigInt::from(rng.gen_bigint(y_bits));
            if rng.gen_bigint(1).is_one() {
                y = -y
            }
            println!("x={x} y={y}");

            let actual = table.prod_exp(&x, &y).unwrap();

            let expected = (s
                .clone()
                .modpow_ext(&x, &N)
                .expect("Failed to compute modpow_ext")
                * t.clone()
                    .modpow_ext(&y, &N)
                    .expect("Failed to compute modpow_ext"))
                % &N;
            assert_eq!(actual, expected);
        }
    }
}
