pub mod sqrt;
use generic_ec::Scalar;
use num_bigint::{BigInt, RandBigInt, Sign};
use num_integer::Integer; // This brings the Integer trait (and mod_floor) into scope
use std::sync::Arc;

#[cfg(feature = "serde")]
use fast_paillier::utils::{serializable_bigint};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Auxiliary data known to both prover and verifier
// #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    any(feature = "serde", feature = "__internal_doctest"),
    derive(Serialize, Deserialize)
)]
#[derive(Clone, Debug)]
pub struct Aux {
    /// ring-pedersen parameter
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub s: BigInt,
    /// ring-pedersen parameter
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub t: BigInt,
    /// N^ in paper
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub rsa_modulo: BigInt,
    /// Precomuted table for computing `s^x t^y mod rsa_modulo` faster
    ///
    /// If absent, optimization is disabled.
    #[cfg_attr(any(feature = "serde", feature = "__internal_doctest"), serde(skip))]
    pub multiexp: Option<Arc<crate::multiexp::MultiexpTable>>,
    #[cfg_attr(any(feature = "serde", feature = "__internal_doctest"), serde(skip))]
    pub crt: Option<fast_paillier::utils::CrtExp>,
}

impl Aux {
    /// Returns `s^x t^y mod rsa_modulo`
    pub fn combine(&self, x: &BigInt, y: &BigInt) -> Result<BigInt, BadExponent> {
        if let Some(table) = &self.multiexp {
            match table.prod_exp(x, y) {
                Some(res) => return Ok(res),
                None if cfg!(debug_assertions) => {
                    return Err(BadExponentReason::ExpSize {
                        exp_size: (x.bits() as u32, y.bits() as u32),
                        max_exp_size: table.max_exponents_size(),
                    }
                    .into())
                }
                None => {
                    // When debug assertions are disabled, we fallback to naive exponentiation
                }
            }
        }

        // Naive exponentiation when optimizations are not enabled
        self.rsa_modulo.combine(&self.s, x, &self.t, y)
    }

    /// Returns `x^e mod rsa_modulo`
    pub fn pow_mod(&self, x: &BigInt, e: &BigInt) -> Result<BigInt, BadExponent> {
        match &self.crt {
            Some(crt) => {
                let e = crt.prepare_exponent(e);
                crt.exp(x, &e).ok_or_else(BadExponent::undefined)
            }
            None => Ok(x
                .modpow_ext(e, &self.rsa_modulo)
                .ok_or_else(BadExponent::undefined)?
                .into()),
        }
    }

    /// Returns a stripped version of `Aux` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        // TODO: check if this is correct
        let (_s_sign, s_digits) = self.s.to_bytes_be();
        let (_t_sign, t_digits) = self.t.to_bytes_be();
        let (_rsa_sign, rsa_digits) = self.rsa_modulo.to_bytes_be();
        udigest::inline_struct!("paillier_zk.aux" {
            s: udigest::Bytes(s_digits),
            t: udigest::Bytes(t_digits),
            rsa_modulo: udigest::Bytes(rsa_digits),
        })
    }
}

/// Error indicating that proof is invalid
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof(
    #[source]
    #[from]
    InvalidProofReason,
);

/// Reason for failure. If the proof failes, you should only be interested in a
/// reason for debugging purposes
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum InvalidProofReason {
    /// One equality doesn't hold. Parameterized by equality index
    #[error("equality check failed {0}")]
    EqualityCheck(usize),
    /// One range check doesn't hold. Parameterized by check index
    #[error("range check failed {0}")]
    RangeCheck(usize),
    /// Encryption of supplied data failed when attempting to verify
    #[error("encryption failed")]
    Encryption,
    #[error("paillier encryption failed")]
    PaillierEnc,
    #[error("paillier homomorphic op failed")]
    PaillierOp,
    /// Failed to evaluate powmod
    #[error("powmod failed")]
    ModPow,
    /// Paillier-Blum modulus is prime
    #[error("modulus is prime")]
    ModulusIsPrime,
    /// Paillier-Blum modulus is even
    #[error("modulus is even")]
    ModulusIsEven,
    /// Proof's z value in n-th power does not equal commitment value
    #[error("incorrect nth root")]
    IncorrectNthRoot,
    /// Proof's x value in 4-th power does not equal commitment value
    #[error("incorrect 4th root")]
    IncorrectFourthRoot,
}

impl InvalidProof {
    #[cfg(test)]
    pub(crate) fn reason(&self) -> InvalidProofReason {
        self.0
    }
}

impl From<BadExponent> for InvalidProof {
    fn from(_err: BadExponent) -> Self {
        InvalidProofReason::ModPow.into()
    }
}

impl From<PaillierError> for InvalidProof {
    fn from(_err: PaillierError) -> Self {
        InvalidProof(InvalidProofReason::Encryption)
    }
}

/// Error indicating that encryption failed
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("paillier encryption failed")]
pub struct PaillierError;

pub trait BigIntExt: Sized {
    /// Generate element in Zm*. Does so by trial.
    fn gen_invertible<R: rand_core::RngCore>(modulo: &Self, rng: &mut R) -> Self;

    /// Compute l^le * r^re modulo self
    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Result<Self, BadExponent>;

    /// Embed BigInt into chosen scalar type
    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C>;

    /// Returns prime order of curve C
    fn curve_order<C: generic_ec::Curve>() -> Self;

    /// Generates a random integer in interval `[-range; range]`
    fn from_rng_pm<R: rand_core::RngCore>(range: &Self, rng: &mut R) -> Self;

    /// Checks whether `self` is in interval `[-range; range]`
    fn is_in_pm(&self, range: &Self) -> bool;

    /// Returns `self smod n`
    ///
    /// For odd `n`, result is in `{-n/2, .., n/2}`. For even `n`, result is in
    /// `{-n/2, .., n/2 - 1}`
    fn signed_modulo(&self, n: &Self) -> Self;

    /// Returns `self` as a tuple of `(sign, digits)`
    fn to_bytes_be(&self) -> (Sign, Vec<u8>);

    /// Returns `self ^ exp mod modulo`
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self>;
}

use num_traits::Signed;

impl BigIntExt for BigInt {
    fn gen_invertible<R: rand::RngCore>(modulo: &BigInt, rng: &mut R) -> Self {
        fast_paillier::utils::sample_in_mult_group(rng, modulo)
    }

    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Result<Self, BadExponent> {
        let l_to_le: BigInt = l
            .modpow_ext(le, self)
            .ok_or(BadExponent(BadExponentReason::Undefined))?;
        let r_to_re: BigInt = r
            .modpow_ext(re, self)
            .ok_or(BadExponent(BadExponentReason::Undefined))?;
        Ok((l_to_le * r_to_re).mod_floor(self))
    }

    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C> {
        let (sign, bytes_be) = self.to_bytes_be();
        let s = Scalar::<C>::from_be_bytes_mod_order(bytes_be);
        match sign {
            Sign::Plus => s,
            Sign::Minus => -s,
            Sign::NoSign => -s,
        }
    }

    fn curve_order<C: generic_ec::Curve>() -> Self {
        let order_minus_one = -Scalar::<C>::one();
        let bytes_be = order_minus_one.to_be_bytes();
        let i = BigInt::from_bytes_be(Sign::Plus, &bytes_be);
        i + 1
    }

    fn from_rng_pm<R: rand::RngCore>(range: &Self, rng: &mut R) -> Self {
        // let mut rng = fast_paillier::utils::external_rand(rng);
        if range.is_negative() {
            let l_range = range.clone();
            let u_range = -range.clone();
            rng.gen_bigint_range(&l_range, &u_range)
        } else {
            let l_range = -range.clone();
            let u_range = range.clone();
            rng.gen_bigint_range(&l_range, &u_range)
        }
        
        
        // rng.gen_bigint_range(&l_range, &u_range)
    }

    fn is_in_pm(&self, range: &Self) -> bool {
        let minus_range = -range.clone();
        minus_range <= *self && self <= range
    }

    fn signed_modulo(&self, n: &Self) -> Self {
        let self_mod_n = self.mod_floor(n);
        let half_n = n >> 1_u32;
        if half_n.is_odd() && self_mod_n <= half_n || self_mod_n < half_n {
            self_mod_n
        } else {
            self_mod_n - n
        }
    }

    fn to_bytes_be(&self) -> (Sign, Vec<u8>) {
        let (sign, digits) = self.to_bytes_be();
        (sign, digits)
    }

    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self> {
        if exp.is_negative() {
            // For negative exponents: x^(-n) mod m = (x^(-1) mod m)^n mod m
            let base_inverse = self.clone().modinv(modulo)?;
            let positive_exp = -exp.clone();
            Some(base_inverse.modpow(&positive_exp, modulo))
        } else {
            // For positive exponents, use regular modpow
            Some(self.modpow(exp, modulo))
        }
    }
}

/// Error indicating that computation cannot be evaluated because of bad exponent
///
/// Returned by [`BigNumberExt::powmod`] and other functions that do exponentiation internally
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(transparent)]
pub struct BadExponent(#[from] BadExponentReason);

impl BadExponent {
    /// Constructs an error that exponent is undefined
    pub fn undefined() -> Self {
        Self(BadExponentReason::Undefined)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum BadExponentReason {
    #[error("exponent is undefined")]
    Undefined,
    #[error("multiexp error: exponent size is too large (exponents size: {exp_size:?}, max exponent size: {max_exp_size:?})")]
    ExpSize {
        exp_size: (u32, u32),
        max_exp_size: (usize, usize),
    },
}

/// Returns `Err(err)` if `assertion` is false
pub fn fail_if<E>(err: E, assertion: bool) -> Result<(), E> {
    if assertion {
        Ok(())
    } else {
        Err(err)
    }
}

/// Returns `Err(err)` if `lhs != rhs`
pub fn fail_if_ne<T: PartialEq, E>(err: E, lhs: T, rhs: T) -> Result<(), E> {
    if lhs == rhs {
        Ok(())
    } else {
        Err(err)
    }
}

pub mod encoding {

    /// Digests a rug integer
    pub struct BigInt;
    impl udigest::DigestAs<num_bigint::BigInt> for BigInt {
        fn digest_as<B: udigest::Buffer>(
            value: &num_bigint::BigInt,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let (_, digits) = value.to_bytes_be();
            encoder.encode_leaf_value(digits)
        }
    }
    /// Digests any encryption key
    pub struct AnyEncryptionKey;
    impl udigest::DigestAs<&dyn fast_paillier::AnyEncryptionKey> for AnyEncryptionKey {
        fn digest_as<B: udigest::Buffer>(
            value: &&dyn fast_paillier::AnyEncryptionKey,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            BigInt::digest_as(value.n(), encoder)
        }
    }
}

/// A common logic shared across tests and doctests
pub mod test {
    use super::BigIntExt;
    use num_bigint::BigInt;
    use num_bigint::RandBigInt;
    use num_integer::Integer;
    use num_traits::Num;

    pub fn sample_key() -> fast_paillier::DecryptionKey {
        fast_paillier::DecryptionKey::sample_128()
    }

    pub fn sample_other_key() -> fast_paillier::DecryptionKey {
        fast_paillier::DecryptionKey::sample_other_128()
    }

    pub fn random_key(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Result<fast_paillier::DecryptionKey, fast_paillier::Error> {
        fast_paillier::DecryptionKey::generate(rng, 2048, 448)
    }

    pub fn sample_aux<R: rand_core::RngCore>(rng: &mut R) -> super::Aux {
        let dk = fast_paillier::DecryptionKey::sample_128();
        let p = dk.p();
        let q = dk.q();
        let n = p * q;

        let (s, t) = {
            let phi_n = (p.clone() - 1u8) * (q.clone() - 1u8);
            let r = BigInt::gen_invertible(&n, rng);
            let lambda = rng.gen_bigint_range(&BigInt::ZERO, &phi_n);

            let t = (&r * &r) % &n;
            let s = t.modpow(&lambda, &n);

            (s, t)
        };

        super::Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        }
    }

    pub fn aux<R: rand_core::RngCore>(rng: &mut R) -> super::Aux {
        // let p = generate_blum_prime(rng, 1024);
        // let q = generate_blum_prime(rng, 1024);

        // Because generating primes is slow, we use hardcoded values
        let p = BigInt::from_str_radix("119718298173119878105125282170952301903604788836137192672971085086931697454850578932741977173627414449815867352984108049440807338548948797578442102781940057113712352026131358062988204403634623787863403524694314770165787749649165099519120341381625516324331282224170802953909133093459522735120382898061575755427", 10).unwrap();
        let q = BigInt::from_str_radix("90684028399912762319968138686204104120379010978734483157509623196436980870215927551569968173582391210838773744285614231471344350473494545770380636071402624403290484788376380599113518289534999987953418185019079958140799840748557330172676687793563591522131283238279656530154885714292887606570952169867532646327", 10).unwrap();
        assert_eq!(&p % 4, BigInt::from(3));
        assert_eq!(&q % 4, BigInt::from(3));

        let n = &p * &q;

        let (s, t) = {
            let phi_n = (p.clone() - 1u8) * (q.clone() - 1u8);
            let r = BigInt::gen_invertible(&n, rng);
            let lambda = rng.gen_bigint_range(&BigInt::ZERO, &phi_n);

            let t = (&r * &r).mod_floor(&n);
            let s = t.modpow(&lambda, &n);

            (s, t)
        };

        super::Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        }
    }

    pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> BigInt {
        loop {
            let n = generate_prime(rng, bits_size);
            if &n % 4 == BigInt::from(3) {
                println!("Generated prime: {}", n);
                break n;
            }
        }
    }

    pub fn generate_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> BigInt {
        fast_paillier::utils::generate_safe_prime(rng, bits_size)
    }
}

#[cfg(test)]
mod _test {
    use num_bigint::BigInt;

    use super::BigIntExt;

    #[test]
    fn test_modpow_ext() {
        // Test case 1: Positive exponent
        let base = BigInt::from(3);
        let exp = BigInt::from(5);
        let modulo = BigInt::from(10);
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        let expected = base.modpow(&exp, &modulo);
        assert_eq!(result, expected);

        // Test case 2: Negative exponent
        let exp_neg = BigInt::from(-5);
        let result_neg = base.modpow_ext(&exp_neg, &modulo).unwrap();

        // Since 3^5 mod 10 = 3, we need modinv(3, 10)
        // So: 3^(-5) ≡ modinv(3, 10) = 7
        // => 7 is inverse of 3 mod 10, and (7^5) % 10 = 7
        let expected = BigInt::from(7);
        assert_eq!(result_neg, expected);

        // Test case 3: Positive and Negative exponent with prime modulo
        let base = BigInt::from(7);
        let exp = BigInt::from(13);
        let modulo = BigInt::from(31); // prime modulo

        // Positive exponent
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        let expected = base.modpow(&exp, &modulo);
        assert_eq!(result, expected);

        // Negative exponent
        let exp_neg = BigInt::from(-13);
        let result_neg = base.modpow_ext(&exp_neg, &modulo).unwrap();

        // Compute base^-13 mod 31 = (modinv(base, 31))^13 mod 31
        let base_inv = base.modinv(&modulo).unwrap();
        let expected = base_inv.modpow(&(-exp_neg), &modulo);
        assert_eq!(result_neg, expected);
    }
}
