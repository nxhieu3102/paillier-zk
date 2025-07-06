//! ZK-proof of Paillier-Blum modulus. Called Пmod or Rmod in the CGGMP21 paper.
//!
//! ## Description
//! A party P has a modulus `N = pq`, with p and q being Blum primes, and
//! `gcd(N, phi(N)) = 1`. P wants to prove that those equalities about N hold,
//! without disclosing p and q.
//!
//! ## Example
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use malachite::Integer;
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Prover P derives two Blum primes and makes a Paillier-Blum modulus
//! let p = fast_paillier::utils::generate_safe_prime(&mut rng, 256);
//! let q = fast_paillier::utils::generate_safe_prime(&mut rng, 256);
//! let n = (&p * &q);
//!
//! // 1. P computes a non-interactive proof that `n` is a Paillier-Blum modulus:
//! use paillier_zk::paillier_blum_modulus as p;
//!
//! // Security parameter
//! const SECURITY: usize = 33;
//! // Verifier and prover share the same state
//! let shared_state = "some shared state";
//!
//! let data = p::Data { n };
//! let pdata = p::PrivateData { p, q };
//!
//! let (commitment, proof) =
//!     p::non_interactive::prove::<{SECURITY}, sha2::Sha256>(
//!         &shared_state,
//!         &data,
//!         &pdata,
//!         &mut rng,
//!     )?;
//!
//! // 2. P sends `data, commitment, proof` to the verifier V
//!
//! # fn send(_: &p::Data, _: &p::Commitment, _: &p::Proof<{SECURITY}>) { }
//! send(&data, &commitment, &proof);
//!
//! // 3. V receives and verifies the proof:
//!
//! # let recv = || (data, commitment, proof);
//! let (data, commitment, proof) = recv();
//!
//! p::non_interactive::verify::<{SECURITY}, sha2::Sha256>(
//!     &shared_state,
//!     &data,
//!     &commitment,
//!     &proof,
//! )?;
//! # Ok(()) }
//! ```
//! If the verification succeeded, V can continue communication with P
use malachite::Integer;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
/// Public data that both parties know: the Paillier-Blum modulus
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Data {
    #[udigest(as = crate::common::encoding::Integer)]
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub n: Integer,
}

/// Private data of prover
#[derive(Clone)]
pub struct PrivateData {
    pub p: Integer,
    pub q: Integer,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    #[udigest(as = crate::common::encoding::Integer)]
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub w: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
///
/// Consists of `M` singular challenges
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Challenge<const M: usize> {
    pub ys: [Integer; M],
}

/// A part of proof. Having enough of those guarantees security
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofPoint {
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub x: Integer,
    pub a: bool,
    pub b: bool,
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub z: Integer,
}

/// The ZK proof. Computed by [`interactive::prove`] or
/// [`non_interactive::prove`]. Consists of M proofs for each challenge
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof<const M: usize> {
    #[cfg_attr(
        // A trick to serialize arbitrary size arrays
        feature = "serde",
        serde(with = "serde_with::As::<[serde_with::Same; M]>")
    )]
    pub points: [ProofPoint; M],
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use rand_core::RngCore;
    use crate::integer_ext::mod_inverse_int;
    use crate::common::sqrt::{blum_sqrt, find_residue, sample_neg_jacobi};
    use crate::{BadExponent, Error, ErrorReason, InvalidProof};
    use crate::common::InvalidProofReason;
    use super::{Challenge, Commitment, Data, PrivateData, Proof, ProofPoint};
    use crate::integer_ext::mod_pow_int;
    use malachite::Integer;
    use malachite_base::num::arithmetic::traits::Parity;
    use fast_paillier::utils::is_prime;
    use malachite_base::num::arithmetic::traits::Mod;
    use crate::integer_ext::IntegerExt;
    /// Create random commitment
    pub fn commit<R: RngCore>(Data { ref n }: &Data, rng: &mut R) -> Commitment {
        Commitment {
            w: sample_neg_jacobi(n, rng),
        }
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<const M: usize>(
        Data { ref n }: &Data,
        PrivateData { ref p, ref q }: &PrivateData,
        Commitment { ref w }: &Commitment,
        challenge: &Challenge<M>,
    ) -> Result<Proof<M>, Error> {
        let blum_sqrt = |x| blum_sqrt(&x, p, q, n);
        let phi = (p - Integer::from(1u8)) * (q - Integer::from(1u8));
        let n_inverse = mod_inverse_int(&n, &phi).ok_or(ErrorReason::Invert)?;

        // We do an extra allocation as workaround while `array::try_map` is not stable
        let points = challenge
            .ys
            .iter()
            .map(|y| {
                let z = mod_pow_int(y, &n_inverse, n);
                let (a, b, y_) = find_residue(y, w, p, q, n).ok_or(ErrorReason::FindResidue)?;
                let x = blum_sqrt(blum_sqrt(y_));
                Ok(ProofPoint { x, a, b, z })
            })
            .collect::<Result<Vec<_>, ErrorReason>>()?
            .try_into()
            .map_err(|_| ErrorReason::Length)?;
        Ok(Proof { points })
    }

    /// Verify the proof. If this succeeds, the relation Rmod holds with chance
    /// `1/2^M`
    pub fn verify<const M: usize>(
        data: &Data,
        commitment: &Commitment,
        challenge: &Challenge<M>,
        proof: &Proof<M>,
    ) -> Result<(), InvalidProof> {
        if is_prime(&data.n) {
            return Err(InvalidProofReason::ModulusIsPrime.into());
        }
        if data.n.even() {
            return Err(InvalidProofReason::ModulusIsEven.into());
        }
        for (point, y) in proof.points.iter().zip(challenge.ys.iter()) {
            if mod_pow_int(&point.z, &data.n, &data.n) != *y
            {
                return Err(InvalidProofReason::IncorrectNthRoot.into());
            }
            let y = y.clone();
            let y = if point.a { &data.n - y } else { y };
            let y = if point.b {
                (y * &commitment.w).mod_op(&data.n)
            } else {
                y
            };
            if mod_pow_int(&point.x, &Integer::from(4u8), &data.n) != y
            {
                return Err(InvalidProofReason::IncorrectFourthRoot.into());
            }
        }
        Ok(())
    }

    /// Generate random challenge
    ///
    /// `data` parameter is used to generate challenge in correct range
    pub fn challenge<const M: usize, R: RngCore>(
        Data { ref n }: &Data,
        rng: &mut R,
    ) -> Challenge<M> {
        let ys = [(); M].map(|()| {
            n.random_below(rng)
                .into()
        });
        Challenge { ys }
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use crate::integer_ext::IntegerExt;
    use crate::{Error, InvalidProof};

    use super::{Challenge, Commitment, Data, PrivateData, Proof};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: &Data,
        pdata: &PrivateData,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Commitment, Proof<M>), Error> {
        let commitment = super::interactive::commit(data, rng);
        let challenge = challenge::<M, D>(shared_state, data, &commitment);
        let proof = super::interactive::prove(data, pdata, &commitment, &challenge)?;
        Ok((commitment, proof))
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: &Data,
        commitment: &Commitment,
        proof: &Proof<M>,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<M, D>(shared_state, data, commitment);
        super::interactive::verify(data, commitment, &challenge, proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: &Data,
        commitment: &Commitment,
    ) -> Challenge<M> {
        let tag = "paillier_zk.blum_modulus.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        // since we can't use Default and Integer isn't copy, we initialize
        // like this
        let ys = [(); M].map(|()| {
            data.n
                .random_below(&mut rng)
                .into()
        });
        Challenge { ys }
    }
}

#[cfg(test)]
mod test {
    use malachite::Integer;
    use crate::common::test::{generate_blum_prime};
    use malachite_base::num::conversion::traits::FromStringBase;
    type D = sha2::Sha256;

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = generate_blum_prime(&mut rng, 256);
        let n = (&p * &q);
        let data = super::Data { n };
        let pdata = super::PrivateData { p, q };
        let shared_state = "shared state";
        let (commitment, proof) =
            super::non_interactive::prove::<65, D>(&shared_state, &data, &pdata, &mut rng).unwrap();
        let r = super::non_interactive::verify::<65, D>(&shared_state, &data, &commitment, &proof);
        match r {
            Ok(()) => (),
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn failing() {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = Integer::from_string_base(10, "83068444371047794141187595475503751543138564039474151978032204006692380162693").unwrap();
        let n = (&p * &q);
        let data = super::Data { n };
        let pdata = super::PrivateData { p, q };
        let shared_state = "shared state";
        let (commitment, proof) =
            super::non_interactive::prove::<65, D>(&shared_state, &data, &pdata, &mut rng).unwrap();
        let r = super::non_interactive::verify::<65, D>(&shared_state, &data, &commitment, &proof);
        if r.is_ok() {
            panic!("proof should not pass");
        }
    }
}
