//! ZK-proof for factoring of a RSA modulus. Called Пfac or Rfac in the CGGMP21
//! paper.
//!
//! ## Description
//!
//! A party P has a modulus `N = pq`. P wants to prove to a verifier V that p
//! and q are sufficiently large without disclosing p or q, with p and q each no
//! larger than `sqrt(N) * 2^l`, or equivalently no smaller than `sqrt(N) /
//! 2^l`
//!
//! Because of key generation algorithm of optimized paillier, l should be at least 3
//!
//! ## Example
//!
//! ```rust
//! use rug::{Integer, Complete};
//! use paillier_zk::no_small_factor::non_interactive as p;
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #     );
//! # }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let shared_state = "some shared state";
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Setup: prover and verifier share common Ring-Pedersen parameters, and
//! // agree on the level of security
//!
//! let aux: p::Aux = pregenerated::verifier_aux();
//! let security = p::SecurityParams {
//!     l: 4,
//!     epsilon: 128,
//!     q: (Integer::ONE << 128_u32),
//! };
//!
//! // 1. Prover prepares the data to obtain proof about
//!
//! let p = fast_paillier::utils::generate_safe_prime(&mut rng, 256);
//! let q = fast_paillier::utils::generate_safe_prime(&mut rng, 256);
//! let n = (&p * &q);
//! let n_root = n.sqrt_ref();
//! let data = p::Data {
//!     n: &n,
//!     n_root: &n_root,
//! };
//!
//! // 2. Prover computes a non-interactive proof that both factors are large enough
//!
//! let proof = p::prove::<sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     p::PrivateData { p: &p, q: &q },
//!     &security,
//!     &mut rng,
//! )?;
//!
//! // 4. Prover sends this data to verifier
//!
//! # fn send(_: &Integer, _: &p::Proof) {  }
//! send(data.n, &proof);
//!
//! // 5. Verifier receives the data and the proof and verifies it
//!
//! # let recv = || (data.n, proof);
//! let (n, proof) = recv();
//! let n_root = n.sqrt_ref();;
//! let data = p::Data {
//!     n: &n,
//!     n_root: &n_root,
//! };
//! p::verify::<sha2::Sha256>(&shared_state, &aux, data, &security, &proof)?;
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

use fast_paillier::utils::serde_wrapper::{serializable_bigint, serializable_vec_bigint};
use num_bigint::BigInt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::{Aux, InvalidProof};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// l in paper, security parameter for bit size of plaintext: it needs to
    /// differ from sqrt(n) not more than by 2^l
    /// l should be at least 3
    pub l: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
    /// q in paper. Security parameter for challenge
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub q: BigInt,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    /// N0 - rsa modulus
    #[udigest(as = &crate::common::encoding::BigInt)]
    // #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub n: &'a BigInt,
    /// A number close to square root of n
    #[udigest(as = &crate::common::encoding::BigInt)]
    // #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub n_root: &'a BigInt,
}

/// Private data of prover
#[derive(Debug, Clone, Copy)]
pub struct PrivateData<'a> {
    // #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub p: &'a BigInt,
    // #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub q: &'a BigInt,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrivateCommitment {
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub alpha: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub beta: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub mu: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub nu: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub r: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub x: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub y: BigInt,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub p: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub q: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub a: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub b: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub t: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub sigma: BigInt,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = BigInt;

/// The ZK proof, computed by [`interactive::prove`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z1: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z2: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub w1: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub w2: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub v: BigInt,
}

/// Interactive version of the proof
pub mod interactive {
    use rand_core::RngCore;
    use num_bigint::BigInt;
    use crate::common::BigIntExt;
    use crate::{
        common::{fail_if, fail_if_ne, InvalidProofReason},
        Error,
    };

    use super::{
        Aux, Challenge, Commitment, Data, InvalidProof, PrivateCommitment, PrivateData, Proof,
        SecurityParams,
    };

    /// Create random commitment
    pub fn commit<R: RngCore>(
        aux: &Aux,
        data: Data,
        pdata: PrivateData,
        security: &SecurityParams,
        mut rng: R,
    ) -> Result<(Commitment, PrivateCommitment), Error> {
        let two_to_l = (BigInt::from(1) << security.l);
        let two_to_l_plus_e = (BigInt::from(1) << (security.l + security.epsilon));
        let n_root_modulo = (&two_to_l_plus_e * data.n_root);
        let l_n_circ_modulo = (&two_to_l * &aux.rsa_modulo);
        let l_e_n_circ_modulo = (&two_to_l_plus_e * &aux.rsa_modulo);
        let n_n_circ = (&aux.rsa_modulo * data.n);

        let alpha = BigInt::from_rng_pm(&n_root_modulo, &mut rng);
        let beta = BigInt::from_rng_pm(&n_root_modulo, &mut rng);
        let mu = BigInt::from_rng_pm(&l_n_circ_modulo, &mut rng);
        let nu = BigInt::from_rng_pm(&l_n_circ_modulo, &mut rng);
        let sigma = BigInt::from_rng_pm(&(&two_to_l * &n_n_circ), &mut rng);
        let r = BigInt::from_rng_pm(&(&two_to_l_plus_e * &n_n_circ), &mut rng);
        let x = BigInt::from_rng_pm(&l_e_n_circ_modulo, &mut rng);
        let y = BigInt::from_rng_pm(&l_e_n_circ_modulo, &mut rng);

        let p = aux.combine(pdata.p, &mu)?;
        let q = aux.combine(pdata.q, &nu)?;
        let a = aux.combine(&alpha, &x)?;
        let b = aux.combine(&beta, &y)?;
        let t = aux.rsa_modulo.combine(&q, &alpha, &aux.t, &r)?;

        let commitment = Commitment {
            p,
            q,
            a,
            b,
            t,
            sigma,
        };
        let private_commitment = PrivateCommitment {
            alpha,
            beta,
            mu,
            nu,
            r,
            x,
            y,
        };
        Ok((commitment, private_commitment))
    }

    /// Generate random challenge
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge<R: RngCore>(security: &SecurityParams, rng: &mut R) -> Challenge {
        BigInt::from_rng_pm(&security.q, rng)
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove(
        pdata: PrivateData,
        comm: &Commitment,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        let sigma_circ = (&comm.sigma - &pcomm.nu * pdata.p);

        Ok(Proof {
            z1: (&pcomm.alpha + challenge * pdata.p),
            z2: (&pcomm.beta + challenge * pdata.q),
            w1: (&pcomm.x + challenge * &pcomm.mu),
            w2: (&pcomm.y + challenge * &pcomm.nu),
            v: &pcomm.r + challenge * sigma_circ,
        })
    }

    /// Verify the proof
    pub fn verify(
        aux: &Aux,
        data: Data,
        commitment: &Commitment,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        // check 1
        {
            let lhs = aux.combine(&proof.z1, &proof.w1)?;
            let p_to_e = aux.pow_mod(&commitment.p, challenge)?;
            let rhs = (&commitment.a * p_to_e) % &aux.rsa_modulo;
            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }
        // check 2
        {
            let lhs = aux.combine(&proof.z2, &proof.w2)?;
            let q_to_e = aux.pow_mod(&commitment.q, challenge)?;
            let rhs = (&commitment.b * q_to_e) % &aux.rsa_modulo;
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        // check 3
        {
            let r = aux.combine(data.n, &commitment.sigma)?;
            let q_to_z1 = aux.pow_mod(&commitment.q, &proof.z1)?;
            let t_to_v = aux.pow_mod(&aux.t, &proof.v)?;
            let lhs = (q_to_z1 * t_to_v) % &aux.rsa_modulo;
            let rhs = aux
                .rsa_modulo
                .combine(&commitment.t, &BigInt::from(1), &r, challenge)?;
            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }
        let range = (BigInt::from(1) << (security.l + security.epsilon)) * data.n_root;
        // range check for z1
        fail_if(InvalidProofReason::RangeCheck(1), proof.z1.is_in_pm(&range))?;
        // range check for z2
        fail_if(InvalidProofReason::RangeCheck(2), proof.z2.is_in_pm(&range))?;

        Ok(())
    }
}

/// Non-interactive version of the proof
pub mod non_interactive {
    use digest::Digest;

    pub use crate::{Error, InvalidProof};

    pub use super::{Aux, Challenge, Data, PrivateData, SecurityParams};

    /// The ZK proof, computed by [`prove`]
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Proof {
        commitment: super::Commitment,
        proof: super::Proof,
    }

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<Proof, Error> {
        let (commitment, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<D>(shared_state, aux, data, &commitment, security);
        let proof = super::interactive::prove(pdata, &commitment, &pcomm, &challenge)?;
        Ok(Proof { commitment, proof })
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        commitment: &super::Commitment,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.no_small_factor.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            security,
            aux: aux.digest_public_data(),
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(&seed);
        super::interactive::challenge(security, &mut rng)
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        security: &SecurityParams,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<D>(shared_state, aux, data, &proof.commitment, security);
        super::interactive::verify(
            aux,
            data,
            &proof.commitment,
            security,
            &challenge,
            &proof.proof,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::common::test::generate_blum_prime;
    use crate::common::InvalidProofReason;
    use num_bigint::BigInt;

    // If q > 2^epsilon, the proof will never pass. We can make l however small
    // we wish though, provided the statement we want to prove holds

    #[test]
    fn passing() {
        type D = sha2::Sha256;

        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = generate_blum_prime(&mut rng, 256);
        let n = (&p * &q);
        let n_root = n.sqrt();
        let data = super::Data {
            n: &n,
            n_root: &n_root,
        };
        let security = super::SecurityParams {
            l: 64,
            epsilon: 128,
            q: (BigInt::from(1) << 128_u32),
        };
        let aux = crate::common::test::aux(&mut rng);
        let shared_state = "shared state";
        let proof = super::non_interactive::prove::<D>(
            &shared_state,
            &aux,
            data,
            super::PrivateData { p: &p, q: &q },
            &security,
            &mut rng,
        )
        .unwrap();
        let r = super::non_interactive::verify::<D>(&shared_state, &aux, data, &security, &proof);
        match r {
            Ok(()) => (),
            Err(e) => panic!("Proof should not fail with {e:?}"),
        }
    }

    #[test]
    fn failing() {
        type D = sha2::Sha256;

        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 128);
        let q = generate_blum_prime(&mut rng, 384);
        let n = (&p * &q);
        let n_root = n.sqrt();
        let data = super::Data {
            n: &n,
            n_root: &n_root,
        };
        let security = super::SecurityParams {
            l: 4,
            epsilon: 128,
            q: (BigInt::from(1) << 128_u32),
        };
        let aux = crate::common::test::aux(&mut rng);
        let shared_state = "shared state";
        let proof = super::non_interactive::prove::<D>(
            &shared_state,
            &aux,
            data,
            super::PrivateData { p: &p, q: &q },
            &security,
            &mut rng,
        )
        .unwrap();
        let r = super::non_interactive::verify::<D>(&shared_state, &aux, data, &security, &proof)
            .expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(2) => (),
            e => panic!("Proof should not fail with {e:?}"),
        }
    }

    #[test]
    fn test_sqrt() {
        assert_eq!(BigInt::from(1).sqrt(), BigInt::from(1));
        assert_eq!(BigInt::from(2).sqrt(), BigInt::from(1));
        assert_eq!(BigInt::from(3).sqrt(), BigInt::from(1));
        assert_eq!(BigInt::from(4).sqrt(), BigInt::from(2));
        assert_eq!(BigInt::from(5).sqrt(), BigInt::from(2));
        assert_eq!(BigInt::from(6).sqrt(), BigInt::from(2));
        assert_eq!(BigInt::from(7).sqrt(), BigInt::from(2));
        assert_eq!(BigInt::from(8).sqrt(), BigInt::from(2));
        assert_eq!(BigInt::from(9).sqrt(), BigInt::from(3));
    }
}
