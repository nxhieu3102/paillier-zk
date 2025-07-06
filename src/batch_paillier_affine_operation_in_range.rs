//! Zero-knowledge proof of a Paillier affine operation with range bounds and group commitment.
//!
//! This module implements a batched version of the Π_aff-g protocol (called Raff-g in the CGGMP21 paper).
//! It allows a prover to efficiently prove knowledge of multiple plaintexts `x_i`, `y_i` used in encrypted
//! affine computations of the form:
//!
//! ```text
//!     D_i = C_i * x_i + Enc(y_i)
//! ```
//!
//! where:
//! - `C_i` is an encrypted value under public key `key0`,
//! - `Y_i = Enc_key1(y_i)` is `y_i` encrypted under a separate key `key1`,
//! - `X_i = g * x_i` is a group commitment to `x_i` using generator `g` of a group of order `q`,
//! - `D_i` is computed using Paillier homomorphic operations on `C_i` and `Enc_key0(y_i)`.
//!
//! The goal is to prove in zero-knowledge that all `x_i` and `y_i` are within known bitlength bounds (`l_x`, `l_y`),
//! without revealing their values.
//!
//! ## Protocol Inputs
//!
//! For each instance `i` in the batch, the prover uses:
//! - Paillier public keys: `key0` for `C_i`, `D_i` and `key1` for `Y_i`
//! - Plaintexts: `x_i`, `y_i`
//! - Nonces used during encryption: `nonce_i`, `nonce_y_i`
//! - Group parameters: `g`, `q` where `<g> = Zq*`
//! - Encrypted values: `C_i`, `Y_i`, `X_i`, `D_i`
//!
//! The verifier only receives public data: `key0`, `key1`, all `C_i`, `D_i`, `X_i`, and `Y_i`.
//!
//! ## Batched Proof
//!
//! Unlike the original protocol which handles a single affine statement, this implementation supports
//! proving and verifying multiple such statements in one batch. This greatly improves efficiency when
//! dealing with many encrypted computations.
//!
//! ## Proves
//!
//! For each i-th element in the batch:
//! - `|x_i| < 2^l_x`
//! - `|y_i| < 2^l_y`
//!
//! ## Example
//!
//! See full example in the documentation below, where both prover and verifier perform the setup,
//! generate commitments and proofs, and finally verify the batched zero-knowledge proof.

pub use crate::common::{Aux, InvalidProof};
pub use crate::integer_ext::IntegerExt;
use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce};
use generic_ec::{Curve, Point};
use malachite::Integer;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// l in paper, bit size of +-x
    pub l_x: usize,
    /// l' in paper, bit size of +-y
    pub l_y: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
    /// q in paper. Security parameter for challenge
    #[udigest(as = crate::common::encoding::Integer)]
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub q: Integer,
    /// size of challenge
    pub t: usize,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct PublicElement<C: Curve> {
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub c: Ciphertext,
    pub x: Point<C>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub d: Ciphertext,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub y: Ciphertext,
}

impl<C: Curve> PublicElement<C> {
    /// Returns a stripped version of `PublicData` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.public_element" {
            c: udigest::Bytes(self.c.to_string().into_bytes()),
            x: udigest::Bytes(self.x.to_bytes(true)),
            d: udigest::Bytes(self.d.to_string().into_bytes()),
            y: udigest::Bytes(self.y.to_string().into_bytes()),
        })
    }
}

/// Public data that both parties know
#[derive(Debug, Clone)]
pub struct PublicData<'a, C: Curve> {
    /// N0 in paper, public key that C was encrypted on
    // #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key0: &'a dyn AnyEncryptionKey,
    /// N1 in paper, public key that y -> Y was encrypted on
    // #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key1: &'a dyn AnyEncryptionKey,
    pub batch: Vec<PublicElement<C>>,
}

impl<'a, C: Curve> PublicData<'a, C> {
    /// Returns a stripped version of `PublicData` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.public_data" {
            key0: udigest::Bytes(self.key0.n().to_string().into_bytes()),
            key1: udigest::Bytes(self.key1.n().to_string().into_bytes()),
            batch: self.batch.iter().map(|e| e.digest_public_data()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PrivateElement<'a> {
    pub x: &'a Integer,
    pub y: &'a Integer,
    pub nonce: &'a Nonce,
    pub nonce_y: &'a Nonce,
}

/// Private data of prover
#[derive(Debug, Clone)]
pub struct PrivateData<'a> {
    pub batch: Vec<PrivateElement<'a>>,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<C: Curve> {
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub a: Ciphertext,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_vec_bigint")
    )]
    pub s: Vec<Integer>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_vec_bigint")
    )]
    pub e: Vec<Integer>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub f: Integer,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_vec_bigint")
    )]
    pub t: Vec<Integer>,
    pub b_x: Vec<Point<C>>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub b_y: Integer,
}

impl<C: Curve> Commitment<C> {
    /// Returns a stripped version of `Commitment` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.commitment" {
            a: udigest::Bytes(self.a.to_string().into_bytes()),
            s: self.s.iter().map(|s| udigest::Bytes(s.to_string().into_bytes())).collect::<Vec<_>>(),
            e: self.e.iter().map(|e| udigest::Bytes(e.to_string().into_bytes())).collect::<Vec<_>>(),
            f: udigest::Bytes(self.f.to_string().into_bytes()),
            t: self.t.iter().map(|t| udigest::Bytes(t.to_string().into_bytes())).collect::<Vec<_>>(),
            b_x: self.b_x.iter().map(|b_x| udigest::Bytes(b_x.to_bytes(true))).collect::<Vec<_>>(),
            b_y: udigest::Bytes(self.b_y.to_string().into_bytes()),
        })
    }
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment {
    pub m: Vec<Integer>,
    pub mu: Vec<Integer>,
    pub alpha: Vec<Integer>,
    pub gamma: Vec<Integer>,
    pub beta: Integer,
    pub r: Integer,
    pub delta: Integer,
    pub r_y: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Vec<Integer>;

/// The ZK proof. Computed by [`interactive::prove`] or
/// [`non_interactive::prove`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_vec_bigint")
    )]
    pub z1: Vec<Integer>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub z2: Integer,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_vec_bigint")
    )]
    pub z3: Vec<Integer>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub z4: Integer,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub w: Integer,
    #[cfg_attr(
        feature = "serde",
        serde(with = "fast_paillier::utils::serializable_bigint")
    )]
    pub w_y: Integer,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use generic_ec::{Curve, Point};
    use malachite::Integer;
    use rand_core::RngCore;
    use fast_paillier::integer_ext::mod_pow_int;
    use malachite_base::num::arithmetic::traits::Mod;
    use crate::common::{fail_if, fail_if_ne, InvalidProof, InvalidProofReason};
    use crate::Error;

    use super::*;

    /// Create random commitment
    pub fn commit<C: Curve, R: RngCore>(
        aux: &Aux,
        data: PublicData<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        batch_size: usize,
        mut rng: R,
    ) -> Result<(Commitment<C>, PrivateCommitment), Error> {
        let two_to_l = Integer::from(1) << security.l_x;
        let two_to_l_y = Integer::from(1) << security.l_y;
        let two_to_l_e_t = Integer::from(1) << (security.l_x + security.epsilon + security.t);
        let two_to_l_prime_e_t = Integer::from(1) << (security.l_y + security.epsilon + security.t);
        let hat_n_at_two_to_l = &aux.rsa_modulo * &two_to_l;
        let hat_n_at_two_to_l_y = &aux.rsa_modulo * &two_to_l_y;
        let hat_n_at_two_to_l_e_t = &aux.rsa_modulo * &two_to_l_e_t;
        let hat_n_at_two_to_l_prime_e_t = &aux.rsa_modulo * &two_to_l_prime_e_t;

        let m = vec![Integer::from_rng_pm(&hat_n_at_two_to_l, &mut rng); batch_size];
        let mu = vec![Integer::from_rng_pm(&hat_n_at_two_to_l_y, &mut rng); batch_size];
        let alpha = vec![Integer::from_rng_pm(&two_to_l_e_t, &mut rng); batch_size];
        let gamma = vec![Integer::from_rng_pm(&hat_n_at_two_to_l_e_t, &mut rng); batch_size];
        let beta = Integer::from_rng_pm(&two_to_l_prime_e_t, &mut rng);
        // let r = data.key0.n().rand_below(&mut rng);
        use malachite_base::num::basic::traits::Zero;
        let r = Integer::rand_in_range(&mut rng, Integer::ZERO, Integer::from(1) << data.key0.nounce_size());
        use malachite_base::num::logic::traits::SignificantBits;
        std::println!("r: {}", r.significant_bits());
        std::println!("nonce size: {}", data.key0.nounce_size());
        let delta = Integer::from_rng_pm(&hat_n_at_two_to_l_prime_e_t, &mut rng);
        let r_y = fast_paillier::utils::sample_with_size(&mut rng, data.key1.nounce_size());

        let beta_enc_key0 = data.key0.encrypt_with(&beta, &r)?;
        // ∏(c_i^alpha_i) * enc_n0(beta, r)
        let a = data
            .batch
            .iter()
            .zip(alpha.iter())
            .fold(beta_enc_key0, |acc, (element, a)| {
                let c_at_a = data.key0.omul(&a, &element.c).unwrap();
                data.key0.oadd(&acc, &c_at_a).unwrap()
            });

        let s = pdata
            .batch
            .iter()
            .zip(m.iter())
            .map(|(element, m_i)| aux.combine(&element.x, &m_i).unwrap())
            .collect();

        let e = alpha
            .iter()
            .zip(gamma.iter())
            .map(|(alpha_i, gamma_i)| aux.combine(&alpha_i, &gamma_i).unwrap())
            .collect();

        let f = aux.combine(&beta, &delta).unwrap();

        let t = pdata
            .batch
            .iter()
            .zip(mu.iter())
            .map(|(element, mu_i)| aux.combine(&element.y, &mu_i).unwrap())
            .collect();

        let b_x = alpha
            .iter()
            .map(|alpha_i| Point::<C>::generator() * alpha_i.to_scalar())
            .collect();

        let b_y = data.key1.encrypt_with(&beta, &r_y)?;

        let commitment = Commitment {
            a,
            s,
            e,
            f,
            t,
            b_x,
            b_y,
        };
        let private_commitment = PrivateCommitment {
            alpha,
            beta,
            r,
            r_y,
            gamma,
            m,
            delta,
            mu,
        };
        Ok((commitment, private_commitment))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<C: Curve>(
        _data: PublicData<C>,
        pdata: PrivateData,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        let z1 = pcomm
            .alpha
            .iter()
            .zip(challenge.iter())
            .zip(pdata.batch.iter())
            .map(|((alpha_i, challenge_i), element)| alpha_i + challenge_i * element.x)
            .collect();

        let z2 = pdata
            .batch
            .iter()
            .zip(challenge.iter())
            .fold(pcomm.beta.clone(), |acc, (element, challenge_i)| {
                acc + challenge_i * element.y
            });

        let z3 = pcomm
            .gamma
            .iter()
            .zip(challenge.iter())
            .zip(pcomm.m.iter())
            .map(|((gamma_i, challenge_i), m_i)| gamma_i + challenge_i * m_i)
            .collect();

        let z4 = pcomm
            .mu
            .iter()
            .zip(challenge.iter())
            .fold(pcomm.delta.clone(), |acc, (mu_i, challenge_i)| {
                acc + challenge_i * mu_i
            });

        let w = pdata
            .batch
            .iter()
            .zip(challenge.iter())
            .fold(pcomm.r.clone(), |acc, (element, challenge_i)| {
                std::println!("challenge_i: {}", challenge_i.significant_bits());
                acc + element.nonce * challenge_i
            });
        use malachite_base::num::logic::traits::SignificantBits;
        std::println!("w: {}", w.significant_bits());
        std::println!("nonce size: {}", _data.key0.nounce_size());
            
        let w_y = pdata
            .batch
            .iter()
            .zip(challenge.iter())
            .fold(pcomm.r_y.clone(), |acc, (element, challenge_i)| {
                acc + element.nonce_y * challenge_i
            });

        Ok(Proof {
            z1,
            z2,
            z3,
            z4,
            w,
            w_y,
        })
    }

    /// Verify the proof
    pub fn verify<C: Curve>(
        aux: &Aux,
        data: PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        // Five equality checks and two range checks

        {
            let lhs = proof.z1.iter().zip(data.batch.iter()).fold(
                data.key0.encrypt_with(&proof.z2, &proof.w).unwrap(),
                |acc, (z1_i, element)| {
                    let z1_i_at_c = data.key0.omul(&z1_i, &element.c).unwrap();
                    data.key0.oadd(&acc, &z1_i_at_c).unwrap()
                },
            );

            std::println!("lhs: {lhs}");
            let rhs = data.batch.iter().zip(challenge.iter()).fold(
                commitment.a.clone(),
                |acc, (element, challenge_i)| {
                    let e_at_d = data.key0.omul(&challenge_i, &element.d).unwrap();
                    data.key0.oadd(&acc, &e_at_d).unwrap()
                },
            );

            std::println!("rhs: {rhs}");

            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }

        {
            println!("proof.z1: {:?}", proof.z1);
            println!("challenge: {:?}", challenge);
            let lhs: Vec<Point<C>> = proof
                .z1
                .iter()
                .map(|z1_i| Point::<C>::generator() * z1_i.to_scalar())
                .collect();
            let rhs: Vec<Point<C>> = commitment
                .b_x
                .iter()
                .zip(data.batch.iter())
                .zip(challenge.iter())
                .map(|((b_x_i, element), challenge_i)| b_x_i + element.x * challenge_i.to_scalar())
                .collect();

            for (lhs_i, rhs_i) in lhs.iter().zip(rhs.iter()) {
                std::println!("lhs_i: {lhs_i:?} rhs_i: {rhs_i:?}");
                fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs_i, rhs_i)?;
            }
        }

        {
            let lhs: Vec<Integer> = proof
                .z1
                .iter()
                .zip(proof.z3.iter())
                .map(|(z1_i, z3_i)| aux.combine(&z1_i, &z3_i).unwrap())
                .collect();
            let rhs: Vec<Integer> = commitment
                .s
                .iter()
                .zip(commitment.e.iter())
                .zip(challenge.iter())
                .map(|((s_i, e_i), challenge_i)| {
                    
                    let s_i_i = mod_pow_int(s_i, &challenge_i, &aux.rsa_modulo);
                    (e_i * s_i_i).mod_op(&aux.rsa_modulo)
                })
                .collect();

            for (lhs_i, rhs_i) in lhs.iter().zip(rhs.iter()) {
                println!("lhs_i: {lhs_i:?} rhs_i: {rhs_i:?}");
                fail_if_ne(InvalidProofReason::EqualityCheck(4), lhs_i, rhs_i)?;
            }
        }

        {
            let lhs = data
                .key1
                .encrypt_with(&proof.z2, &proof.w_y)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;

            let rhs = data.batch.iter().zip(challenge.iter()).fold(
                commitment.b_y.clone(),
                |acc, (element, challenge_i)| {
                    let e_at_y = data.key1.omul(&challenge_i, &element.y).unwrap();
                    data.key1.oadd(&acc, &e_at_y).unwrap()
                },
            );

            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }

        {
            let lhs = aux.combine(&proof.z2, &proof.z4)?;
            let rhs = commitment.t.iter().zip(challenge.iter()).fold(
                commitment.f.clone(),
                |acc, (t_i, challenge_i)| {
                    let t_i_i = mod_pow_int(t_i, &challenge_i, &aux.rsa_modulo);
                    (acc * t_i_i).mod_op(&aux.rsa_modulo)
                },
            );

            fail_if_ne(InvalidProofReason::EqualityCheck(5), lhs, rhs)?;
        }

        fail_if(
            InvalidProofReason::RangeCheck(6),
            proof.z1.iter().any(|z1_i| {
                z1_i.is_in_pm(&(Integer::from(1) << (security.l_x + security.epsilon + security.t)))
            }),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(7),
            proof
                .z2
                .is_in_pm(&(Integer::from(1) << (security.l_y + security.epsilon + security.t))),
        )?;

        Ok(())
    }

    /// Generate random challenge
    pub fn challenge<R>(security: &SecurityParams, rng: &mut R, batch_size: usize) -> Vec<Integer>
    where
        R: RngCore,
    {
        vec![Integer::from_rng_pm(&security.q, rng); batch_size]
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use generic_ec::Curve;

    use crate::{Error, InvalidProof};

    use super::{Aux, Challenge, Commitment, PrivateData, Proof, PublicData, SecurityParams};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
        batch_size: usize,
    ) -> Result<(Commitment<C>, Proof), Error> {
        let (comm, pcomm) = super::interactive::commit(
            aux,
            data.clone(),
            pdata.clone(),
            security,
            batch_size,
            rng,
        )?;
        let challenge =
            challenge::<C, D>(shared_state, aux, data.clone(), &comm, security, batch_size);
        let proof = super::interactive::prove(data.clone(), pdata.clone(), &pcomm, &challenge)?;
        Ok((comm, proof))
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        proof: &Proof,
        batch_size: usize,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<C, D>(
            shared_state,
            aux,
            data.clone(),
            commitment,
            security,
            batch_size,
        );
        super::interactive::verify(aux, data, commitment, security, &challenge, proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        batch_size: usize,
    ) -> Challenge {
        let tag = "paillier_zk.batch_paillier_affine_operation_in_range.ni_challenge";
        let aux = aux.digest_public_data();
        let data = data.digest_public_data();
        let commitment = commitment.digest_public_data();

        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux,
            security,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge(security, &mut rng, batch_size)
    }
}

#[cfg(test)]
mod test {
    use fast_paillier::AnyEncryptionKey;
    use generic_ec::{Curve, Point};
    use malachite::Integer;
    use sha2::Digest;

    use crate::common::test::{random_key, sample_key, sample_other_key};
    use crate::common::InvalidProofReason;
    use crate::integer_ext::IntegerExt;
    fn run<R: rand_core::RngCore + rand_core::CryptoRng, C: Curve, D: Digest>(
        rng: &mut R,
        security: super::SecurityParams,
        x: Integer,
        y: Integer,
    ) -> Result<(), crate::common::InvalidProof> {
        let batch_size = 2;
        let dk0 = sample_key();
        std::println!("generated dk0");
        let dk1 = sample_other_key();
        std::println!("generated dk1");
        let _ek0 = dk0.encryption_key().clone();
        std::println!("generated ek0");
        let ek1 = dk1.encryption_key().clone();
        std::println!("generated ek1");
        let (c, _) = {
            let plaintext = Integer::from_rng_pm(dk0.half_n(), rng);
            dk0.encrypt_with_random(rng, &plaintext).unwrap()
        };
        std::println!("generated c");
        let rho_y = Integer::rand_in_range(rng, Integer::ZERO, Integer::from(1) << (ek1.nounce_size() - 129));
        let y_enc_ek1 = ek1.encrypt_with(&y, &rho_y).unwrap();
        std::println!("generated y_enc_ek1");
        use malachite_base::num::basic::traits::Zero;
        let rho = Integer::rand_in_range(rng, Integer::ZERO, Integer::from(1) << (dk0.nounce_size() - 129));
        let d = {
            let x_at_c = dk0.omul(&x, &c).unwrap();
            let y_enc_ek0 = dk0.encrypt_with(&y, &rho).unwrap();
            dk0.oadd(&x_at_c, &y_enc_ek0).unwrap()
        };
        std::println!("generated rho");
        let (c2, _) = {
            let plaintext = Integer::from_rng_pm(dk0.half_n(), rng);
            dk0.encrypt_with_random(rng, &plaintext).unwrap()
        };
        std::println!("generated d");
        std::println!("generated y_enc_ek1_2");
        let rho_y_2 = Integer::rand_in_range(rng, Integer::ZERO, Integer::from(1) << (dk0.nounce_size() - 129));
        let y_enc_ek1_2 = ek1.encrypt_with(&y, &rho_y_2).unwrap();
        let rho_2 = Integer::rand_in_range(rng, Integer::ZERO, Integer::from(1) << (dk0.nounce_size() - 129));

        let d2 = {
            let x_at_c2 = dk0.omul(&x, &c2).unwrap();
            let y_enc_ek0_2 = dk0.encrypt_with(&y, &rho_2).unwrap();
            dk0.oadd(&x_at_c2, &y_enc_ek0_2).unwrap()
        };
        std::println!("generated rho_2");
        let data = super::PublicData {
            key0: &dk0,
            key1: &ek1,
            batch: vec![
                super::PublicElement {
                    c: c,
                    d: d,
                    y: y_enc_ek1,
                    x: x.to_scalar::<C>() * Point::generator(),
                },
                super::PublicElement {
                    c: c2,
                    d: d2,
                    y: y_enc_ek1_2,
                    x: x.to_scalar::<C>() * Point::generator(),
                },
            ],
        };
        std::println!("generated data");
        let pdata = super::PrivateData {
            batch: vec![
                super::PrivateElement {
                    x: &x,
                    y: &y,
                    nonce: &rho,
                    nonce_y: &rho_y,
                },
                super::PrivateElement {
                    x: &x,
                    y: &y,
                    nonce: &rho_2,
                    nonce_y: &rho_y_2,
                },
            ],
        };

        std::println!("generated pdata");
        let aux = crate::common::test::aux(rng);
        std::println!("generated aux");
        let shared_state = "shared state";
        std::println!("generated shared_state");
        // Ok(())

        let (commitment, proof) = super::non_interactive::prove::<C, D>(
            &shared_state,
            &aux,
            data.clone(),
            pdata.clone(),
            &security,
            rng,
            batch_size,
        )
        .unwrap();
        std::println!("generated commitment");
        std::println!("generated proof");
        super::non_interactive::verify::<C, D>(
            &shared_state,
            &aux,
            data,
            &commitment,
            &security,
            &proof,
            batch_size,
        )
    }

    fn passing_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 1024,
            l_y: 1024,
            epsilon: 300,
            q: (Integer::from(1) << 128_u32) - Integer::from(1),
            t: 128,
        };
        let x = Integer::from_rng_pm(&(Integer::from(1) << security.l_x), &mut rng);
        std::println!("generated x");
        let y = Integer::from_rng_pm(&(Integer::from(1) << security.l_y), &mut rng);
        std::println!("generated y");
        run::<_, C, D>(&mut rng, security, x, y).expect("proof failed");
    }

    fn failing_on_additive<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 1024,
            l_y: 1024,
            epsilon: 300,
            q: (Integer::from(1) << 128_u32),
            t: 128,
        };
        let x = Integer::from_rng_pm(&(Integer::from(1) << security.l_x), &mut rng);
        let y = (Integer::from(1) << (security.l_y + security.epsilon + 3)) + Integer::from(1);
        let r = run::<_, C, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(7) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    fn failing_on_multiplicative<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 1024,
            l_y: 1024,
            epsilon: 300,
            q: (Integer::from(1) << 128_u32),
            t: 128,
        };
        let x: Integer =
            (Integer::from(1) << (security.l_x + security.epsilon + 3)) + Integer::from(1);
        let y = Integer::from_rng_pm(&(Integer::from(1) << security.l_y), &mut rng);
        let r = run::<_, C, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(6) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_add() {
        failing_on_additive::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_mul() {
        failing_on_multiplicative::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn passing_million() {
        passing_test::<crate::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_add() {
        failing_on_additive::<crate::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_mul() {
        failing_on_multiplicative::<crate::curve::C, sha2::Sha256>()
    }
}
