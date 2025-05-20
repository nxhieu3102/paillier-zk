//! ZK-proof of paillier operation with group commitment in range. Called Пaff-g
//! or Raff-g in the CGGMP21 paper.
//!
//! ## Description
//!
//! A party P performs a paillier affine operation with C, Y, and X
//! obtaining `D = C*X + Y`. `X` and `Y` are encrypted values of `x` and `y`. P
//! then wants to prove that `y` and `x` are at most `L` and `L'` bits,
//! correspondingly, and P doesn't want to disclose none of the plaintexts
//!
//! Given:
//! - `key0`, `pkey0`, `key1`, `pkey1` - pairs of public and private keys in
//!   paillier cryptosystem
//! - `nonce_y`, `nonce` - nonces in paillier encryption
//! - `x`, `y` - some numbers
//! - `q`, `g` such that `<g> = Zq*` - prime order group
//! - `C` is some ciphertext encrypted by `key0`
//! - `Y = key1.encrypt(y, nonce_y)`
//! - `X = g * x`
//! - `D = oadd(enc(y, nonce), omul(x, C))` where `enc`, `oadd` and `omul` are
//!   paillier encryption, homomorphic addition and multiplication with `key0`
//!
//! Prove:
//! - `bitsize(abs(x)) <= l_x`
//! - `bitsize(abs(y)) <= l_y`
//!
//! Disclosing only: `key0`, `key1`, `C`, `D`, `Y`, `X`
//!
//! ## Example
//!
//! ```rust
//! use paillier_zk::{paillier_affine_operation_in_range as p, IntegerExt};
//! use rug::{Integer, Complete};
//! use generic_ec::{Point, curves::Secp256k1 as E};
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #         someone_encryption_key0: fast_paillier::EncryptionKey,
//! #         someone_encryption_key1: fast_paillier::EncryptionKey,
//! #     );
//! # }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Prover and verifier have a shared protocol state
//! let shared_state = "some shared state";
//!
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Setup: prover and verifier share common Ring-Pedersen parameters:
//!
//! let aux: p::Aux = pregenerated::verifier_aux();
//! let security = p::SecurityParams {
//!     l_x: 256,
//!     l_y: 848,
//!     epsilon: 230,
//!     q: (Integer::ONE << 128_u32).complete(),
//! };
//!
//! // 1. Setup: prover prepares the paillier keys
//!
//! // C and D are encrypted by this key
//! let key0: fast_paillier::EncryptionKey = pregenerated::someone_encryption_key0();
//! // Y is encrypted using this key
//! let key1: fast_paillier::EncryptionKey = pregenerated::someone_encryption_key1();
//!
//! // C is some number encrypted using key0. Neither of parties
//! // need to know the plaintext
//! let ciphertext_c = Integer::gen_invertible(&key0.nn(), &mut rng);
//!
//! // 2. Setup: prover prepares all plaintexts
//!
//! // x in paper
//! let plaintext_x = Integer::from_rng_pm(
//!     &(Integer::ONE << security.l_x).complete(),
//!     &mut rng,
//! );
//! // y in paper
//! let plaintext_y = Integer::from_rng_pm(
//!     &(Integer::ONE << security.l_y).complete(),
//!     &mut rng,
//! );
//!
//! // 3. Setup: prover encrypts everything on correct keys and remembers some nonces
//!
//! // X in paper
//! let ciphertext_x = Point::<E>::generator() * plaintext_x.to_scalar();
//! // Y and ρ_y in paper
//! let (ciphertext_y, nonce_y) = key1.encrypt_with_random(
//!     &mut rng,
//!     &(plaintext_y.signed_modulo(key1.n())),
//! )?;
//! // nonce is ρ in paper
//! let (ciphertext_y_by_key1, nonce) = key0.encrypt_with_random(
//!     &mut rng,
//!     &(plaintext_y.signed_modulo(key0.n()))
//! )?;
//! // D in paper
//! let ciphertext_d = key0
//!     .oadd(
//!         &key0.omul(&plaintext_x, &ciphertext_c)?,
//!         &ciphertext_y_by_key1,
//!     )?;
//!
//! // 4. Prover computes a non-interactive proof that plaintext_x and
//! //    plaintext_y are at most `l_x` and `l_y` bits
//!
//! let data = p::Data {
//!     key0: &key0,
//!     key1: &key1,
//!     c: &ciphertext_c,
//!     d: &ciphertext_d,
//!     x: &ciphertext_x,
//!     y: &ciphertext_y,
//! };
//! let pdata = p::PrivateData {
//!     x: &plaintext_x,
//!     y: &plaintext_y,
//!     nonce: &nonce,
//!     nonce_y: &nonce_y,
//! };
//! let (commitment, proof) =
//!     p::non_interactive::prove::<E, sha2::Sha256>(
//!         &shared_state,
//!         &aux,
//!         data,
//!         pdata,
//!         &security,
//!         &mut rng,
//!     )?;
//!
//! // 5. Prover sends this data to verifier
//!
//! # use generic_ec::Curve;
//! # fn send<E: Curve>(_: &p::Data<E>, _: &p::Commitment<E>, _: &p::Proof) {  }
//! send(&data, &commitment, &proof);
//!
//! // 6. Verifier receives the data and the proof and verifies it
//!
//! # let recv = || (data, commitment, proof);
//! let (data, commitment, proof) = recv();
//! let r = p::non_interactive::verify::<E, sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     &commitment,
//!     &security,
//!     &proof,
//! )?;
//! #
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce};
use generic_ec::{Curve, Point};
use rug::Integer;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::{Aux, InvalidProof};

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
    pub q: Integer,
    /// size of challenge
    pub t: usize,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct PublicElement<C: Curve> {
    pub c: Ciphertext,
    pub x: Point<C>,
    pub d: Ciphertext,
    pub y: Ciphertext,
}

/// Public data that both parties know
#[derive(Debug, Clone)]
// #[udigest(bound = "")]
pub struct PublicData<'a, C: Curve> {
    /// N0 in paper, public key that C was encrypted on
    // #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key0: &'a dyn AnyEncryptionKey,
    /// N1 in paper, public key that y -> Y was encrypted on
    // #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key1: &'a dyn AnyEncryptionKey,
    pub batch: Vec<PublicElement<C>>,
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

// As described in cggmp21 at page 35
/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone)]
// #[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<C: Curve> {
    // #[udigest(as = crate::common::encoding::Integer)]
    pub a: Ciphertext,
    pub s: Vec<Integer>,
    pub e: Vec<Integer>,
    pub f: Integer,
    pub t: Vec<Integer>,
    pub b_x: Vec<Point<C>>,
    pub b_y: Integer,
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
    pub z1: Vec<Integer>,
    pub z2: Integer,
    pub z3: Vec<Integer>,
    pub z4: Integer,
    pub w: Integer,
    pub w_y: Integer,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use generic_ec::{Curve, Point};
    use rand_core::RngCore;
    use rug::{Complete, Integer};

    use crate::common::{fail_if, fail_if_ne, IntegerExt, InvalidProof, InvalidProofReason};
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
        let two_to_l = (Integer::ONE << security.l_x).complete();
        let two_to_l_y = (Integer::ONE << security.l_y).complete();
        let two_to_l_e = (Integer::ONE << (security.l_x + security.epsilon)).complete();
        let two_to_l_e_t =
            (Integer::ONE << (security.l_x + security.epsilon + security.t)).complete();
        let two_to_l_prime_e_t =
            (Integer::ONE << (security.l_y + security.epsilon + security.t)).complete();
        let two_to_l_prime_e = (Integer::ONE << (security.l_y + security.epsilon)).complete();
        let hat_n_at_two_to_l_e = (&aux.rsa_modulo * &two_to_l_e).complete();
        let hat_n_at_two_to_l = (&aux.rsa_modulo * &two_to_l).complete();
        let hat_n_at_two_to_l_y = (&aux.rsa_modulo * &two_to_l_y).complete();
        let hat_n_at_two_to_l_e_t = (&aux.rsa_modulo * &two_to_l_e_t).complete();
        let hat_n_at_two_to_l_prime_e_t = (&aux.rsa_modulo * &two_to_l_prime_e_t).complete();

        let m = vec![Integer::from_rng_pm(&hat_n_at_two_to_l, &mut rng); batch_size];
        let mu = vec![Integer::from_rng_pm(&hat_n_at_two_to_l_y, &mut rng); batch_size];
        let alpha = vec![Integer::from_rng_pm(&two_to_l_e_t, &mut rng); batch_size];
        let gamma = vec![Integer::from_rng_pm(&hat_n_at_two_to_l_e_t, &mut rng); batch_size];
        let beta = Integer::from_rng_pm(&two_to_l_prime_e_t, &mut rng);
        let r = Integer::gen_invertible(data.key0.n(), &mut rng);
        let delta = Integer::from_rng_pm(&hat_n_at_two_to_l_prime_e_t, &mut rng);
        let r_y = Integer::gen_invertible(data.key1.n(), &mut rng);

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
            .map(|((alpha_i, challenge_i), element)| (alpha_i + challenge_i * element.x).complete())
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
            .map(|((gamma_i, challenge_i), m_i)| (gamma_i + challenge_i * m_i).complete())
            .collect();

        let z4 = pcomm
            .mu
            .iter()
            .zip(challenge.iter())
            .fold(pcomm.delta.clone(), |acc, (mu_i, challenge_i)| {
                acc + challenge_i * mu_i
            });

        let w = pdata.batch.iter().zip(challenge.iter()).fold(
            pcomm.r.clone(),
            |acc, (element, challenge_i)| {
                (acc + element.nonce * challenge_i).modulo(&_data.key0.n())
            },
        );

        let w_y = pdata.batch.iter().zip(challenge.iter()).fold(
            pcomm.r_y.clone(),
            |acc, (element, challenge_i)| {
                (acc + element.nonce_y * challenge_i).modulo(&_data.key1.n())
            },
        );

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
            let rhs = data.batch.iter().zip(challenge.iter()).fold(
                commitment.a.clone(),
                |acc, (element, challenge_i)| {
                    let e_at_d = data.key0.omul(&challenge_i, &element.d).unwrap();
                    data.key0.oadd(&acc, &e_at_d).unwrap()
                },
            );

            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }

        {
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
            // TODO: compare each point in lhs and rhs
            for (lhs_i, rhs_i) in lhs.iter().zip(rhs.iter()) {
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
                    (e_i * s_i.clone().pow_mod(&challenge_i, &aux.rsa_modulo).unwrap())
                        .modulo(&aux.rsa_modulo)
                })
                .collect();
            for (lhs_i, rhs_i) in lhs.iter().zip(rhs.iter()) {
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
                    (acc * t_i.clone().pow_mod(&challenge_i, &aux.rsa_modulo).unwrap())
                        .modulo(&aux.rsa_modulo)
                },
            );

            fail_if_ne(InvalidProofReason::EqualityCheck(5), lhs, rhs)?;
        }

        fail_if(
            InvalidProofReason::RangeCheck(6),
            proof.z1.iter().any(|z1_i| {
                z1_i.is_in_pm(
                    &(Integer::ONE << (security.l_x + security.epsilon + security.t)).complete(),
                )
            }),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(7),
            proof.z2.is_in_pm(
                &(Integer::ONE << (security.l_y + security.epsilon + security.t)).complete(),
            ),
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
        let tag = "paillier_zk.paillier_affine_operation_in_range.ni_challenge";
        let aux = aux.digest_public_data();
        let seed = udigest::inline_struct!(tag {
            shared_state,
            // aux,
            // security,
            // data,
            // commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge(security, &mut rng, batch_size)
    }
}

#[cfg(test)]
mod test {
    use fast_paillier::AnyEncryptionKey;
    use generic_ec::{Curve, Point};
    use rug::{Complete, Integer};
    use sha2::Digest;

    use crate::common::test::random_key;
    use crate::common::{IntegerExt, InvalidProofReason};

    fn run<R: rand_core::RngCore + rand_core::CryptoRng, C: Curve, D: Digest>(
        rng: &mut R,
        security: super::SecurityParams,
        x: Integer,
        y: Integer,
    ) -> Result<(), crate::common::InvalidProof> {
        let batch_size = 2;
        let dk0 = random_key(rng).unwrap();
        let dk1 = random_key(rng).unwrap();
        let _ek0 = dk0.encryption_key().clone();
        let ek1 = dk1.encryption_key().clone();

        let (c, _) = {
            let plaintext = Integer::from_rng_pm(dk0.half_n(), rng);
            dk0.encrypt_with_random(rng, &plaintext).unwrap()
        };

        let (y_enc_ek1, rho_y) = ek1.encrypt_with_random(rng, &y).unwrap();

        let (rho, d) = {
            let x_at_c = dk0.omul(&x, &c).unwrap();
            let (y_enc_ek0, rho) = dk0.encrypt_with_random(rng, &y).unwrap();
            (rho, dk0.oadd(&x_at_c, &y_enc_ek0).unwrap())
        };

        let (c2, _) = {
            let plaintext = Integer::from_rng_pm(dk0.half_n(), rng);
            dk0.encrypt_with_random(rng, &plaintext).unwrap()
        };

        let (y_enc_ek1_2, rho_y_2) = ek1.encrypt_with_random(rng, &y).unwrap();

        let (rho_2, d2) = {
            let x_at_c2 = dk0.omul(&x, &c2).unwrap();
            let (y_enc_ek0_2, rho_2) = dk0.encrypt_with_random(rng, &y).unwrap();
            (rho_2, dk0.oadd(&x_at_c2, &y_enc_ek0_2).unwrap())
        };

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

        let aux = crate::common::test::aux(rng);

        let shared_state = "shared state";

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
            q: (Integer::ONE << 128_u32).complete() - 1,
            t: 128,
        };
        let x = Integer::from_rng_pm(&(Integer::ONE << security.l_x).complete(), &mut rng);
        let y = Integer::from_rng_pm(&(Integer::ONE << security.l_y).complete(), &mut rng);
        run::<_, C, D>(&mut rng, security, x, y).expect("proof failed");
    }

    fn failing_on_additive<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 1024,
            l_y: 1024,
            epsilon: 300,
            q: (Integer::ONE << 128_u32).complete(),
            t: 128,
        };
        let x = Integer::from_rng_pm(&(Integer::ONE << security.l_x).complete(), &mut rng);
        let y = (Integer::ONE << (security.l_y + security.epsilon + 3)).complete() + 1;
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
            q: (Integer::ONE << 128_u32).complete(),
            t: 128,
        };
        let x: Integer = (Integer::ONE << (security.l_x + security.epsilon + 3)).complete() + 1;
        let y = Integer::from_rng_pm(&(Integer::ONE << security.l_y).complete(), &mut rng);
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
