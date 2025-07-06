//! Zero-Knowledge Proof of Paillier Encryption in Range using ElGamal Commitment.
//!
//! This protocol—referred to as Π_enc-elg or R_enc-elg in the CGGMP24 paper—proves in
//! zero knowledge that a Paillier-encrypted integer lies within a specific range.
//!
//! ## Overview
//!
//! The proof demonstrates that a Paillier-encrypted plaintext lies within the interval
//! $[-2^\ell, 2^\ell]$, while hiding the plaintext. It leverages ElGamal commitments over
//! an elliptic curve to bind randomness and secret values used in the encryption.
//!
//! ### Public Inputs
//! - Verifier's [`Aux`] data (used for homomorphic commitments).
//! - [`SecurityParams`] containing $\ell$, $\varepsilon$, $q$, and $t$.
//! - An elliptic curve implementing the [`Curve`] trait.
//! - Paillier public encryption key (`key`).
//! - A batch of [`Ciphertext`] values and corresponding elliptic curve points $A$, $B$, and $X$:
//!     - $A = a \cdot G$
//!     - $B = b \cdot G$
//!     - $X = (ab + \text{plaintext}) \cdot G$
//!
//! ### Prover's Secret Inputs
//! - `plaintext` in range $[-2^\ell, 2^\ell]$
//! - `nonce` used in Paillier encryption
//! - Scalars `a`, `b` used in computing ElGamal-style commitments
//!
//! ### Guarantees
//! The proof guarantees that `plaintext` ∈ $[-2^{\ell + \varepsilon}, 2^{\ell + \varepsilon}]$.
//!
//! ## Example
//!
//! See full example in the documentation below, where both prover and verifier perform the setup,
//! generate commitments and proofs, and finally verify the batched zero-knowledge proof.

use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce, Plaintext};
use generic_ec::{Curve, Point, Scalar};
use malachite::Integer;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::Aux;
pub use crate::common::InvalidProof;
use crate::integer_ext::IntegerExt;

/// Security parameters for proof. Choosing the values is a tradeoff between
/// security, speed and correctness
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// $\ell$ in paper
    pub l: usize,
    /// $\varepsilon$ in paper, slackness parameter
    pub epsilon: usize,
    /// q in paper. Security parameter for challenge
    #[udigest(as = crate::common::encoding::Integer)]
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub q: Integer,
    /// t is size of challenge
    pub t: usize,
}

/// Single element in a batch proof
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct PublicElement<C: Curve> {
    /// $C$ in paper
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub ciphertext: Ciphertext,
    /// $B = g^b = g_1^b$ - b is the prover's secret scalar (random)
    pub b: Point<C>,
    /// $X = g^{a b + x} = g_1^x * g_2^b$ - x is the plaintext (secret)
    pub x: Point<C>,
}

impl<C: Curve> PublicElement<C> {
    /// Returns a stripped version of `PublicData` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.public_element" {
            ciphertext: udigest::Bytes(self.ciphertext.to_bytes()),
            b: udigest::Bytes(self.b.to_bytes(true)),
            x: udigest::Bytes(self.x.to_bytes(true)),
        })
    }
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy)]
// #[udigest(bound = "")]
pub struct PublicData<'a, C: Curve> {
    /// $N_0$ in paper
    // #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key: &'a dyn AnyEncryptionKey,
    /// Batch elements containing ciphertext, b and x values
    pub batch: &'a Vec<PublicElement<C>>,
    /// $A = g^a$ is El-Gamal commitment generator ~ g_2 (Batch Range Proof)
    /// g_1 is curve's generator
    pub a: &'a Point<C>,
}

impl<'a, C: Curve> PublicData<'a, C> {
    /// Returns a stripped version of `PublicData` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.public_data" {
            key: udigest::Bytes(self.key.n().to_bytes()),
            a: udigest::Bytes(self.a.to_bytes(true)),
            batch: self.batch.iter().map(|e| e.digest_public_data()).collect::<Vec<_>>(),
        })
    }
}

/// Single private element in a batch proof
#[derive(Clone)]
pub struct PrivateElement<'a, E: Curve> {
    /// $x$ in paper
    pub plaintext: &'a Plaintext,
    /// $\rho$ in paper
    pub nonce: &'a Nonce,
    /// $b$ in paper
    pub b: &'a Scalar<E>,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a, E: Curve> {
    /// Batch of private elements
    pub batch: &'a Vec<PrivateElement<'a, E>>,
}

/// Prover's public commitment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<E: Curve> {
    // #[udigest(as = crate::common::encoding::Integer)]
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_vec_bigint"))]
    pub s: Vec<Integer>,
    // #[udigest(as = crate::common::encoding::Integer)]
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub d: Integer,
    pub y: Point<E>,
    pub z: Point<E>,
}

impl<C: Curve> Commitment<C> {
    /// Returns a stripped version of `Commitment` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.commitment" {
            s: self.s.iter().map(|e| udigest::Bytes(e.to_bytes())).collect::<Vec<_>>(),
            d: udigest::Bytes(self.d.to_bytes()),
            y: udigest::Bytes(self.y.to_bytes(true)),
            z: udigest::Bytes(self.z.to_bytes(true)),
        })
    }
}

/// Prover's secret commitment nonce
#[derive(Clone)]
pub struct PrivateCommitment<E: Curve> {
    pub alpha: Integer,
    pub mu: Vec<Integer>,
    pub r: Integer,
    pub beta: Scalar<E>,
    pub gamma: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Vec<Integer>;

/// Range Proof with El-Gamal commitment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Proof<E: Curve> {
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub z1: Integer,
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub z2: Integer,
    #[cfg_attr(feature = "serde", serde(with = "fast_paillier::utils::serializable_bigint"))]
    pub z3: Integer,
    pub w: Scalar<E>,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use generic_ec::{Curve, Point, Scalar};
    use rand_core::RngCore;
    use malachite::Integer;
    use malachite_base::num::basic::traits::One;
    use malachite_base::num::arithmetic::traits::Mod;
    use crate::{
        common::{fail_if, fail_if_ne, InvalidProofReason},
        Error
    };
    use crate::common::InvalidProof;
    use crate::integer_ext::IntegerExt;

    use super::{
        Aux, Challenge, Commitment, PrivateCommitment, PrivateData, Proof, PublicData,
        SecurityParams,
    };

    /// Create random commitment
    pub fn commit<E: Curve>(
        aux: &Aux,
        data: PublicData<E>,
        pdata: PrivateData<E>,
        security: &SecurityParams,
        rng: &mut impl RngCore,
        batch_size: usize,
    ) -> Result<(Commitment<E>, PrivateCommitment<E>), Error> {
        let two_to_l_plus_e_plus_t =
            Integer::ONE << (security.l + security.epsilon + security.t); // test not include t
        let n_j_at_two_to_l = (Integer::ONE << security.l) * &aux.rsa_modulo;
        let n_j_at_two_to_l_plus_e = &two_to_l_plus_e_plus_t * &aux.rsa_modulo;

        let alpha = Integer::from_rng_pm(&two_to_l_plus_e_plus_t, rng);
        let gamma = Integer::from_rng_pm(&n_j_at_two_to_l_plus_e, rng);
        // let mu = Integer::from_rng_pm(&n_j_at_two_to_l, rng);
        let mu = vec![Integer::from_rng_pm(&n_j_at_two_to_l, rng); batch_size];
        let beta = Scalar::random(rng);
        let r = Integer::gen_invertible(data.key.n(), rng);

        let mut s = vec![];
        s.push(aux.combine(&alpha, &gamma)?);
        for i in 0..batch_size {
            s.push(aux.combine(pdata.batch[i].plaintext, &mu[i])?);
        }
        let d = data.key.encrypt_with(&alpha, &r)?;
        let y = data.a * beta + Point::<E>::generator() * alpha.to_scalar();
        let z = Point::<E>::generator() * beta;

        Ok((
            Commitment { s, d, y, z },
            PrivateCommitment {
                alpha,
                mu,
                r,
                beta,
                gamma,
            },
        ))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<E: Curve>(
        _data: PublicData<E>,
        pdata: PrivateData<E>,
        private_commitment: &PrivateCommitment<E>,
        challenge: &Challenge,
    ) -> Result<Proof<E>, Error> {
        let z1 = private_commitment.alpha.clone()
            + challenge
                .iter()
                .zip(pdata.batch.iter())
                .map(|(e, elem)| e * elem.plaintext)
                .sum::<Integer>();
        // TODO: recheck
        let z2 = private_commitment.r.clone()
            + challenge
                .iter()
                .zip(pdata.batch.iter())
                .map(|(e, elem)| e * elem.nonce)
                .sum::<Integer>();

        let z3 = private_commitment.gamma.clone()
            + challenge
                .iter()
                .zip(private_commitment.mu.iter())
                .map(|(e, m)| e * m)
                .sum::<Integer>();

        let w = private_commitment.beta
            + challenge
                .iter()
                .zip(pdata.batch.iter())
                .map(|(e, elem)| e.to_scalar() * elem.b)
                .sum::<Scalar<E>>();

        Ok(Proof { z1, z2, z3, w })
    }

    /// Verify the proof
    pub fn verify<E: Curve>(
        aux: &Aux,
        data: PublicData<E>,
        commitment: &Commitment<E>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof<E>,
    ) -> Result<(), InvalidProof> {
        {
            let lhs = data
                .key
                .encrypt_with(&proof.z1, &proof.z2)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;

            // C0 * C1^e1 * C2^e2 * ... * Cn^en
            let rhs = {
                let mut e_at_c = vec![];
                for (e, elem) in challenge.iter().zip(data.batch.iter()) {
                    let result = data
                        .key
                        .omul(e, &elem.ciphertext)
                        .map_err(|_| InvalidProofReason::PaillierOp);
                    e_at_c.push(result.unwrap());
                }

                e_at_c.iter().fold(commitment.d.clone(), |acc: Integer, e| {
                    let result = data
                        .key
                        .oadd(&acc, e)
                        .map_err(|_| InvalidProofReason::PaillierOp);
                    result.unwrap()
                })
            };

            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }
        {
            let lhs = data.a * proof.w + Point::<E>::generator() * proof.z1.to_scalar();

            let rhs = {
                let mut e_at_x = vec![];
                for (e, elem) in challenge.iter().zip(data.batch.iter()) {
                    let result = e.to_scalar() * &elem.x;
                    e_at_x.push(result);
                }

                e_at_x.iter().fold(commitment.y.clone(), |acc, e| acc + e)
            };

            // let rhs = commitment.y + data.x * challenge.to_scalar();
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        {
            let lhs = Point::<E>::generator() * proof.w;
            let rhs = {
                let mut e_at_b = vec![];
                for (e, elem) in challenge.iter().zip(data.batch.iter()) {
                    let result = e.to_scalar() * &elem.b;
                    e_at_b.push(result);
                }

                e_at_b.iter().fold(commitment.z.clone(), |acc, e| acc + e)
            };

            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z1, &proof.z3)?;
            let rhs = {
                let mut e_at_s = vec![];
                for (e, s) in challenge.iter().zip(commitment.s.iter().skip(1)) {
                    let result = aux.pow_mod(s, e)?;
                    e_at_s.push(result);
                }

                e_at_s.iter().fold(commitment.s[0].clone(), |acc, e| {
                    (acc * e).mod_op(&aux.rsa_modulo)
                })
            };
            // let rhs = {
            //     let s_to_e = aux.pow_mod(&commitment.s, challenge)?;
            //     (&commitment.t * s_to_e).modulo(&aux.rsa_modulo)
            // };
            fail_if_ne(InvalidProofReason::EqualityCheck(4), lhs, rhs)?;
        }

        fail_if(
            InvalidProofReason::RangeCheck(5),
            proof.z1.is_in_pm(
                &(Integer::ONE << (security.l + security.epsilon + security.t)),
            ),
        )?;

        Ok(())
    }

    /// Generate random challenge
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge<R: RngCore>(
        security: &SecurityParams,
        rng: &mut R,
        batch_size: usize,
    ) -> Challenge {
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
    /// deriving deterministic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<E>,
        pdata: PrivateData<E>,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
        batch_size: usize,
    ) -> Result<(Commitment<E>, Proof<E>), Error> {
        let (comm, pcomm) =
            super::interactive::commit(aux, data, pdata, security, rng, batch_size)?;
        let challenge = challenge::<E, D>(shared_state, aux, data, &comm, security, batch_size);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok((comm, proof))
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<E>,
        commitment: &Commitment<E>,
        proof: &Proof<E>,
        security: &SecurityParams,
        batch_size: usize,
    ) -> Result<(), InvalidProof> {
        let challenge =
            challenge::<E, D>(shared_state, aux, data, commitment, security, batch_size);
        super::interactive::verify(aux, data, commitment, security, &challenge, proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<E>,
        commitment: &Commitment<E>,
        security: &SecurityParams,
        batch_size: usize,
    ) -> Challenge {
        let tag = "paillier_zk.encryption_in_range_with_el_gamal.ni_challenge";
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
    use generic_ec::{Curve, Point, Scalar};
    use malachite::Integer;
    use malachite_base::num::basic::traits::One;
    use sha2::Digest;

    use crate::common::InvalidProofReason;
    use crate::integer_ext::IntegerExt;

    fn run_with<E: Curve, D: Digest>(
        mut rng: &mut impl rand_core::CryptoRngCore,
        security: super::SecurityParams,
        plaintext: Vec<Integer>,
        batch_size: usize,
    ) -> Result<(), crate::common::InvalidProof> {
        let aux = crate::common::test::aux(&mut rng);

        let private_key = crate::common::test::sample_key();
        let a = Scalar::random(rng);
        let generator = Point::<E>::generator();

        // Create nonces and b values first so they exist for the entire scope
        let nonces: Vec<Integer> = (0..batch_size)
            .map(|_| Integer::gen_invertible(private_key.n(), rng))
            .collect();
        let b_values: Vec<Scalar<E>> = (0..batch_size).map(|_| Scalar::random(rng)).collect();

        // Create private elements
        let private_elements: Vec<super::PrivateElement<E>> = (0..batch_size)
            .map(|i| super::PrivateElement {
                plaintext: &plaintext[i],
                nonce: &nonces[i],
                b: &b_values[i],
            })
            .collect();

        let pdata = super::PrivateData {
            batch: &private_elements,
        };

        // Create public elements
        let elements: Vec<super::PublicElement<E>> = (0..batch_size)
            .map(|i| super::PublicElement {
                ciphertext: private_key
                    .encrypt_with(private_elements[i].plaintext, private_elements[i].nonce)
                    .unwrap(),
                b: generator * private_elements[i].b,
                x: generator
                    * (a * private_elements[i].b + private_elements[i].plaintext.to_scalar()),
            })
            .collect();

        let a_point = generator * a;

        let data = super::PublicData {
            key: private_key.encryption_key(),
            batch: &elements,
            a: &a_point,
        };

        let shared_state = "shared state";
        let (commitment, proof) = super::non_interactive::prove::<E, D>(
            &shared_state,
            &aux,
            data,
            pdata,
            &security,
            rng,
            batch_size,
        )
        .unwrap();
        super::non_interactive::verify::<E, D>(
            &shared_state,
            &aux,
            data,
            &commitment,
            &proof,
            &security,
            batch_size,
        )
    }

    fn passing_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 1024,
            epsilon: 300,
            q: (Integer::ONE << 128_u32) - Integer::ONE,
            t: 128,
        };
        let batch_size = 2;
        let plaintext =
            vec![
                Integer::from_rng_pm(&(Integer::ONE << security.l), &mut rng);
                batch_size
            ];
        run_with::<C, D>(&mut rng, security, plaintext, batch_size).expect("proof failed");
    }

    fn failing_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 1024,
            epsilon: 300,
            q: (Integer::ONE << 128_u32) - Integer::ONE,
            t: 128,
        };
        let batch_size = 2;
        let plaintext = vec![
            Integer::from_rng_pm(
                &(Integer::ONE << (security.l + security.epsilon + 4)),
                &mut rng
            );
            batch_size
        ];
        let r = run_with::<C, D>(&mut rng, security, plaintext, batch_size)
            .expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(5) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_add() {
        failing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    // TODO: Re-enable once curve module is properly set up
    #[test]
    fn passing_million() {
        passing_test::<crate::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_add() {
        failing_test::<crate::curve::C, sha2::Sha256>()
    }
}
