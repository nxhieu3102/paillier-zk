// Import necessary cryptographic libraries and types for Paillier encryption, elliptic curves, and big integers
use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce, Plaintext}; // Paillier encryption utilities
use generic_ec::{Curve, Point, Scalar}; // Elliptic curve operations (generic over curve type E)
use rug::Integer; // Arbitrary-precision integer arithmetic
use rand_core::RngCore; // Random number generation trait
use digest::Digest; // Hash function trait for Fiat-Shamir heuristic (if non-interactive)
use crate::common::{Aux, InvalidProof, InvalidProofReason, IntegerExt, BadExponent}; // Common utilities and error types
use std::io; // For Error type

// Utility function to create a rug random state from any RngCore implementation
#[allow(dead_code)] // Used indirectly through IntegerExt::from_rng_pm
fn external_rand<R: RngCore>(rng: &mut R) -> rug::rand::ThreadRandState {
    use bytemuck::TransparentWrapper;

    #[derive(TransparentWrapper)]
    #[repr(transparent)]
    struct ExternalRand<R>(R);

    impl<R: RngCore> rug::rand::ThreadRandGen for ExternalRand<R> {
        fn gen(&mut self) -> u32 {
            self.0.next_u32()
        }
    }

    rug::rand::ThreadRandState::new_custom(ExternalRand::wrap_mut(rng))
}

// Error type for this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Paillier error: {0}")]
    Paillier(#[from] fast_paillier::Error),
    #[error("Bad exponent error: {0}")]
    BadExponent(#[from] BadExponent),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

// --- Original Structs (Unchanged) ---
// These structs define the public and private data for a single-instance proof, preserved for compatibility

/// Public data for a single instance of the proof, holding encryption and commitment values
#[derive(Debug, Clone)]
pub struct Data<'a, E: Curve> {
    pub key: &'a dyn AnyEncryptionKey, // Reference to the Paillier public key (N), used for encryption
    pub aux: &'a Aux,                  // Reference to auxiliary data, including Ring-Pedersen parameters (eN, h1, h2)
    pub g1: Point<E>,                  // First elliptic curve generator point g1, used in El-Gamal commitments
    pub g2: Point<E>,                  // Second elliptic curve generator point g2, used in El-Gamal commitments
    pub c: Ciphertext,                 // Paillier ciphertext C = (1 + N)^m * ρ^N mod N^2, encrypting plaintext m
    pub a: Point<E>,                   // El-Gamal commitment A = a * g1, hiding scalar a
    pub b: Point<E>,                   // El-Gamal commitment B = m * g1 + a * g2, linking plaintext m and scalar a
}

/// Private data for a single instance of the proof, containing the secrets to be proven
#[derive(Clone)]
pub struct PrivateData<'a, E: Curve> {
    pub plaintext: &'a Plaintext,      // Reference to the plaintext m, the value encrypted in c
    pub nonce: &'a Nonce,              // Reference to the nonce ρ, used in Paillier encryption of m
    pub a: Scalar<E>,                  // Scalar a, the randomness used in El-Gamal commitments A and B
}

// --- New Structs for Batch Processing ---
// These structs extend the single-instance structs to support batch proofs over multiple instances

/// Public data for the batch proof, aggregating multiple ciphertexts and commitments
#[derive(Debug, Clone)]
pub struct BatchData<'a, E: Curve> {
    pub key: &'a dyn AnyEncryptionKey, // Shared Paillier public key (N) across all instances
    pub ciphertexts: Vec<Ciphertext>,            // Vector of Paillier ciphertexts {C_1, ..., C_ℓ}, each encrypting m_i
    pub a: Point<E>,                  //  $A = g^a$ is El-Gamal commitment generator ~ g_2 (Batch Range Proof)
    pub b: Vec<Point<E>>,              // Vector of El-Gamal commitments {B_1, ..., B_ℓ}, where B_i = g^b_i
    pub x: Vec<Point<E>>,              // Vector of El-Gamal commitments {X_1, ..., X_ℓ}, where X_i = g^{a b_i + x_i}
}

/// Private data for the batch proof, aggregating multiple secrets for efficiency
#[derive(Clone)]
pub struct BatchPrivateData<'a, E: Curve> {
    pub plaintext: Vec<&'a Plaintext>, // Vector of plaintexts {m_1, ..., m_ℓ}, encrypted in c
    pub nonce: Vec<&'a Nonce>,         // Vector of nonces {ρ_1, ..., ρ_ℓ}, used in Paillier encryptions
    pub b: Vec<Scalar<E>>,             // Vector of scalars {b_1, ..., b_ℓ}, used in El-Gamal commitments
}

// --- Security Parameters for Batch Proof ---
/// Security parameters defining the cryptographic bounds and batch size
#[derive(Debug, Clone)]
pub struct BatchSecurityParams {
    pub l: usize,        // Bit length of the plaintext range, where B = 2^l is the upper bound
    pub epsilon: usize,  // Security parameter ε for range expansion, ensuring statistical zero-knowledge
    pub t: usize,        // Bit length of the challenge space, where challenges e_i ∈ [0, 2^t - 1]
    pub batch_size: usize, // Number of instances ℓ in the batch, determining the proof's scale
}

// --- Commitment Structs for Batch Proof ---
/// Public commitment sent by the prover in the first step of the batch proof protocol
#[derive(Debug, Clone)]
pub struct BatchCommitment<E: Curve> {
    pub c0: Ciphertext,       // Paillier commitment ciphertext C0 = (1 + N)^{m0} * ρ0^N mod N^2, for random m0
    pub p: Vec<Integer>,      // Ring-Pedersen commitments {P0, P1, ..., P_ℓ}
                              // P0 = h1^{m0} * h2^{r0} mod eN, for random m0 and r0
                              // P_i = h1^{m_i} * h2^{r_i} mod eN, for each plaintext m_i and random r_i
    pub a0: Point<E>,         // El-Gamal commitment A0 = a0 * g1, for random scalar a0
    pub b0: Point<E>,         // El-Gamal commitment B0 = m0 * g1 + a0 * g2, tying m0 and a0
}

/// Private commitment data used internally by the prover during commitment generation
#[derive(Clone)]
pub struct BatchPrivateCommitment<E: Curve> {
    pub m0: Integer,          // Random plaintext m0 ∈ [0, 2^{ε+t} * B], used in C0 and B0
    pub rho0: Integer,        // Random nonce ρ0 ∈ ℤ_N^*, used in Paillier encryption of m0
    pub r0: Integer,          // Random scalar r0 ∈ [0, 2^{ε+t} * B * eN], used in P0
    pub r: Vec<Integer>,      // Random scalars {r1, ..., r_ℓ} ∈ [0, B * eN], used in P_i for i=1 to ℓ
    pub a0: Scalar<E>,        // Random scalar a0 ∈ ℤ_q, used in A0 and B0
}

// --- Batch Proof Struct ---
/// The batch proof containing aggregated values, sent as the prover's response
#[derive(Debug, Clone)]
pub struct BatchProof<E: Curve> {
    pub m_star: Integer,    // Aggregated plaintext m* = m0 + Σ e_i * m_i, used in verification equations
    pub r_star: Integer,    // Aggregated randomness r* = r0 + Σ e_i * r_i, for Ring-Pedersen verification
    pub rho_star: Integer,  // Aggregated nonce ρ* = ρ0 * Π ρ_i^{e_i} mod N, for Paillier verification
    pub a_star: Scalar<E>,  // Aggregated scalar a* = a0 + Σ e_i * a_i mod q, for El-Gamal verification
}

// --- Interactive Batch Proof Module ---
// Contains functions for the interactive Σenc-elg[ℓ] protocol, as per CGGMP21
pub mod batch_interactive {
    use super::*; // Import all outer scope items for use within this module

    /// Generates the commitment for the batch proof (Step 1 of Σenc-elg[ℓ])
    /// The prover commits to random values, which will be combined with the real secrets later
    pub fn commit<E: Curve>(
        data: &BatchData<E>,              // Public batch data containing ciphertexts and commitments
        pdata: &BatchPrivateData<E>,      // Private batch data containing plaintexts, nonces, and scalars
        security: &BatchSecurityParams,   // Security parameters defining range and challenge bounds
        rng: &mut impl RngCore,           // Random number generator for sampling secrets
    ) -> Result<(BatchCommitment<E>, BatchPrivateCommitment<E>), Error> {
        let ell = security.batch_size; // Number of instances ℓ in the batch
        let two_to_epsilon_plus_t = Integer::from(1) << (security.epsilon + security.t); // Compute 2^{ε + t}, range factor
        let b: Integer = Integer::from(1) << security.l; // Compute B = 2^l, the plaintext range bound
        let n = data.key.n(); // Paillier modulus N, used for encryption and nonce sampling
        let e_n = &data.aux.rsa_modulo; // Ring-Pedersen modulus eN, used for commitments
        let _s = &data.aux.s; // Ring-Pedersen generator s, base for plaintext commitment
        let _t = &data.aux.t; // Ring-Pedersen generator t, base for randomness commitment

        // Sample random values for the initial commitment (m0, ρ0, r0, a0, and r_i's)
        
        // Calculate upper bound for m0: 2^{ε+t} * B
        let mut upper_bound_m0 = Integer::from(&two_to_epsilon_plus_t);
        upper_bound_m0 *= &b;
        
        let m0 = Integer::from_rng_pm(&upper_bound_m0, rng); // m0 ∈ [-2^{ε+t}*B, 2^{ε+t}*B]
        
        let rho0 = Integer::gen_invertible(n, rng); // ρ0 ∈ ℤ_N^*, invertible modulo N for Paillier encryption
        
        // Calculate upper bound for r0: 2^{ε+t} * B * eN
        let mut upper_bound_r0 = Integer::from(&two_to_epsilon_plus_t);
        upper_bound_r0 *= &b;
        upper_bound_r0 *= e_n;
        
        let r0 = Integer::from_rng_pm(&upper_bound_r0, rng); // r0 ∈ [-2^{ε+t}*B*eN, 2^{ε+t}*B*eN]
        
        let a0 = Scalar::random(rng); // a0 ∈ ℤ_q, random scalar in the elliptic curve's order
        
        // Calculate upper bound for r_i: B * eN
        let mut upper_bound_r = Integer::from(&b);
        upper_bound_r *= e_n;
        
        // Generate r_i values in the range [-B*eN, B*eN]
        let r = (0..ell)
            .map(|_| Integer::from_rng_pm(&upper_bound_r, rng))
            .collect::<Vec<_>>(); // Collect into a vector of random scalars

        // Compute Paillier commitment C0 = (1 + N)^{m0} * ρ0^N mod N^2
        // This encrypts the random plaintext m0 with nonce ρ0 under the public key N
        let c0 = data.key.encrypt_with(&m0, &rho0)?;

        // Compute Ring-Pedersen commitment P0 = s^{m0} * t^{r0} mod eN
        // This commits to m0 with randomness r0, verifiable under eN
        let p0 = data.aux.combine(&m0, &r0)?;

        // Compute Ring-Pedersen commitments P_i = s^{m_i} * t^{r_i} mod eN for i=1 to ℓ
        // Each P_i commits to the actual plaintext m_i with randomness r_i
        let p = (0..ell)
            .map(|i| {
                let m_i = &pdata.plaintext[i]; // Plaintext m_i from private data
                let r_i = &r[i]; // Corresponding randomness r_i
                data.aux.combine(m_i, r_i) // P_i computation
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Compute El-Gamal commitment A0 = a0 * g1
        // This commits to the random scalar a0 using the generator g1
        let a0_point = a0 * data.g1;

        // Compute El-Gamal commitment B0 = m0 * g1 + a0 * g2
        // This ties the random plaintext m0 and scalar a0, using both generators
        let b0_point = m0.to_scalar::<E>() * data.g1 + a0 * data.g2;

        // Construct and return the public and private commitment structs
        Ok((
            BatchCommitment {
                c0, // Paillier commitment to m0
                p: [vec![p0], p].concat(), // Concatenate P0 with P_1 to P_ℓ into a single vector
                a0: a0_point, // El-Gamal commitment to a0
                b0: b0_point, // El-Gamal commitment to m0 and a0
            },
            BatchPrivateCommitment { m0, rho0, r0, r, a0 }, // Private values for later proof generation
        ))
    }

    /// Generates the batch proof (Step 3 of Σenc-elg[ℓ])
    /// The prover responds to the verifier's challenge by aggregating secrets
    pub fn prove<E: Curve>(
        data: &BatchData<E>,              // Public batch data for verification context
        pdata: &BatchPrivateData<E>,      // Private batch data containing the secrets
        pcomm: &BatchPrivateCommitment<E>,// Private commitment data from Step 1
        challenge: &[Integer],            // Challenge vector e = (e1, ..., eℓ) from the verifier
    ) -> Result<BatchProof<E>, Error> {
        let ell = data.c.len(); // Number of instances in the batch
        assert_eq!(challenge.len(), ell, "Challenge length must match batch size"); // Ensure consistency

        // Compute m* = m0 + Σ_{i=1}^ℓ e_i * m_i
        // Aggregates the random m0 with challenged plaintexts m_i, for Paillier and El-Gamal verification
        let m_star = pcomm.m0.clone()
            + challenge
                .iter()
                .zip(pdata.plaintext.iter())
                .map(|(e_i, m_i)| e_i.clone() * *m_i) // e_i * m_i for each instance
                .sum::<Integer>(); // Sum all terms

        // Compute r* = r0 + Σ_{i=1}^ℓ e_i * r_i
        // Aggregates the random r0 with challenged randomness r_i, for Ring-Pedersen verification
        let r_star = pcomm.r0.clone()
            + challenge
                .iter()
                .zip(pcomm.r.iter())
                .map(|(e_i, r_i)| e_i.clone() * r_i) // e_i * r_i for each instance
                .sum::<Integer>(); // Sum all terms

        // Compute ρ* = ρ0 * Π_{i=1}^ℓ ρ_i^{e_i} mod N
        // Aggregates the random nonce ρ0 with challenged nonces ρ_i, for Paillier verification
        let mut rho_star = challenge
            .iter()
            .zip(pdata.nonce.iter())
            .fold(pcomm.rho0.clone(), |acc, (e_i, rho_i)| {
                // First clone rho_i to get owned value
                let rho_i = (*rho_i).clone();
                // Then compute the power mod and accumulate
                acc + rho_i * e_i // Accumulate product
            });

        rho_star = rho_star.modulo(data.key.n());

        // Compute a* = a0 + Σ_{i=1}^ℓ e_i * a_i mod q
        // Aggregates the random scalar a0 with challenged scalars a_i, for El-Gamal verification
        let a_star = challenge
            .iter()
            .zip(pdata.a.iter())
            .fold(pcomm.a0.clone(), |acc, (e_i, a_i)| {
                // Convert e_i to a scalar and multiply by a_i, then add to accumulator
                acc + a_i.clone() * e_i.to_scalar::<E>()
            });

        // Construct and return the batch proof with aggregated values
        Ok(BatchProof { m_star, r_star, rho_star, a_star })
    }

    /// Verifies the batch proof (Step 4 of Σenc-elg[ℓ])
    /// The verifier checks the proof's validity using public data and commitments
    pub fn verify<E: Curve>(
        data: &BatchData<E>,             // Public batch data containing original ciphertexts and commitments
        comm: &BatchCommitment<E>,       // Public commitment from the prover
        security: &BatchSecurityParams,  // Security parameters for range and challenge bounds
        challenge: &[Integer],           // Challenge vector e = (e1, ..., eℓ) used in proof
        proof: &BatchProof<E>,           // Batch proof containing aggregated values
    ) -> Result<(), InvalidProof> {
        let ell = data.c.len(); // Number of instances in the batch
        assert_eq!(challenge.len(), ell, "Challenge length must match batch size"); // Ensure consistency
        let two_to_epsilon_plus_t = Integer::from(1) << (security.epsilon + security.t); // 2^{ε + t}
        let b = Integer::from(1) << security.l; // B = 2^l, plaintext range bound

        // Range check: ensure m* ∈ [0, 2^{ε + t} * B]
        // Verifies that the aggregated plaintext m* is within the expected range, implying
        // each m_i is statistically within [-2^{ε + t} * B, 2^{ε + t} * B]
        if proof.m_star < 0 || proof.m_star > two_to_epsilon_plus_t * &b {
            return Err(InvalidProofReason::RangeCheck(1).into()); // Fail if out of range
        }

        // Verify Paillier encryption: check C0 * Π_{i=1}^ℓ C_i^{e_i} == (1 + N)^{m*} * (ρ*)^N mod N^2
        // Ensures the aggregated plaintext m* and nonce ρ* match the combined ciphertexts
        let lhs_c = match challenge.iter().zip(data.c.iter()).try_fold(
            comm.c0.clone(), // Start with the commitment ciphertext C0
            |acc, (e_i, c_i)| {
                let e_i_c_i = data.key.omul(e_i, c_i)?; // Compute C_i^{e_i} using optimized multiplication
                data.key.oadd(&acc, &e_i_c_i) // Add to accumulator
            },
        ) {
            Ok(c) => c,
            Err(_) => return Err(InvalidProofReason::PaillierOp.into()),
        };
        
        let rhs_c: Integer = match data.key.encrypt_with(&proof.m_star, &proof.rho_star) {
            Ok(c) => c,
            Err(_) => return Err(InvalidProofReason::PaillierEnc.into()),
        };
        
        if lhs_c != rhs_c {
            return Err(InvalidProofReason::EqualityCheck(2).into()); // Fail if encryption doesn't match
        }

        // Verify Ring-Pedersen commitment: check P0 * Π_{i=1}^ℓ P_i^{e_i} == s^{m*} * t^{r*} mod eN
        // Ensures the aggregated plaintext m* and randomness r* match the combined commitments
        let p0 = &comm.p[0]; // P0 from the commitment
        let p_i = &comm.p[1..]; // P_1 to P_ℓ
        let lhs_p = match challenge
            .iter()
            .zip(p_i.iter())
            .try_fold(
                p0.clone(), 
                |acc, (e_i, p_i)| {
                    // Handle errors from pow_mod by mapping them to BadExponent
                    match p_i.pow_mod_ref(e_i, &data.aux.rsa_modulo) {
                        Some(result) => {
                            // Convert result to Integer before multiplication
                            let result: Integer = result.into();
                            Ok((acc * result).modulo(&data.aux.rsa_modulo))
                        },
                        None => Err(BadExponent::undefined())
                    }
                }
            ) {
                Ok(p) => p,
                Err(_) => return Err(InvalidProofReason::ModPow.into()),
            };
            
        let rhs_p = match data.aux.combine(&proof.m_star, &proof.r_star) {
            Ok(p) => p,
            Err(_) => return Err(InvalidProofReason::ModPow.into()),
        };
        
        if lhs_p != rhs_p {
            return Err(InvalidProofReason::EqualityCheck(3).into()); // Fail if commitments don't match
        }

        // Verify El-Gamal commitment A: check A0 + Σ_{i=1}^ℓ e_i * A_i == a* * g1
        // Ensures the aggregated scalar a* matches the combined A commitments
        let lhs_a = challenge.iter().zip(data.a.iter()).fold(
            comm.a0.clone(), // Start with A0
            |acc, (e_i, a_i)| {
                // Calculate e_i * A_i and add to accumulator
                acc + a_i.clone() * e_i.to_scalar::<E>()
            }
        );
        
        let rhs_a = proof.a_star * data.g1; // a* * g1
        if lhs_a != rhs_a {
            return Err(InvalidProofReason::EqualityCheck(4).into()); // Fail if A commitments don't match
        }

        // Verify El-Gamal commitment B: check B0 + Σ_{i=1}^ℓ e_i * B_i == m* * g1 + a* * g2
        // Ensures the aggregated m* and a* match the combined B commitments
        let lhs_b = challenge.iter().zip(data.b.iter()).fold(
            comm.b0.clone(), // Start with B0
            |acc, (e_i, b_i)| {
                // Calculate e_i * B_i and add to accumulator
                acc + b_i.clone() * e_i.to_scalar::<E>()
            }
        );
        
        let rhs_b = proof.m_star.to_scalar::<E>() * data.g1 + proof.a_star * data.g2; // m* * g1 + a* * g2
        if lhs_b != rhs_b {
            return Err(InvalidProofReason::EqualityCheck(5).into()); // Fail if B commitments don't match
        }

        Ok(()) // All checks passed, proof is valid
    }

    /// Generates a random challenge vector for the batch proof (Step 2 of Σenc-elg[ℓ])
    /// In an interactive setting, this is provided by the verifier
    pub fn challenge<E: Curve>(
        security: &BatchSecurityParams, // Security parameters defining challenge space
        rng: &mut impl RngCore,         // Random number generator for challenge sampling
    ) -> Vec<Integer> {
        let ell = security.batch_size; // Number of instances ℓ
        let two_to_t = Integer::from(1) << security.t; // 2^t, upper bound of challenge space
        
        // Create challenges in range [0, 2^t - 1]
        (0..ell)
            .map(|_| {
                // Use IntegerExt::from_rng_pm to sample e_i
                let mut challenge = Integer::from_rng_pm(&two_to_t, rng);
                // Adjust to [0, 2^t - 1] range by adding 2^t if negative
                if challenge < 0 {
                    challenge += &two_to_t * 2;
                }
                challenge
            })
            .collect() // Collect into a vector of challenges
    }
}

// --- Batch Prove and Verify Functions ---
// High-level functions to generate and verify batch proofs, integrating the interactive steps

/// Generates a batch proof for multiple instances, simulating the interactive protocol
pub fn prove_batch<E: Curve, D: Digest>(
    _shared_state: &impl udigest::Digestable, // Shared state for potential Fiat-Shamir transformation 
    aux: &Aux,                               // Auxiliary data with Ring-Pedersen parameters
    data: Vec<Data<E>>,                      // Vector of single-instance public data
    pdata: Vec<PrivateData<E>>,              // Vector of single-instance private data
    security: &BatchSecurityParams,          // Security parameters for the proof
    rng: &mut impl RngCore,                  // Random number generator for sampling
) -> Result<(BatchCommitment<E>, BatchProof<E>), Error> {
    // Convert single-instance data to batch format for unified processing
    let batch_data = BatchData {
        key: data[0].key, // Assume all instances share the same Paillier key
        aux,              // Shared auxiliary data
        g1: data[0].g1,   // Shared generator g1
        g2: data[0].g2,   // Shared generator g2
        c: data.iter().map(|d| d.c.clone()).collect(), // Collect ciphertexts
        a: data.iter().map(|d| d.a.clone()).collect(), // Collect A commitments
        b: data.iter().map(|d| d.b.clone()).collect(), // Collect B commitments
    };
    let batch_pdata = BatchPrivateData {
        plaintext: pdata.iter().map(|p| p.plaintext).collect(), // Collect plaintexts
        nonce: pdata.iter().map(|p| p.nonce).collect(),         // Collect nonces
        a: pdata.iter().map(|p| p.a.clone()).collect(),        // Collect scalars
    };

    // Step 1: Generate the commitment using the interactive module
    let (comm, pcomm) = batch_interactive::commit(&batch_data, &batch_pdata, security, rng)?;

    // Step 2: Generate a random challenge vector (in practice, could use Fiat-Shamir with D)
    let challenge = batch_interactive::challenge::<E>(security, rng);

    // Step 3: Generate the proof using the challenge
    let proof = batch_interactive::prove(&batch_data, &batch_pdata, &pcomm, &challenge)?;

    // Return the commitment and proof as a tuple
    Ok((comm, proof))
}

/// Verifies a batch proof for multiple instances, simulating the interactive protocol
pub fn verify_batch<E: Curve, D: Digest>(
    _shared_state: &impl udigest::Digestable, // Shared state for potential Fiat-Shamir transformation
    aux: &Aux,                               // Auxiliary data with Ring-Pedersen parameters
    data: Vec<Data<E>>,                      // Vector of single-instance public data
    commitment: &BatchCommitment<E>,         // Public commitment from the prover
    proof: &BatchProof<E>,                   // Batch proof from the prover
    security: &BatchSecurityParams,          // Security parameters for the proof
) -> Result<(), InvalidProof> {
    // Convert single-instance data to batch format for unified verification
    let batch_data = BatchData {
        key: data[0].key, // Assume all instances share the same Paillier key
        aux,              // Shared auxiliary data
        g1: data[0].g1,   // Shared generator g1
        g2: data[0].g2,   // Shared generator g2
        c: data.iter().map(|d| d.c.clone()).collect(), // Collect ciphertexts
        a: data.iter().map(|d| d.a.clone()).collect(), // Collect A commitments
        b: data.iter().map(|d| d.b.clone()).collect(), // Collect B commitments
    };

    // Generate a random challenge vector (in practice, should match prove_batch or use Fiat-Shamir)
    let challenge = batch_interactive::challenge::<E>(security, &mut rand_core::OsRng::default());

    // Step 4: Verify the proof using the interactive module
    batch_interactive::verify(&batch_data, commitment, security, &challenge, proof)
}

#[cfg(test)]
mod test {
    use generic_ec::{Curve, Point, Scalar};
    use rug::{Complete, Integer};
    use sha2::Digest;
    
    use crate::common::{IntegerExt, InvalidProofReason};
    use fast_paillier::{AnyEncryptionKey, Plaintext, Nonce};

    /// Run a batch proof test with the specified parameters
    fn run_with_batch<E: Curve, D: Digest>(
        mut rng: &mut impl rand_core::CryptoRngCore,
        security: super::BatchSecurityParams,
        plaintexts: Vec<Integer>,
    ) -> Result<(), crate::common::InvalidProof> {
        // Make all plaintexts owned by converting them to Plaintext
        let plaintexts: Vec<Plaintext> = plaintexts.into_iter()
            .map(|p| p.into())
            .collect();

        let aux = crate::common::test::aux(&mut rng);
        let private_key = crate::common::test::sample_key();
        let encryption_key = private_key.encryption_key();
        
        // Explicitly create Point instances
        let generator = Point::<E>::generator();
        let g1: Point<E> = generator.into();
        let g2: Point<E> = (generator * Scalar::random(rng)).into();
        
        // Create individual instances
        let mut data_vec = Vec::with_capacity(plaintexts.len());
        let mut pdata_vec = Vec::with_capacity(plaintexts.len());
        
        // Create nonces as owned values
        let nonces: Vec<Nonce> = (0..plaintexts.len())
            .map(|_| Integer::gen_invertible(encryption_key.n(), rng).into())
            .collect();
            
        // Create scalars for a values
        let a_values: Vec<Scalar<E>> = (0..plaintexts.len())
            .map(|_| Scalar::random(rng))
            .collect();
        
        for i in 0..plaintexts.len() {
            let ciphertext = encryption_key.encrypt_with(&plaintexts[i], &nonces[i]).unwrap();
            
            // Create private data with references to stored values
            let pdata = super::PrivateData {
                plaintext: &plaintexts[i],
                nonce: &nonces[i],
                a: a_values[i].clone(),
            };
            
            // Create public data
            let data = super::Data {
                key: encryption_key,
                aux: &aux,
                g1,
                g2,
                c: ciphertext,
                a: a_values[i].clone() * g1,
                b: plaintexts[i].to_scalar::<E>() * g1 + a_values[i].clone() * g2,
            };
            
            data_vec.push(data);
            pdata_vec.push(pdata);
        }
        
        let shared_state = "batch shared state";
        
        // Clone data_vec to avoid the move issue
        let data_vec_clone = data_vec.clone();
        
        // Run the batch proof
        let (commitment, proof) = super::prove_batch::<E, D>(
            &shared_state,
            &aux,
            data_vec,
            pdata_vec,
            &security,
            rng,
        ).unwrap();
        
        // Verify the batch proof with the clone
        super::verify_batch::<E, D>(
            &shared_state,
            &aux,
            data_vec_clone,
            &commitment,
            &proof,
            &security,
        )
    }

    /// Test that passes with valid plaintexts
    fn passing_batch_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        
        // Configure security parameters
        let batch_size = 5; // Test with 5 proofs in batch
        let security = super::BatchSecurityParams {
            l: 1024,          // Bit length of plaintext range
            epsilon: 128,     // Security parameter for range expansion
            t: 256,           // Bit length of challenge space
            batch_size,
        };
        
        // Generate random plaintexts within the valid range
        let plaintexts: Vec<Integer> = (0..batch_size)
            .map(|_| Integer::from_rng_pm(&(Integer::ONE << security.l).complete(), &mut rng))
            .collect();
        
        run_with_batch::<C, D>(&mut rng, security, plaintexts)
            .expect("batch proof should pass with valid plaintexts");
    }

    /// Test that fails with an invalid plaintext
    fn failing_batch_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        
        // Configure security parameters
        let batch_size = 5; // Test with 5 proofs in batch
        let security = super::BatchSecurityParams {
            l: 1024,
            epsilon: 128,
            t: 256,
            batch_size,
        };
        
        // Generate valid plaintexts
        let mut plaintexts: Vec<Integer> = (0..batch_size-1)
            .map(|_| Integer::from_rng_pm(&(Integer::ONE << security.l).complete(), &mut rng))
            .collect();
        
        // Add one invalid plaintext that's out of range
        let invalid_plaintext = (Integer::ONE << (security.l + security.epsilon)).complete() + 1;
        plaintexts.push(invalid_plaintext);
        
        let result = run_with_batch::<C, D>(&mut rng, security, plaintexts);
        assert!(result.is_err(), "batch proof should fail with invalid plaintext");
        
        // Check that it failed for the right reason
        if let Err(err) = result {
            match err.reason() {
                InvalidProofReason::RangeCheck(1) => (), // Expected failure
                e => panic!("batch proof failed for unexpected reason: {e:?}"),
            }
        }
    }

    // Tests with Secp256r1 curve
    #[test]
    fn passing_batch_p256() {
        passing_batch_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    
    #[test]
    fn failing_batch_p256() {
        failing_batch_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    // Tests with custom curve
    #[test]
    fn passing_batch_million() {
        passing_batch_test::<crate::curve::C, sha2::Sha256>()
    }
    
    #[test]
    fn failing_batch_million() {
        failing_batch_test::<crate::curve::C, sha2::Sha256>()
    }
}
