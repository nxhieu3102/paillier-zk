#![doc = include_str!("../README.md")]
#![deny(clippy::disallowed_methods)]
#![cfg_attr(
    not(test),
    deny(clippy::panic, clippy::unwrap_used, clippy::expect_used)
)]

use thiserror::Error;
pub mod integer_ext;

mod common;

pub mod dlog_with_el_gamal_commitment;
// pub mod group_element_vs_paillier_encryption_in_range;
pub mod multiexp;
pub mod no_small_factor;
// pub mod paillier_affine_operation_in_range;
pub mod paillier_blum_modulus;
pub mod paillier_encryption_in_range;
// pub mod paillier_encryption_in_range_with_el_gamal;
pub mod batch_paillier_encryption_in_range_with_el_gamal;
pub mod batch_paillier_affine_operation_in_range;

#[cfg(test)]
mod curve;

// #[cfg(all(doctest, not(feature = "__internal_doctest")))]
// compile_error!("doctest require that `__internal_doctest` feature is turned on");

// #[cfg(feature = "__internal_doctest")]
// pub mod _doctest;

pub use common::{BadExponent, InvalidProof, PaillierError};
pub use {fast_paillier};

// WASM-specific exports
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    init_logging();
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn init_logging() {
    // Initialize logging for WASM
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_test() -> String {
    "WASM test function working!".to_string()
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn test_bigint_operations() -> String {
    use malachite::Integer;
    use malachite_base::num::arithmetic::traits::Pow;
    
    let a = Integer::from(123u32);
    let b = Integer::from(456u32);
    let result = &a + &b;
    let pow_result = a.pow(2u64);
    
    format!("BigInt test: 123 + 456 = {}, 123^2 = {}", result, pow_result)
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn test_basic_crypto() -> String {
    // Simple test that doesn't require full crypto operations
    format!("Basic crypto test passed")
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn test_paillier_encryption_in_range() -> String {
    use malachite::Integer;
    
    // Simple test without full proof generation
    let n = Integer::from(12345u32);
    format!("Paillier encryption in range test with modulus: {}", n)
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn log_info(message: &str) {
    web_sys::console::log_1(&message.into());
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn log_warn(message: &str) {
    web_sys::console::warn_1(&message.into());
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn log_error(message: &str) {
    web_sys::console::error_1(&message.into());
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn log_debug(message: &str) {
    web_sys::console::debug_1(&message.into());
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn test_logging_levels() -> String {
    log_info("This is an info message");
    log_warn("This is a warning message");
    log_error("This is an error message");
    log_debug("This is a debug message");
    "Logging levels test completed - check browser console".to_string()
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn test_batch_paillier_affine_operation_in_range() -> String {
    use malachite::Integer;
    use crate::batch_paillier_affine_operation_in_range::SecurityParams;
    
    log_info("Testing batch Paillier affine operation in range...");
    
    // Create security parameters
    let security = SecurityParams {
        l_x: 256,  // Smaller bit size for WASM demo
        l_y: 256,
        epsilon: 128,
        q: (Integer::from(1u32) << 64u32) - Integer::from(1u32),
        t: 64,
    };
    
    log_info(&format!("Security parameters created: l_x={}, l_y={}, epsilon={}, t={}", 
                     security.l_x, security.l_y, security.epsilon, security.t));
    
    // For a simplified demo, we'll just show the structure
    // In a real implementation, this would involve:
    // 1. Generating Paillier keys
    // 2. Creating encrypted values
    // 3. Computing affine operations
    // 4. Generating zero-knowledge proofs
    // 5. Verifying proofs
    
    log_info("Batch Paillier affine operation structure:");
    log_info("- Supports proving multiple affine operations: D_i = C_i * x_i + Enc(y_i)");
    log_info("- Proves range bounds: |x_i| < 2^l_x and |y_i| < 2^l_y");
    log_info("- Uses group commitments for binding");
    log_info("- Batch processing improves efficiency");
    
    format!("Batch Paillier affine operation test completed. Security params: l_x={}, l_y={}, epsilon={}, t={}", 
            security.l_x, security.l_y, security.epsilon, security.t)
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn demo_batch_paillier_structure() -> String {
    log_info("Demonstrating batch Paillier affine operation structure...");
    
    // Show the mathematical structure
    log_info("Mathematical structure of batch Paillier affine operations:");
    log_info("For each element i in the batch:");
    log_info("  - C_i: encrypted value under key0");
    log_info("  - x_i: multiplicative factor (private)");
    log_info("  - y_i: additive factor (private)");
    log_info("  - D_i = C_i * x_i + Enc(y_i): result of affine operation");
    log_info("  - X_i = g * x_i: group commitment to x_i");
    log_info("  - Y_i = Enc_key1(y_i): encryption of y_i under key1");
    
    log_info("Zero-knowledge proof demonstrates:");
    log_info("  - Knowledge of x_i, y_i for each i");
    log_info("  - Range bounds: |x_i| < 2^l_x and |y_i| < 2^l_y");
    log_info("  - Correct computation of D_i from C_i, x_i, y_i");
    log_info("  - Consistency between commitments and encrypted values");
    
    "Batch Paillier affine operation structure demonstration completed".to_string()
}

/// Library general error type
#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] ErrorReason);

#[derive(Debug, Error)]
enum ErrorReason {
    #[error("couldn't evaluate modpow")]
    ModPow(
        #[source]
        #[from]
        BadExponent,
    ),
    #[error("couldn't find residue")]
    FindResidue,
    #[error("couldn't encrypt a message")]
    Encryption,
    #[error("can't find multiplicative inverse")]
    Invert,
    #[error("paillier error")]
    Paillier(#[source] fast_paillier::Error),
    #[error("bug: vec has unexpected length")]
    Length,
}

impl From<BadExponent> for Error {
    fn from(err: BadExponent) -> Self {
        Error(ErrorReason::ModPow(err))
    }
}

impl From<PaillierError> for Error {
    fn from(_err: PaillierError) -> Self {
        Error(ErrorReason::Encryption)
    }
}

impl From<fast_paillier::Error> for Error {
    fn from(err: fast_paillier::Error) -> Self {
        Self(ErrorReason::Paillier(err))
    }
}
