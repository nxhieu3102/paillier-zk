use wasm_bindgen::prelude::*;
use num_bigint::BigInt;
use crate::common::BigIntExt;

// Import web-sys for direct console access
use web_sys::console;
use log;

// Macro for easy logging to browser console
#[macro_export]
macro_rules! log {
    ( $( $t:tt )* ) => {
        console::log_1(&format!( $( $t )* ).into());
    }
}

// Initialize console logging (call this once at the start)
#[wasm_bindgen(start)]
pub fn init_logging() {
    console_log::init_with_level(log::Level::Debug).expect("Failed to initialize logger");
    log!("🚀 WASM logging initialized!");
}

// Simple function to verify that WASM bindings work
#[wasm_bindgen]
pub fn wasm_test() -> String {
    log!("📝 wasm_test() called");
    "WASM bindings for paillier-zk are working!".to_string()
}

// Test math operations to verify BigInt works in WASM
#[wasm_bindgen]
pub fn test_bigint_operations() -> String {
    log!("🔢 Starting BigInt operations test");
    
    let a = BigInt::from(12345);
    let b = BigInt::from(54321);
    let c = a + b;
    
    log!("✅ BigInt calculation completed: {} + {} = {}", 12345, 54321, c);
    
    format!("BigInt operations: 12345 + 54321 = {}", c)
}

// Function to check if cryptographic operations work
#[wasm_bindgen]
pub fn test_basic_crypto() -> String {
    log!("🔐 Starting basic crypto test");
    
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    
    // Generate a random number
    let random_number = rand::random::<u32>();
    
    log!("🎲 Generated random number: {}", random_number);
    
    format!("Basic crypto: Generated random number: {}", random_number)
}

// Function to test Paillier encryption in range proof
#[wasm_bindgen]
pub fn test_paillier_encryption_in_range() -> String {
    log!("🔒 Starting Paillier encryption in range proof test");
    
    use crate::paillier_encryption_in_range as zk;
    use sha2::Sha256;
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    
    // Set up security parameters (smaller values for WASM performance)
    let security = zk::SecurityParams {
        l: 128,  // Smaller bit size for faster computation in browser
        epsilon: 64,
        q: (BigInt::from(1) << 64) - 1,
    };
    
    log!("⚙️ Security parameters set: l={}, epsilon={}", security.l, security.epsilon);
    
    // Create auxiliary data for the proof
    log!("🔧 Creating auxiliary data...");
    let aux = crate::common::test::aux(&mut rng);
    log!("🔧 Auxiliary data created: {:?}", aux);
    // Create a test plaintext within range
    log!("📊 Generating test plaintext...");
    let plaintext = BigInt::from_rng_pm(&(BigInt::from(1) << security.l), &mut rng);
    log!("📊 Plaintext generated with {} bits", plaintext.bits());
    
    // Sample encryption key (using smaller key for WASM)
    log!("🔑 Generating encryption keys...");
    let private_key = crate::common::test::random_key(&mut rng).unwrap();
    log!("🔑 Decryption key generated: {:?}", private_key);
    let key = private_key.encryption_key();
    log!("🔑 Encryption key: {:?}", key);
    
    // Encrypt the plaintext
    log!("🔐 Encrypting plaintext...");
    match key.encrypt_with_random(&mut rng, &plaintext) {
        Ok((ciphertext, nonce)) => {
            log!("✅ Encryption successful");
            
            // Create data structures for the proof
            let pdata = zk::PrivateData {
                plaintext: &plaintext,
                nonce: &nonce,
            };
            
            let data = zk::Data {
                key,
                ciphertext: &ciphertext,
            };
            
            // Generate the proof
            log!("🧮 Generating zero-knowledge proof...");
            match zk::non_interactive::prove::<Sha256>(
                &"shared state",
                &aux,
                data,
                pdata,
                &security,
                &mut rng,
            ) {
                Ok((commitment, proof)) => {
                    log!("✅ Proof generation successful");
                    
                    // Verify the proof
                    log!("🔍 Verifying proof...");
                    match zk::non_interactive::verify::<Sha256>(
                        &"shared state",
                        &aux,
                        data,
                        &commitment,
                        &security,
                        &proof,
                    ) {
                        Ok(()) => {
                            log!("🎉 Proof verification successful!");
                            format!(
                                "✅ Paillier encryption in range proof successful!\nPlaintext bit size: {} bits\nActual plaintext: {} (truncated)\nProof verified successfully!",
                                security.l,
                                format!("{}", plaintext).chars().take(20).collect::<String>()
                            )
                        },
                        Err(e) => {
                            log!("❌ Proof verification failed: {:?}", e);
                            format!("❌ Proof verification failed: {:?}", e)
                        }
                    }
                },
                Err(e) => {
                    log!("❌ Failed to create proof: {:?}", e);
                    format!("❌ Failed to create proof: {:?}", e)
                }
            }
            
        },
        Err(e) => {
            log!("❌ Failed to encrypt plaintext: {:?}", e);
            format!("❌ Failed to encrypt plaintext: {:?}", e)
        }
    }
}

// Additional logging utility functions

/// Log an info message to the browser console
#[wasm_bindgen]
pub fn log_info(message: &str) {
    log!("ℹ️ {}", message);
}

/// Log a warning message to the browser console
#[wasm_bindgen]
pub fn log_warn(message: &str) {
    console::warn_1(&message.into());
}

/// Log an error message to the browser console
#[wasm_bindgen]
pub fn log_error(message: &str) {
    console::error_1(&message.into());
}

/// Log a debug message to the browser console
#[wasm_bindgen]
pub fn log_debug(message: &str) {
    console::debug_1(&message.into());
}

/// Example function showing different logging levels
#[wasm_bindgen]
pub fn test_logging_levels() -> String {
    log_info("This is an info message");
    log_warn("This is a warning message");
    log_error("This is an error message");
    log_debug("This is a debug message");
    log!("This is a regular log message");
    
    "Check the browser console to see different log levels!".to_string()
} 
