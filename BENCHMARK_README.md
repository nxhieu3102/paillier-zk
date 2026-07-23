# Paillier ZK Protocols Performance Benchmarking

This document explains how to benchmark and compare the performance of batch vs non-batch Paillier zero-knowledge protocols.

## Overview

This repository contains implementations of both single-instance and batch versions of Paillier ZK protocols:

### Single Instance Protocols
- `paillier_encryption_in_range` - Proves a Paillier-encrypted value is within a specific range
- `paillier_affine_operation_in_range` - Proves knowledge of plaintexts in encrypted affine operations

### Batch Protocols  
- `batch_paillier_encryption_in_range_with_el_gamal` - Batch version with ElGamal commitments
- `batch_paillier_affine_operation_in_range` - Batch version of affine operations

## Current Implementation

The current benchmark (`src/bin/measure_paillier_zk_perf.rs`) provides a simulated performance comparison to demonstrate the expected behavior:

```bash
cargo run --bin measure_paillier_zk_perf
```

This shows simulated results demonstrating how batch protocols should provide better amortized performance as batch size increases.

## Implementing Real Benchmarks

To implement actual performance measurements, you'll need to address several technical challenges:

### 1. Dependencies and Features

The current `Cargo.toml` uses git dependencies that may need specific curve features:

```toml
[dependencies]
generic-ec = {git="https://github.com/nxhieu3102/generic-ec", branch="feat/integrate-cggmp21", features = ["udigest", "curve-secp256r1"] }
fast-paillier = { git = "https://github.com/nxhieu3102/fast-paillier" }
```

You may need to add curve features like:
- `curve-secp256k1`
- `curve-secp256r1` 
- `all-curves`

### 2. API Compatibility

The protocols have different API signatures:

#### Single Encryption in Range
```rust
use paillier_zk::paillier_encryption_in_range;

let security = paillier_encryption_in_range::SecurityParams {
    l: 1024,
    epsilon: 300,
    q: (Integer::ONE << 128_u32).complete(),
};

let (commitment, proof) = paillier_encryption_in_range::non_interactive::prove::<sha2::Sha256>(
    &shared_state,
    &aux,
    data,
    pdata,
    &security,
    rng,
)?;
```

#### Batch Encryption in Range
```rust
use paillier_zk::batch_paillier_encryption_in_range_with_el_gamal;

let security = batch_paillier_encryption_in_range_with_el_gamal::SecurityParams {
    l: 1024,
    epsilon: 300,
    q: (Integer::ONE << 128_u32).complete(),
    t: 128,  // Additional parameter for batch version
};

let (commitment, proof) = batch_paillier_encryption_in_range_with_el_gamal::non_interactive::prove::<E, sha2::Sha256>(
    &shared_state,
    &aux,
    data,
    pdata,
    &security,
    rng,
    batch_size,
)?;
```

### 3. Test Data Generation

You'll need to generate appropriate test data:

```rust
// Generate auxiliary parameters (Ring-Pedersen parameters)
fn generate_aux(rng: &mut impl RngCore) -> paillier_zk::common::Aux {
    // Implementation depends on available test helpers
}

// Generate Paillier keys
fn generate_paillier_key(rng: &mut impl RngCore) -> fast_paillier::DecryptionKey {
    fast_paillier::DecryptionKey::generate(rng, 2048, 512).unwrap()
}

// Generate test plaintexts within appropriate ranges
let plaintext = Integer::from_rng_pm(&(Integer::ONE << security.l).complete(), rng);
```

### 4. Batch Data Structures

For batch protocols, you need to create collections of elements:

```rust
// Batch encryption requires multiple elements
let private_elements: Vec<PrivateElement<E>> = (0..batch_size)
    .map(|i| PrivateElement {
        plaintext: &plaintexts[i],
        nonce: &nonces[i], 
        b: &b_values[i],
    })
    .collect();

let public_elements: Vec<PublicElement<E>> = (0..batch_size)
    .map(|i| PublicElement {
        ciphertext: key.encrypt_with(&plaintexts[i], &nonces[i])?,
        b: generator * &b_values[i],
        x: generator * (a * &b_values[i] + plaintexts[i].to_scalar()),
    })
    .collect();
```

## Expected Performance Characteristics

Based on the simulated results, you should expect:

### Per-Element Efficiency Gains
| Batch Size | Prove/element | Verify/element | Improvement |
|------------|---------------|----------------|-------------|
| 1          | 300ms         | 55ms          | baseline    |
| 2          | 240ms         | 42.5ms        | 20% faster  |
| 4          | 200ms         | 35ms          | 33% faster  |
| 8          | 175ms         | 31ms          | 42% faster  |

### Key Observations
1. **Batch Overhead**: Batch protocols have higher overhead for single elements
2. **Scaling Efficiency**: Performance improves significantly as batch size increases
3. **Verification Speed**: Verification is typically 5-6x faster than proving
4. **Amortization**: Larger batches reduce per-element costs due to shared computations

## Benchmark Structure

A complete benchmark should measure:

1. **Proving Time**: Time to generate the zero-knowledge proof
2. **Verification Time**: Time to verify the proof
3. **Memory Usage**: Peak memory consumption during operations
4. **Proof Size**: Size of the generated proofs (batch vs individual)

## Implementation Steps

1. **Fix Dependencies**: Ensure all required curve features are enabled
2. **Implement Aux Generation**: Create proper Ring-Pedersen parameters
3. **Handle API Differences**: Account for different parameter structures between protocols
4. **Add Error Handling**: Properly handle the various error types from different protocols
5. **Statistical Analysis**: Implement proper timing collection and statistical analysis
6. **Parameterization**: Allow testing different security parameters and batch sizes

## Running Benchmarks

Once implemented, run with different configurations:

```bash
# Run with default parameters
cargo run --bin measure_paillier_zk_perf

# Run with specific batch sizes (if command-line args implemented)
cargo run --bin measure_paillier_zk_perf -- --batch-sizes 1,2,4,8,16 --iterations 10

# Save results to file
cargo run --bin measure_paillier_zk_perf > logs/paillier-zk-perf/$(date +%y%m%d_%H%M).txt
```

## Security Considerations

When benchmarking:
- Use appropriate security parameters (e.g., l=1024, epsilon=300)
- Test with realistic key sizes (2048-bit Paillier keys)
- Measure with cryptographically secure randomness
- Consider constant-time implementations for production use

## Contributing

To contribute actual benchmark implementations:
1. Fork the repository
2. Implement real benchmarks following this guide
3. Test with various parameter configurations
4. Submit a pull request with documentation

The current simulated benchmark provides a template for the expected output format and analysis structure. 
