# Paillier ZK WebAssembly Demo

This directory contains a WebAssembly (WASM) demo for the `paillier-zk` library, showcasing zero-knowledge proofs for Paillier encryption schemes with batch operations.

## Features

The WASM demo includes:

1. **Basic WASM functionality tests**
   - BigInt operations using Malachite
   - Basic cryptographic operations
   - Logging system integration

2. **Batch Paillier Affine Operation in Range**
   - Demonstration of the batch Paillier affine operation structure
   - Security parameter configuration
   - Mathematical proof concepts explanation

## Quick Start

### Prerequisites

- Rust with `wasm32-unknown-unknown` target
- `wasm-pack` tool
- Python 3 (for the HTTP server)
- Modern web browser with WebAssembly support

### Building the WASM Module

1. Make sure you have the required Rust target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. Install wasm-pack if you haven't already:
   ```bash
   cargo install wasm-pack
   ```

3. Build the WASM module:
   ```bash
   wasm-pack build --target web --features wasm
   ```

### Running the Demo

1. Start the HTTP server:
   ```bash
   python3 serve.py
   ```

2. Open your browser to `http://localhost:8000/demo.html`

3. The demo page will automatically load the WASM module and provide interactive buttons to test different functionality.

## Demo Features

### Basic Tests

- **Test Basic WASM**: Verifies that the WASM module loads and basic functions work
- **Test BigInt Operations**: Tests large integer arithmetic using Malachite
- **Test Basic Crypto**: Basic cryptographic functionality test
- **Test Logging Levels**: Demonstrates different logging levels

### Batch Paillier Affine Operation Tests

- **Test Batch Paillier Affine Operation**: Shows the security parameter configuration for batch operations
- **Demo Batch Paillier Structure**: Explains the mathematical structure of batch Paillier affine operations

## Mathematical Background

The batch Paillier affine operation in range protocol allows efficient zero-knowledge proofs for multiple encrypted affine computations of the form:

```
D_i = C_i * x_i + Enc(y_i)
```

Where:
- `C_i` is an encrypted value under public key `key0`
- `x_i` is a multiplicative factor (private)
- `y_i` is an additive factor (private)
- `D_i` is the result of the homomorphic affine operation
- `X_i = g * x_i` is a group commitment to `x_i`
- `Y_i = Enc_key1(y_i)` is `y_i` encrypted under a separate key `key1`

The protocol proves in zero-knowledge that:
- The prover knows `x_i` and `y_i` for each instance `i`
- All values are within specified bit-length bounds: `|x_i| < 2^l_x` and `|y_i| < 2^l_y`
- The computation of `D_i` is correct
- The commitments are consistent with the encrypted values

## Security Parameters

The demo uses the following security parameters:

- `l_x`: Bit size bound for multiplicative factors (256 bits in demo)
- `l_y`: Bit size bound for additive factors (256 bits in demo)
- `epsilon`: Slackness parameter for statistical security (128 bits in demo)
- `q`: Security parameter for challenge space
- `t`: Size of challenge (64 bits in demo)

## Browser Console

The demo captures console output and displays it in a dedicated console section on the page. This allows you to see:
- WASM module loading status
- Test execution results
- Detailed logging from the cryptographic operations
- Any errors that occur during execution

## Files

- `demo.html`: Interactive web demo page
- `serve.py`: HTTP server with WASM support
- `pkg/`: Generated WASM bindings and files
  - `paillier_zk.js`: JavaScript bindings
  - `paillier_zk_bg.wasm`: WASM binary
  - `paillier_zk.d.ts`: TypeScript definitions

## Troubleshooting

If you encounter issues:

1. **WASM module fails to load**: Make sure you're serving the files over HTTP (not file://)
2. **Functions not found**: Ensure the WASM module was built with the `--features wasm` flag
3. **Browser compatibility**: Use a modern browser that supports WebAssembly and ES modules

## Development

To add new WASM functions:

1. Add the function to `src/lib.rs` with `#[cfg(feature = "wasm")]` and `#[wasm_bindgen]` attributes
2. Rebuild the WASM module: `wasm-pack build --target web --features wasm`
3. Update the HTML demo to import and use the new function

## Performance Notes

The WASM demo is optimized for demonstration purposes rather than production performance. The security parameters are reduced from production values to ensure reasonable execution times in the browser environment.

For production use, you would typically use larger security parameters and run the protocols on server-side infrastructure rather than in the browser. 
