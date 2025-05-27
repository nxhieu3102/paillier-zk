# WebAssembly Support for Paillier-ZK

This project now supports WebAssembly (WASM), allowing you to use the Paillier-ZK library in web browsers.

## Quick Start

To build and test the WASM version:

1. Make sure you have Rust and wasm-pack installed:
   ```bash
   curl https://sh.rustup.rs -sSf | sh
   curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
   ```

2. Build the WASM package:
   ```bash
   ./build_wasm.sh
   ```

3. Serve the test page:
   ```bash
   # If you don't have http-server installed
   npm install -g http-server
   
   # Serve the test page
   cd www && http-server
   ```

4. Open your browser and navigate to http://localhost:8080 to test the WASM functionality.

## How It Works

The WASM support is implemented with the following components:

1. **Cargo.toml configuration:**
   - Added `wasm-bindgen` dependency
   - Added `getrandom` with `js` feature for random number generation in browsers
   - Set `crate-type = ["cdylib", "rlib"]` to generate a WebAssembly library

2. **src/wasm.rs module:**
   - Contains WebAssembly bindings using the `#[wasm_bindgen]` attribute
   - Exposes simple test functions to verify the library works in browsers

3. **build_wasm.sh script:**
   - Installs `wasm-pack` if needed
   - Builds the WASM package using `wasm-pack build --target web`
   - Sets up a directory for testing with an HTML file

## Current Functionality

The WASM build currently exposes these functions:

- `wasm_test()`: Simple function to verify the bindings work
- `test_bigint_operations()`: Tests basic BigInt arithmetic
- `test_basic_crypto()`: Tests random number generation
- `test_paillier_encryption_in_range()`: **Complete zero-knowledge proof demonstration**

### Zero-Knowledge Proof Demo

The `test_paillier_encryption_in_range()` function provides a complete demonstration of the library's core functionality:

```javascript
// Example usage in browser
const result = paillierZk.test_paillier_encryption_in_range();
console.log(result); // Shows proof generation and verification results
```

This function:
- Generates cryptographic keys and parameters
- Creates a random plaintext within a specified range
- Encrypts the plaintext using Paillier encryption
- Generates a zero-knowledge proof that the encrypted value is within range
- Verifies the proof without revealing the original plaintext

**Note:** The proof generation may take several seconds in browsers due to the computational complexity of cryptographic operations.

## Performance & Security

For browser compatibility, the WASM implementation uses reduced security parameters:
- 128-bit range size (vs 1024+ bits in production)
- 64-bit slackness parameter (vs 256+ bits in production)
- Optimized for demonstration rather than production security

## Next Steps

To further develop the WASM support:

1. **Expose more functionality:**
   - Add bindings for creating and verifying proofs with custom parameters
   - Implement serialization for complex types
   - Add support for batch proofs

2. **Improve performance:**
   - Add WebWorker support for CPU-intensive operations
   - Consider memory optimizations for large numbers
   - Implement progress callbacks for long-running operations

3. **Integration examples:**
   - Create examples showing integration with popular frameworks (React, Vue, etc.)
   - Develop a TypeScript definition file for better type support

## Troubleshooting

If you encounter issues:

- **Build failures:** Make sure you have the WebAssembly target installed (`rustup target add wasm32-unknown-unknown`)
- **Runtime errors:** Check browser console for details
- **Performance issues:** Consider reducing the security parameters for better browser performance
- **Slow proof generation:** This is normal - cryptographic proofs are computationally intensive

## Browser Compatibility

The WASM build should work in all modern browsers that support WebAssembly:
- Chrome/Edge (v79+)
- Firefox (v72+)
- Safari (v14+)
- Opera (v69+) 
