# WebAssembly Support for Paillier-ZK

This document explains how to build and use the Paillier-ZK library with WebAssembly.

## Building for WebAssembly

1. Make sure you have Rust and wasm-pack installed:
   ```bash
   curl https://sh.rustup.rs -sSf | sh
   curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
   ```

2. Run the build script:
   ```bash
   ./build_wasm.sh
   ```

3. To test the WASM build, you can serve the `www` directory with a web server:
   ```bash
   # Install http-server if you don't have it
   npm install -g http-server
   
   # Serve the directory
   http-server www
   ```

4. Open your browser and navigate to http://localhost:8080 to test the WASM functionality.

## Using in your own project

To use the WASM build of Paillier-ZK in your own project:

1. Copy the contents of the `pkg` directory to your project.
2. Import the module in your JavaScript or TypeScript code:
   
   ```javascript
   import * as paillierZk from './paillier_zk.js';
   
   async function init() {
     await paillierZk.default();
     
     // Now you can use the library
     const result = paillierZk.wasm_test();
     console.log(result);
   }
   
   init();
   ```

## Available WASM Functions

- `wasm_test()`: Simple test function to verify that the WASM bindings are working.
- `test_bigint_operations()`: Tests basic BigInt operations to verify numeric functionality.
- `test_basic_crypto()`: Tests random number generation to verify cryptographic capabilities.
- `test_paillier_encryption_in_range()`: **NEW!** Tests a complete Paillier encryption in range zero-knowledge proof.

### Paillier Encryption in Range Proof

The `test_paillier_encryption_in_range()` function demonstrates a complete zero-knowledge proof workflow:

1. **Setup**: Creates security parameters optimized for browser performance (128-bit range, 64-bit epsilon)
2. **Key Generation**: Generates Paillier encryption keys and auxiliary parameters
3. **Encryption**: Encrypts a random plaintext within the specified range
4. **Proof Generation**: Creates a zero-knowledge proof that the encrypted value is within range
5. **Verification**: Verifies the proof without revealing the plaintext

This function showcases the core functionality of the library and proves that complex cryptographic operations work correctly in WebAssembly.

## Performance Considerations

The WASM implementation uses smaller security parameters compared to production settings to ensure reasonable performance in browsers:

- **Range size (l)**: 128 bits (vs 1024+ in production)
- **Slackness (epsilon)**: 64 bits (vs 256+ in production)
- **Challenge size (q)**: 64 bits (vs 128+ in production)

For production use, you should adjust these parameters based on your security requirements and performance constraints.

## Next Steps

To further develop the WASM support:

1. **Expose more functionality:**
   - Add bindings for batch proofs
   - Implement serialization for complex types
   - Add support for different proof types

2. **Improve performance:**
   - Add WebWorker support for CPU-intensive operations
   - Consider memory optimizations for large numbers
   - Implement progressive proof generation with progress callbacks

3. **Integration examples:**
   - Create examples showing integration with popular frameworks (React, Vue, etc.)
   - Develop a TypeScript definition file for better type support

## Troubleshooting

If you encounter issues:

- **Build failures:** Make sure you have the WebAssembly target installed (`rustup target add wasm32-unknown-unknown`)
- **Runtime errors:** Check browser console for details
- **Performance issues:** The proof generation may take several seconds in browsers - this is normal for cryptographic operations
- **Memory issues:** Large proofs may require significant memory; consider using smaller security parameters for testing

## Browser Compatibility

The WASM build should work in all modern browsers that support WebAssembly:
- Chrome/Edge (v79+)
- Firefox (v72+)
- Safari (v14+)
- Opera (v69+)

## Notes

- This is a basic WASM binding primarily for testing library compatibility with WebAssembly.
- For a full-featured application, you would likely want to expose more of the library's functionality.
- WebAssembly builds currently use the browser's built-in random number generator via the `getrandom` crate with the `js` feature.
- If you encounter issues related to memory or performance, you might need to adjust the security parameters or the size of data being processed. 
