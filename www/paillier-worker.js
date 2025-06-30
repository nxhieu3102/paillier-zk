// Web Worker for Paillier ZK operations
// This runs in a separate thread to avoid blocking the main UI

let paillierZk = null;

// Initialize the WASM module in the worker
async function initWasm() {
  try {
    // Import the WASM module
    const module = await import('./pkg/paillier_zk.js');
    await module.default();
    paillierZk = module;
    
    // Send ready message to main thread
    self.postMessage({
      type: 'ready',
      message: 'WASM module loaded in worker'
    });
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: `Failed to load WASM in worker: ${error.message}`
    });
  }
}

// Handle messages from the main thread
self.onmessage = async function(e) {
  const { type, data } = e.data;
  
  switch (type) {
    case 'init':
      await initWasm();
      break;
      
    case 'test_paillier_range':
      if (!paillierZk) {
        self.postMessage({
          type: 'error',
          message: 'WASM module not initialized'
        });
        return;
      }
      
      try {
        // Send progress update
        self.postMessage({
          type: 'progress',
          message: '🔄 Starting Paillier encryption in range proof...'
        });
        
        // Run the test
        const result = paillierZk.test_paillier_encryption_in_range();
        
        // Send the result back to main thread
        self.postMessage({
          type: 'result',
          message: result
        });
      } catch (error) {
        self.postMessage({
          type: 'error',
          message: `❌ Error in Paillier test: ${error.message}`
        });
      }
      break;
      
    default:
      self.postMessage({
        type: 'error',
        message: `Unknown message type: ${type}`
      });
  }
};

// Handle any unhandled errors in the worker
self.onerror = function(error) {
  self.postMessage({
    type: 'error',
    message: `Worker error: ${error.message}`
  });
}; 
