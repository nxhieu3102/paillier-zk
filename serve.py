#!/usr/bin/env python3
"""
Simple HTTP server to serve the Paillier ZK WASM demo.
This server adds the necessary CORS headers and MIME types for WASM files.
"""

import http.server
import socketserver
import os
import webbrowser
from urllib.parse import urlparse

class WAsmHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        # Add WASM MIME type
        if self.path.endswith('.wasm'):
            self.send_header('Content-Type', 'application/wasm')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

def main():
    port = 8000
    # Change to the directory containing the demo files
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    print(f"Starting HTTP server on port {port}")
    print(f"Serving files from: {os.getcwd()}")
    print(f"Open your browser to: http://localhost:{port}/demo.html")
    print("Press Ctrl+C to stop the server")
    
    # Automatically open the browser
    try:
        webbrowser.open(f'http://localhost:{port}/demo.html')
    except:
        print("Could not automatically open browser")
    
    with socketserver.TCPServer(("", port), WAsmHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    main() 
