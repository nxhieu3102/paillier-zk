#!/bin/bash
set -e

# Install wasm-pack if not already installed
if ! command -v wasm-pack &> /dev/null; then
  echo "Installing wasm-pack..."
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Build the project for web
echo "Building WASM package..."
wasm-pack build --target web

# Create a directory for serving if it doesn't exist
mkdir -p www

# Copy the HTML file to the www directory
cp index.html www/

# Copy the WASM package to the www directory
cp -r pkg www/

echo "Build complete! You can now serve the 'www' directory with a web server."
echo "For example, run: npx http-server www" 
