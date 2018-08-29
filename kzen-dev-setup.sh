#!/bin/sh

echo "KZen dev Setup"
echo "Installing Git hooks..."
git clone https://github.com/KZen-networks/scripts.git
chmod -R +x scripts/git/hooks/rust/
cp scripts/git/hooks/rust/* .git/hooks/
rm -rf scripts
echo "Done."