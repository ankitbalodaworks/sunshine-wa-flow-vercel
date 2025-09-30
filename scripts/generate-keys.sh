#!/usr/bin/env bash
set -euo pipefail
mkdir -p keys
# 2048-bit RSA private key (PKCS#8)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private_key.pem
# Public key to upload in WhatsApp Manager (Flows encryption)
openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
echo "Keys in ./keys. Upload public_key.pem to WhatsApp Manager > Phone Number > Business En"
