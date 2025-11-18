#!/bin/bash
# Generate ECDSA P-256 Certificate Chain for TLS 1.3 Testing

set -e

echo "=== Generating ECDSA P-256 Certificate Chain ==="
echo

# 1. Generate Root CA
echo "1. Generating Root CA (ECDSA P-256)..."
openssl ecparam -name prime256v1 -genkey -noout -out root-ca.key
openssl req -new -x509 -days 3650 -key root-ca.key -out root-ca.crt \
    -subj "/C=US/ST=CA/O=HPTLS Test/CN=HPTLS Root CA ECDSA" \
    -sha256

# 2. Generate Intermediate CA
echo "2. Generating Intermediate CA (ECDSA P-256)..."
openssl ecparam -name prime256v1 -genkey -noout -out intermediate-ca.key
openssl req -new -key intermediate-ca.key -out intermediate-ca.csr \
    -subj "/C=US/ST=CA/O=HPTLS Test/CN=HPTLS Intermediate CA ECDSA" \
    -sha256

# Sign Intermediate CA with Root CA
openssl x509 -req -in intermediate-ca.csr -CA root-ca.crt -CAkey root-ca.key \
    -CAcreateserial -out intermediate-ca.crt -days 1825 -sha256 \
    -extfile <(echo "basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,cRLSign")

# 3. Generate Server Certificate
echo "3. Generating Server Certificate (ECDSA P-256)..."
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=CA/O=HPTLS Test/CN=test.example.com" \
    -sha256

# Sign Server Certificate with Intermediate CA
openssl x509 -req -in server.csr -CA intermediate-ca.crt -CAkey intermediate-ca.key \
    -CAcreateserial -out server.crt -days 365 -sha256 \
    -extfile <(echo "subjectAltName=DNS:test.example.com,DNS:*.test.example.com
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth")

# 4. Convert to DER format for Rust tests
echo "4. Converting to DER format..."
openssl x509 -in root-ca.crt -outform DER -out root-ca.der
openssl x509 -in intermediate-ca.crt -outform DER -out intermediate-ca.der
openssl x509 -in server.crt -outform DER -out server.der
openssl ec -in server.key -outform DER -out server.key.der

# 5. Verify certificate chain
echo "5. Verifying certificate chain..."
openssl verify -CAfile root-ca.crt intermediate-ca.crt
openssl verify -CAfile root-ca.crt -untrusted intermediate-ca.crt server.crt

echo
echo "=== ECDSA P-256 Certificate Chain Generated Successfully ==="
echo
echo "Files created:"
echo "  Root CA:         root-ca.{key,crt,der}"
echo "  Intermediate CA: intermediate-ca.{key,crt,der}"
echo "  Server:          server.{key,crt,der}, server.key.der"
echo
echo "Certificate details:"
openssl x509 -in server.crt -noout -text | grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)"
