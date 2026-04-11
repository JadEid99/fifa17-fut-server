#!/bin/bash
# Generate test certificates for the FIFA 17 server
# Run this once after cloning the repo

cd server-standalone

# CA key and cert
openssl genrsa -out ca.key 1024 2>/dev/null
openssl req -new -md5 -x509 -days 28124 -key ca.key -out ca.crt \
  -subj "/OU=Online Technology Group/O=Electronic Arts, Inc./L=Redwood City/ST=California/C=US/CN=OTG3 Certificate Authority" 2>/dev/null

# Server key and cert (1024-bit, SHA1)
openssl genrsa -out server1024.key 1024 2>/dev/null
openssl req -new -key server1024.key -out server1024.csr \
  -subj "/CN=winter15.gosredirector.ea.com/OU=Global Online Studio/O=Electronic Arts, Inc./ST=California/C=US" 2>/dev/null
openssl x509 -req -in server1024.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server1024_sha1.crt -days 10000 -sha1 2>/dev/null
openssl x509 -outform der -in server1024_sha1.crt -out server1024_sha1.der 2>/dev/null
openssl x509 -outform der -in ca.crt -out ca.der 2>/dev/null

echo "Certificates generated in server-standalone/"
