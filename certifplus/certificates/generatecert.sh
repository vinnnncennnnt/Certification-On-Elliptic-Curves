#!/bin/bash -x

# AC Keys
openssl ecparam -out ecc.ca.private.key.pem -name prime256v1 -genkey
openssl ec -in ecc.ca.private.key.pem -pubout -out ecc.ca.public.key.pem

# Server Keys
openssl ecparam -out ecc.server.private.key.pem -name prime256v1 -genkey
openssl ec -in ecc.server.private.key.pem -pubout -out ecc.public.key.pem

# AC certificate
openssl req -config <(printf "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=CA:TRUE") -new -nodes -subj "/C=FR/L=LIMOGES/O=CRYPTIS/OU=SECUTIC/CN=ACCRYPTIS" -x509 -extensions ext -sha256 -key ecc.ca.private.key.pem -text -out ecc.ca.cert.pem

# Server certificate
openssl req -config <(printf "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=CA:FALSE") -new -subj "/C=FR/L=LIMOGES/O=CRYPTIS/OU=SECUTIC/CN=localhost" -reqexts ext -sha256 -key ecc.server.private.key.pem -text -out ecc.server.csr.pem

# sign Server certificate with AC private key
openssl x509 -req -days 3650 -CA ecc.ca.cert.pem -CAkey ecc.ca.private.key.pem -CAcreateserial -extfile <(printf "basicConstraints=critical,CA:FALSE") -in ecc.server.csr.pem -text -out ecc.server.cert.pem

# create Server bundle for TLS
cat ecc.server.private.key.pem ecc.server.cert.pem > server_bundle.pem