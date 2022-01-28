#!/bin/bash

cd ${0%/*}

# Generate a new CA if there isn't one already
if [ ! -e ca_cert_DONOTUSE.pem ]; then
  openssl genrsa -out ca_key_DONOTUSE.pem 1024

  openssl req -new -sha512 -x509 -key ca_key_DONOTUSE.pem \
   -subj "/C=US/O=Test Security/OU=Certificate Authority Example" \
   -days 3650 \
   -out ca_cert_DONOTUSE.pem
fi

if [ ! -e cacerts_DONOTUSE.pem ]; then
  curl https://www.incommon.org/custom/certificates/repository/sha384%20Intermediate%20cert.txt > cacerts_DONOTUSE.pem
  echo >> cacerts_DONOTUSE.pem
  cat ca_cert_DONOTUSE.pem >> cacerts_DONOTUSE.pem
fi


gen_cert() {
  openssl genrsa -out "${1}_key_DONOTUSE.pem" 1024
  openssl req -config test.conf -new -sha512 -key "${1}_key_DONOTUSE.pem" -out temp.csr

  touch ca.db.index
  serial=$(( 100 + RANDOM % 9900 ))
  echo $serial > ca.db.serial
  yes | openssl ca -config test_ca.conf -extensions v3_ca -extfile test.conf \
    -subj "$2" \
    -out "${1}_cert_DONOTUSE.pem" -infiles temp.csr

  rm ca.db.index ca.db.index.attr ca.db.index.old ca.db.serial ca.db.serial.old ${serial}.pem temp.csr

  openssl x509 -in "${1}_cert_DONOTUSE.pem" -noout -text
}

for kind in server npe{1,2}; do
  gen_cert $kind "/C=US/O=Global Security/CN=$kind"
done


gen_cert user "/CN=uid=ppena,ou=people,dc=umich,dc=edu"

