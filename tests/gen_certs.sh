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


for kind in server npe{1,2}; do
  echo serial=$serial
  openssl genrsa -out ${kind}_key_DONOTUSE.pem 1024
  openssl req -config test.conf -new -sha512 -key ${kind}_key_DONOTUSE.pem -out temp.csr

  touch ca.db.index
  serial=$(( 100 + RANDOM % 9900 ))
  echo $serial > ca.db.serial
  yes | openssl ca -config test_ca.conf -extensions v3_ca -extfile test.conf \
    -subj "/C=US/O=Global Security/CN=$kind" \
    -out ${kind}_cert_DONOTUSE.pem -infiles temp.csr

  rm ca.db.index ca.db.index.attr ca.db.index.old ca.db.serial ca.db.serial.old ${serial}.pem temp.csr

  openssl x509 -in ${kind}_cert_DONOTUSE.pem -noout -text
done


