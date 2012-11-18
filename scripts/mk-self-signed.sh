#!/bin/bash
#
# This script will generate a self signed certificate which claims
# validity for one or more domain names using the subjectAltName extension.
#
# Country, organization and other expected fields are left blank.
#

DOMAIN=$1
if [ "$DOMAIN" = "" ]; then
  echo "Usage: $0 maindomain.com [otherdomain1.net otherdomain2.org ...]"
  exit 1
fi

cat <<tac >self-signed.cfg
subjectAltName = @alt_names

[alt_names]
tac
COUNT=1
for dom in $@; do
  echo "DNS.$COUNT = $dom" >>self-signed.cfg
  let COUNT=$COUNT+1
done

openssl genrsa -out self-signed.key 2048
openssl req -new -key self-signed.key -out self-signed.csr \
             -subj "/CN=Anonymous/O=Independent/OU=Person"
openssl x509 -req -extfile self-signed.cfg -days 3650 \
             -in self-signed.csr -signkey self-signed.key -out self-signed.crt

cat self-signed.key self-signed.crt >self-signed.pem

rm -f self-signed.cfg self-signed.key self-signed.csr self-signed.crt
