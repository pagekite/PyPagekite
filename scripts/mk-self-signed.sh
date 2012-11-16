#!/bin/bash
DOMAIN=$1
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=$DOMAIN"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
cat server.key server.crt >server.pem
rm -f server.key server.csr server.crt

