#!/bin/bash

cat './scripts/jws-example-clear.json' | jose-util sign --key ./scripts/jwk-sig-example.com-priv.json --alg EdDSA
