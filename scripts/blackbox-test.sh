#!/bin/bash
#
# Primitive black-box test for pagekite.py
#
export PATH=.:$PATH

PK=$1
shift
LOG="/tmp/pk-test.log"
PKARGS="$*"
PKA="$PKARGS --clean --nullui --logfile=$LOG"
PORT=12000
let PORT="$PORT+($$%10000)"

[ "$PK" = "" ] && {
  echo "Usage: $0 /path/to/pagekite.py [global pagekite options]"
  exit 1
}
echo -n "Testing version: "
echo -n "$($PK --clean --appver) ($PKARGS)"

HAVE_TLS=" (SSL Enabled)"
$PK --clean $PKARGS --tls_endpoint=a:b --settings >/dev/null 2>&1 || HAVE_TLS="" 
echo "$HAVE_TLS"


###############################################################################

__logwait() {
  COUNT=0
  while [ 1 ]; do
    [ -e "$1" ] && grep "$2" $1 >/dev/null && return 0
    sleep 1
    let COUNT=$COUNT+1
    [ $COUNT -gt 10 ] && {
      echo -n ' TIMED OUT! '
      return 1
    }
  done
}
__TEST__() { echo -n " * $1 ..."; shift; rm -f "$@"; }
__PART_OK__() { echo -n " ok:$1"; }
__TEST_OK__() { echo ' OK'; }
__TEST_FAIL__() { echo " FAIL:$1"; shift; kill "$@"; exit 1; }
__TEST_END__() { echo; kill "$@"; }

###############################################################################
__TEST__ "Basic HTTP/HTTPD setup" "$LOG-1" "$LOG-2" "$LOG-3"

  FE_ARGS="$PKA-1 --isfrontend --ports=$PORT --domain=*:testing:ok"
  [ "$HAVE_TLS" = "" ] || FE_ARGS="$FE_ARGS --tls_endpoint=testing:$0 \
                                            --tls_default=testing"
  $PK $FE_ARGS --settings >$LOG-1
  $PK $FE_ARGS &
  KID_FE=$!
__logwait $LOG-1 listen=:$PORT || __TEST_FAIL__ 'setup:FE' $KID_FE

  # Create large file of crap
  dd if=/dev/urandom of=$LOG-4 bs=1M count=1 2>/dev/null
  (echo; echo EOF;) >>$LOG-4

  BE_ARGS1="$PKA-2 --frontend=localhost:$PORT \
                   --backend=http:testing:localhost:80:ok"
  [ "$HAVE_TLS" = "" ] || BE_ARGS1="$BE_ARGS1 --fe_certname=testing"
  BE_ARGS2="/etc/passwd $LOG-4 http://testing/"
  $PK $BE_ARGS1 --settings $BE_ARGS2 >$LOG-2
  $PK $BE_ARGS1 $BE_ARGS2 &
  KID_BE=$!
__logwait $LOG-2 connect= || __TEST_FAIL__ 'setup:BE' $KID_FE $KID_BE

  # First, make sure we get a Sorry response for invalid requests.
  curl -v --silent -H "Host: invalid" http://localhost:$PORT/ 2>&1 \
    |tee $LOG-3 |grep -i 'sorry! (fe)' >/dev/null \
    && __PART_OK__ 'frontend' || __TEST_FAIL__ 'frontend' $KID_FE $KID_BE

  # Next, see if our test host responds at all...
  curl -v --silent -H "Host: testing" http://localhost:$PORT/ 2>&1 \
    |tee $LOG-3 |grep -i 'html' >/dev/null \
    && __PART_OK__ 'backend' || __TEST_FAIL__ 'backend' $KID_FE $KID_BE

  # See if expected content is served.
  curl -v --silent -H "Host: testing" http://localhost:$PORT/etc/passwd 2>&1 \
    |tee $LOG-3 |grep -i 'root' >/dev/null \
    && __PART_OK__ 'httpd' || __TEST_FAIL__ 'httpd' $KID_FE $KID_BE

  # Check large-file download
  curl -v --silent -H "Host: testing" http://localhost:$PORT$LOG-4 2>&1 \
    |tail -1|tee $LOG-3 |grep 'EOF' >/dev/null \
    && __PART_OK__ 'bigfile' || __TEST_FAIL__ 'bigfile' $KID_FE $KID_BE

__TEST_END__ $KID_FE $KID_BE


###############################################################################




exit 0
##[ Test certificates follow ]#################################################

-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC6qqBXNTTF41621/M8nLwyxdeN88juhzsfikFqZzeLftyzAX1H
o8uN5Sq/Mm4NApi8gRddoalWEzmDeGTzgiiIZqCwTSLa57e9mp5oIB72TT/WaAA/
9S7sbYuyQvsh6ZqDrO+vUzDGJB3bBhhEG/p3dZpHsgcwbQXGONiUANcppwIDAQAB
AoGBALY537GCxXPxlQLWKiQftjGypc10EdGZvoP5ygZ/oN/TBszRRWXsZsis0WA5
cOnOgSB0vUSwjsjyl5DatWJqy/k/YnJHT/XT4kYMTucMogKeBVSo+BVHY9pYnNZH
cCosfu9eIAkxF1lZYZGNM4zmZ7iXu4UKAYEYffQXG8PyIP0RAkEA8q736sf7d3I8
I+3nw0wfBed3PwEoTxFuzgwRtgs+MXvfWtFEwVAfvGUlrevZ7Zo/LFsYk210Ds3R
DBvYPirVxQJBAMToxkcnFRsKs6eRA16WhOoMoYaX+dc7RyujUugga3WQe0dHCHGP
baecn3xfn7xZpUccEJ1tC0ZyOz4akclT5HsCQFxxEba5HqzNMuNsyA+4e0jAdsfl
JPmZZl/OcSCq/7HRwa7ScCJC5xPYY5XwdT7wtoeq252s37yT4cF/CcwEfRECQCfD
IZboq3hkdtbVj6qgFoL0vgFh2w+9ZqfHOUyqj0iUPnCsRWY5IlmAZSxGWwk7yQZN
AoXnqSk2lAP8dYgEKtUCQDAdxF2sO5re4ZrifJnlY7/aaUC1qF9GHVtDVc/RYf+8
fWqmY7Lcl6g0Dq3ZtZul5SrZBAzaaXzbdznpabZjuww=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDNDCCAp2gAwIBAgIJAKcyd6cpKGgWMA0GCSqGSIb3DQEBBQUAMHAxCzAJBgNV
BAYTAklTMREwDwYDVQQIEwhUZXN0bGFuZDESMBAGA1UEBxMJVGVzdHZpbGxlMQ8w
DQYDVQQKEwZUZXN0Y28xEDAOBgNVBAsTB1Rlc3RlcnMxFzAVBgNVBAMTDlRlc3Qg
TWNUZXN0c29uMB4XDTExMDcwNjEzMDMyMVoXDTc1MDUwNjA2MzUwNVowcDELMAkG
A1UEBhMCSVMxETAPBgNVBAgTCFRlc3RsYW5kMRIwEAYDVQQHEwlUZXN0dmlsbGUx
DzANBgNVBAoTBlRlc3RjbzEQMA4GA1UECxMHVGVzdGVyczEXMBUGA1UEAxMOVGVz
dCBNY1Rlc3Rzb24wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALqqoFc1NMXj
XrbX8zycvDLF143zyO6HOx+KQWpnN4t+3LMBfUejy43lKr8ybg0CmLyBF12hqVYT
OYN4ZPOCKIhmoLBNItrnt72anmggHvZNP9ZoAD/1Luxti7JC+yHpmoOs769TMMYk
HdsGGEQb+nd1mkeyBzBtBcY42JQA1ymnAgMBAAGjgdUwgdIwHQYDVR0OBBYEFAR3
mICMIdts75XO1rgMbjNVhw3hMIGiBgNVHSMEgZowgZeAFAR3mICMIdts75XO1rgM
bjNVhw3hoXSkcjBwMQswCQYDVQQGEwJJUzERMA8GA1UECBMIVGVzdGxhbmQxEjAQ
BgNVBAcTCVRlc3R2aWxsZTEPMA0GA1UEChMGVGVzdGNvMRAwDgYDVQQLEwdUZXN0
ZXJzMRcwFQYDVQQDEw5UZXN0IE1jVGVzdHNvboIJAKcyd6cpKGgWMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAKPi4ApAJwyNGVhNN7V20unb6iByHjDiY
PYuLUgYxSw9mWmot5d/Trslm2T1Qm3/xlMyPWBJA1o57ayo9rQxcnjJm53uzxT2y
KipeTAr7rNc4mhPj1gawCIFU7Za5hvKW/NOMqaqTCK7Cs33GvWaFeURLXC8D4rro
2Xy3wOCFpeE=
-----END CERTIFICATE-----
