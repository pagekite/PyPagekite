#!/bin/bash
#
# Primitive black-box test for pagekite.py
#
export PATH=.:$PATH
export http_proxy=

PKB=$1
PKF=$2
[ "$PKF" = "-" ] && PKF="$PKB"
shift
shift

LOG="/tmp/pk-test.log"
PKARGS="$*"
PKA="--clean --debugio --ca_certs=$0"
PORT=12000
let PORT="$PORT+($$%10000)"

[ "$PKF" = "" ] && {
  echo "Usage: $0 /path/to/pagekite.py [global pagekite options]"
  exit 1
}
echo -n "Testing versions: $($PKB --clean --appver)/$($PKF --clean --appver) ($PKARGS)"

HAVE_TLS=" (SSL Enabled)"
$PKB --clean $PKARGS "--tls_endpoint=a:$0" --settings >/dev/null 2>&1 \
  || HAVE_TLS=""
$PKF --clean $PKARGS "--tls_endpoint=a:$0" --settings >/dev/null 2>&1 \
  || HAVE_TLS=""
echo "$HAVE_TLS"


###############################################################################

__logwait() {
  COUNT=0
  while [ 1 ]; do
    [ -e "$1" ] && grep "$2" $1 >/dev/null && return 0
    perl -e 'use Time::HiRes qw(sleep); sleep(0.2)'
    let COUNT=$COUNT+1
    [ $COUNT -gt 30 ] && {
      echo -n ' TIMED OUT! '
      return 1
    }
  done
}
__TEST__() { echo -n " * $1 ..."; shift; rm -f "$@"; touch "$@"; }
__PART_OK__() { echo -n " ok:$1"; }
__TEST_OK__() { echo ' OK'; }
__TEST_FAIL__() { echo " FAIL:$1"; shift; kill "$@"; exit 1; }
__TEST_END__() { echo; kill "$@"; }

###############################################################################
__TEST__ "Basic FE/BE/HTTPD setup" "$LOG-1" "$LOG-2" "$LOG-3" "$LOG-4"

  FE_ARGS="$PKARGS $PKA --isfrontend --ports=$PORT --domain=*:testing:ok"
  [ "$HAVE_TLS" = "" ] || FE_ARGS="$FE_ARGS --tls_endpoint=testing:$0 \
                                            --tls_default=testing"
 ($PKF $FE_ARGS --settings
  $PKF $FE_ARGS --logfile=stdio 2>&1) >$LOG-1 2>&1 &
  KID_FE=$!
__logwait $LOG-1 listen=:$PORT || __TEST_FAIL__ 'setup:FE' $KID_FE

  BE_ARGS1="$PKA --frontend=localhost:$PORT \
                 --backend=http:testing:localhost:80:ok"
  [ "$PKF" = "$PKB" ] && BE_ARGS1="$PKARGS $BE_ARGS1"
  [ "$HAVE_TLS" = "" ] || BE_ARGS1="$BE_ARGS1 --fe_certname=testing"
  if [ $(echo $PKB |grep -c 0.3.2) = "0" ]; then
      TESTINGv3="no"
      BE_ARGS2="/etc/passwd $LOG-4 http://testing/"
  else
      TESTINGv3="yes"
      BE_ARGS2=""
  fi

 ($PKB $BE_ARGS1 --settings $BE_ARGS2
  $PKB $BE_ARGS1 --logfile=stdio $BE_ARGS2 2>&1) >$LOG-2 2>&1 &
  KID_BE=$!
__logwait $LOG-2 domain=testing || __TEST_FAIL__ 'setup:BE' $KID_FE $KID_BE

  # First, make sure we get a Sorry response for invalid requests.
  curl -v --silent -H "Host: invalid" http://localhost:$PORT/ 2>&1 \
    |tee $LOG-3 |grep -i 'sorry! (fe)' >/dev/null \
    && __PART_OK__ 'frontend' || __TEST_FAIL__ 'frontend' $KID_FE $KID_BE

  # Next, see if our test host responds at all...
  curl -v --silent -H "Host: testing" http://localhost:$PORT/ 2>&1 \
    |tee -a $LOG-3 |grep -i '<body' >/dev/null \
    && __PART_OK__ 'backend' || __TEST_FAIL__ 'backend' $KID_FE $KID_BE

  if [ "$TESTINGv3" = "no" ]; then
    # See if expected content is served.
    curl -v --silent -H "Host: testing" http://localhost:$PORT/etc/passwd 2>&1 \
      |tee -a $LOG-3 |grep -i 'root' >/dev/null \
      && __PART_OK__ 'httpd' || __TEST_FAIL__ 'httpd' $KID_FE $KID_BE

    # Check large-file download
    dd if=/dev/urandom of=$LOG-4 bs=1M count=1 2>/dev/null
    (echo; echo EOF;) >>$LOG-4
    curl -v --silent -H "Host: testing" http://localhost:$PORT$LOG-4 2>&1 \
      |tail -3|tee -a $LOG-3 |grep 'EOF' >/dev/null \
      && __PART_OK__ 'bigfile' || __TEST_FAIL__ 'bigfile' $KID_FE $KID_BE
  fi

  rm -f "$LOG-1" "$LOG-2" "$LOG-3" "$LOG-4"
__TEST_END__ $KID_FE $KID_BE


###############################################################################




exit 0
##[ Test certificates follow ]#################################################

-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCcwquehPtcFov1
COXKSrU2NjB5FeRcrYlRHtzLQGv1YYsNf8b/MAzwOWQteElulKnY0XsfwEOt3jUs
WHSs9vIitStzkhGa75Z4BoxVUC+mztMgS5zyd9d7DFmvagfDf54jzPNmBALnzLCF
cCioiSFxObBDHm3VFN5yeRs1tqvBg2FopnNDLrwwj4pzsF8PVrbceADTtreyNbkh
UEzmFq4SbVZ5/IwvzKbPgeI456bsjPyZookJHEyhGtsxHg/DMN2/19CBo9lbMqVu
JQkc80se9/QWFG7ldY7N2jPI6ljXgNFajTB0RXvhJIKK2yDCXxaeRYUVNjqVMuzJ
VCpHrCPlAgMBAAECggEACHCGnX3aq9uJj236M8jlNqpLiR6qRmm6sdkFLsAkz8zU
7VYgGDm1s0feYoBOW8YPMDLJpoJLDSpLFzxv6Pv75Jh3uBIjdoGdn+VNBYQlUfK3
9SN9AKTTv2Er1ut7ctqvteJhMZstA4kb8SMtB93SJMQOqZ5oGrJemNp3ojhXyOQ8
nzhq/YS+6aBBt9zp1HCkvTjG0A07rDcFSrmxJ9BuIHd6TScvdY5ml1fshNMWceCp
Uh+b9IMysfJxXiaKsMULf+bVYA4hYbUfYZl2t6U9vGULbKnEBmu5UO6PgnHH+pRD
tOngy9EXVvUba2BBPsL9grKUW93todzaCSAPDBUfQQKBgQDN4cmXlnFdFWybm89t
2O9kMXgF7cdE9hGa3UQ/KdyiMT7ZKXXsPAMtRF1CodNy0HFGfMC+qV99y+Z9j6oy
rP0UaewdMiIbfQmP/wzERMgJYgHjrKjS+Bgh+0OV/v/fwqVBDXC1SIh0vrXyeVTl
rompkTo2B5Rq1GaFMyX8G4udsQKBgQDC67ZEeUTG9E6WH5caX8xnZ4jE1SXDja3v
2UVO/5zMeTz+RcCZwWUxP5l/Ab1oWi8Rvelzlrk2pjPoVoJi4XMPPBEYRH10EQJt
7GjOhcwb3cvfxb7aVelUyIlIUWeA9sDwctJmGoCmfK7Fbysze20F5lEzKNf/m0a9
lzzZJriydQKBgQDGrodJ95ANAVjfTly+KCTVrvuh1RaBkWnp5nAu+GoIR7fcACvh
vwRd0eSiIeMZoNg/6rJjDLavgm87asIXx2MwKQwIHNJXbrIkuUCLw8i7bU5fdccy
WOOJH57YiM5LFN8/SQYknAu7hjO1/KsWP/pvnkvryiLLeZA6KOMWSUrR8QKBgQC2
MnQF30Ddo4FNrCumuIMs6MccDYymFOnP90xkwmODcZQErZiRYAfBmAxXfn3Ya+vx
bo4nwGxR29tLQonP+aJ+TAxCncqSUk/uBfwVh1U5ewHVolZ6abGX0XcZRRY1ovDI
ENwAGqfEd2k6HWbJUYaf7CBcbMIyJ6dhElwLMrmT/QKBgQC0Dpt8gxG/mODv8dHo
an1WTsg6mjVevsLxejD3X8frY//ezm1H2vh7bIAcponH4x0TFMony3A4HMAKCmYW
XCi7uBJDHJSjBbCP2pdMVsc4S2u4LTgz+C0kkjsDPJ+jDDJYEn3sgV2ZRBPgT8Oe
n0HR5+etzvDhsNwXsFstWQsTnQ==
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDGTCCAgECAQEwDQYJKoZIhvcNAQELBQAwTDELMAkGA1UEBhMCSVMxEjAQBgNV
BAgMCVJleWtqYXZpazETMBEGA1UECgwKQmVhbnN0YWxrczEUMBIGA1UEAwwLZXhh
bXBsZS5vcmcwIBcNMjMwNzE2MDE0MjMwWhgPMzAyMjExMTYwMTQyMzBaMFcxCzAJ
BgNVBAYTAklTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQxEDAOBgNVBAMMB3Rlc3RpbmcwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCcwquehPtcFov1COXKSrU2NjB5FeRcrYlRHtzL
QGv1YYsNf8b/MAzwOWQteElulKnY0XsfwEOt3jUsWHSs9vIitStzkhGa75Z4BoxV
UC+mztMgS5zyd9d7DFmvagfDf54jzPNmBALnzLCFcCioiSFxObBDHm3VFN5yeRs1
tqvBg2FopnNDLrwwj4pzsF8PVrbceADTtreyNbkhUEzmFq4SbVZ5/IwvzKbPgeI4
56bsjPyZookJHEyhGtsxHg/DMN2/19CBo9lbMqVuJQkc80se9/QWFG7ldY7N2jPI
6ljXgNFajTB0RXvhJIKK2yDCXxaeRYUVNjqVMuzJVCpHrCPlAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAE2MkOMJ+h4dPcz6nhPggd6uF5DkBkuUQ3tZlHP9plJZG1Z/
gIHT1QVw4QaYsNfWJLMJOiKLVly17I7aSMmXRxxKYCvLe5nkpt8J7M38wbB9/cqg
1nVNIV9RP7Og7gXfMsJJdzV5u/L6kXRDa5besNsGV4SYCdRr1I2f5mBF6nIBx9Zo
mZs5fGNGt7qaIrscs6APkTDyEvGMF1iuBfEQtliTP56f/slFlf/RVTULerril4Wn
rifqbbEIFEJe9G2YTxNQrfzG5kkHyejTOi7+L8EYim3vzsZ6f1VF9d+qUTvlx4sH
ply+O9tEYo+79qQs2JcSacSpDWHAO6/NGjTQHcM=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDezCCAmOgAwIBAgIUX3K3z/DNuDiAdPYkZkxtVBg+REUwDQYJKoZIhvcNAQEL
BQAwTDELMAkGA1UEBhMCSVMxEjAQBgNVBAgMCVJleWtqYXZpazETMBEGA1UECgwK
QmVhbnN0YWxrczEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwIBcNMjMwNzE2MDEzNTQx
WhgPMzAyMjExMTYwMTM1NDFaMEwxCzAJBgNVBAYTAklTMRIwEAYDVQQIDAlSZXlr
amF2aWsxEzARBgNVBAoMCkJlYW5zdGFsa3MxFDASBgNVBAMMC2V4YW1wbGUub3Jn
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5w6J9glSct6zUCP48wf9
Wo5/mKBsfVDw0AJou0tuvb2VqeCvpkSACgFjSez6w97dM4YcNsFZb7fpbSuDMr3G
uwyI7bUo3AHEhgra0BG34eJxeyCv1CVRrS8eSQ/+OYkYr/MR3bA3reoSnvofz3zu
aG6gymA3tq4vZyU1GeOrEuUzZTeCJ8jXAs3CtH4n6QXTp3JYzI3tJXGGnGo+fjAS
PjhqN/mCy2gY8symI5weEUk7Ef/cC9Gyu/hPI35qp+ywl5q9Ro9A3YMZdNDEkvMM
ZMYdAKC757S+rVQBJOTYas6FTRfR/mfFdATExos/Cqv6DKyxIDV8TYnSaiuV01NO
KQIDAQABo1MwUTAdBgNVHQ4EFgQULXZ8hqHK2meSFF1denZlj749wIIwHwYDVR0j
BBgwFoAULXZ8hqHK2meSFF1denZlj749wIIwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAGu6wDVHHFtln+MQwqrYOHub/n2ApsyvKAmk0owv/zUS9
F+eKUMB28jpe50NyRFo2v935TgX2oPuttLQezu9X47TCbAc99HQLQsWajYvLQUji
zkafSV1iaVBHphEnCjEa+wpO//EbQiGugDZGe4J4K87DEZFuOsSCwo4ji77AGh1y
V2+yhGgk6HQL5lHzlAvFIHn5+Pq9Z2/laTm0zANu7jXtlXPf3tDzV1TW7KU2LT7s
jSI1aTgT3wXfnlw3i2Hi7uuHdKGvwE9jTitclO6F5qVLy3fp2cjO3P9JZj6LhKDn
SSNvJik/CqSxrHo69eRwfbPUsra4vFIhidYJI3IETQ==
-----END CERTIFICATE-----
