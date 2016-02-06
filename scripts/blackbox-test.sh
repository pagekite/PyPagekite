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

-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDId+cQqU0fR9sxaP96ukUdpdYMDXU7hyl/7AGTz6RkpQWzFRFr
8OwHKLLzMQMTCv31WtrjxtEWm/3mJcePCajcukfb9aXSGtMG06btwZyNDbp9H2No
Qkzspg4o86tLo6NY4ts4qTUJQJVrvcwW27n2FZhJFzU6EIzPmCzJviBYiwIDAQAB
AoGBALIHUYvJXnUuIiniHiiGrYSj1tBDT147LY6uL8RtvYenycT9K8iZX3MIIMu6
Ngm+VESFmCh6UwtqIvQ1juCnam5vGFoJoFwNKkPgXVDaXLF1UvgT9eknUMvCI757
wLsNy8rTJqzhUeBwiJvloi8vTQ4emFzt3/QWWtOrsHGi1A+JAkEA+mnZGxeA6uHM
dNatMSkOxSQP1/gbBTS0SkoYa5XiGvOht/wPBn6xobkOXvi9ZoU5Wfh4eS0wH+Gf
Ik2lelWcrQJBAMzwz1no6BzGw6RWC9y8uJzV5owcgW5MCOTcsHcOUFdTmAxIMgqP
B3JFwakiY0X0qoZCSmc/e5NGUTbTpHWX+RcCQQDEpxlbgEK6sqaI3wpWAANcaGyU
04AMv44ShUvWOXe+aLQIs8bs99PxyE1z4e2DtH4MnOenaghQETSSkN2yS8dlAkEA
l07LqDP++w/87d3hkC19l72NI7EAFnDouB//4UaeJns/bQH4gDctZj7+RmNvK/0B
0XIsAKKsGAX4fCQx7egwLQJBAKHzGacCxAqBzA7Vnr/vPtA8mJVAYXsDibbYMpVC
HT9ybtKfqL4HHWZfOmUYc9qUtS4jmRnsRVjFuNDMbO80bT4=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAM5iMtoXM7wvMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAklTMRIwEAYDVQQIEwlUZXN0c3RhdGUxEjAQBgNVBAcTCVRlc3R2aWxsZTEP
MA0GA1UEChMGVGVzdGNvMRAwDgYDVQQLEwdUZXN0ZXJzMRAwDgYDVQQDEwd0ZXN0
aW5nMB4XDTExMDcwNjE5NDM1N1oXDTIxMDcwMzE5NDM1N1owajELMAkGA1UEBhMC
SVMxEjAQBgNVBAgTCVRlc3RzdGF0ZTESMBAGA1UEBxMJVGVzdHZpbGxlMQ8wDQYD
VQQKEwZUZXN0Y28xEDAOBgNVBAsTB1Rlc3RlcnMxEDAOBgNVBAMTB3Rlc3Rpbmcw
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMh35xCpTR9H2zFo/3q6RR2l1gwN
dTuHKX/sAZPPpGSlBbMVEWvw7AcosvMxAxMK/fVa2uPG0Rab/eYlx48JqNy6R9v1
pdIa0wbTpu3BnI0Nun0fY2hCTOymDijzq0ujo1ji2zipNQlAlWu9zBbbufYVmEkX
NToQjM+YLMm+IFiLAgMBAAGjgc8wgcwwHQYDVR0OBBYEFLoSm4Mq/Wt5MOYyb5Dp
L246YgDWMIGcBgNVHSMEgZQwgZGAFLoSm4Mq/Wt5MOYyb5DpL246YgDWoW6kbDBq
MQswCQYDVQQGEwJJUzESMBAGA1UECBMJVGVzdHN0YXRlMRIwEAYDVQQHEwlUZXN0
dmlsbGUxDzANBgNVBAoTBlRlc3RjbzEQMA4GA1UECxMHVGVzdGVyczEQMA4GA1UE
AxMHdGVzdGluZ4IJAM5iMtoXM7wvMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAjLF30yL6HBmbAEMcylPBRYgO4S951jOB+u4017sD2agiDd1cip2K8ND9
DaLCv7c3MWgzR9/EQmi0BMyhNxtddPF+FZ9RgK3H0bOWlrN5u+MhIHhSMUAp8tdk
pD3zEbiDGGOZi5zjAYXUZtCOZTVcGz3IS42dX9RDNZIrIE1Lb/I=
-----END CERTIFICATE-----
