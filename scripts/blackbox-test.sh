#!/bin/bash
#
# Primitive black-box test for pagekite.py
#
export PATH=.:$PATH

PK=$1
shift
LOG="/tmp/pk-test.log"
PKA="$* --clean --nullui --logfile=$LOG"
PORT=12000
let PORT="$PORT+($$%10000)"

[ "$PK" = "" ] && {
  echo "Usage: $0 /path/to/pagekite.py [global pagekite options]"
  exit 1
}
echo -n "Testing version: "; $PK --appver

__logwait() {
  COUNT=0
  while [ 1 ]; do
    [ -e "$1" ] && grep "$2" $1 >/dev/null && break
    sleep 1
    let COUNT=$COUNT+1
    [ $COUNT -gt 5 ] && {
      echo 'TIMED OUT'
      break
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
  $PK $FE_ARGS --settings >$LOG-1
  $PK $FE_ARGS &
  KID_FE=$!
__logwait $LOG-1 listen=:$PORT

  BE_ARGS1="$PKA-2 --frontend=localhost:$PORT \
                   --backend=http:testing:localhost:80:ok"
  BE_ARGS2="/etc/passwd http://testing/"
  $PK $BE_ARGS1 --settings $BE_ARGS2 >$LOG-2
  $PK $BE_ARGS1 $BE_ARGS2 &
  KID_BE=$!
__logwait $LOG-2 connect=

  # First, make sure we get a Sorry response for invalid requests.
  curl -v --silent -H "Host: invalid" http://localhost:$PORT/ 2>&1 \
    |tee $LOG-3 |grep -i 'sorry! (fe)' >/dev/null \
    && __PART_OK__ 'frontend' || __TEST_FAIL__ 'frontend' $KID_FE $KID_BE

  # Next, see if our test host responds at all...
  curl -v --silent -H "Host: testing" http://localhost:$PORT/ 2>&1 \
    |tee $LOG-3 |grep -i 'html' >/dev/null \
    && __PART_OK__ 'backend' || __TEST_FAIL__ 'backend' $KID_FE $KID_BE

  # Finally, see if expected content is served.
  curl -v --silent -H "Host: testing" http://localhost:$PORT/etc/passwd 2>&1 \
    |tee $LOG-3 |grep -i 'root' >/dev/null \
    && __PART_OK__ 'httpd' || __TEST_FAIL__ 'httpd' $KID_FE $KID_BE

__TEST_END__ $KID_FE $KID_BE


###############################################################################

# TODO: Add duplicate tests with --nopyopenssl to test both code paths.


