#!/bin/bash
# <h2>This is the PageKite mini-installer!</h2><p>
#  Run with: <b>curl https://pagekite.net/pk/ |sudo bash</b>
# <br>
#   or just: <b>curl https://pagekite.net/pk/ |bash</b>
# </p><hr><pre>

DEST=/usr/local/bin
echo ":$PATH:" |grep -c :$DEST: >/dev/null 2>&1 || DEST=/usr/bin
if [ ! -w "$DEST" ]; then
  [ -w "$HOME/bin" ] && DEST="$HOME/bin" || DEST="$HOME"
fi

DESTFILE="$DEST/pagekite.py"
PAGEKITE="$DESTFILE"
echo ":$PATH:" |grep -c :$DEST: >/dev/null 2>&1 && PAGEKITE=pagekite.py
export DESTFILE

(
  set -x
  curl https://pagekite.net/pk/pagekite.py >"$DESTFILE"  || exit 1
  chmod +x "$DESTFILE"                                   || exit 2
)\
 && cat <<tac

~~~~'~~~~~,~~~~~~'~~~~</>
 Welcome to PageKite!

PageKite has been installed to $DESTFILE !

Some useful commands:

  $ $PAGEKITE --signup             # Sign up for service
  $ $PAGEKITE 80 NAME.pagekite.me  # Expose port 80 as NAME.pagekite.me

For further instructions:

  $ $PAGEKITE --help |less

tac
if [ "$PAGEKITE" != "pagekite.py" ]; then
  echo 'To install system-wide, run: '
  echo
  echo "  $ sudo mv $PAGEKITE /usr/local/bin"
  echo
fi
rm -f "$TEMPFILE"
