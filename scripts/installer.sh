#!/bin/bash
# <h2>This is the PageKite mini-installer!</h2><p>
#  Run with: <b>curl http://pagekite.net/pk/ |sudo bash</b>
# <br>
#   or just: <b>curl http://pagekite.net/pk/ |bash</b>
# </p><hr><pre>

###############################################################################
# Check if SSL works
if [ "$(which curl)" == "" ]; then
    cat <<tac

WARNING: You don't seem to have curl installed!
         This script depends on it.  Sorry. :-(

  You can manually download pagekite.py from these URLs instead:

      https://pagekite.net/pk/pagekite.py

  Remember to run 'chmod +x pagekite*.py' after downloading.
  There are also Debian and RPM packages on: https://pagekite.net/downloads/

tac
    exit 0
else
    if ! curl -s https://pagekite.net/pk/ >/dev/null; then
        cat <<tac

WARNING: Your curl does not handle the pagekite.net SSL certificate
         properly.  Bailing out!  If you aren't afraid of the evil
         hax0rz, you can install over plain HTTP like so:

$ curl http://pagekite.net/pk/ |sed -e s/https:/http:/g | sudo bash

tac
        exit 0
    fi
fi

###############################################################################
# Choose our destination
DEST=/usr/local/bin
echo ":$PATH:" |grep -c :$DEST: >/dev/null 2>&1 || DEST=/usr/bin
if [ ! -d "$DEST" ]; then
  mkdir -p "$DEST" >/dev/null 2>&1 || true
fi
if [ ! -w "$DEST" ]; then
  [ -w "$HOME/bin" ] && DEST="$HOME/bin" || DEST="$HOME"
fi
DESTFILE="$DEST/pagekite.py"
PAGEKITE="$DESTFILE"
echo ":$PATH:" |grep -c :$DEST: >/dev/null 2>&1 && PAGEKITE=pagekite.py
export DESTFILE

DESTFILE_GTK=
echo 'import gtk' |python 2>/dev/null && DESTFILE_GTK="$DEST/pagekite-gtk.py"
PAGEKITE_GTK="$DESTFILE_GTK"
echo ":$PATH:" |grep -c :$DEST: >/dev/null 2>&1 && PAGEKITE_GTK=pagekite-gtk.py
export DESTFILE_GTK

###############################################################################
# Install!
(
  set -x
  curl https://pagekite.net/pk/pagekite.py >"$DESTFILE"  || exit 1
  chmod +x "$DESTFILE"                                   || exit 2
  if [ "$DESTFILE_GTK" != "" ]; then
    curl https://pagekite.net/pk/pagekite-gtk.py >"$DESTFILE_GTK" || exit 3
    chmod +x "$DESTFILE_GTK"                                      || exit 4
  fi
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
if [ "$DESTFILE_GTK" != "" ]; then
  cat <<tac
Alternately, you can try the experimental GUI version by running:

  $ $PAGEKITE_GTK &

tac
fi

