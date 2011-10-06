#!/bin/bash
# <h1>PageKite mini-installer</h1><pre>

# Figure out if /usr/local/bin will work, else default to /usr/bin
DEST=/usr/local/bin
echo $PATH |grep -c $DEST >/dev/null 2>&1 || DEST=/usr/bin
export DEST
TEMPFILE=/tmp/pagekite.$$
export TEMPFILE

# Talk to the user.
cat <<tac
~~~~'~~~~~,~~~~~~'~~~~</>
 Welcome to PageKite!

This script will download the latest version of pagekite and
install it here: $DEST

Note: You will need to give it permission (your sudo passowrd)
      in order to complete the installation.

[ Press ENTER to continue, CTRL-C to abort ]
tac
read

# Go!
(
  set -ex
  curl https://pagekite.net/pk/pagekite-0.4.py >$TEMPFILE
  chmod +x $TEMPFILE
  sudo mv -i $TEMPFILE $DEST/pagekite || exit 1
)
rm $TEMPFILE 2>/dev/null || cat <<tac

~~~~'~~~~~,~~~~~~'~~~~</>
Installation complete!

Some useful commands:

  $ pagekite --signup              # Sign up for service
  $ pagekite 80 NAME.pagekite.me   # Expose localhost:80 as NAME.pagekite.me

For further instructions:

  $ pagekite --help |less

tac
# </pre>
