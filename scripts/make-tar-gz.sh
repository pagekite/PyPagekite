#!/bin/bash
set -e
make dev
PKVER=$(./pk --appver)

make distclean
rm -f ../pagekite-$PKVER && ln -fs $(pwd) ../pagekite-$PKVER
(
  cd ..
  tar cvhfz pagekite-$PKVER.tar.gz pagekite-$PKVER/ --exclude=.git
  rm -f pagekite-$PKVER
)
