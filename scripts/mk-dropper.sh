#!/bin/bash
#
set -e
KITENAME="$1"
SECRET="$2"
[ "$SECRET" = "" ] && {
  echo "Usage: $0 kitename.pagekite.me secret"
  exit 1
}
shift
shift
ARGS="$*"

make tools
make dev
./scripts/breeder.py sockschain \
	             pagekite/__init__.py \
	             pagekite/basicui.py \
	             pagekite/remoteui.py \
	             pagekite/yamond.py \
	             pagekite/httpd.py \
	             pagekite/__main__.py \
	             pagekite/__dropper__.py \
                     |sed -e "s/@KITENAME@/$KITENAME/g" \
                          -e "s/@SECRET@/$SECRET/g" \
                          -e "s#@ARGS@#$ARGS#g" \
	             >pagekite-tmp.py
python pagekite-tmp.py --appver >/dev/null \
  || rm -f bin/pagekite-tmp.py .failplease
chmod +x pagekite-tmp.py
mv pagekite-tmp.py dist/pagekite-$KITENAME.py
ls -l dist/pagekite-$KITENAME.py
