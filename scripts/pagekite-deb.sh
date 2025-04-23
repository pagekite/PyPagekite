#!/bin/sh
if [ -e /usr/lib/python3/dist-packages/pagekite/__main__.py ]; then
    exec python3 -m pagekite "$@"
else
    exec python -m pagekite "$@"
fi
