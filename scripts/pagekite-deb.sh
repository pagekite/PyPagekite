#!/bin/sh
#
# Figure out which version of pagekite (Python 2 or 3) is installed,
# and run that. Prefer Python 3 if available.
#
"""true"
if [ -e /usr/lib/python3/dist-packages/pagekite/__main__.py ]; then
    exec python3 "$0" "$@"
else
    exec python "$0" "$@"
fi
"""
from pagekite.__main__ import main
main()
