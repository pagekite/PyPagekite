"""
This is a "dropper template".  A dropper is a single-purpose PageKite
back-end connector which embeds its own configuration.
"""
##############################################################################

from __future__ import absolute_import

LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2020, the Beanstalks Project ehf. and Bjarni Runar Einarsson

This program is free software: you can redistribute it and/or modify it under
the terms of the  GNU  Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,  but  WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see: <http://www.gnu.org/licenses/>
"""
##############################################################################
import sys
import pagekite.pk as pk
import pagekite.httpd as httpd

if __name__ == "__main__":
  kn = '@KITENAME@'
  ss = '@SECRET@'
  if len(sys.argv) == 1:
    sys.argv.extend([
      '--daemonize',
      '--runas=nobody',
      '--logfile=/tmp/pagekite-%s.log' % kn,
    ])
  sys.argv[1:1] = [
    '--clean',
    '--noloop',
    '--nocrashreport',
    '--defaults',
    '--kitename=%s' % kn,
    '--kitesecret=%s' % ss,
    '--all'
  ]
  sys.argv.extend('@ARGS@'.split())

  pk.Main(pk.PageKite, pk.Configure,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

