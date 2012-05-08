#!/usr/bin/python
"""
This is the main function for the Android version of PageKite.
"""
#############################################################################
LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2012, the Beanstalks Project ehf. and Bjarni Runar Einarsson

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
#############################################################################
import sys
import pagekite.pk as pk
import pagekite.httpd as httpd


def Configure(pkobj):
  pkobj.rcfile = "/sdcard/pagekite.cfg"
  pkobj.enable_sslzlib = True
  pk.Configure(pkobj)

if __name__ == "__main__":
  if sys.stdout.isatty():
    import pagekite.ui.basic
    uiclass = pagekite.ui.basic.BasicUi
  else:
    uiclass = pk.NullUi

  pk.Main(pk.PageKite, Configure,
          uiclass=uiclass,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

