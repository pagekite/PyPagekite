#!/usr/bin/python -u
#
# droidkite.py, Copyright 2010, The Beanstalks Project ehf.
#                               http://beanstalks-project.net/
#
# This is a proof-of-concept PageKite enabled HTTP server for Android.
# It has been developed and tested in the SL4A Python environment.
#
DOMAIN='YOU.test.beanstalks.me'
SECRET='EDIT_ME'
#
#############################################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#############################################################################
#
import android
import pagekite


class UiRequestHandler(pagekite.UiRequestHandler):
  def do_GET(self):
    self.server.pkite.droid.makeToast('Oh, a visitor!')
    return pagekite.UiRequestHandler.do_GET(self)


class DroidKite(pagekite.PageKite):
  def __init__(self, droid):
    pagekite.PageKite.__init__(self)
    self.droid = droid
    self.ui_request_handler = UiRequestHandler


def Start(host, secret):
  ds = DroidKite(android.Android())
  ds.Configure(['--defaults',
                '--backend=http:%s:localhost:9999:%s' % (host, secret)])
  ds.Start()


Start(DOMAIN, SECRET)
