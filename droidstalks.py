#!/usr/bin/python -u
#
# droidstalks.py, Copyright 2010, The Beanstalks Project ehf.
#                                 http://beanstalks-project.net/
#
# This is a proof-of-concept Beanstalks enabled HTTP server for Android.
# It has been developed and tested in the SL4A Python environment.
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
import beanstalks_net


class UiRequestHandler(beanstalks_net.UiRequestHandler):
  def do_GET(self):
    self.server.beanstalk.droid.makeToast('Oh, a visitor!')
    return beanstalks_net.UiRequestHandler.do_GET(self)


class Droidstalk(beanstalks_net.BeanstalksNet):
  def __init__(self, droid):
    beanstalks_net.BeanstalksNet.__init__(self)
    self.droid = droid
    self.ui_request_handler = UiRequestHandler


def Start(host, secret):
  ds = Droidstalk(android.Android())
  ds.Configure(['--frontends=1:frontends.b5p.us:2222',
                '--httpd=localhost:9999',
                '--dyndns=beanstalks.net',
                '--backend=http:%s:localhost:9999:%s' % (host, secret)])
  ds.Start()


Start('YOU.test.beanstalks.me', 'SECRET')
