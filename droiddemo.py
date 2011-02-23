#!/usr/bin/python -u
#
# droiddemo.py, Copyright 2010, The Beanstalks Project ehf.
#                               http://beanstalks-project.net/
#
# This is a proof-of-concept PageKite enabled HTTP server for Android.
# It has been developed and tested in the SL4A Python environment.
#
DOMAIN='m.tweak.pagekite.me'
SECRET='z628782ec38kfckdzkz64988aaf92eza'

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
import pagekite
import os
import sys
from urllib import unquote
try:
  from urlparse import parse_qs, urlparse
except Exception, e:
  from cgi import parse_qs
  from urlparse import urlparse



class UiRequestHandler(pagekite.UiRequestHandler):

  CAMERA_PATHS = ['/sdcard/dcim/.thumbnails',
    '/sdcard/.thumbnails',
    '/home/karl/public_html']
  HOME = ('<html><head>\n'
          '<script type=text/javascript>'
           'lastImage = "";'
           'function getImage() {'
            'xhr = new XMLHttpRequest();'
            'xhr.open("GET", "/latest-image.txt", true);'
            'xhr.onreadystatechange = function() {'
             'if (xhr.readyState == 4) {'
              'if (xhr.responseText && xhr.responseText != lastImage) {'
               'document.getElementById("i").src = lastImage = xhr.responseText;'
              '}'
              'setTimeout("getImage()", 2000);'
             '}'
            '};'
           'xhr.send(null);'
           '}'
          '</script>\n'
          '</head><body onLoad="getImage();" style="text-align: center;">\n'
          '<h1>Android photos!</h1>\n'
          '<img id=i height=80% src="http://www.android.com/images/opensourceproject.gif">\n'
          '<br><a href="/droiddemo.py">source code</a>'
          '| <a href="/status.html">kite status</a>\n'
          '</body></head>')

  def listFiles(self):
    mtimes = {}
    for item in self.CAMERA_PATHS:
        if os.path.exists(item):
            self.server.viable_path = item
            break

    if self.server.viable_path is None:
        print "where do you keep your photos mang, couldn't find any!"
        return None
        
    for item in os.listdir(self.server.viable_path):
      iname = '%s/%s' % (self.server.viable_path, item)
      if iname.endswith('.jpg'):
        mtimes[iname] = os.path.getmtime(iname)

    files = mtimes.keys()
    files.sort(lambda x,y: cmp(mtimes[x], mtimes[y]))
    return files

  def do_GET(self):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    # ugly hacky init ... ;)
    try:
        blah = self.server.viable_path
    except AttributeError:
        self.server.viable_path = None
    p = unquote(path)
    if p.endswith('.jpg') and p.startswith(self.server.viable_path) and ('..' not in p):
      try:
        jpgfile = open(p)
        self.send_response(200)
        self.send_header('Content-Type', 'image/jpeg')
        self.send_header('Content-Length', '%s' % os.path.getsize(p))
        self.send_header('Cache-Control', 'max-age: 36000')
        self.send_header('Expires', 'Sat, 1 Jan 2011 12:00:00 GMT')
        self.send_header('Last-Modified', 'Wed, 1 Sep 2011 12:00:00 GMT')
        self.end_headers()
        data = jpgfile.read() 
        while data:
          try:
            sent = self.wfile.write(data[0:15000])
            data = data[15000:]
          except Exception:
            pass
        return
 
      except Exception, e:
        print '%s' % e
        pass 

    if path == '/latest-image.txt':
      flist = self.listFiles() # fixme, no files found!
      self.begin_headers(200, 'text/plain')
      self.end_headers()
      if flist:
        self.wfile.write(flist[-1])
      return
    elif path == '/droiddemo.py':
      pyfile = open(__file__)
      self.begin_headers(200, 'text/plain')
      self.end_headers()
      self.wfile.write(pyfile.read().replace(SECRET, 'mysecret'))
      return
    elif path == '/':
      self.begin_headers(200, 'text/html')
      self.end_headers()
      self.wfile.write(self.HOME)
      return

    return pagekite.UiRequestHandler.do_GET(self)


class DroidKite(pagekite.PageKite):
  def __init__(self):
    pagekite.PageKite.__init__(self)
    self.ui_request_handler = UiRequestHandler


def Start(host, secret):
  ds = DroidKite()
  ds.Configure(['--defaults',
                '--httpd=localhost:9999',
                '--backend=http:%s:localhost:9999:%s' % (host, secret)])
  try:
    ds.Start()
  except KeyboardInterrupt:
    print "Interrupted from keyboard, quitting now..."
    os._exit(os.EX_OK)

Start(DOMAIN, SECRET)
