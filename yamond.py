#!/usr/bin/python -u
#
# yamond.py, Copyright 2010, The Beanstalks Project ehf.
#                            http://beanstalks-project.net/
#
# This is a class implementing a flexible metric-store and an HTTP
# thread for browsing the numbers.
#
#############################################################################
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
import getopt
import os
import random
import re
import select
import socket
import struct
import sys
import threading
import time
import traceback
import urllib
 
import BaseHTTPServer
try:
  from urlparse import parse_qs, urlparse
except Exception, e:
  from cgi import parse_qs
  from urlparse import urlparse


class YamonRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_yamon_vars(self):
    yamond = self.server.yamond
    yamond.values['yamond_hits'] += 1
    yamond.scale('bjarni', 0.9)

    self.send_response(200)
    self.send_header('Content-Type', 'text/plain')
    self.send_header('Cache-Control', 'no-cache')
    self.end_headers()

    self.wfile.write('unixtime: %d\n' % time.time())
    for var in yamond.values:
      self.wfile.write('%s: %s\n' % (var, yamond.values[var]))

  def do_404(self):
    self.send_response(404)
    self.send_header('Content-Type', 'text/html')
    self.end_headers()
    self.wfile.write('<h1>404: What? Where? Cannot find it!</h1>')

  def do_root(self):
    self.send_response(200)
    self.send_header('Content-Type', 'text/html')
    self.end_headers()
    self.wfile.write('<h1>Hello!</h1>')

  def handle_path(self, path, query):
    if path == '/vars.txt':
      self.do_yamon_vars()
    elif path == '/':
      self.do_root()
    else:
      self.do_404()

  def do_GET(self):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path) 
    qs = parse_qs(query)
    return self.handle_path(path, query)


class YamonHttpServer(BaseHTTPServer.HTTPServer):
  def __init__(self, yamond, handler):
    BaseHTTPServer.HTTPServer.__init__(self, yamond.sspec, handler)
    self.yamond = yamond


class YamonD(threading.Thread):
  """Handle HTTP in a separate thread."""

  def __init__(self, sspec, 
               server=YamonHttpServer,
               handler=YamonRequestHandler):
    threading.Thread.__init__(self)
    self.sspec = sspec
    self.httpd = server(self, handler)
    self.serve = True
    self.values = {'yamond_hits': 0}
    self.lists = {}

  def scale(self, var, ratio, add=0):
    if var in self.values: 
      self.values[var] *= ratio
      self.values[var] += add

  def lcreate(self, listn, elems):
    self.lists[listn] = [elems, 0, []]

  def ladd(self, listn, value):
    list = self.lists[listn]
    list[2][list[1]] = value
    list[1] += 1
    list[1] %= list[0]

  def quit(self):
    self.serve = False
    urllib.urlopen('http://%s:%s/exiting/' % self.sspec,
                   proxies={}).readlines()

  def run(self):
    while self.serve: self.httpd.handle_request()


yd = YamonD(('', 7999))
yd.values['bjarni'] = 100
yd.run()
