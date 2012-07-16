#!/usr/bin/python -u
"""
This is a class implementing a flexible metric-store and an HTTP
thread for browsing the numbers.
"""
##############################################################################
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
##############################################################################

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
    self.send_response(200)
    self.send_header('Content-Type', 'text/plain')
    self.send_header('Cache-Control', 'no-cache')
    self.end_headers()
    self.wfile.write(self.server.yamond.render_vars_text())

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
    self.server = server
    self.handler = handler
    self.sspec = sspec
    self.httpd = None
    self.running = False
    self.values = {}
    self.lists = {}

  def vmax(self, var, value):
    if value > self.values[var]: self.values[var] = value

  def vscale(self, var, ratio, add=0):
    if var not in self.values: self.values[var] = 0
    self.values[var] *= ratio
    self.values[var] += add

  def vset(self, var, value):
    self.values[var] = value

  def vadd(self, var, value, wrap=None):
    if var not in self.values: self.values[var] = 0
    self.values[var] += value
    if wrap is not None and self.values[var] >= wrap:
      self.values[var] -= wrap

  def vmin(self, var, value):
    if value < self.values[var]: self.values[var] = value

  def vdel(self, var):
    if var in self.values: del self.values[var]

  def lcreate(self, listn, elems):
    self.lists[listn] = [elems, 0, ['' for x in xrange(0, elems)]]

  def ladd(self, listn, value):
    list = self.lists[listn]
    list[2][list[1]] = value
    list[1] += 1
    list[1] %= list[0]

  def render_vars_text(self):
    data = []
    for var in self.values:
      data.append('%s: %s\n' % (var, self.values[var]))

    for lname in self.lists:
      (elems, offset, list) = self.lists[lname]
      l = list[offset:]
      l.extend(list[:offset])
      data.append('%s: %s\n' % (lname, ' '.join(['%s' % x for x in l])))

    data.sort()
    return ''.join(data)

  def quit(self):
    if self.httpd:
      self.running = False
      urllib.urlopen('http://%s:%s/exiting/' % self.sspec,
                     proxies={}).readlines()

  def run(self):
    self.httpd = self.server(self, self.handler)
    self.sspec = self.httpd.server_address
    self.running = True
    while self.running: self.httpd.handle_request()


if __name__ == '__main__':
  yd = YamonD(('', 0))
  yd.vset('bjarni', 100)
  yd.lcreate('foo', 2)
  yd.ladd('foo', 1)
  yd.ladd('foo', 2)
  yd.ladd('foo', 3)
  yd.run()

