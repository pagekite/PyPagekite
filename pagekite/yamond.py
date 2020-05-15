"""
This is a class implementing a flexible metric-store and an HTTP
thread for browsing the numbers.
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

from six.moves import range
from six.moves import BaseHTTPServer
from six.moves.urllib.request import urlopen
from six.moves.urllib.parse import parse_qs, urlparse

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
 

class YamonRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_yamon_vars(self):
    self.send_response(200)
    self.send_header('Content-Type', 'text/plain')
    self.send_header('Cache-Control', 'no-cache')
    self.end_headers()
    self.wfile.write(self.server.yamond.render_vars_text())

  def do_heapy(self):
    from guppy import hpy
    self.send_response(200)
    self.send_header('Content-Type', 'text/plain')
    self.send_header('Cache-Control', 'no-cache')
    self.end_headers()
    self.wfile.write(hpy().heap())

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
    elif path == '/heap.txt':
      self.do_heapy()
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
  daemon = True

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
    self.views = {}

    # Important: threading.Lock() will deadlock pypy and generally we want
    #            to avoid locking. The methods below only hold this lock
    #            if they are adding/removing elements from our dicts and
    #            lists. For mutating existing values we either just accept
    #            things getting overwritten or rely on the GIL.
    self.lock = threading.RLock()

  def vmax(self, var, value):
    # Unlocked, since we don't change the size of self.values
    if value > self.values[var]:
      self.values[var] = value

  def vmin(self, var, value):
    # Unlocked, since we don't change the size of self.values
    if value < self.values[var]:
      self.values[var] = value

  def vscale(self, var, ratio, add=0):
    if var not in self.values:
      with self.lock:
        self.values[var] = self.values.get(var, 0)
    # Unlocked, since we don't change the size of self.values
    self.values[var] *= ratio
    self.values[var] += add

  def vset(self, var, value):
    with self.lock:
      self.values[var] = value

  def vadd(self, var, value, wrap=None):
    if var not in self.values:
      with self.lock:
        self.values[var] = self.values.get(var, 0)
    # We assume the GIL will guarantee these do sane things
    self.values[var] += value
    if wrap:
      self.values[var] %= wrap

  def vdel(self, var):
    if var in self.values:
      with self.lock:
        del self.values[var]

  def lcreate(self, listn, elems):
    with self.lock:
      self.lists[listn] = [elems, 0, ['' for x in range(0, elems)]]

  def ladd(self, listn, value):
    with self.lock:
      lst = self.lists[listn]
      lst[2][lst[1]] = value
      lst[1] += 1
      lst[1] %= lst[0]

  def render_vars_text(self, view=None):
    if view:
      if view == 'heapy':
        from guppy import hpy
        return hpy().heap()
      else:
        values, lists = self.views[view]
    else:
      values, lists = self.values, self.lists

    data = []
    for var in values:
      data.append('%s: %s\n' % (var, values[var]))
      if var == 'started':
        data.append(
          'started_days_ago: %.3f\n' % ((time.time() - values[var]) / 86400))

    for lname in lists:
      (elems, offset, lst) = lists[lname]
      l = lst[offset:]
      l.extend(lst[:offset])
      data.append('%s: %s\n' % (lname, ' '.join(['%s' % (x, ) for x in l])))
      try:
        slist = sorted([float(i) for i in l if i])
        if len(slist) >= 10:
          data.append('%s_m50: %.2f\n' % (lname, slist[int(len(slist) * 0.5)]))
          data.append('%s_m90: %.2f\n' % (lname, slist[int(len(slist) * 0.9)]))
          data.append('%s_avg: %.2f\n' % (lname, sum(slist) / len(slist)))
      except (ValueError, TypeError, IndexError, ZeroDivisionError):
        pass

    data.sort()
    return ''.join(data)

  def quit(self):
    if self.httpd:
      self.running = False
      urlopen('http://%s:%s/exiting/' % self.sspec, proxies={}).readlines()

  def run(self):
    self.httpd = self.server(self, self.handler)
    self.sspec = self.httpd.server_address
    self.running = True
    while self.running:
      self.httpd.handle_request()


if __name__ == '__main__':
  yd = YamonD(('', 0))
  yd.vset('bjarni', 100)
  yd.lcreate('foo', 2)
  yd.ladd('foo', 1)
  yd.ladd('foo', 2)
  yd.ladd('foo', 3)
  yd.run()

