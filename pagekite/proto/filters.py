"""
These are filters placed at the end of a tunnel for watching or modifying
the traffic.
"""
##############################################################################
LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2017, the Beanstalks Project ehf. and Bjarni Runar Einarsson

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
import re
import time
from pagekite.compat import *


class TunnelFilter:
  """Base class for watchers/filters for data going in/out of Tunnels."""

  IDLE_TIMEOUT = 1800

  def __init__(self, ui):
    self.sid = {}
    self.ui = ui

  def clean_idle_sids(self, now=None):
    now = now or time.time()
    for sid in self.sid.keys():
      if self.sid[sid]['_ts'] < now - self.IDLE_TIMEOUT:
        del self.sid[sid]

  def filter_set_sid(self, sid, info):
    now = time.time()
    if sid not in self.sid:
      self.sid[sid] = {}
    self.sid[sid].update(info)
    self.sid[sid]['_ts'] = now
    self.clean_idle_sids(now=now)

  def filter_data_in(self, tunnel, sid, data):
    if sid not in self.sid:
      self.sid[sid] = {}
    self.sid[sid]['_ts'] = time.time()
    return data

  def filter_data_out(self, tunnel, sid, data):
    if sid not in self.sid:
      self.sid[sid] = {}
    self.sid[sid]['_ts'] = time.time()
    return data


class TunnelWatcher(TunnelFilter):
  """Base class for watchers/filters for data going in/out of Tunnels."""

  def __init__(self, ui, watch_level=0):
    TunnelFilter.__init__(self, ui)
    self.watch_level = watch_level

  def format_data(self, data, level):
    if '\r\n\r\n' in data:
      head, tail = data.split('\r\n\r\n', 1)
      output = self.format_data(head, level)
      output[-1] += '\\r\\n'
      output.append('\\r\\n')
      if tail:
        output.extend(self.format_data(tail, level))
      return output
    else:
      output = data.encode('string_escape').replace('\\n', '\\n\n')
      if output.count('\\') > 0.15*len(output):
        if level > 2:
          output = [['', '']]
          count = 0
          for d in data:
            output[-1][0] += '%2.2x' % ord(d)
            output[-1][1] += '%c' % ((ord(d) > 31 and ord(d) < 127) and d or '.')
            count += 1
            if (count % 2) == 0:
              output[-1][0] += ' '
            if (count % 20) == 0:
              output.append(['', ''])
          return ['%-50s %s' % (l[0], l[1]) for l in output]
        else:
          return ['<< Binary bytes: %d >>' % len(data)]
      else:
        return output.strip().splitlines()

  def now(self):
    return ts_to_iso(int(10*time.time())/10.0
                     ).replace('T', ' ').replace('00000', '')

  def filter_data_in(self, tunnel, sid, data):
    if data and self.watch_level[0] > 0:
      self.ui.Notify('===[ INCOMING @ %s ]===' % self.now(),
                     color=self.ui.WHITE, prefix=' __')
      for line in self.format_data(data, self.watch_level[0]):
        self.ui.Notify(line, prefix=' <=', now=-1, color=self.ui.GREEN)
    return TunnelFilter.filter_data_in(self, tunnel, sid, data)

  def filter_data_out(self, tunnel, sid, data):
    if data and self.watch_level[0] > 1:
      self.ui.Notify('===[ OUTGOING @ %s ]===' % self.now(),
                     color=self.ui.WHITE, prefix=' __')
      for line in self.format_data(data, self.watch_level[0]):
        self.ui.Notify(line, prefix=' =>', now=-1, color=self.ui.BLUE)
    return TunnelFilter.filter_data_out(self, tunnel, sid, data)


class HttpHeaderFilter(TunnelFilter):
  """Filter that adds X-Forwarded-For and X-Forwarded-Proto to requests."""

  HTTP_HEADER = re.compile('(?ism)^(([A-Z]+) ([^\n]+) HTTP/\d+\.\d+\s*)$')
  DISABLE = 'rawheaders'

  def filter_data_in(self, tunnel, sid, data):
    info = self.sid.get(sid)
    if (info and
        info.get('proto') in ('http', 'http2', 'http3', 'websocket') and
        not info.get(self.DISABLE, False)):

      # FIXME: Check content-length and skip bodies entirely
      http_hdr = self.HTTP_HEADER.search(data)
      if http_hdr:
        data = self.filter_header_data_in(http_hdr, data, info)

    return TunnelFilter.filter_data_in(self, tunnel, sid, data)

  def filter_header_data_in(self, http_hdr, data, info):
    clean_headers = [
      r'(?mi)^(X-(PageKite|Forwarded)-(For|Proto|Port):)'
    ]
    add_headers = [
      'X-Forwarded-For: %s' % info.get('remote_ip', 'unknown'),
      'X-Forwarded-Proto: %s' % (info.get('using_tls') and 'https' or 'http'),
      'X-PageKite-Port: %s' % info.get('port', 0)
    ]

    if info.get('rewritehost', False):
      add_headers.append('Host: %s' % info.get('rewritehost'))
      clean_headers.append(r'(?mi)^(Host:)')

    if http_hdr.group(1).upper() in ('POST', 'PUT'):
      # FIXME: This is a bit ugly
      add_headers.append('Connection: close')
      clean_headers.append(r'(?mi)^(Connection|Keep-Alive):')
      info['rawheaders'] = True

    for hdr_re in clean_headers:
      data = re.sub(hdr_re, 'X-Old-\\1', data)

    return re.sub(self.HTTP_HEADER,
                  '\\1\n%s\r' % '\r\n'.join(add_headers),
                  data)


class HttpSecurityFilter(HttpHeaderFilter):
  """Filter that blocks known-to-be-dangerous requests."""

  DISABLE = 'trusted'
  HTTP_DANGER = re.compile('(?ism)^((get|post|put|patch|delete) '
                           # xampp paths, anything starting with /adm*
                           '((?:/+(?:xampp/|security/|licenses/|webalizer/|server-(?:status|info)|adm)'
                           '|[^\n]*/'
                             # WordPress admin pages
                             '(?:wp-admin/(?!admin-ajax|css/)|wp-config\.php'
                             # Hackzor tricks
                             '|system32/|\.\.|\.ht(?:access|pass)'
                             # phpMyAdmin and similar tools
                             '|(?:php|sql)?my(?:sql)?(?:adm|manager)'
                             # Setup pages for common PHP tools
                             '|(?:adm[^\n]*|install[^\n]*|setup)\.php)'
                           ')[^\n]*)'
                           ' HTTP/\d+\.\d+\s*)$')
  REJECT = 'PAGEKITE_REJECT_'

  def filter_header_data_in(self, http_hdr, data, info):
    danger = self.HTTP_DANGER.search(data)
    if danger:
      self.ui.Notify('BLOCKED: %s %s' % (danger.group(2), danger.group(3)),
                     color=self.ui.RED, prefix='***')
      self.ui.Notify('See https://pagekite.net/support/security/ for more'
                     ' details.')
      return self.REJECT+data
    else:
      return data
