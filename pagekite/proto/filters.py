#!/usr/bin/python -u
"""
These are filters placed at the end of a tunnel for watching or modifying
the traffic.
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
import time
from pagekite.compat import *


class TunnelFilter:
  """Base class for watchers/filters for data going in/out of Tunnels."""

  IDLE_TIMEOUT = 1800

  def __init__(self):
    self.sid = {}

  def clean_idle_sids(self, now=None):
    now = now or time.time()
    for sid in self.sid.keys():
      if self.sid[sid]['_ts'] < now - self.IDLE_TIMEOUT:
        del self.sid[sid]

  def filter_set_sid(self, sid, info):
    now = time.time()
    self.sid[sid] = info
    self.sid[sid]['_ts'] = now
    self.clean_idle_sids(now=now)

  def filter_data_in(self, tunnel, sid, data):
    self.sid[sid]['_ts'] = time.time()
    return data

  def filter_data_out(self, tunnel, sid, data):
    self.sid[sid]['_ts'] = time.time()
    return data


class TunnelWatcher(TunnelFilter):
  """Base class for watchers/filters for data going in/out of Tunnels."""

  def __init__(self, watch_level, ui):
    TunnelFilter.__init__(self)
    self.watch_level = watch_level
    self.ui = ui

  def format_data(self, data):
    return [x.encode('string_escape') for x
            in re.sub('([^\r\n\x20-\x7e]{3,}..|[^\r\n\x20-\x7e]{2,}.)+',
                      ' .. ', data).splitlines(True)]

  def now(self):
    return ts_to_iso(int(10*time.time())/10.0
                     ).replace('T', ' ').replace('00000', '')

  def filter_data_in(self, tunnel, sid, data):
    if data and self.watch_level[0] > 0:
      self.ui.Notify('===[ INCOMING @ %s ]===' % self.now(),
                     color=self.ui.WHITE, prefix=' __')
      for line in self.format_data(data):
        self.ui.Notify(line, prefix=' <=', now=-1, color=self.ui.GREEN)
    return TunnelFilter.filter_data_in(self, tunnel, sid, data)

  def filter_data_out(self, tunnel, sid, data):
    if data and self.watch_level[0] > 1:
      self.ui.Notify('===[ OUTGOING @ %s ]===' % self.now(),
                     color=self.ui.WHITE, prefix=' __')
      for line in self.format_data(data):
        self.ui.Notify(line, prefix=' =>', now=-1, color=self.ui.BLUE)
    return TunnelFilter.filter_data_out(self, tunnel, sid, data)

