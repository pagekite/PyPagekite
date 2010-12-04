#!/usr/bin/python -u
#
# pagekite_logparse.py, Copyright 2010, The Beanstalks Project ehf.
#                                       http://beanstalks-project.net/
#
# Basic tool for processing and parsing the Pagekite logs. This class
# doesn't actually do anything much, it's meant for subclassing.
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
import os
import sys
import time
 

class PageKiteLogParser(object):
  def __init__(self):
    pass

  def ParseLine(self, line, data=None):
    if data is None: data = {}
    for word in line.split('; '):
      key, val = word.split('=', 1);
      data[key] = val
    return data

  def ProcessData(self, data):
    print '%s' % data

  def ProcessLine(self, line, data=None):
    self.ProcessData(self.ParseLine(line, data))

  def ReadSyslog(self, filename, pname='pagekite.py', after=None, follow=False):
    fd = open(filename, 'r')
    tag = ' %s[' % pname
    sleep = 1
    while follow:
      for line in fd:
        try:
          parts = line.split(':', 3)
          if parts[2].find(tag) > -1:
            data = self.ParseLine(parts[3].strip())
            if after is None or int(data['ts'], 16) > after:
              self.ProcessData(data) 
            sleep = 1
        except ValueError, e:
          pass

      if follow:
        # Record last position...      
        pos = fd.tell()

        if os.stat(filename).st_size < pos:
          # Re-open log-file if it's been rotated/trucated
          fd.close() 
          fd = open(filename, 'r')
        else:
          # Else, sleep a bit and then try to read some more
          time.sleep(sleep)
          if sleep < 10: sleep += 1
          fd.seek(pos)


if __name__ == '__main__':
  sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
  PageKiteLogParser().ReadSyslog('/var/log/daemon.log', after=time.time(), 
                                                        follow=True)

