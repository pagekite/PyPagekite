"""
Compatibility hacks to work around differences between Python versions.
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
import common
from common import *


# System logging on Unix
try:
  import syslog
except ImportError:
  class mockSyslog:
    def openlog(*args): raise ConfigError('No Syslog on this machine')
    def syslog(*args): raise ConfigError('No Syslog on this machine')
    LOG_DAEMON = 0
    LOG_DEBUG = 0
    LOG_ERROR = 0
    LOG_PID = 0
  syslog = mockSyslog()


# Backwards compatibility for old Pythons.
import socket
rawsocket = socket.socket
if not 'SHUT_RD' in dir(socket):
  socket.SHUT_RD = 0
  socket.SHUT_WR = 1
  socket.SHUT_RDWR = 2

try:
  import datetime
  ts_to_date = datetime.datetime.fromtimestamp
  def ts_to_iso(ts=None):
    return datetime.datetime.utcfromtimestamp(ts).isoformat()
except ImportError:
  ts_to_date = str
  ts_to_iso = str

try:
  sorted([1, 2, 3])
except:
  def sorted(l):
    tmp = l[:]
    tmp.sort()
    return tmp

try:
  sum([1, 2, 3])
except:
  def sum(l):
    s = 0
    for v in l:
      s += v
    return s

try:
  from urlparse import parse_qs, urlparse
except ImportError, e:
  from cgi import parse_qs
  from urlparse import urlparse
try:
  import hashlib
  def sha1hex(data):
    hl = hashlib.sha1()
    hl.update(data)
    return hl.hexdigest().lower()
except ImportError:
  import sha
  def sha1hex(data):
    return sha.new(data).hexdigest().lower()

common.MAGIC_UUID = sha1hex(common.MAGIC_UUID)

try:
  from traceback import format_exc
except ImportError:
  import traceback
  import StringIO
  def format_exc():
    sio = StringIO.StringIO()
    traceback.print_exc(file=sio)
    return sio.getvalue()

# Old Pythons lack rsplit
def rsplit(ch, data):
  parts = data.split(ch)
  if (len(parts) > 2):
    tail = parts.pop(-1)
    return (ch.join(parts), tail)
  else:
    return parts

# SSL/TLS strategy: prefer pyOpenSSL, as it comes with built-in Context
# objects. If that fails, look for Python 2.6+ native ssl support and
# create a compatibility wrapper. If both fail, bomb with a ConfigError
# when the user tries to enable anything SSL-related.
#
import sockschain
socks = sockschain
if socks.HAVE_PYOPENSSL:
  SSL = socks.SSL
  SEND_ALWAYS_BUFFERS = False
  SEND_MAX_BYTES = 16 * 1024
  TUNNEL_SOCKET_BLOCKS = False

elif socks.HAVE_SSL:
  SSL = socks.SSL
  SEND_ALWAYS_BUFFERS = True
  SEND_MAX_BYTES = 4 * 1024
  TUNNEL_SOCKET_BLOCKS = True # Workaround for http://bugs.python.org/issue8240

else:
  SEND_ALWAYS_BUFFERS = False
  SEND_MAX_BYTES = 16 * 1024
  TUNNEL_SOCKET_BLOCKS = False
  class SSL(object):
    TLSv1_METHOD = 0
    SSLv23_METHOD = 0
    class Error(Exception): pass
    class SysCallError(Exception): pass
    class WantReadError(Exception): pass
    class WantWriteError(Exception): pass
    class ZeroReturnError(Exception): pass
    class Context(object):
      def __init__(self, method):
        raise ConfigError('Neither pyOpenSSL nor python 2.6+ '
                          'ssl modules found!')

