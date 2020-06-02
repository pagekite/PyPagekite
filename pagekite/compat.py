"""
Compatibility hacks to work around differences between Python versions.
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
import sys
from six.moves.urllib.parse import parse_qs, urlparse

from . import common
from .common import *


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


import datetime
ts_to_date = datetime.datetime.fromtimestamp
def ts_to_iso(ts=None):
  return datetime.datetime.utcfromtimestamp(ts).isoformat()


if sys.version_info < (3,):
  def b(data):
    return data
  def s(data):
    if isinstance(data, unicode):
      return data.encode('utf-8')
    return str(data)
  def u(data):
    if isinstance(data, unicode):
      return data
    return data.decode('utf-8')
else:
  # We are using the latin-1 encoding here, on the assumption that
  # the string contains binary data we do not want to modify.
  import codecs
  def b(data):
    if isinstance(data, bytes):
      return data
    return codecs.latin_1_encode(data)[0]
  def s(data):
    if isinstance(data, str):
      return data
    return str(data, 'iso-8859-1')
  def u(data):
    if isinstance(data, str):
      return data
    return str(data, 'utf-8')


import base64
import hashlib

def sha1hex(data):
  return hashlib.sha1(b(data)).hexdigest().lower()

def sha1b64(data):
  return base64.b64encode(hashlib.sha1(b(data)).digest())

def sha256b64(data):
  return base64.b64encode(hashlib.sha256(b(data)).digest())


try:
  from traceback import format_exc
except ImportError:
  import traceback
  from six import StringIO
  def format_exc():
    sio = StringIO()
    traceback.print_exc(file=sio)
    return sio.getvalue()

try:
  from Queue import Queue
except ImportError:
  from queue import Queue

# SSL/TLS strategy: prefer pyOpenSSL, as it comes with built-in Context
# objects. If that fails, look for Python 2.6+ native ssl support and
# create a compatibility wrapper. If both fail, bomb with a ConfigError
# when the user tries to enable anything SSL-related.
#
import sockschain
socks = sockschain
if tuple(sys.version_info) >= (2, 7, 13):
  SSL = socks.SSL
  SEND_ALWAYS_BUFFERS = False
  SEND_MAX_BYTES = (16 * 1024) - 64  # Under 16kB to avoid WANT_WRITE errors
  TUNNEL_SOCKET_BLOCKS = False

elif socks.HAVE_SSL:
  SSL = socks.SSL
  SEND_ALWAYS_BUFFERS = True
  SEND_MAX_BYTES = 4 * 1024
  TUNNEL_SOCKET_BLOCKS = True  # Workaround for http://bugs.python.org/issue8240

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


class WithableStub(object):
    def __enter__(self): pass
    def __exit__(self, et, ev, tb): pass


# Only calculate this just once
MAGIC_UUID_SHA1 = sha1hex(MAGIC_UUID)
