#!/usr/bin/python2 -u
#
# pagekite.py, Copyright 2010, 2011, the Beanstalks Project ehf.
#                                    and Bjarni Runar Einarsson
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
#
##[ Maybe TODO: ]##############################################################
#
# Optimization:
#  - Implement epoll() support.
#  - Stress test this thing: when do we need a C rewrite?
#  - Make multi-process, use the FD-over-socket trick? Threads=>GIL=>bleh
#  - Add QoS and bandwidth shaping
#  - Add a scheduler for deferred/periodic processing.
#  - Replace string concatenation ops with lists of buffers.
#
# Protocols:
#  - Make tunnel creation more stubborn (try multiple ports etc.)
#  - Add XMPP and incoming SMTP support.
#  - Replace/augment current tunnel auth scheme with SSL certificates.
#
# User interface:
#  - Enable (re)configuration from within HTTP UI.
#  - More human readable console output?
#
# Bugs?
#  - Front-ends should time-out dead back-ends.
#  - Gzip-related memory issues.
#
#
##[ Hacking guide! ]###########################################################
#
# Hello! Welcome to my source code.
#
# Here's a brief intro to how the program is structured, to encourage people
# to hack and improve.
#
#  * The PageKite object contains the master configuration and some related
#    routines. It takes care of parsing configuration files and implements
#    things like the authentication protocol. It also contains the main event
#    loop, which is select() or epoll() based. In short, it's the boss.
#
#  * The Connections object keeps track of which tunnels and user connections
#    are open at any given time and which protocol/domain pairs they belong to.
#    It gets passed around as an argument quite a lot - not too elegant.
#
#  * The Selectable and it's *Parser subclasses incrementally build up basic
#    parsers for the supported protocols. Note that none of the protocols
#    are fully implemented, we only implement the bare minimum required to
#    figure out which back-end should handle a given request, and then forward
#    the bytes unmodified over that channel. As a result, the current HTTP
#    proxy code is not HTTP 1.1 compliant - but if you put it behind Varnish
#    or some other decent reverse-proxy, then *the combination* should be!
#
#  * The UserConn object represents connections on behalf of users. It can
#    be created as a FrontEnd, which will find the right tunnel and send
#    traffic to the back-end PageKite process, where a BackEnd UserConn
#    will be created to connect to the actual HTTP server.
#
#  * The Tunnel object represents one end of a PageKite tunnel and is also
#    created either as a FrontEnd or BackEnd, depending on which end it is.
#    Tunnels handle multiplexing and demultiplexing all the traffic for
#    a given back-end so multiple requests can share a single TCP/IP
#    connection.
#
# Although most of the work done by pagekite.py happens in an event-loop
# on a single thread, there are some exceptions:
#
#  * The AuthThread handles checking whether an incoming tunnel request is
#    allowed or not; authentication requests may end up blocking and waiting
#    for each other, but the main work of proxying data back and forth won't
#    be blocked.
#
#  * The HttpUiThread implements a basic HTTP (or HTTPS) server, for basic
#    monitoring and interactive configuration.
#
# WARNING: The UI threading code assumes it is running in CPython, where the
#          GIL makes snooping across the thread-boundary relatively safe, even
#          without explicit locking. Beware!
#
###############################################################################
#
PROTOVER = '0.8'
APPVER = '0.3.21'
AUTHOR = 'Bjarni Runar Einarsson, http://bre.klaki.net/'
WWWHOME = 'http://pagekite.net/'
DOC = """\
pagekite.py is Copyright 2010, 2011, the Beanstalks Project ehf.
     v%s                               http://pagekite.net/

This the reference implementation of the PageKite tunneling protocol,
both the front- and back-end. This following protocols are supported:

  HTTP      - HTTP 1.1 only, requires a valid HTTP Host: header
  HTTPS     - Recent versions of TLS only, requires the SNI extension.
  WEBSOCKET - Using the proposed Upgrade: WebSocket method.
  XMPP      - ...unfinished... (FIXME)
  SMTP      - ...unfinished... (FIXME)

Other protocols may be proxied by using "raw" back-ends and HTTP CONNECT.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License. For the full text of the
license, see: http://www.gnu.org/licenses/agpl-3.0.html

Usage:

  pagekite.py [options]

Common Options:

 --optfile=X    -o X    Read options from file X. Default is ~/.pagekite.rc.
 --savefile=X   -S X    Read/write options from file X.
 --reloadfile=X         Re-read config from X on SIGHUP.
 --httpd=X:P    -H X:P  Enable the HTTP user interface on hostname X, port P.
 --pemfile=X    -P X    Use X as a PEM key for the HTTPS UI.
 --httppass=X   -X X    Require password X to access the UI.
 --nozchunks            Disable zlib tunnel compression.
 --sslzlib              Enable zlib compression in OpenSSL.
 --buffers       N      Buffer at most N kB of back-end data before blocking.
 --logfile=F    -L F    Log to file F.
 --daemonize    -Z      Run as a daemon.
 --runas        -U U:G  Set UID:GID after opening our listening sockets.
 --pidfile=P    -I P    Write PID to the named file.
 --clean                Skip loading the default configuration file.
 --nocrashreport        Don't send anonymous crash reports to PageKite.net.
 --tls_default=N        Default name to use for SSL, if SNI and tracking fail.
 --tls_endpoint=N:F     Terminate SSL/TLS for name N, using key/cert from F.
 --defaults             Set some reasonable default setings.
 --errorurl=U  -E U    URL to redirect to when back-ends are not found.
 --settings             Dump the current settings to STDOUT, formatted as
                       an options file would be.

Front-end Options:

 --isfrontend   -f      Enable front-end mode.
 --authdomain=X -A X    Use X as a remote authentication domain.
 --host=H       -h H    Listen on H (hostname).
 --ports=A,B,C  -p A,B  Listen on ports A, B, C, ...
 --portalias=A:B        Report port A as port B to backends.
 --protos=A,B,C         Accept the listed protocols for tunneling.
 --rawports=A,B,C       Listen on ports A, B, C, ... (raw/timed connections)

 --domain=proto,proto2,pN:domain:secret
                  Accept tunneling requests for the named protocols and
                 specified domain, using the given secret.  A * may be
               used as a wildcard for subdomains. (FIXME)

Back-end Options:

 --all          -a      Terminate early if any tunnels fail to register.
 --dyndns=X     -D X    Register changes with DynDNS provider X.  X can either
                       be simply the name of one of the 'built-in' providers,
                      or a URL format string for ad-hoc updating.

 --frontends=N:X:P      Choose N front-ends from X (a DNS domain name), port P.
 --frontend=host:port   Connect to the named front-end server.
 --new          -N      Don't attempt to connect to the domain's old front-end.           
 --socksify=S:P         Connect via SOCKS server S, port P (requires socks.py)
 --torify=S:P           Same as socksify, but more paranoid.
 --noprobes             Reject all probes for back-end liveness.
 --fe_certname=N        Connect using SSL, accepting valid certs for domain N.
 --ca_certs=PATH        Path to your trusted root SSL certificates file.

 --backend=proto:domain:host:port:secret
                  Configure a back-end service on host:port, using
                 protocol proto and the given domain. As a special
                case, if host and port are left blank and the proto
               is HTTP or HTTPS, the built-in server will be used.

About the options file:

The options file contains the same options as are available to the command
line, with the restriction that there be exactly one "argument" per line.

The leading '--' may also be omitted for readability, and for the same reason
it is recommended to use the long form of the options in the configuration
file (also, as the short form may not always parse correctly).

Blank lines and lines beginning with # (comments) are stripped from the
options file before it is parsed.  It is perfectly acceptable to have multiple
options files, and options files can include other options files.


Examples:

# Create a config-file with default options, and then edit it.
pagekite.py --defaults --settings > ~/.pagekite.rc
vim ~/.pagekite.rc

# Run pagekite with the HTTP UI, for browsing state over the web.
pagekite.py --httpd=localhost:8888
firefox http://localhost:8888/

# Fly a PageKite on pagekite.net for somedomain.com, and register the new
# front-ends with the No-IP Dynamic DNS provider.
pagekite.py \\
       --frontends=1:frontends.b5p.us:443 \\
       --dyndns=user:pass@no-ip.com \\
       --backend=http:somedomain.com:localhost:80:mygreatsecret

""" % APPVER

MAGIC_PREFIX = '/~:PageKite:~/'
MAGIC_PATH = '%sv%s' % (MAGIC_PREFIX, PROTOVER)
MAGIC_PATHS = (MAGIC_PATH, '/Beanstalk~Magic~Beans/0.2')

OPT_FLAGS = 'o:S:H:P:X:L:ZI:fA:R:h:p:aD:U:NE:'
OPT_ARGS = ['noloop', 'clean', 'nopyopenssl', 'nocrashreport',
            'optfile=', 'savefile=', 'reloadfile=',
            'httpd=', 'pemfile=', 'httppass=', 'errorurl=',
            'logfile=', 'daemonize', 'nodaemonize', 'runas=', 'pidfile=',
            'isfrontend', 'noisfrontend', 'settings', 'defaults', 'domain=',
            'authdomain=', 'authhelpurl=', 'register=', 'host=',
            'noupgradeinfo', 'upgradeinfo=', 'motd=',
            'ports=', 'protos=', 'portalias=', 'rawports=',
            'tls_default=', 'tls_endpoint=', 'fe_certname=', 'ca_certs=',
            'backend=', 'frontend=', 'frontends=', 'torify=', 'socksify=',
            'new', 'all', 'noall', 'dyndns=', 'nozchunks', 'sslzlib',
            'buffers=', 'noprobes', 'debugio',]

DEBUG_IO = False

AUTH_ERRORS           = '255.255.255.'
AUTH_ERR_USER_UNKNOWN = '.0'
AUTH_ERR_INVALID      = '.1'
AUTH_QUOTA_MAX        = '255.255.254.255'

VIRTUAL_PN = 'virtual'
CATCHALL_HN = 'unknown'
LOOPBACK_HN = 'loopback'
LOOPBACK_FE = LOOPBACK_HN + ':1'
LOOPBACK_BE = LOOPBACK_HN + ':2'
LOOPBACK = {'FE': LOOPBACK_FE, 'BE': LOOPBACK_BE}

BE_PROTO = 0
BE_PORT = 1
BE_DOMAIN = 2
BE_BACKEND = 3
BE_SECRET = 4
BE_STATUS = 5

BE_STATUS_OK = 0
BE_STATUS_BE_FAIL = 2
BE_STATUS_NO_TUNNEL = 1
BE_STATUS_DISABLED = -1
BE_STATUS_UNKNOWN = -2

DYNDNS = {
  'pagekite.net': ('http://up.pagekite.net/'
                   '?hostname=%(domain)s&myip=%(ips)s&sign=%(sign)s'),
  'beanstalks.net': ('http://up.b5p.us/'
                     '?hostname=%(domain)s&myip=%(ips)s&sign=%(sign)s'),
  'dyndns.org': ('https://%(user)s:%(pass)s@members.dyndns.org'
                 '/nic/update?wildcard=NOCHG&backmx=NOCHG'
                 '&hostname=%(domain)s&myip=%(ip)s'),
  'no-ip.com': ('https://%(user)s:%(pass)s@dynupdate.no-ip.com'
                '/nic/update?hostname=%(domain)s&myip=%(ip)s'),
}


##[ Standard imports ]########################################################

import base64
from cgi import escape as escape_html
import errno
import getopt
import os
import random
import re
import select
import socket
rawsocket = socket.socket

import struct
import sys
import threading
import time
import traceback
import urllib
import zlib

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler


##[ Conditional imports & compatibility magic! ]###############################

# System logging on Unix
try:
  import syslog
except ImportError:
  pass


# Backwards compatibility for old Pythons.
if not 'SHUT_RD' in dir(socket):
  socket.SHUT_RD = 0
  socket.SHUT_WR = 1
  socket.SHUT_RDWR = 2

try:
  sorted([1, 2, 3])
except:
  def sorted(l):
    tmp = l[:]
    tmp.sort()
    return tmp


# SSL/TLS strategy: prefer pyOpenSSL, as it comes with built-in Context
# objects. If that fails, look for Python 2.6+ native ssl support and 
# create a compatibility wrapper. If both fail, bomb with a ConfigError
# when the user tries to enable anything SSL-related.
SEND_MAX_BYTES = 16 * 1024
SEND_ALWAYS_BUFFERS = False
try:
  if '--nopyopenssl' in sys.argv:
    raise ImportError('pyOpenSSL disabled')

  from OpenSSL import SSL
  def SSL_Connect(ctx, sock,
                  server_side=False, accepted=False, connected=False,
                  verify_names=None):
    LogInfo('TLS is provided by pyOpenSSL')
    if verify_names:
      def vcb(conn, x509, errno, depth, rc):
        # FIXME: No ALT names, no wildcards ...
        if errno != 0: return False
        if depth != 0: return True
        commonName = x509.get_subject().commonName.lower()
        cNameDigest = '%s/%s' % (commonName, x509.digest('sha1').replace(':','').lower())
        if (commonName in verify_names) or (cNameDigest in verify_names):
          LogDebug('Cert OK: %s' % (cNameDigest))
          return True
        return False
      ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, vcb)
    else:
      def vcb(conn, x509, errno, depth, rc): return (errno == 0)
      ctx.set_verify(SSL.VERIFY_NONE, vcb)

    nsock = SSL.Connection(ctx, sock)
    if accepted: nsock.set_accept_state()
    if connected: nsock.set_connect_state()
    if verify_names: nsock.do_handshake()

    return nsock

except ImportError:
  try:
    import ssl

    # Because the native Python ssl module does not expose WantWriteError,
    # we need this to keep tunnels from shutting down when busy.
    SEND_ALWAYS_BUFFERS = True
    SEND_MAX_BYTES = 4 * 1024

    class SSL(object):
      SSLv23_METHOD = ssl.PROTOCOL_SSLv23
      TLSv1_METHOD = ssl.PROTOCOL_TLSv1
      WantReadError = ssl.SSLError
      class Error(Exception): pass
      class SysCallError(Exception): pass
      class WantWriteError(Exception): pass
      class ZeroReturnError(Exception): pass
      class Context(object):
        def __init__(self, method):
          self.method = method
          self.privatekey_file = None
          self.certchain_file = None
          self.ca_certs = None
        def use_privatekey_file(self, fn): self.privatekey_file = fn
        def use_certificate_chain_file(self, fn): self.certchain_file = fn
        def load_verify_locations(self, pemfile, capath=None): self.ca_certs = pemfile

    def SSL_CheckPeerName(fd, names):
      cert = fd.getpeercert()
      certhash = sha1hex(fd.getpeercert(binary_form=True))
      if not cert: return None
      for field in cert['subject']:
        if field[0][0].lower() == 'commonname':
          name = field[0][1].lower()
          namehash = '%s/%s' % (name, certhash)
          if name in names or namehash in names:
            LogDebug('Cert OK: %s' % (namehash))
            return name

      if 'subjectAltName' in cert:
        for field in cert['subjectAltName']:
          if field[0].lower() == 'dns':
            name = field[1].lower()
            namehash = '%s/%s' % (name, certhash)
            if name in names or namehash in names:
              LogDebug('Cert OK: %s' % (namehash))
              return name

      return None

    def SSL_Connect(ctx, sock,
                    server_side=False, accepted=False, connected=False,
                    verify_names=None):
      LogInfo('TLS is provided by native Python ssl')
      reqs = (verify_names and ssl.CERT_REQUIRED or ssl.CERT_NONE)
      fd = ssl.wrap_socket(sock, keyfile=ctx.privatekey_file, 
                                 certfile=ctx.certchain_file,
                                 cert_reqs=reqs,
                                 ca_certs=ctx.ca_certs,
                                 do_handshake_on_connect=False,
                                 ssl_version=ctx.method,
                                 server_side=server_side)
      if verify_names:
        fd.do_handshake()
        if not SSL_CheckPeerName(fd, verify_names):
          raise SSL.Error('Cert not in %s (%s)' % (verify_names, reqs)) 
      return fd

  except ImportError:
    class SSL(object):
      SSLv23_METHOD = 0
      TLSv1_METHOD = 0
      class Error(Exception): pass
      class SysCallError(Exception): pass
      class WantReadError(Exception): pass
      class WantWriteError(Exception): pass
      class ZeroReturnError(Exception): pass
      class Context(object):
        def __init__(self, method):
          raise ConfigError('Neither pyOpenSSL nor python 2.6+ ssl modules found!')


def DisableSSLCompression():
  # Hack to disable compression in OpenSSL and reduce memory usage *lots*.
  # Source:
  #   http://journal.paul.querna.org/articles/2011/04/05/openssl-memory-use/
  try:
    import ctypes
    import glob
    openssl = ctypes.CDLL(None, ctypes.RTLD_GLOBAL)
    try:
      f = openssl.SSL_COMP_get_compression_methods
    except AttributeError:
      ssllib = sorted(glob.glob("/usr/lib/libssl.so.*"))[0]
      openssl = ctypes.CDLL(ssllib, ctypes.RTLD_GLOBAL)

    openssl.SSL_COMP_get_compression_methods.restype = ctypes.c_void_p
    openssl.sk_zero.argtypes = [ctypes.c_void_p]
    openssl.sk_zero(openssl.SSL_COMP_get_compression_methods())
  except Exception, e:
    LogError('disableSSLCompression: Failed: %s' % e)
 

# Different Python 2.x versions complain about deprecation depending on
# where we pull these from.
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


# YamonD is a part of PageKite.net's internal monitoring systems. It's not
# required, so if you don't have it, the mock makes things Just Work.
class MockYamonD(object):
  def __init__(self, sspec, server=None, handler=None): pass
  def vmax(self, var, value): pass
  def vscale(self, var, ratio, add=0): pass
  def vset(self, var, value): pass
  def vadd(self, var, value, wrap=None): pass
  def vmin(self, var, value): pass
  def vdel(self, var): pass
  def lcreate(self, listn, elems): pass
  def ladd(self, listn, value): pass
  def render_vars_text(self): return ''
  def quit(self): pass
  def run(self): pass

gYamon = MockYamonD(())

try:
  import yamond
  YamonD=yamond.YamonD
except Exception:
  YamonD=MockYamonD


##[ PageKite.py code starts here! ]############################################

gSecret = None
def globalSecret():
  global gSecret
  if not gSecret:
    # This always works...
    gSecret = '%8.8x%8.8x%8.8x' % (random.randint(0, 0x7FFFFFFE), 
                                   time.time(),
                                   random.randint(0, 0x7FFFFFFE))

    # Next, see if we can augment that with some real randomness.
    try:
      newSecret = sha1hex(open('/dev/random').read(16) + gSecret)
      gSecret = newSecret
      LogDebug('Seeded signatures using /dev/random, hooray!')
    except:
      try:
        newSecret = sha1hex(os.urandom(64) + gSecret)
        gSecret = newSecret
        LogDebug('Seeded signatures using os.urandom(), hooray!')
      except:
        LogInfo('WARNING: Seeding signatures with time.time() and random.randint()')

  return gSecret

TOKEN_LENGTH=36
def signToken(token=None, secret=None, payload='', timestamp=None,
              length=TOKEN_LENGTH):
  """
  This will generate a random token with a signature which could only have come
  from this server.  If a token is provided, it is re-signed so the original
  can be compared with what we would have generated, for verification purposes.

  If a timestamp is provided it will be embedded in the signature to a
  resolution of 10 minutes, and the signature will begin with the letter 't'

  Note: This is only as secure as random.randint() is random.
  """
  if not secret: secret = globalSecret()
  if not token: token = sha1hex('%s%8.8x' % (globalSecret(),
                                             random.randint(0, 0x7FFFFFFD)+1))
  if timestamp:
    tok = 't' + token[1:]
    ts = '%x' % int(timestamp/600)
    return tok[0:8] + sha1hex(secret + payload + ts + tok[0:8])[0:length-8]
  else:
    return token[0:8] + sha1hex(secret + payload + token[0:8])[0:length-8]

def checkSignature(sign='', secret='', payload=''):
  """
  Check a signature for validity. When using timestamped signatures, we only
  accept signatures from the current and previous windows.
  """
  if sign[0] == 't':
    ts = int(time.time())
    for window in (0, 1):
      valid = signToken(token=sign, secret=secret, payload=payload,
                        timestamp=(ts-(window*600)))
      if sign == valid: return True
    return False
  else:
    valid = signToken(token=sign, secret=secret, payload=payload)
    return sign == valid


class ConfigError(Exception):
  pass

class ConnectError(Exception):
  pass


def HTTP_PageKiteRequest(server, backends, tokens=None, nozchunks=False,
                         tls=False, testtoken=None, replace=None):
  req = ['CONNECT PageKite:1 HTTP/1.0\r\n',
         'X-PageKite-Version: %s\r\n' % APPVER]

  if not nozchunks: req.append('X-PageKite-Features: ZChunks\r\n')
  if replace: req.append('X-PageKite-Replace: %s\r\n' % replace)
  if tls: req.append('X-PageKite-Features: TLS\r\n')
         
  tokens = tokens or {}
  for d in backends.keys():
    if backends[d][BE_BACKEND]:

      # A stable (for replay on challenge) but unguessable salt.
      my_token = sha1hex(globalSecret() + server + backends[d][BE_SECRET]
                         )[:TOKEN_LENGTH]

      # This is the challenge (salt) from the front-end, if any.
      server_token = d in tokens and tokens[d] or ''

      # Our payload is the (proto, name) combined with both salts
      data = '%s:%s:%s' % (d, my_token, server_token)

      # Sign the payload with the shared secret (random salt).
      sign = signToken(secret=backends[d][BE_SECRET],
                       payload=data,
                       token=testtoken)

      req.append('X-PageKite: %s:%s\r\n' % (data, sign))

  req.append('\r\n')
  return ''.join(req)

def HTTP_ResponseHeader(code, title, mimetype='text/html'):
  return ('HTTP/1.1 %s %s\r\nContent-Type: %s\r\nPragma: no-cache\r\n'
          'Expires: 0\r\nCache-Control: no-store\r\nConnection: close'
          '\r\n') % (code, title, mimetype)

def HTTP_Header(name, value):
  return '%s: %s\r\n' % (name, value)

def HTTP_StartBody():
  return '\r\n'

def HTTP_ConnectOK():
  return 'HTTP/1.0 200 Connection Established\r\n\r\n'

def HTTP_ConnectBad():
  return 'HTTP/1.0 503 Sorry\r\n\r\n'

def HTTP_Response(code, title, body, mimetype='text/html', headers=None):
  data = [HTTP_ResponseHeader(code, title, mimetype)]
  if headers: data.extend(headers)
  data.extend([HTTP_StartBody(), ''.join(body)])
  return ''.join(data)

def HTTP_NoFeConnection():
  return HTTP_Response(200, 'OK', base64.decodestring(
    'R0lGODlhCgAKAMQCAN4hIf/+/v///+EzM+AuLvGkpORISPW+vudgYOhiYvKpqeZY'
    'WPbAwOdaWup1dfOurvW7u++Rkepycu6PjwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAACH5BAEAAAIALAAAAAAKAAoAAAUtoCAcyEA0jyhEQOs6AuPO'
    'QJHQrjEAQe+3O98PcMMBDAdjTTDBSVSQEmGhEIUAADs='),
      headers=[HTTP_Header('X-PageKite-Status', 'Down-FE')],
      mimetype='image/gif')

def HTTP_NoBeConnection():
  return HTTP_Response(200, 'OK', base64.decodestring(
    'R0lGODlhCgAKAPcAAI9hE6t2Fv/GAf/NH//RMf/hd7u6uv/mj/ntq8XExMbFxc7N'
    'zc/Ozv/xwfj31+jn5+vq6v///////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAACH5BAEAABIALAAAAAAKAAoAAAhDACUIlBAgwMCDARo4MHiQ'
    '4IEGDAcGKAAAAESEBCoiiBhgQEYABzYK7OiRQIEDBgMIEDCgokmUKlcOKFkgZcGb'
    'BSUEBAA7'),
      headers=[HTTP_Header('X-PageKite-Status', 'Down-BE')],
      mimetype='image/gif')
                            
def HTTP_GoodBeConnection():
  return HTTP_Response(200, 'OK', base64.decodestring(
    'R0lGODlhCgAKANUCAEKtP0StQf8AAG2/a97w3qbYpd/x3mu/aajZp/b79vT69Mnn'
    'yK7crXTDcqraqcfmxtLr0VG0T0ivRpbRlF24Wr7jveHy4Pv9+53UnPn8+cjnx4LI'
    'gNfu1v///37HfKfZpq/crmG6XgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAACH5BAEAAAIALAAAAAAKAAoAAAZIQIGAUDgMEASh4BEANAGA'
    'xRAaaHoYAAPCCZUoOIDPAdCAQhIRgJGiAG0uE+igAMB0MhYoAFmtJEJcBgILVU8B'
    'GkpEAwMOggJBADs='),
      headers=[HTTP_Header('X-PageKite-Status', 'OK')],
      mimetype='image/gif')
 
def HTTP_Unavailable(where, proto, domain, comment='', frame_url=None):
  code, status = 503, 'Unavailable'
  message = ''.join(['<h1>Sorry! (', where, ')</h1>',
                     '<p>The ', proto.upper(),' <a href="', WWWHOME, '">',
                     '<i>PageKite</i></a> for <b>', domain, 
                     '</b> is unavailable at the moment.</p>',
                     '<p>Please try again later.</p><!-- ', comment, ' -->'])
  if frame_url:
    if '?' in frame_url:
      frame_url += '&where=%s&proto=%s&domain=%s' % (where.upper(), proto, domain)
    return HTTP_Response(code, status,
                         ['<html><frameset cols="*">',
                          '<frame target="_top" src="', frame_url, '" />',
                          '<noframes>', message, '</noframes>',
                          '</frameset></html>'])
  else:
    return HTTP_Response(code, status,
                         ['<html><body>', message, '</body></html>'])

LOG = []
LOG_LENGTH = 300
LOG_THRESHOLD = 256 * 1024

def LogValues(values, testtime=None):
  words = [('ts', '%x' % (testtime or time.time()))]
  words.extend([(kv[0], ('%s' % kv[1]).replace('\t', ' ')
                                      .replace('\r', ' ')
                                      .replace('\n', ' ')
                                      .replace('; ', ', ')
                                      .strip()) for kv in values])
  wdict = dict(words)
  LOG.append(wdict)
  while len(LOG) > LOG_LENGTH: LOG.pop(0)
  return (words, wdict)
 
def LogSyslog(values, wdict=None, words=None):
  if values:
    words, wdict = LogValues(values)
  if 'err' in wdict:
    syslog.syslog(syslog.LOG_ERR, '; '.join(['='.join(x) for x in words]))
  elif 'debug' in wdict:
    syslog.syslog(syslog.LOG_DEBUG, '; '.join(['='.join(x) for x in words]))
  else:
    syslog.syslog(syslog.LOG_INFO, '; '.join(['='.join(x) for x in words]))

LogFile = sys.stdout
def LogToFile(values, wdict=None, words=None):
  if values:
    words, wdict = LogValues(values)
  LogFile.write('; '.join(['='.join(x) for x in words]))
  LogFile.write('\n')

def LogToMemory(values, wdict=None, words=None):
  if values: LogValues(values)

def FlushLogMemory():
  for l in LOG:
    Log(None, wdict=l, words=[(w, l[w]) for w in l])

Log = LogToMemory

def LogError(msg, parms=None):
  emsg = [('err', msg)]
  if parms: emsg.extend(parms)
  Log(emsg)

  global gYamon
  gYamon.vadd('errors', 1, wrap=1000000)

def LogDebug(msg, parms=None):
  emsg = [('debug', msg)]
  if parms: emsg.extend(parms)
  Log(emsg)

def LogInfo(msg, parms=None):
  emsg = [('info', msg)]
  if parms: emsg.extend(parms)
  Log(emsg)


# FIXME: This could easily be a pool of threads to let us handle more
#        than one incoming request at a time.
class AuthThread(threading.Thread):
  """Handle authentication work in a separate thread."""
  
  def __init__(self, conns):
    threading.Thread.__init__(self)
    self.qc = threading.Condition()
    self.jobs = []
    self.conns = conns

  def check(self, requests, conn, callback):
    self.qc.acquire()
    self.jobs.append((requests, conn, callback))
    self.qc.notify()
    self.qc.release()

  def quit(self):
    self.qc.acquire()
    self.keep_running = False
    self.qc.notify()
    self.qc.release()

  def run(self):
    self.keep_running = True
    while self.keep_running:
      try:
        self._run()
      except Exception, e:
        LogError('AuthThread died: %s' % e)
        time.sleep(5)

  def _run(self):
    self.qc.acquire()
    while self.keep_running:
      now = int(time.time())
      if self.jobs:
        (requests, conn, callback) = self.jobs.pop(0)
        if DEBUG_IO: print '=== AUTH REQUESTS\n%s\n===' % requests
        self.qc.release()

        quotas = []
        results = []
        session = '%x:%s:' % (now, globalSecret())
        for request in requests:
          try:
            proto, domain, srand, token, sign, prefix = request
          except:
            LogError('Invalid request: %s' % (request, ))
            continue

          what = '%s:%s:%s' % (proto, domain, srand)
          session += what
          if not token or not sign:
            # Send a challenge. Our challenges are time-stamped, so we can
            # put stict bounds on possible replay attacks (20 minutes atm).
            results.append(('%s-SignThis' % prefix,
                            '%s:%s' % (what, signToken(payload=what,
                                                       timestamp=now))))
          else:
            # This is a bit lame, but we only check the token if the quota
            # for this connection has never been verified.
            (quota, reason) = self.conns.config.GetDomainQuota(proto,
                                                    domain, srand, token, sign,
                                               check_token=(conn.quota is None))
            if not quota:
              results.append(('%s-Invalid' % prefix, what))
              results.append(('%s-Invalid-Why' % prefix,
                              '%s;%s' % (what, reason)))
            elif self.conns.Tunnel(proto, domain):
              # FIXME: Allow multiple backends?
              results.append(('%s-Duplicate' % prefix, what))
            else:
              results.append(('%s-OK' % prefix, what))
              quotas.append(quota)
              if (proto.startswith('http') and
                  self.conns.config.GetTlsEndpointCtx(domain)):
                results.append(('%s-SSL-OK' % prefix, what))

        results.append(('%s-SessionID' % prefix,
                        '%x:%s' % (now, sha1hex(session))))
        if self.conns.config.motd:
          results.append(('%s-MOTD' % prefix, self.conns.config.motd))
        for upgrade in self.conns.config.upgrade_info:
          results.append(('%s-Upgrade' % prefix, ';'.join(upgrade)))

        if quotas:
          nz_quotas = [q for q in quotas if q and q > 0]
          if nz_quotas:
            quota = min(nz_quotas)
            if quota is not None:
              conn.quota = [quota, requests[quotas.index(quota)], time.time()]
              results.append(('%s-Quota' % prefix, quota))
          elif requests:
            if not conn.quota:
              conn.quota = [None, requests[0], time.time()]
            else:
              conn.quota[2] = time.time()

        if DEBUG_IO: print '=== AUTH RESULTS\n%s\n===' % results
        callback(results)
        self.qc.acquire()
      else:
        self.qc.wait()
      
    self.buffering = 0
    self.qc.release()


def fmt_size(count):
  if count > 2*(1024*1024*1024):
    return '%dGB' % (count / (1024*1024*1024))
  if count > 2*(1024*1024):
    return '%dMB' % (count / (1024*1024))
  if count > 2*(1024):
    return '%dKB' % (count / 1024)
  return '%dB' % count


class UiRequestHandler(SimpleXMLRPCRequestHandler):

  # Make all paths/endpoints legal, we interpret them below.
  rpc_paths = ( )

  TEMPLATE_TEXT = ('%(body)s')
  TEMPLATE_HTML = ('<html><head>\n'
               '<link rel="stylesheet" media="screen, screen"'
                ' href="http://pagekite.net/css/pagekite.css"'
                ' type="text/css" title="Default stylesheet" />\n'
               '<title>%(title)s - %(prog)s v%(ver)s</title>\n'
              '</head><body>\n'
               '<h1>%(title)s</h1>\n'
               '<div id=body>%(body)s</div>\n'
               '<div id=footer><hr><i>Powered by <b>pagekite.py'
                ' v%(ver)s</b> and'
                ' <a href="' + WWWHOME + '"><i>PageKite.net</i></a>.<br>'
                'Local time is %(now)s.</i></div>\n'
              '</body></html>\n')
 
  def setup(self):
    if self.server.enable_ssl:
      self.connection = self.request
      self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
      self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)
    else:
      SimpleXMLRPCRequestHandler.setup(self)
 
  def log_message(self, format, *args):
    Log([('uireq', format % args)])

  def html_overview(self):
    conns = self.server.conns
    backends = self.server.pkite.backends

    html = [(
      '<div id=welcome><p>Welcome to your <i>PageKite</i> control panel!</p></div>\n'
      '<p id=links>[ <a href="/log.html">Logs</a>, '
                    '<a href="/conns/">Connections</a> ]</p>\n'
      '<div id=live><h2>Flying kites:</h2><ul>\n'
    )]

    for tid in conns.tunnels:
      proto, domain = tid.split(':')
      if '-' in proto: proto, port = proto.split('-')
      if tid in backends:
        backend = backends[tid][BE_BACKEND]
        if proto.startswith('http'):
          binfo = '<a href="%s://%s">%s</a>' % (proto, backend, backend)
        else:
          binfo = '<b>%s</b>' % backend
      else:
        binfo = '<i>none</i>'

      if proto.startswith('http'):
        tinfo = '%s: <a href="%s://%s">%s</a>' % (proto, proto, domain, domain)
      else:
        tinfo = '%s: <b>%s</b>' % (proto, domain) 

      for tunnel in conns.tunnels[tid]:
        html.append(('<li><span class=tid>%s</span></b>'
                     ' (<span class=ips>%s</span> to'
                     ' <span class=backend>%s</span>,'
                     ' <span class=bytes>%s in, %s out</span>)'
                     '</li>\n') % (tinfo,
                                   tunnel.server_info[tunnel.S_NAME].split(':')[0],
                                   binfo,
                                   fmt_size(tunnel.all_in + tunnel.read_bytes),
                                   fmt_size(tunnel.all_out + tunnel.wrote_bytes))) 
    if not conns.tunnels:
      html.append('<i>None</i>')
    
    html.append(
      '</ul></div>\n'
    )
    return {
      'title': 'Control Panel',
      'body': ''.join(html)
    }

  def txt_log(self):
    return '\n'.join(['%s' % x for x in LOG])

  def html_log(self, path):
    debug = path.find('debug') >= 0
    httpd = path.find('httpd') >= 0
    alllog = path.find('all') >= 0
    html = ['<p id=links>[ <a href="/status.html">Control Panel</a> | Logs: '
                         ' <a href="/log.html">normal</a>,'
                         ' <a href="/debug-log.html">debug</a>,'
                         ' <a href="/httpd-log.html">httpd</a>,'
                         ' <a href="/all-log.html">all</a>,'
                         ' <a href="/log.txt">raw</a> ]</p>'
            '<table>']
    lines = []
    for line in LOG:
      if not alllog and ('debug' in line) != debug: continue
      if not alllog and ('uireq' in line) != httpd: continue

      keys = line.keys()
      keys.sort()
      lhtml = ('<tr><td colspan=3><b>%s</b></td>'
               '</tr>' % time.strftime('%Y-%m-%d %H:%M:%S',
                                       time.localtime(int(line['ts'], 16))))
      for key in keys:
        if key != 'ts':
          lhtml += ('<tr><td></td><td align=right>%s&nbsp;=</td><td>%s</td>'
                    '</tr>' % (key, escape_html(line[key])))
      lines.insert(0, lhtml)

    html.extend(lines)
    html.append('</table>')
    return {
      'title': 'Log viewer, recent events',
      'body': ''.join(html)
    }

  def html_conns(self):
    html = ['<ul>']
    sids = SELECTABLES.keys()
    sids.sort(reverse=True)
    for sid in sids:
      sel = SELECTABLES[sid]
      html.append('<li><a href="/conn/%s">%s</a>%s'
                  ' ' % (sid, escape_html(str(sel)),
                         sel.dead and ' ' or ' <i>alive</i>'))
    html.append('</ul>')
    return {
      'title': 'Connection log',
      'body': ''.join(html)
    }

  def html_conn(self, path):
    sid = int(path[len('/conn/'):])
    if sid in SELECTABLES:
      html = ['<h2>%s</h2>' % escape_html('%s' % SELECTABLES[sid]),
              SELECTABLES[sid].__html__()]
    else:
      html = ['<h2>Connection %s not found. Expired?</h2>' % sid]
    return {
      'title': 'Connection details',
      'body': ''.join(html)
    }

  def begin_headers(self, code, mimetype):
    self.send_response(code)
    self.send_header('Cache-Control', 'no-store')
    self.send_header('Pragma', 'no-cache')
    self.send_header('Content-Type', mimetype)

  def do_GET(self):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path) 

    data = {
      'prog': (sys.argv[0] or 'pagekite.py').split('/')[-1],
      'now': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
      'ver': APPVER
    }

    authenticated = False
    if self.server.pkite.ui_password: 
      auth = self.headers.get('authorization')
      if auth:
        (how, ab64) = auth.split()
        if how.lower() == 'basic':
          (uid, password) = base64.b64decode(ab64).split(':')
          authenticated = (password == self.server.pkite.ui_password)
      elif query.find('auth=%s' % self.server.pkite.ui_password) != -1:
        authenticated = True

      if not authenticated:
        self.begin_headers(401, 'text/html')
        self.send_header('WWW-Authenticate',
                         'Basic realm=PK%d' % (time.time()/3600))
        self.end_headers()
        data['title'] = data['body'] = 'Authentication required.'
        self.wfile.write(self.TEMPLATE_HTML % data)
        return
    
    if path.endswith('.txt'):
      template = self.TEMPLATE_TEXT
      self.begin_headers(200, 'text/plain')
    else:
      template = self.TEMPLATE_HTML
      self.begin_headers(200, 'text/html')
    self.end_headers()

    qs = parse_qs(query)

    if path == '/vars.txt':
      global gYamon
      data['body'] = gYamon.render_vars_text()

    elif path == '/log.txt':        data['body'] = self.txt_log()
    elif path.endswith('log.html'): data.update(self.html_log(path))
    elif path == '/conns/':         data.update(self.html_conns())
    elif path.startswith('/conn/'): data.update(self.html_conn(path))
    else: data.update(self.html_overview())
        
    self.wfile.write(template % data)

class UiHttpServer(SimpleXMLRPCServer):
  def __init__(self, sspec, pkite, conns,
               handler=UiRequestHandler,
               ssl_pem_filename=None):
    SimpleXMLRPCServer.__init__(self, sspec, handler)
    self.pkite = pkite
    self.conns = conns

    # FIXME: There should be access control on these
    #self.register_introspection_functions()
    #self.register_instance(conns)

    if ssl_pem_filename:
      ctx = SSL.Context(SSL.SSLv23_METHOD)
      ctx.use_privatekey_file (ssl_pem_filename)
      ctx.use_certificate_chain_file(ssl_pem_filename)
      self.socket = SSL_Connect(ctx, socket.socket(self.address_family,
                                                   self.socket_type),
                                server_side=True)
      self.server_bind()
      self.server_activate()
      self.enable_ssl = True
    else:
      self.enable_ssl = False

    global gYamon
    gYamon = YamonD(sspec)
    gYamon.vset('started', int(time.time()))
    gYamon.vset('version', APPVER)
    gYamon.vset('httpd_ssl_enabled', self.enable_ssl)
    gYamon.vset('errors', 0)
    gYamon.vset("bytes_all", 0)

class HttpUiThread(threading.Thread):
  """Handle HTTP UI in a separate thread."""

  def __init__(self, pkite, conns, 
               server=UiHttpServer, handler=UiRequestHandler,
               ssl_pem_filename=None):
    threading.Thread.__init__(self)
    self.ui_sspec = pkite.ui_sspec
    self.httpd = server(self.ui_sspec, pkite, conns,
                        handler=handler,
                        ssl_pem_filename=ssl_pem_filename)
    self.httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.serve = True

    global SELECTABLES
    SELECTABLES = {}

  def quit(self):
    self.serve = False
    try:
      knock = rawsocket(socket.AF_INET, socket.SOCK_STREAM)
      knock.connect(self.ui_sspec)
      knock.close()
    except Exception:
      pass

  def run(self):
    while self.serve:
      try:
        self.httpd.handle_request()
      except KeyboardInterrupt:
        self.serve = False
      except Exception, e:
        LogInfo('HTTP UI caught exception: %s' % e)
    LogDebug('HttpUiThread: done')
    self.httpd.socket.close()


HTTP_METHODS = ['OPTIONS', 'CONNECT', 'GET', 'HEAD', 'POST', 'PUT', 'TRACE',
                'PROPFIND', 'PROPPATCH', 'MKCOL', 'DELETE', 'COPY', 'MOVE',
                'LOCK', 'UNLOCK', 'PING']
HTTP_VERSIONS = ['HTTP/1.0', 'HTTP/1.1']

class HttpParser(object):
  """Parse an HTTP request, line-by-line."""

  IN_REQUEST = 1
  IN_HEADERS = 2
  IN_BODY = 3
  IN_RESPONSE = 4
  PARSE_FAILED = -1

  def __init__(self, lines=None, state=None, testbody=False):
    self.state = state or self.IN_REQUEST
    self.method = None
    self.path = None
    self.version = None
    self.code = None
    self.message = None
    self.headers = []
    self.lines = []
    self.body_result = testbody

    if lines is not None:
      for line in lines:
        if not self.Parse(line): break

  def ParseResponse(self, line):
    self.version, self.code, self.message = line.split()

    if not self.version.upper() in HTTP_VERSIONS:
      LogDebug('Invalid version: %s' % self.version)
      return False

    self.state = self.IN_HEADERS
    return True

  def ParseRequest(self, line):
    self.method, self.path, self.version = line.split()

    if not self.method in HTTP_METHODS:
      LogDebug('Invalid method: %s' % self.method)
      return False

    if not self.version.upper() in HTTP_VERSIONS:
      LogDebug('Invalid version: %s' % self.version)
      return False

    self.state = self.IN_HEADERS
    return True

  def ParseHeader(self, line):
    if line in ('', '\r', '\n', '\r\n'):
      self.state = self.IN_BODY
      return True

    header, value = line.split(':', 1)
    if value and value.startswith(' '): value = value[1:]

    self.headers.append((header.lower(), value)) 
    return True

  def ParseBody(self, line):
    # Could be overridden by subclasses, for now we just play dumb.
    return self.body_result

  def Parse(self, line):
    self.lines.append(line)
    try:
      if (self.state == self.IN_RESPONSE):
        return self.ParseResponse(line)

      elif (self.state == self.IN_REQUEST):
        return self.ParseRequest(line)

      elif (self.state == self.IN_HEADERS):
        return self.ParseHeader(line)

      elif (self.state == self.IN_BODY):
        return self.ParseBody(line)

    except ValueError, err:
      LogInfo('Parse failed: %s, %s, %s' % (self.state, err, self.lines))

    self.state = self.PARSE_FAILED
    return False

  def Header(self, header):
    return [h[1].strip() for h in self.headers if h[0] == header.lower()]


def obfuIp(ip):
  quads = ('%s' % ip).replace(':', '.').split('.')
  return '~%s' % '.'.join([q for q in quads[-2:]])

selectable_id = 0
buffered_bytes = 0
SELECTABLES = None

class Selectable(object):
  """A wrapper around a socket, for use with select."""

  HARMLESS_ERRNOS = (errno.EINTR, errno.EAGAIN, errno.ENOMEM, errno.EBUSY,
                     errno.EDEADLK, errno.EWOULDBLOCK, errno.ENOBUFS,
                     errno.EALREADY)

  def __init__(self, fd=None, address=None, on_port=None, maxread=16000,
                     tracked=True):
    self.fd = None
    try:
      self.SetFD(fd or rawsocket(socket.AF_INET6, socket.SOCK_STREAM), six=True)
    except Exception:
      self.SetFD(fd or rawsocket(socket.AF_INET, socket.SOCK_STREAM))
    self.address = address
    self.on_port = on_port
    self.created = self.bytes_logged = time.time()
    self.dead = False

    # Quota-related stuff
    self.quota = None

    # Read-related variables
    self.maxread = maxread
    self.read_bytes = self.all_in = 0
    self.read_eof = False
    self.peeking = False
    self.peeked = 0

    # Write-related variables
    self.wrote_bytes = self.all_out = 0
    self.write_blocked = ''
    self.write_speed = 102400
    self.write_eof = False
    self.write_retry = None

    # Throttle reads and writes
    self.throttle_until = 0

    # Compression stuff
    self.zw = None
    self.zlevel = 1
    self.zreset = False

    # Logging
    self.logged = []
    global selectable_id
    selectable_id += 1
    self.sid = selectable_id
    self.alt_id = None

    if address:
      addr = address or ('x.x.x.x', 'x')
      self.log_id = 's%s/%s:%s' % (self.sid, obfuIp(addr[0]), addr[1])
    else:
      self.log_id = 's%s' % self.sid

    # Introspection
    if SELECTABLES is not None:
      old = selectable_id-150
      if old in SELECTABLES: del SELECTABLES[old]
      if tracked: SELECTABLES[selectable_id] = self

    global gYamon
    self.countas = 'selectables_live'
    gYamon.vadd(self.countas, 1)
    gYamon.vadd('selectables', 1)

  def CountAs(self, what):
    global gYamon
    gYamon.vadd(self.countas, -1)
    self.countas = what
    gYamon.vadd(self.countas, 1)

  def __del__(self):
    global gYamon
    gYamon.vadd(self.countas, -1)
    gYamon.vadd('selectables', -1)

  def __str__(self):
    return '%s: %s' % (self.log_id, self.__class__)

  def __html__(self):
    try:
      peer = self.fd.getpeername()
      sock = self.fd.getsockname()
    except Exception:
      peer = ('x.x.x.x', 'x')
      sock = ('x.x.x.x', 'x')

    return ('<b>Outgoing ZChunks</b>: %s<br>'
            '<b>Buffered bytes</b>: %s<br>'
            '<b>Remote address</b>: %s<br>'
            '<b>Local address</b>: %s<br>'
            '<b>Bytes in / out</b>: %s / %s<br>'
            '<b>Created</b>: %s<br>'
            '<b>Status</b>: %s<br>'
            '<br>'
            '<b>Logged</b>: <ul>%s</ul><br>'
            '\n') % (self.zw and ('level %d' % self.zlevel) or 'off',
                     len(self.write_blocked),
                     self.dead and '-' or (obfuIp(peer[0]), peer[1]),
                     self.dead and '-' or (obfuIp(sock[0]), sock[1]),
                     fmt_size(self.all_in + self.read_bytes),
                     fmt_size(self.all_out + self.wrote_bytes),
                     time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.localtime(self.created)),
                     self.dead and 'dead' or 'alive',
                     ''.join(['<li>%s' % (l, ) for l in self.logged]))

  def ResetZChunks(self):
    if self.zw:
      self.zreset = True
      self.zw = zlib.compressobj(self.zlevel)

  def EnableZChunks(self, level=1):
    self.zlevel = level
    self.zw = zlib.compressobj(level)

  def SetFD(self, fd, six=False):
    if self.fd:
      self.fd.close()
    self.fd = fd
    self.fd.setblocking(0)
    try:
      if six: self.fd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
      self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
      self.fd.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)
      self.fd.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 10)
      self.fd.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 1)
    except Exception:
      pass

  def SetConn(self, conn):
    self.SetFD(conn.fd)
    self.log_id = conn.log_id
    self.read_bytes = conn.read_bytes
    self.wrote_bytes = conn.wrote_bytes

  def Log(self, values):
    if self.log_id: values.append(('id', self.log_id))
    Log(values)
    self.logged.append(('', values))

  def LogError(self, error, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    LogError(error, values)
    self.logged.append((error, values))

  def LogDebug(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    LogDebug(message, values)
    self.logged.append((message, values))

  def LogInfo(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    LogInfo(message, values)
    self.logged.append((message, values))

  def LogTraffic(self, final=False):
    if self.wrote_bytes or self.read_bytes:
      now = time.time()
      self.all_out += self.wrote_bytes
      self.all_in += self.read_bytes

      global gYamon
      gYamon.vadd("bytes_all", self.wrote_bytes
                             + self.read_bytes, wrap=1000000000)

      if final:
        self.Log([('wrote', '%d' % self.wrote_bytes),
                  ('wbps', '%d' % self.write_speed),
                  ('read', '%d' % self.read_bytes),
                  ('eof', '1')])
      else:
        self.Log([('wrote', '%d' % self.wrote_bytes),
                  ('wbps', '%d' % self.write_speed),
                  ('read', '%d' % self.read_bytes)])

      self.bytes_logged = now
      self.wrote_bytes = self.read_bytes = 0
    elif final:
      self.Log([('eof', '1')])

  def Cleanup(self, close=True):
    global buffered_bytes
    buffered_bytes -= len(self.write_blocked)
    self.write_blocked = self.peeked = self.zw = ''

    if not self.dead:
      self.dead = True
      self.CountAs('selectables_dead')

    if close:
      if self.fd:
        self.fd.close()
        self.fd = None
      self.LogTraffic(final=True)

  def ProcessData(self, data):
    self.LogError('Selectable::ProcessData: Should be overridden!')
    return False

  def ProcessEof(self):
    if self.read_eof and self.write_eof and not self.write_blocked:
      self.Cleanup()
      return False
    return True

  def ProcessEofRead(self):
    self.read_eof = True
    self.LogError('Selectable::ProcessEofRead: Should be overridden!')
    return False

  def ProcessEofWrite(self):
    self.write_eof = True
    self.LogError('Selectable::ProcessEofWrite: Should be overridden!')
    return False

  def EatPeeked(self, eat_bytes=None, keep_peeking=False):
    if not self.peeking: return
    if eat_bytes is None: eat_bytes = self.peeked
    discard = ''
    while len(discard) < eat_bytes:
      try:
        discard += self.fd.recv(eat_bytes - len(discard))
      except socket.error, (errno, msg):
        self.LogInfo('Error reading (%d/%d) socket: %s (errno=%s)' % (
                       eat_bytes, self.peeked, msg, errno))
        time.sleep(0.1)

    self.peeked -= eat_bytes
    self.peeking = keep_peeking
    return

  def ReadData(self, maxread=None):
    if self.read_eof:
      return False

    try:
      maxread = maxread or self.maxread
      if self.peeking:
        data = self.fd.recv(maxread, socket.MSG_PEEK)
        self.peeked = len(data)
        if DEBUG_IO: print '<== IN (peeked)\n%s\n===' % data
      else:
        data = self.fd.recv(maxread)
        if DEBUG_IO: print '<== IN\n%s\n===' % data
    except (SSL.WantReadError, SSL.WantWriteError), err:
      return True
    except IOError, err:
      if err.errno not in self.HARMLESS_ERRNOS:
        self.LogDebug('Error reading socket: %s (%s)' % (err, err.errno))
        return False
      else:
        return True
    except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError), err:
      self.LogDebug('Error reading socket (SSL): %s' % err)
      return False
    except socket.error, (errno, msg):
      if errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogInfo('Error reading socket: %s (errno=%s)' % (msg, errno))
        return False

    if data is None or data == '':
      self.read_eof = True
      return self.ProcessData('')
    else:
      if not self.peeking:
        self.read_bytes += len(data)
        if self.read_bytes > LOG_THRESHOLD: self.LogTraffic()
      return self.ProcessData(data)

  def Throttle(self, max_speed=None, remote=False, delay=0.2):
    if max_speed:
      self.throttle_until = time.time()
      flooded = self.read_bytes + self.all_in
      flooded -= max_speed * (time.time() - self.created)
      delay = min(15, max(0.2, flooded/max_speed))
      if flooded < 0: delay = 15
    else:
      if self.throttle_until < time.time(): self.throttle_until = time.time()
      flooded = '?'

    self.throttle_until += delay
    self.LogInfo('Throttled until %x (flooded=%s, bps=%s, remote=%s)' % (
                    int(self.throttle_until), flooded, max_speed, remote))
    return True

  def Send(self, data, try_flush=False):
    global buffered_bytes
    buffered_bytes -= len(self.write_blocked)

    # If we're already blocked, just buffer unless explicitly asked to flush.
    if (not try_flush) and (len(self.write_blocked) > 0 or SEND_ALWAYS_BUFFERS):
      self.write_blocked += ''.join(data)
      buffered_bytes += len(self.write_blocked)
      return True

    self.write_speed = int((self.wrote_bytes + self.all_out) / (0.1 + time.time() - self.created))

    sending = self.write_blocked+(''.join(data))
    self.write_blocked = ''
    sent_bytes = 0
    if sending:
      try:
        sent_bytes = self.fd.send(sending[:(self.write_retry or SEND_MAX_BYTES)])
        if DEBUG_IO: print '==> OUT\n%s\n===' % sending[:sent_bytes]
        self.wrote_bytes += sent_bytes
        self.write_retry = None
      except IOError, err:
        if err.errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s' % err)
          self.ProcessEofWrite()
          return False
        else:
          self.write_retry = len(sending)
      except (SSL.WantWriteError, SSL.WantReadError), err:
        self.write_retry = len(sending)
      except socket.error, (errno, msg):
        if errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s (errno=%s)' % (msg, errno))
          self.ProcessEofWrite()
          return False
        else:
          self.write_retry = len(sending)
      except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError), err:
        self.LogInfo('Error sending (SSL): %s' % err)
        self.ProcessEofWrite()
        return False

    self.write_blocked = sending[sent_bytes:]
    buffered_bytes += len(self.write_blocked)
    if self.wrote_bytes >= LOG_THRESHOLD: self.LogTraffic()

    if self.write_eof and not self.write_blocked: self.ProcessEofWrite()
    return True

  def SendChunked(self, data, compress=True, zhistory=None):
    rst = ''
    if self.zreset:
      self.zreset = False
      rst = 'R'

    # Stop compressing streams that just get bigger.
    if zhistory and (zhistory[0] < zhistory[1]): compress = False

    sdata = ''.join(data)
    if self.zw and compress:
      try:
        zdata = self.zw.compress(sdata) + self.zw.flush(zlib.Z_SYNC_FLUSH)
        if zhistory:
          zhistory[0] = len(sdata)
          zhistory[1] = len(zdata)
        return self.Send(['%xZ%x%s\r\n%s' % (len(sdata), len(zdata), rst, zdata)])
      except zlib.error:
        LogError('Error compressing, resetting ZChunks.')
        self.ResetZChunks()

    return self.Send(['%x%s\r\n%s' % (len(sdata), rst, sdata)])

  def Flush(self, loops=50, wait=False):
    while loops != 0 and len(self.write_blocked) > 0 and self.Send([],
                                                                try_flush=True):
      if wait and len(self.write_blocked) > 0: time.sleep(0.1)
      loops -= 1

    if self.write_blocked: return False
    return True


class Connections(object):
  """A container for connections (Selectables), config and tunnel info.""" 
  
  def __init__(self, config):
    self.config = config
    self.ip_tracker = {}
    self.conns = []
    self.conns_by_id = {}
    self.tunnels = {}
    self.auth = None

  def start(self, auth_thread=None):
    self.auth = auth_thread or AuthThread(self)
    self.auth.start()

  def Add(self, conn, alt_id=None):
    self.conns.append(conn)
    if alt_id: self.conns_by_id[alt_id] = conn

  def TrackIP(self, ip, domain):
    tick = '%d' % (time.time()/12)
    if tick not in self.ip_tracker:
      deadline = int(tick)-10
      for ot in self.ip_tracker.keys():
        if int(ot) < deadline: del self.ip_tracker[ot]
      self.ip_tracker[tick] = {}

    if ip not in self.ip_tracker[tick]:
      self.ip_tracker[tick][ip] = [1, domain]
    else:
      self.ip_tracker[tick][ip][0] += 1
      self.ip_tracker[tick][ip][1] = domain

  def LastIpDomain(self, ip):
    domain = None
    for tick in sorted(self.ip_tracker.keys()):
      if ip in self.ip_tracker[tick]: domain = self.ip_tracker[tick][ip][1]
    return domain

  def Remove(self, conn):
    if conn.alt_id and conn.alt_id in self.conns_by_id:
      del self.conns_by_id[conn.alt_id]
    if conn in self.conns:
      self.conns.remove(conn)
    for tid in self.tunnels.keys():
      if conn in self.tunnels[tid]:
        self.tunnels[tid].remove(conn)
        if not self.tunnels[tid]: del self.tunnels[tid]

  def Readable(self):
    # FIXME: This is O(n)
    now = time.time()
    return [s.fd for s in self.conns if (s.fd 
                                         and (not s.read_eof)
                                         and (s.throttle_until <= now))]

  def Blocked(self):
    # FIXME: This is O(n)
    return [s.fd for s in self.conns if s.fd and len(s.write_blocked) > 0]

  def DeadConns(self):
    return [s for s in self.conns if s.read_eof and s.write_eof and not s.write_blocked]

  def CleanFds(self):
    evil = []
    for s in self.conns:
      try:
        i, o, e = select.select([s.fd], [s.fd], [s.fd], 0)
      except Exception:
        evil.append(s)
    for s in evil:
      LogDebug('Removing broken Selectable: %s' % s)
      self.Remove(s)

  def Connection(self, fd):
    for conn in self.conns:
      if conn.fd == fd:
        return conn
    return None

  def TunnelServers(self):
    servers = {}
    for tid in self.tunnels:
      for tunnel in self.tunnels[tid]:
        server = tunnel.server_info[tunnel.S_NAME]
        if server is not None:
          servers[server] = 1
    return servers.keys() 

  def Tunnel(self, proto, domain, conn=None):
    tid = '%s:%s' % (proto, domain)
    if conn is not None: 
      if tid not in self.tunnels:
        self.tunnels[tid] = []
      self.tunnels[tid].append(conn)

    if tid in self.tunnels:
      return self.tunnels[tid]
    else:
      return []


class LineParser(Selectable):
  """A Selectable which parses the input as lines of text."""

  def __init__(self, fd=None, address=None, on_port=None, tracked=True):
    Selectable.__init__(self, fd, address, on_port, tracked=tracked)
    self.leftovers = ''

  def __html__(self):
    return Selectable.__html__(self)

  def Cleanup(self, close=True):
    Selectable.Cleanup(self, close=close)
    self.leftovers = ''

  def ProcessData(self, data):
    lines = (self.leftovers+data).splitlines(True)
    self.leftovers = ''

    while lines:
      line = lines.pop(0)
      if line.endswith('\n'):
        if self.ProcessLine(line, lines) is False:
          return False
      else:
        if not self.peeking: self.leftovers += line

    if self.read_eof: return self.ProcessEofRead()
    return True

  def ProcessLine(self, line, lines):
    self.LogError('LineParser::ProcessLine: Should be overridden!')
    return False


TLS_CLIENTHELLO = '%c' % 026
SSL_CLIENTHELLO = '\x80'

# FIXME: XMPP support
class MagicProtocolParser(LineParser):
  """A Selectable which recognizes HTTP, TLS or XMPP preambles."""

  def __init__(self, fd=None, address=None, on_port=None):
    LineParser.__init__(self, fd, address, on_port, tracked=False)
    self.leftovers = ''
    self.might_be_tls = True
    self.is_tls = False

  def __html__(self):
    return ('<b>Detected TLS</b>: %s<br>'
            '%s') % (self.is_tls,
                     LineParser.__html__(self))

  # FIXME: DEPRECATE: Make this all go away, switch to CONNECT.
  def ProcessMagic(self, data):
    args = {}
    try:
      prefix, words, data = data.split('\r\n', 2)
      for arg in words.split('; '):
        key, val = arg.split('=', 1)
        args[key] = val

      self.EatPeeked(eat_bytes=len(prefix)+2+len(words)+2)
    except ValueError, e:
      return True 

    try:
      port = 'port' in args and args['port'] or None
      if port: self.on_port = int(port)
    except ValueError, e:
      return False

    proto = 'proto' in args and args['proto'] or None
    if proto in ('http', 'websocket'):
      return LineParser.ProcessData(self, data)

    domain = 'domain' in args and args['domain'] or None
    if proto == 'https': return self.ProcessTls(data, domain)
    if proto == 'raw' and domain: return self.ProcessRaw(data, domain)
    return False

  def ProcessData(self, data):
    if data.startswith(MAGIC_PREFIX): return self.ProcessMagic(data)

    if self.might_be_tls:
      self.might_be_tls = False
      if not data.startswith(TLS_CLIENTHELLO) and not data.startswith(SSL_CLIENTHELLO):
        self.EatPeeked()
        return LineParser.ProcessData(self, data)
      self.is_tls = True

    if self.is_tls:
      return self.ProcessTls(data)
    else:
      self.EatPeeked()
      return LineParser.ProcessData(self, data)

  def GetMsg(self, data):
    mtype, ml24, mlen = struct.unpack('>BBH', data[0:4])    
    mlen += ml24 * 0x10000
    return mtype, data[4:4+mlen], data[4+mlen:]

  def GetClientHelloExtensions(self, msg):
    # Ugh, so many magic numbers! These are accumulated sizes of
    # the different fields we are ignoring in the TLS headers.
    slen = struct.unpack('>B', msg[34])[0]
    cslen = struct.unpack('>H', msg[35+slen:37+slen])[0]
    cmlen = struct.unpack('>B', msg[37+slen+cslen])[0]
    extofs = 34+1+2+1+2+slen+cslen+cmlen
    if extofs < len(msg): return msg[extofs:]
    return None

  def GetSniNames(self, extensions):
    names = []
    while extensions:
      etype, elen = struct.unpack('>HH', extensions[0:4])
      if etype == 0:
        # OK, we found an SNI extension, get the list.
        namelist = extensions[6:4+elen]  
        while namelist:
          ntype, nlen = struct.unpack('>BH', namelist[0:3])
          if ntype == 0: names.append(namelist[3:3+nlen].lower())
          namelist = namelist[3+nlen:]
      extensions = extensions[4+elen:]
    return names 

  def GetSni(self, data):
    hello, vmajor, vminor, mlen = struct.unpack('>BBBH', data[0:5])    
    data = data[5:]
    sni = []
    while data:
      mtype, msg, data = self.GetMsg(data)
      if mtype == 1:
        # ClientHello!
        sni.extend(self.GetSniNames(self.GetClientHelloExtensions(msg)))
    return sni

  def ProcessTls(self, data, domain=None):
    self.LogError('TlsOrLineParser::ProcessTls: Should be overridden!')
    return False

  def ProcessRaw(self, data, domain):
    self.LogError('TlsOrLineParser::ProcessRaw: Should be overridden!')
    return False


class ChunkParser(Selectable):
  """A Selectable which parses the input as chunks."""

  def __init__(self, fd=None, address=None, on_port=None):
    Selectable.__init__(self, fd, address, on_port)
    self.want_cbytes = 0
    self.want_bytes = 0
    self.compressed = False
    self.header = ''
    self.chunk = ''
    self.zr = zlib.decompressobj()

  def __html__(self):
    return Selectable.__html__(self)

  def Cleanup(self, close=True):
    Selectable.Cleanup(self, close=close)
    self.zr = self.chunk = self.header = None

  def ProcessData(self, data):
    if self.peeking:
      self.want_cbytes = 0
      self.want_bytes = 0
      self.header = ''
      self.chunk = ''

    if self.want_bytes == 0:
      self.header += data
      if self.header.find('\r\n') < 0:
        if self.read_eof: return self.ProcessEofRead()
        return True
      try:
        size, data = self.header.split('\r\n', 1)
        self.header = ''

        if size.endswith('R'):
          self.zr = zlib.decompressobj()
          size = size[0:-1]

        if 'Z' in size:
          csize, zsize = size.split('Z')
          self.compressed = True
          self.want_cbytes = int(csize, 16)
          self.want_bytes = int(zsize, 16)
        else:   
          self.compressed = False
          self.want_bytes = int(size, 16)

      except ValueError, err:
        self.LogError('ChunkParser::ProcessData: %s' % err)
        self.Log([('bad_data', data)])
        return False

      if self.want_bytes == 0:
        return False

    process = data[:self.want_bytes]
    leftover = data[self.want_bytes:]

    self.chunk += process
    self.want_bytes -= len(process)

    result = 1
    if self.want_bytes == 0:
      if self.compressed:
        try:
          cchunk = self.zr.decompress(self.chunk)
        except zlib.error:
          cchunk = ''

        if len(cchunk) != self.want_cbytes:
          result = self.ProcessCorruptChunk(self.chunk)
        else:
          result = self.ProcessChunk(cchunk)
      else:
        result = self.ProcessChunk(self.chunk)
      self.chunk = ''
      if result and leftover:
        result = self.ProcessData(leftover)

    if self.read_eof: result = self.ProcessEofRead() and result
    return result

  def ProcessCorruptChunk(self, chunk):
    self.LogError('ChunkParser::ProcessData: ProcessCorruptChunk not overridden!')
    return False

  def ProcessChunk(self, chunk):
    self.LogError('ChunkParser::ProcessData: ProcessChunk not overridden!')
    return False


class Tunnel(ChunkParser):
  """A Selectable representing a PageKite tunnel."""
  
  S_NAME = 0
  S_PORTS = 1
  S_RAW_PORTS = 2
  S_PROTOS = 3

  def __init__(self, conns):
    ChunkParser.__init__(self)

    # We want to be sure to read the entire chunk at once, including
    # headers to save cycles, so we double the size we're willing to 
    # read here.
    self.maxread *= 2

    self.server_info = ['x.x.x.x:x', [], [], []]
    self.conns = conns
    self.users = {}
    self.remote_ssl = {}
    self.zhistory = {}
    self.backends = {}
    self.rtt = 100000
    self.last_activity = time.time()
    self.last_ping = 0

  def __html__(self):
    return ('<b>Server name</b>: %s<br>'
            '%s') % (self.server_info[self.S_NAME], ChunkParser.__html__(self))

  def _FrontEnd(conn, body, conns):
    """This is what the front-end does when a back-end requests a new tunnel."""
    self = Tunnel(conns)
    requests = []
    try:
      for prefix in ('X-Beanstalk', 'X-PageKite'):
        for feature in conn.parser.Header(prefix+'-Features'):
          if feature == 'ZChunks': self.EnableZChunks(level=1)

        # Track which versions we see in the wild.
        version = 'old'
        for v in conn.parser.Header(prefix+'-Version'): version = v
        global gYamon
        gYamon.vadd('version-%s' % version, 1, wrap=10000000)

        for replace in conn.parser.Header(prefix+'-Replace'):
          if replace in self.conns.conns_by_id:
            repl = self.conns.conns_by_id[replace]
            self.LogInfo('Disconnecting old tunnel: %s' % repl)
            self.conns.Remove(repl)
            repl.Cleanup()

        for bs in conn.parser.Header(prefix):
          # X-Beanstalk: proto:my.domain.com:token:signature
          proto, domain, srand, token, sign = bs.split(':') 
          requests.append((proto.lower(), domain.lower(), srand, token, sign,
                           prefix))
      
    except Exception, err:
      self.LogError('Discarding connection: %s' % err)
      self.Cleanup()
      return None

    except socket.error, err:
      self.LogInfo('Discarding connection: %s' % err)
      self.Cleanup()
      return None

    self.CountAs('backends_live')
    self.SetConn(conn)
    conns.auth.check(requests[:], conn, lambda r: self.AuthCallback(conn, r))

    return self

  def RecheckQuota(self, conns, when=None):
    if when is None: when = time.time()
    if (self.quota and
        self.quota[0] is not None and
        self.quota[1] and
        (self.quota[2] < when-900)):
      self.quota[2] = when
      LogDebug('Rechecking: %s' % (self.quota, ))
      conns.auth.check([self.quota[1]], self,
                       lambda r: self.QuotaCallback(conns, r))

  def QuotaCallback(self, conns, results):
    # Report new values to the back-end...
    if self.quota and (self.quota[0] >= 0): self.SendQuota()

    for r in results:
      if r[0] in ('X-PageKite-OK', 'X-PageKite-Duplicate'):
        return self

    self.LogInfo('Ran out of quota or account deleted, closing tunnel.')
    conns.Remove(self)
    self.Cleanup()
    return None

  def AuthCallback(self, conn, results):
    
    output = [HTTP_ResponseHeader(200, 'OK'),
              HTTP_Header('Content-Transfer-Encoding', 'chunked'),
              HTTP_Header('X-PageKite-Features', 'ZChunks'),
              HTTP_Header('X-PageKite-Protos', ', '.join(['%s' % p
                            for p in self.conns.config.server_protos])),
              HTTP_Header('X-PageKite-Ports', ', '.join(
                            ['%s' % self.conns.config.server_portalias.get(p, p)
                             for p in self.conns.config.server_ports]))]

    if self.conns.config.server_raw_ports:
      output.append(
        HTTP_Header('X-PageKite-Raw-Ports',
                    ', '.join(['%s' % p for p
                               in self.conns.config.server_raw_ports])))

    ok = {}
    for r in results:
      if r[0] in ('X-PageKite-OK', 'X-Beanstalk-OK'): ok[r[1]] = 1
      if r[0] == 'X-PageKite-SessionID': self.alt_id = r[1]
      output.append('%s: %s\r\n' % r)

    output.append(HTTP_StartBody())
    if not self.Send(output, try_flush=True):
      conn.LogDebug('No tunnels configured, closing connection (send failed).')
      self.Cleanup()
      return None

    self.backends = ok.keys()
    if self.backends:
      for backend in self.backends:
        proto, domain, srand = backend.split(':')
        self.Log([('BE', 'Live'), ('proto', proto), ('domain', domain)])
        self.conns.Tunnel(proto, domain, self)
      if conn.quota:
        self.quota = conn.quota
        self.Log([('BE', 'Live'), ('quota', self.quota[0])])
      self.conns.Add(self, alt_id=self.alt_id) 
      return self
    else:
      conn.LogDebug('No tunnels configured, closing connection.')
      self.Cleanup()
      return None

  def _RecvHttpHeaders(self):
    data = ''
    while not data.endswith('\r\n\r\n') and not data.endswith('\n\n'):
      try:
        buf = self.fd.recv(4096)
      except:
        # This is sloppy, but the back-end will just connect somewhere else
        # instead, so laziness here should be fine.
        buf = None
      if buf is None or buf == '':
        LogDebug('Remote end closed connection.')
        return None
      data += buf
      self.read_bytes += len(buf)
    if DEBUG_IO: print '<== IN (headers)\n%s\n===' % data
    return data

  def _Connect(self, server, conns, tokens=None):
    if self.fd: self.fd.close()

    if conns.config.socks_server:
      import socks
      sock = socks.socksocket()
      self.SetFD(sock)
    else:
      self.SetFD(rawsocket(socket.AF_INET, socket.SOCK_STREAM))
    try:
      self.fd.settimeout(20.0) # Missing in Python 2.2
    except Exception:
      self.fd.setblocking(1)

    sspec = server.split(':')
    if len(sspec) > 1:
      self.fd.connect((sspec[0], int(sspec[1])))
    else:
      self.fd.connect((server, 443))

    if self.conns.config.fe_certname:
      # We can't set the SNI directly from Python, so we use CONNECT instead
      commonName = self.conns.config.fe_certname[0].split('/')[0]
      if (not self.Send(['CONNECT %s:443 HTTP/1.0\r\n\r\n' % commonName],
                        try_flush=True)
          or not self.Flush(wait=True)):
        return None, None

      data = self._RecvHttpHeaders()
      if data is None or not data.startswith(HTTP_ConnectOK().strip()):
        LogError('CONNECT failed, could not initiate TLS.')
        self.fd.close()
        return None, None

      try:
        self.fd.setblocking(1)
        raw_fd = self.fd
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.load_verify_locations(self.conns.config.ca_certs)
        self.fd = SSL_Connect(ctx, self.fd, connected=True, server_side=False,
                              verify_names=self.conns.config.fe_certname)
        LogDebug('TLS connection to %s OK' % server)
      except SSL.Error, e:
        self.fd = raw_fd
        self.fd.close()
        LogError('SSL handshake failed: probably a bad cert (%s)' % e)
        return None, None

    replace_sessionid = self.conns.config.servers_sessionids.get(server, None)
    if (not self.Send(HTTP_PageKiteRequest(server,
                                         conns.config.backends,
                                       tokens,
                                     nozchunks=conns.config.disable_zchunks,
                                    replace=replace_sessionid), try_flush=True)
        or not self.Flush(wait=True)):
      return None, None

    data = self._RecvHttpHeaders()
    if data is None: return None, None

    self.fd.setblocking(0)
    parse = HttpParser(lines=data.splitlines(), state=HttpParser.IN_RESPONSE)

    return data, parse

  def _BackEnd(server, backends, require_all, conns):
    """This is the back-end end of a tunnel."""
    self = Tunnel(conns)
    self.backends = backends
    self.require_all = require_all
    self.server_info[self.S_NAME] = server
    try:
      begin = time.time()
      data, parse = self._Connect(server, conns)
      if data and parse:

        # Collect info about front-end capabilities, for interactive config
        for portlist in parse.Header('X-PageKite-Ports'):
          self.server_info[self.S_PORTS].extend(portlist.split(', '))
        for portlist in parse.Header('X-PageKite-Raw-Ports'):
          self.server_info[self.S_RAW_PORTS].extend(portlist.split(', '))
        for protolist in parse.Header('X-PageKite-Protos'):
          self.server_info[self.S_PROTOS].extend(protolist.split(', '))

        for sessionid in parse.Header('X-PageKite-SessionID'):
          self.alt_id = sessionid
          conns.config.servers_sessionids[server] = sessionid

        tryagain = False
        tokens = {}
        for request in parse.Header('X-PageKite-SignThis'):
          proto, domain, srand, token = request.split(':')
          tokens['%s:%s' % (proto, domain)] = token
          tryagain = True
 
        if tryagain: 
          begin = time.time()
          data, parse = self._Connect(server, conns, tokens)

        if data and parse:
          if not conns.config.disable_zchunks:
            for feature in parse.Header('X-PageKite-Features'):
              if feature == 'ZChunks': self.EnableZChunks(level=9)

          invalid_reasons = {}
          for request in parse.Header('X-PageKite-Invalid-Why'):
            # This is future-compatible, in that we can add more fields later.
            details = request.split(';')
            invalid_reasons[details[0]] = details[1]

          for request in parse.Header('X-PageKite-Invalid'):
            proto, domain, srand = request.split(':')
            reason = invalid_reasons.get(request, 'unknown')
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('err', 'Rejected'),
                      ('proto', proto),
                      ('reason', reason),
                      ('domain', domain)])

          for request in parse.Header('X-PageKite-Duplicate'):
            proto, domain, srand = request.split(':')
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('err', 'Duplicate'),
                      ('proto', proto),
                      ('domain', domain)])

          for quota in parse.Header('X-PageKite-Quota'):
            self.quota = [int(quota), None, None]
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('quota', quota)])

          ssl_available = {}
          for request in parse.Header('X-PageKite-SSL-OK'):
            ssl_available[request] = True

          for request in parse.Header('X-PageKite-OK'):
            abort = False
            proto, domain, srand = request.split(':')
            conns.Tunnel(proto, domain, self)
            if request in ssl_available:
              self.remote_ssl[(proto, domain)] = True
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('proto', proto),
                      ('ssl', (request in ssl_available)),
                      ('domain', domain)])

        self.rtt = (time.time() - begin)
    

    except socket.error, e:
      self.Cleanup()
      return None

    except Exception, e:
      self.LogError('Server response parsing failed: %s' % e)
      self.Cleanup()
      return None

    conns.Add(self)
    self.CountAs('frontends_live')

    return self

  FrontEnd = staticmethod(_FrontEnd)
  BackEnd = staticmethod(_BackEnd)

  def SendData(self, conn, data, sid=None, host=None, proto=None, port=None,
                                 chunk_headers=None):
    sid = int(sid or conn.sid)
    if conn: self.users[sid] = conn
    if not sid in self.zhistory: self.zhistory[sid] = [0, 0]

    sending = ['SID: %s\r\n' % sid]
    if proto: sending.append('Proto: %s\r\n' % proto)
    if host: sending.append('Host: %s\r\n' % host)
    if port:
      porti = int(port)
      if porti in self.conns.config.server_portalias:
        sending.append('Port: %s\r\n' % self.conns.config.server_portalias[porti])
      else:
        sending.append('Port: %s\r\n' % port)
    if chunk_headers:
      for ch in chunk_headers: sending.append('%s: %s\r\n' % ch)
    sending.append('\r\n')
    sending.append(data)

    return self.SendChunked(sending, zhistory=self.zhistory[sid])

  def SendStreamEof(self, sid, write_eof=False, read_eof=False):
    return self.SendChunked('SID: %s\r\nEOF: 1%s%s\r\n\r\nBye!' % (sid,
                            (write_eof or not read_eof) and 'W' or '',
                            (read_eof or not write_eof) and 'R' or ''))

  def EofStream(self, sid, eof_type='WR'):
    if sid in self.users and self.users[sid] is not None:
      write_eof = (-1 != eof_type.find('W'))
      read_eof = (-1 != eof_type.find('R'))
      self.users[sid].ProcessTunnelEof(read_eof=(read_eof or not write_eof),
                                       write_eof=(write_eof or not read_eof))

  def CloseStream(self, sid, stream_closed=False):
    if sid in self.users:
      stream = self.users[sid]
      del self.users[sid]

      if not stream_closed and stream is not None:
        stream.CloseTunnel(tunnel_closed=True)

    if sid in self.zhistory:
      del self.zhistory[sid]

  def Cleanup(self, close=True):
    if self.users:
      for sid in self.users.keys(): self.CloseStream(sid)
    ChunkParser.Cleanup(self, close=close)
    self.conns = None
    self.users = self.zhistory = self.backends = {}

  def ResetRemoteZChunks(self):
    return self.SendChunked('NOOP: 1\r\nZRST: 1\r\n\r\n!', compress=False)

  def SendPing(self):
    self.last_ping = int(time.time())
    self.LogDebug("Ping", [('host', self.server_info[self.S_NAME])])
    return self.SendChunked('NOOP: 1\r\nPING: 1\r\n\r\n!', compress=False)

  def SendPong(self):
    return self.SendChunked('NOOP: 1\r\n\r\n!', compress=False)

  def SendQuota(self):
    return self.SendChunked('NOOP: 1\r\nQuota: %s\r\n\r\n!' % self.quota[0],
                            compress=False)

  def SendThrottle(self, sid, write_speed):
    return self.SendChunked('NOOP: 1\r\nSID: %s\r\nSPD: %d\r\n\r\n!' % (
                              sid, write_speed), compress=False)

  def ProcessCorruptChunk(self, data):
    self.ResetRemoteZChunks()
    return True

  def Probe(self, host):
    for bid in self.conns.config.backends:
      be = self.conns.config.backends[bid]
      if be[BE_DOMAIN] == host:
        bhost, bport = be[BE_BACKEND].split(':')
        if self.conns.config.Ping(bhost, int(bport)) > 2: return False
    return True

  def Throttle(self, parse):
    try:
      sid = int(parse.Header('SID')[0])
      bps = int(parse.Header('SPD')[0])
      if sid in self.users: self.users[sid].Throttle(bps, remote=True)
    except Exception, e:
      LogError('Tunnel::ProcessChunk: Invalid throttle request!')
    return True

  # If a tunnel goes down, we just go down hard and kill all our connections.
  def ProcessEofRead(self):
    if self.conns: self.conns.Remove(self)
    self.Cleanup()
    return True

  def ProcessEofWrite(self):
    return self.ProcessEofRead()

  def ProcessChunk(self, data):
    try:
      headers, data = data.split('\r\n\r\n', 1)
      parse = HttpParser(lines=headers.splitlines(), 
                         state=HttpParser.IN_HEADERS)
    except ValueError:
      LogError('Tunnel::ProcessChunk: Corrupt packet!')
      return False

    self.last_activity = time.time()
    try:
      if parse.Header('Quota'):
        if self.quota:
          self.quota[0] = int(parse.Header('Quota')[0])
        else:
          self.quota = [int(parse.Header('Quota')[0]), None, None]
      if parse.Header('PING'): return self.SendPong()
      if parse.Header('ZRST') and not self.ResetZChunks(): return False
      if parse.Header('SPD') and not self.Throttle(parse): return False
      if parse.Header('NOOP'): return True
    except Exception, e:
      LogError('Tunnel::ProcessChunk: Corrupt chunk: %s' % e)
      return False

    conn = None
    sid = None
    try:
      sid = int(parse.Header('SID')[0])
      eof = parse.Header('EOF')
    except IndexError, e:
      LogError('Tunnel::ProcessChunk: Corrupt packet!')
      return False

    if eof:
      self.EofStream(sid, eof[0])
    else:
      if sid in self.users:
        conn = self.users[sid]
      else:
        proto = (parse.Header('Proto') or [''])[0].lower()
        port = (parse.Header('Port') or [''])[0].lower()
        host = (parse.Header('Host') or [''])[0].lower()
        rIp = (parse.Header('RIP') or [''])[0].lower()
        rPort = (parse.Header('RPort') or [''])[0].lower()
        if proto and host:
# FIXME: 
#         if proto == 'https':
#           if host in self.conns.config.tls_endpoints:
#             print 'Should unwrap SSL from %s' % host

          if proto == 'probe':
            if self.conns.config.no_probes:
              LogDebug('Responding to probe for %s: rejected' % host)
              if not self.SendChunked('SID: %s\r\n\r\n%s' % (
                                        sid, HTTP_NoFeConnection() )):
                return False
            elif self.Probe(host):
              LogDebug('Responding to probe for %s: good' % host)
              if not self.SendChunked('SID: %s\r\n\r\n%s' % (
                                        sid, HTTP_GoodBeConnection() )):
                return False
            else:
              LogDebug('Responding to probe for %s: back-end down' % host)
              if not self.SendChunked('SID: %s\r\n\r\n%s' % (
                                        sid, HTTP_NoBeConnection() )):
                return False
          else:
            conn = UserConn.BackEnd(proto, host, sid, self, port,
                                    remote_ip=rIp, remote_port=rPort)
            if proto in ('http', 'websocket'):
              if not conn:
                if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                                          HTTP_Unavailable('be', proto, host,
                                                           frame_url=self.conns.config.error_url) )):
                  return False
              elif rIp:
                req, rest = re.sub(r'(?mi)^x-forwarded-for', 'X-Old-Forwarded-For', data
                                   ).split('\n', 1) 
                data = ''.join([req, '\nX-Forwarded-For: %s\r\n' % rIp, rest])
          if conn:
            self.users[sid] = conn

      if not conn:
        self.CloseStream(sid)
        if not self.SendStreamEof(sid): return False
      else:
        if not conn.Send(data):
          # FIXME
          pass
        if len(conn.write_blocked) > 2*max(conn.write_speed, 50000):
          if conn.created < time.time()-3:
            if not self.SendThrottle(sid, conn.write_speed): return False

    return True


class LoopbackTunnel(Tunnel):
  """A Tunnel which just loops back to this process."""

  def __init__(self, conns, which, backends):
    Tunnel.__init__(self, conns)

    self.backends = backends
    self.require_all = True
    self.server_info[self.S_NAME] = LOOPBACK[which]
    self.other_end = None
    if which == 'FE':
      for d in backends.keys():
        if backends[d][BE_BACKEND]:
          proto, domain = d.split(':')
          self.conns.Tunnel(proto, domain, self)
          self.Log([('FE', self.server_info[self.S_NAME]),
                    ('proto', proto),
                    ('domain', domain)])

  def Cleanup(self, close=True):
    Tunnel.Cleanup(self, close=close)
    other = self.other_end
    self.other_end = None
    if other and other.other_end: other.Cleanup()

  def Linkup(self, other):
    self.other_end = other
    other.other_end = self

  def _Loop(conns, backends):
    return LoopbackTunnel(conns, 'FE', backends
                          ).Linkup(LoopbackTunnel(conns, 'BE', backends))

  Loop = staticmethod(_Loop)

  def Send(self, data):
    return self.other_end.ProcessData(''.join(data))


class UserConn(Selectable):
  """A Selectable representing a user's connection."""
  
  def __init__(self, address):
    Selectable.__init__(self, address=address)
    self.tunnel = None
    self.conns = None

  def __html__(self):
    return ('<b>Tunnel</b>: <a href="/conn/%s">%s</a><br>'
            '%s') % (self.tunnel and self.tunnel.sid or '',
                     escape_html('%s' % (self.tunnel or '')),
                     Selectable.__html__(self))
 
  def CloseTunnel(self, tunnel_closed=False):
    tunnel = self.tunnel
    self.tunnel = None
    if tunnel and not tunnel_closed:
      if not self.read_eof or not self.write_eof:
        tunnel.SendStreamEof(self.sid, write_eof=True, read_eof=True)
      tunnel.CloseStream(self.sid, stream_closed=True)
    self.ProcessTunnelEof(read_eof=True, write_eof=True)

  def Cleanup(self, close=True):
    if close:
      self.CloseTunnel()
    Selectable.Cleanup(self, close=close)
    if self.conns:
      self.conns.Remove(self)
      self.conns = None

  def _FrontEnd(conn, address, proto, host, on_port, body, conns):
    # This is when an external user connects to a server and requests a
    # web-page.  We have to give it to them!
    self = UserConn(address)
    self.conns = conns
    self.SetConn(conn)

    if ':' in host: host, port = host.split(':', 1)
    self.proto = proto
    self.host = host

    # If the listening port is an alias for another...
    if int(on_port) in conns.config.server_portalias:
      on_port = conns.config.server_portalias[int(on_port)]

    # Try and find the right tunnel. We prefer proto/port specifications first,
    # then the just the proto. If the protocol is WebSocket and no tunnel is
    # found, look for a plain HTTP tunnel.
    if proto == 'probe':
      protos = ['http', 'https', 'websocket', 'raw']
      ports = conns.config.server_ports[:]
      ports.extend(conns.config.server_aliasport.keys())
      ports.extend([x for x in conns.config.server_raw_ports if x != VIRTUAL_PN])
    else:
      protos = [proto]
      ports = [on_port]
      if proto == 'websocket': protos.append('http')

    tunnels = None
    for p in protos:
      for prt in ports:
        if not tunnels: tunnels = conns.Tunnel('%s-%s' % (p, prt), host)
      if not tunnels: tunnels = conns.Tunnel(p, host)
    if not tunnels: tunnels = conns.Tunnel(protos[0], CATCHALL_HN)

    if self.address:
      chunk_headers = [('RIP', self.address[0]), ('RPort', self.address[1])]

    if tunnels: self.tunnel = tunnels[0]
    if (self.tunnel and self.tunnel.SendData(self, ''.join(body), host=host,
                                             proto=proto, port=on_port,
                                             chunk_headers=chunk_headers)
                    and self.conns):
      self.Log([('domain', self.host), ('on_port', on_port), ('proto', self.proto), ('is', 'FE')])
      self.conns.Add(self)
      self.conns.TrackIP(address[0], host)
      # FIXME: Use the tracked data to detect & mitigate abuse?
      return self
    else:
      self.LogDebug('No back-end', [('on_port', on_port), ('proto', self.proto),
                                    ('domain', self.host), ('is', 'FE')])
      self.Cleanup(close=False)
      return None

  def _BackEnd(proto, host, sid, tunnel, on_port, remote_ip=None, remote_port=None):
    # This is when we open a backend connection, because a user asked for it.
    self = UserConn(None)
    self.sid = sid
    self.proto = proto
    self.host = host 
    self.conns = tunnel.conns
    self.tunnel = tunnel

    # Try and find the right back-end. We prefer proto/port specifications
    # first, then the just the proto. If the protocol is WebSocket and no
    # tunnel is found, look for a plain HTTP tunnel.
    backend = None
    protos = [proto]
    if proto == 'probe': protos = ['http']
    if proto == 'websocket': protos.append('http')
    for p in protos:
      if not backend: backend = self.conns.config.GetBackendServer('%s-%s' % (p, on_port), host)
      if not backend: backend = self.conns.config.GetBackendServer(p, host)
      if not backend: backend = self.conns.config.GetBackendServer(p, CATCHALL_HN)

    logInfo = [
      ('on_port', on_port),
      ('proto', proto),
      ('domain', host),
      ('is', 'BE')
    ]
    if remote_ip: logInfo.append(('remote_ip', remote_ip))

    if not backend:
      logInfo.append(('err', 'No back-end'))
      self.Log(logInfo)
      self.Cleanup(close=False)
      return None

    try:
      self.SetFD(rawsocket(socket.AF_INET, socket.SOCK_STREAM))
      try:
        self.fd.settimeout(2.0) # Missing in Python 2.2
      except Exception:
        self.fd.setblocking(1)

      sspec = backend.split(':')
      if len(sspec) > 1:
        self.fd.connect((sspec[0], int(sspec[1])))
      else:
        self.fd.connect((backend, 80))

      self.fd.setblocking(0)

    except socket.error, err:
      logInfo.append(('socket_error', '%s' % err))
      self.Log(logInfo)
      self.Cleanup(close=False)
      return None

    self.Log(logInfo)
    self.conns.Add(self)
    return self
    
  FrontEnd = staticmethod(_FrontEnd)
  BackEnd = staticmethod(_BackEnd)

  def Shutdown(self, direction):
    try:
      if self.fd:
        if 'sock_shutdown' in dir(self.fd):
          # This is a pyOpenSSL socket, which has incompatible shutdown.
          if direction == socket.SHUT_RD:
            self.fd.shutdown()
          else:
            self.fd.sock_shutdown(direction)
        else:
          self.fd.shutdown(direction)
    except Exception, e:
      pass

  def ProcessTunnelEof(self, read_eof=False, write_eof=False):
    if read_eof and not self.write_eof:
      self.ProcessEofWrite(tell_tunnel=False)
    if write_eof and not self.read_eof:
      self.ProcessEofRead(tell_tunnel=False)
    return True

  def ProcessEofRead(self, tell_tunnel=True):
    self.read_eof = True
    self.Shutdown(socket.SHUT_RD)

    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, read_eof=True)

    return self.ProcessEof()

  def ProcessEofWrite(self, tell_tunnel=True):
    self.write_eof = True
    if not self.write_blocked: self.Shutdown(socket.SHUT_WR)

    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, write_eof=True)

    return self.ProcessEof()

  def Send(self, data, try_flush=False):
    rv = Selectable.Send(self, data, try_flush=try_flush)
    if self.write_eof and not self.write_blocked:
      self.Shutdown(socket.SHUT_WR)
    return rv

  def ProcessData(self, data):
    if not self.tunnel:
      self.LogError('No tunnel! %s' % self)
      return False

    if not self.tunnel.SendData(self, data):
      self.LogDebug('Send to tunnel failed')
      return False

    # Back off if tunnel is stuffed.
    if self.tunnel and len(self.tunnel.write_blocked) > 1024000:
      self.Throttle(delay=(len(self.tunnel.write_blocked)-204800)/max(50000, self.tunnel.write_speed))

    if self.read_eof: return self.ProcessEofRead()
    return True


class UnknownConn(MagicProtocolParser):
  """This class is a connection which we're not sure what is yet."""

  def __init__(self, fd, address, on_port, conns):
    MagicProtocolParser.__init__(self, fd, address, on_port)
    self.peeking = True
    self.parser = HttpParser()
    self.conns = conns
    self.conns.Add(self)
    self.sid = -1

    self.host = None
    self.proto = None

  def Cleanup(self, close=True):
    if self.conns: self.conns.Remove(self)
    MagicProtocolParser.Cleanup(self, close=close)
    self.conns = self.parser = None

  def __str__(self):
    return '%s (%s/%s:%s)' % (MagicProtocolParser.__str__(self),
                              (self.proto or '?'),
                              (self.on_port or '?'),
                              (self.host or '?'))

  def ProcessEofRead(self):
    self.read_eof = True
    return self.ProcessEof()

  def ProcessEofWrite(self):
    self.read_eof = True
    return self.ProcessEof()

  def ProcessLine(self, line, lines):
    if not self.parser: return True
    if self.parser.Parse(line) is False: return False
    if self.parser.state != self.parser.IN_BODY: return True

    done = False

    if self.parser.method == 'PING':
      self.Send('PONG %s\r\n\r\n' % self.parser.path)
      self.read_eof = self.write_eof = done = True
      self.fd.close()

    elif self.parser.method == 'CONNECT':
      if self.parser.path.lower().startswith('pagekite:'):
        if Tunnel.FrontEnd(self, lines, self.conns) is None: return False
        done = True

      else:
        try:
          connect_parser = self.parser
          chost, cport = connect_parser.path.split(':', 1)

          cport = int(cport)
          chost = chost.lower()
          sid1 = ':%s' % chost
          sid2 = '-%s:%s' % (cport, chost)
          tunnels = self.conns.tunnels

          # These allow explicit CONNECTs to direct https or raw backends.
          # If no match is found, we fall through to default HTTP processing.

          if cport == 443:
            if (('https'+sid1) in tunnels) or (
                ('https'+sid2) in tunnels) or (
                chost in self.conns.config.tls_endpoints):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpParser()
              self.Send(HTTP_ConnectOK())
              return self.ProcessTls(''.join(lines), chost)

          if (cport in self.conns.config.server_raw_ports or
              VIRTUAL_PN in self.conns.config.server_raw_ports):
            if (('raw'+sid1) in tunnels) or (('raw'+sid2) in tunnels):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpParser()
              self.Send(HTTP_ConnectOK())
              return self.ProcessRaw(''.join(lines), self.host)

        except ValueError:
          pass

    if (not done and self.parser.method == 'POST'
                 and self.parser.path in MAGIC_PATHS):
      # FIXME: DEPRECATE: Make this go away!
      if Tunnel.FrontEnd(self, lines, self.conns) is None: return False
      done = True

    if not done:
      if not self.host:
        hosts = self.parser.Header('Host')
        if hosts:
          self.host = hosts[0].lower()
        else:
          self.Send(HTTP_Response(400, 'Bad request', 
                    ['<html><body><h1>400 Bad request</h1>',
                     '<p>Invalid request, no Host: found.</p>',
                     '</body></html>']))
          return False

      if self.parser.path.startswith(MAGIC_PREFIX):
        try:
          self.host = self.parser.path.split('/')[2]
          self.proto = 'probe'
        except ValueError:
          pass

      if self.proto is None:
        self.proto = 'http'
        upgrade = self.parser.Header('Upgrade')
        if 'websocket' in self.conns.config.server_protos:
          if upgrade and upgrade[0].lower() == 'websocket':
            self.proto = 'websocket'

      address = self.address
      if int(self.on_port) in self.conns.config.server_portalias:
        xfwdf = self.parser.Header('X-Forwarded-For')
        if xfwdf and address[0] == '127.0.0.1':
          address = (xfwdf[0], address[1])

      done = True
      if UserConn.FrontEnd(self, address,
                           self.proto, self.host, self.on_port,
                           self.parser.lines + lines, self.conns) is None:
        if self.proto == 'probe':
          self.Send(HTTP_NoFeConnection())
        else:
          self.Send(HTTP_Unavailable('fe', self.proto, self.host,
                                     frame_url=self.conns.config.error_url))

        return False

    # We are done!
    self.Cleanup(close=False)
    return True

  def ProcessTls(self, data, domain=None):
    if domain:
      domains = [domain]
    else:
      try:
        domains = self.GetSni(data)
        if not domains:
          domains = [self.conns.LastIpDomain(self.address[0]) or self.conns.config.tls_default]
          LogDebug('No SNI - trying: %s' % domains[0])
          if not domains[0]: domains = None
      except Exception:
        # Probably insufficient data, just return True and assume we'll have
        # better luck on the next round.
        return True

    if domains:
      # If we know how to terminate the TLS/SSL, do so!
      ctx = self.conns.config.GetTlsEndpointCtx(domains[0])
      if ctx:
        self.fd = SSL_Connect(ctx, self.fd, accepted=True, server_side=True)
        self.peeking = False
        self.is_tls = False
        return True

    if domains and domains[0] is not None:
      self.EatPeeked()
      if UserConn.FrontEnd(self, self.address,
                           'https', domains[0], self.on_port,
                           [data], self.conns) is None:
        return False

    # We are done!
    self.Cleanup(close=False)
    return True

  def ProcessRaw(self, data, domain):
    if UserConn.FrontEnd(self, self.address,
                         'raw', domain, self.on_port,
                         [data], self.conns) is None:
      return False

    # We are done!
    self.Cleanup(close=False)
    return True


class RawConn(Selectable):
  """This class is a raw/timed connection."""

  def __init__(self, fd, address, on_port, conns):
    Selectable.__init__(self, fd, address, on_port)
    domain = conns.LastIpDomain(address[0])
    if domain and UserConn.FrontEnd(self, address, 'raw', domain, on_port,
                                    [], conns):
      self.Cleanup(close=False)
    else:
      self.Cleanup()


class Listener(Selectable):
  """This class listens for incoming connections and accepts them."""

  def __init__(self, host, port, conns, backlog=100, connclass=UnknownConn):
    Selectable.__init__(self)
    self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.fd.bind((host, port))
    self.fd.listen(backlog)
    self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.Log([('listen', '%s:%s' % (host, port))])

    self.connclass = connclass
    self.port = port
    self.conns = conns
    self.conns.Add(self)

  def __str__(self):
    return '%s port=%s' % (Selectable.__str__(self), self.port)

  def __html__(self):
    return '<p>Listening on port %s</p>' % self.port
 
  def ReadData(self, maxread=None):
    try:
      client, address = self.fd.accept()
      if client:
        self.Log([('accept', '%s:%s' % (obfuIp(address[0]), address[1]))])
        uc = self.connclass(client, address, self.port, self.conns)
        return True
    except Exception, e:
      LogDebug('Listener::ReadData: %s' % e)
    return False


class TunnelManager(threading.Thread):
  """Create new tunnels as necessary or kill idle ones."""

  def __init__(self, pkite, conns):
    threading.Thread.__init__(self)
    self.pkite = pkite
    self.conns = conns

  def CheckTunnelQuotas(self, now):
    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        tunnel.RecheckQuota(self.conns, when=now)

  def PingTunnels(self, now):
    dead = {}
    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        grace = max(40, len(tunnel.write_blocked)/(tunnel.write_speed or 0.001))
        if tunnel.last_activity < tunnel.last_ping-(5+grace):
          dead['%s' % tunnel] = tunnel
        elif tunnel.last_activity < now-30 and tunnel.last_ping < now-2:
          tunnel.SendPing()

    for tunnel in dead.values():
      Log([('dead', tunnel.server_info[tunnel.S_NAME])])
      self.conns.Remove(tunnel)
      tunnel.Cleanup()

  def quit(self):
    self.keep_running = False

  def run(self):
    self.keep_running = True
    while self.keep_running:
      try:
        self._run()
      except Exception, e:
        LogError('TunnelManager died: %s' % e)
        time.sleep(5)

  def _run(self):
    check_interval = 5
    while self.keep_running:

      # Reconnect if necessary, randomized exponential fallback.
      if self.pkite.CreateTunnels(self.conns) > 0:
        check_interval += int(random.random()*check_interval)
        if check_interval > 300: check_interval = 300
      else:
        check_interval = 5

        # If all connected, make sure tunnels are really alive.
        if self.pkite.isfrontend:
          self.CheckTunnelQuotas(time.time())
          # FIXME: Front-ends should close dead back-end tunnels.
        else:
          self.PingTunnels(time.time())

      for i in xrange(0, check_interval):
        if self.keep_running: time.sleep(1)


class PageKite(object):
  """Configuration and master select loop."""

  def __init__(self):
    self.isfrontend = False
    self.motd = None
    self.upgrade_info = []
    self.auth_domain = None
    self.auth_help_url = None
    self.server_host = ''
    self.server_ports = [80]
    self.server_raw_ports = []
    self.server_portalias = {}
    self.server_aliasport = {}
    self.server_protos = ['http', 'https', 'websocket', 'raw']

    self.tls_default = None
    self.tls_endpoints = {}
    self.fe_certname = []

    self.daemonize = False
    self.pidfile = None
    self.logfile = None
    self.setuid = None
    self.setgid = None
    self.ui_request_handler = UiRequestHandler
    self.ui_http_server = UiHttpServer
    self.ui_sspec = None
    self.ui_httpd = None
    self.ui_password = None
    self.ui_pemfile = None
    self.disable_zchunks = False
    self.enable_sslzlib = False
    self.buffer_max = 1024 
    self.error_url = None

    self.tunnel_manager = None
    self.client_mode = 0

    self.socks_server = None
    self.require_all = False
    self.no_probes = False
    self.servers = []
    self.servers_manual = []
    self.servers_auto = None
    self.servers_new_only = False
    self.servers_no_ping = False
    self.servers_preferred = []
    self.servers_sessionids = {}

    self.dyndns = None
    self.last_updates = []
    self.backends = {}  # These are the backends we want tunnels for.
    self.conns = None
    self.looping = False
    self.main_loop = True

    self.crash_report_url = '%scgi-bin/crashes.pl' % WWWHOME
    self.rcfile_recursion = 0
    self.rcfiles_loaded = []
    self.savefile = None
    self.reloadfile = None

    # Searching for our configuration file!  We prefer the documented
    # 'standard' locations, but if nothing is found there and something local
    # exists, use that instead.
    try:
      if os.getenv('USERPROFILE'):
        # Windows
        self.rcfile = os.path.join(os.getenv('USERPROFILE'), 'pagekite.cfg')
        self.devnull = 'nul'
      else:
        # Everything else
        self.rcfile = os.path.join(os.getenv('HOME'), '.pagekite.rc')
        self.devnull = '/dev/null'

    except Exception, e:
      # The above stuff may fail in some cases, e.g. on Android in SL4A.
      self.rcfile = 'pagekite.cfg'
      self.devnull = '/dev/null'

    if not os.path.exists(self.rcfile):
      for rcf in ('pagekite.rc', 'pagekite.cfg'):
        prog_rcf = os.path.join(os.path.dirname(sys.argv[0]), rcf)
        if os.path.exists(prog_rcf): self.rcfile = prog_rcf 
        elif os.path.exists(rcf): self.rcfile = rcf

    # Look for CA Certificates. If we don't find them in the host OS,
    # we assume there might be something good in the config file.
    self.ca_certs_default = '/etc/ssl/certs/ca-certificates.crt'
    if not os.path.exists(self.ca_certs_default):
      self.ca_certs_default = self.rcfile
    self.ca_certs = self.ca_certs_default


  def PrintSettings(self):
    print '### Current settings for PageKite v%s. ###' % APPVER    
    print
    print '# HTTP control-panel settings:'
    print (self.ui_sspec and 'httpd=%s:%d' % self.ui_sspec or '#httpd=host:port')
    print (self.ui_password and 'httppass=%s' % self.ui_password or '#httppass=YOURSECRET')
    print (self.ui_pemfile and 'pemfile=%s' % self.ui_pemfile or '#pemfile=/path/to/sslcert.pem')
    print
    print '# Back-end Options:'
    print (self.servers_auto and 'frontends=%d:%s:%d' % self.servers_auto or '#frontends=1:frontends.b5p.us:443')
    for server in self.servers_manual:
      print 'frontend=%s' % server
    for server in self.fe_certname:
      print 'fe_certname=%s' % server
    if self.dyndns:
      provider, args = self.dyndns
      for prov in DYNDNS:
        if DYNDNS[prov] == provider and prov != 'beanstalks.net':
          args['prov'] = prov
      if 'prov' not in args:
        args['prov'] = provider
      if args['pass']:
        print 'dyndns=%(user)s:%(pass)s@%(prov)s' % args
      elif args['user']:
        print 'dyndns=%(user)s@%(prov)s' % args
      else:
        print 'dyndns=%(prov)s' % args
    else:
      print '#dyndns=pagekite.net OR' 
      print '#dyndns=user:pass@dyndns.org OR' 
      print '#dyndns=user:pass@no-ip.com' 
    bprinted = 0
    for bid in self.backends:
      be = self.backends[bid]
      if be[BE_BACKEND]:
        print 'backend=%s:%s:%s' % (bid, be[BE_BACKEND], be[BE_SECRET])
        bprinted += 1
    if bprinted == 0:
      print '#backend=http:YOU.pagekite.me:localhost:80:SECRET'
      print '#backend=https:YOU.pagekite.me:localhost:443:SECRET'
      print '#backend=websocket:YOU.pagekite.me:localhost:8080:SECRET'
    print (self.error_url and ('errorurl=%s' % self.error_url) or '#errorurl=http://host/page/')
    print (self.servers_new_only and 'new' or '#new')
    print (self.require_all and 'all' or '#all')
    print (self.no_probes and 'noprobes' or '#noprobes')
    print
    eprinted = 0
    print '# Domains we terminate SSL/TLS for natively, with key/cert-files'
    for ep in self.tls_endpoints:
      print 'tls_endpoint=%s:%s' % (ep, self.tls_endpoints[ep][0])
      eprinted += 1
    if eprinted == 0:
      print '#tls_endpoint=DOMAIN:PEM_FILE'
    print (self.tls_default and 'tls_default=%s' % self.tls_default or '#tls_default=DOMAIN')
    print
    print
    print '### The following stuff can usually be ignored. ###'
    print
    print '# Includes (should usually be at the top of the file)'
    print '#optfile=/path/to/common/settings'
    print
    print '# Front-end Options:'
    print (self.isfrontend and 'isfrontend' or '#isfrontend')
    comment = (self.isfrontend and '' or '#')
    print (self.server_host and '%shost=%s' % (comment, self.server_host) or '#host=machine.domain.com')
    print '%sports=%s' % (comment, ','.join(['%s' % x for x in self.server_ports] or []))
    print '%sprotos=%s' % (comment, ','.join(['%s' % x for x in self.server_protos] or []))
    for pa in self.server_portalias:
      print 'portalias=%s:%s' % (int(pa), int(self.server_portalias[pa]))
    print '%srawports=%s' % (comment, ','.join(['%s' % x for x in self.server_raw_ports] or []))
    print (self.auth_domain and '%sauthdomain=%s' % (comment, self.auth_domain) or '#authdomain=foo.com')
    for bid in self.backends:
      be = self.backends[bid]
      if not be[BE_BACKEND]:
        print 'domain=%s:%s' % (bid, be[BE_SECRET])
    print '#domain=http:*.pagekite.me:SECRET1'
    print '#domain=http,https,websocket:THEM.pagekite.me:SECRET2'

    print
    print '# Systems administration settings:'
    print (self.logfile and 'logfile=%s' % self.logfile or '#logfile=/path/file')
    print (self.daemonize and 'daemonize' % self.logfile or '#daemonize')
    if self.setuid and self.setgid:
      print 'runas=%s:%s' % (self.setuid, self.setgid)
    elif self.setuid:
      print 'runas=%s' % self.setuid
    else:
      print '#runas=uid:gid'
    print (self.pidfile and 'pidfile=%s' % self.pidfile or '#pidfile=/path/file')
    if self.ca_certs != self.ca_certs_default:
      print 'ca_certs=%s' % self.ca_certs
    else:
      print '#ca_certs=%s' % self.ca_certs
    print

  def FallDown(self, message, help=True, noexit=False):
    if self.conns and self.conns.auth: self.conns.auth.quit()
    if self.ui_httpd: self.ui_httpd.quit()
    if self.tunnel_manager: self.tunnel_manager.quit()
    self.conns = self.ui_httpd = self.tunnel_manager = None
    if help:
      print DOC
      print '*****'
    if message: print 'Error: %s' % message
    if not noexit: sys.exit(1)

  def GetTlsEndpointCtx(self, domain):
    if domain in self.tls_endpoints: return self.tls_endpoints[domain][1]
    parts = domain.split('.')
    # Check for wildcards ...
    while len(parts) > 2:
      parts[0] = '*'
      domain = '.'.join(parts)
      if domain in self.tls_endpoints: return self.tls_endpoints[domain][1]
      parts.pop(0)
    return None

  def GetBackendData(self, proto, domain, field, recurse=True):
    backend = '%s:%s' % (proto.lower(), domain.lower())
    if backend in self.backends:
      if BE_STATUS_DISABLED != self.backends[backend][BE_STATUS]:
        return self.backends[backend][field]  

    if recurse:
      dparts = domain.split('.')
      while len(dparts) > 1:
        dparts = dparts[1:]
        data = self.GetBackendData(proto, '.'.join(['*'] + dparts), field, recurse=False)
        if data: return data

    return None

  def GetBackendServer(self, proto, domain, recurse=True):
    server = self.GetBackendData(proto, domain, BE_BACKEND) 
    if server == '-': return None
    return server

  def IsSignatureValid(self, sign, secret, proto, domain, srand, token):
    return checkSignature(sign=sign, secret=secret,
                          payload='%s:%s:%s:%s' % (proto, domain, srand, token))

  def LookupDomainQuota(self, lookup):
    if not lookup.endswith('.'): lookup += '.'
    if DEBUG_IO: print '=== AUTH LOOKUP\n%s\n===' % lookup
    (hn, al, ips) = socket.gethostbyname_ex(lookup)

    # Extract auth error hints from domain name, if we got a CNAME reply.
    if al:
      error = hn.split('.')[0]
    else:
      error = None

    # If not an authentication error, quota should be encoded as an IP.
    ip = ips[0]
    if not ip.startswith(AUTH_ERRORS):
      o = [int(x) for x in ip.split('.')]
      return ((((o[0]*256 + o[1])*256 + o[2])*256 + o[3]), None)

    # Errors on real errors are final.
    if not ip.endswith(AUTH_ERR_USER_UNKNOWN): return (None, error)

    # User unknown, fall through to local test.
    return (-1, error)

  def GetDomainQuota(self, protoport, domain, srand, token, sign,
                     recurse=True, check_token=True):
    if '-' in protoport:
      try:
        proto, port = protoport.split('-', 1)
        if proto == 'raw':
          port_list = self.server_raw_ports
        else:
          port_list = self.server_ports

        porti = int(port)
        if porti in self.server_aliasport: porti = self.server_aliasport[porti]
        if porti not in port_list and VIRTUAL_PN not in port_list:
          LogInfo('Unsupported port request: %s (%s:%s)' % (porti, protoport, domain))
          return (None, 'port')

      except ValueError:
        LogError('Invalid port request: %s:%s' % (protoport, domain))
        return (None, 'port')
    else:
      proto, port = protoport, None

    if proto not in self.server_protos:
      LogInfo('Invalid proto request: %s:%s' % (protoport, domain))
      return (None, 'proto')

    data = '%s:%s:%s' % (protoport, domain, srand)
    auth_error_type = None
    if (not token) or (not check_token) or checkSignature(sign=token, payload=data):
      if self.auth_domain:
        try:
          lookup = '.'.join([srand, token, sign, protoport, domain, self.auth_domain])
          (rv, auth_error_type) = self.LookupDomainQuota(lookup)
          if rv is None or rv >= 0: return (rv, auth_error_type)
        except Exception, e:
          # Lookup failed, fail open.
          LogError('Quota lookup failed: %s' % e)
          return (-2, None)

      secret = self.GetBackendData(protoport, domain, BE_SECRET)
      if not secret: secret = self.GetBackendData(proto, domain, BE_SECRET)
      if secret:
        if self.IsSignatureValid(sign, secret, protoport, domain, srand, token):
          return (-1, None)
        else:
          LogError('Invalid signature for: %s (%s)' % (domain, protoport))
          return (None, auth_error_type or 'signature')

    LogInfo('No authentication found for: %s (%s)' % (domain, protoport))
    return (None, auth_error_type or 'auth')

  def ConfigureFromFile(self, filename=None):
    if not filename: filename = self.rcfile

    if self.rcfile_recursion > 25: 
      raise ConfigError('Nested too deep: %s' % filename)

    self.rcfiles_loaded.append(filename)
    optfile = open(filename) 
    args = []
    for line in optfile:
      line = line.strip()
      if line and not line.startswith('#'):
        if line.startswith('END'): break
        if not line.startswith('-'): line = '--%s' % line
        args.append(line)

    self.rcfile_recursion += 1
    self.Configure(args)
    self.rcfile_recursion -= 1
    return self

  def HelpAndExit(self):
    print DOC
    sys.exit(0)

  def Configure(self, argv):
    opts, args = getopt.getopt(argv, OPT_FLAGS, OPT_ARGS) 

    # Complain about crap on the command-line.
    if args: raise ConfigError("Unknown arguments: %s" % args)

    for opt, arg in opts:
      if opt in ('-o', '--optfile'): self.ConfigureFromFile(arg) 
      elif opt == '--reloadfile':
        self.ConfigureFromFile(arg)
        self.reloadfile = arg
      elif opt in ('-S', '--savefile'):
        if self.savefile: raise ConfigError('Multiple save-files!')
        self.ConfigureFromFile(arg)
        self.savefile = arg

      elif opt in ('-I', '--pidfile'): self.pidfile = arg
      elif opt in ('-L', '--logfile'): self.logfile = arg
      elif opt in ('-Z', '--daemonize'): self.daemonize = True
      elif opt in ('-U', '--runas'):
        import pwd
        import grp
        parts = arg.split(':')
        if len(parts) > 1:
          self.setuid, self.setgid = (pwd.getpwnam(parts[0])[2],
                                      grp.getgrnam(parts[1])[2])
        else:
          self.setuid = pwd.getpwnam(parts[0])[2]
        self.main_loop = False

      elif opt in ('-X', '--httppass'): self.ui_password = arg
      elif opt in ('-P', '--pemfile'): self.ui_pemfile = arg
      elif opt in ('-H', '--httpd'):
        parts = arg.split(':')
        host = parts[0] or 'localhost'
        if len(parts) > 1: 
          self.ui_sspec = (host, int(parts[1]))
        else:
          self.ui_sspec = (host, 80)

      elif opt == '--tls_default': self.tls_default = arg
      elif opt == '--tls_endpoint':
        name, pemfile = arg.split(':', 1)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.use_privatekey_file(pemfile)
        ctx.use_certificate_chain_file(pemfile)
        self.tls_endpoints[name] = (pemfile, ctx)

      elif opt in ('-D', '--dyndns'):
        if arg.startswith('http'):
          self.dyndns = (arg, {'user': '', 'pass': ''})
        elif '@' in arg:
          splits = arg.split('@')
          provider = splits.pop()
          usrpwd = '@'.join(splits)
          if provider in DYNDNS: provider = DYNDNS[provider]
          if ':' in usrpwd:
            usr, pwd = usrpwd.split(':', 1)
            self.dyndns = (provider, {'user': usr, 'pass': pwd})
          else:
            self.dyndns = (provider, {'user': usrpwd, 'pass': ''})
        else:
          if arg in DYNDNS: arg = DYNDNS[arg]
          self.dyndns = (arg, {'user': '', 'pass': ''})

      elif opt in ('-p', '--ports'): self.server_ports = [int(x) for x in arg.split(',')]
      elif opt == '--portalias':
        port, alias = arg.split(':')
        self.server_portalias[int(port)] = int(alias)
        self.server_aliasport[int(alias)] = int(port)
      elif opt == '--protos': self.server_protos = [x.lower() for x in arg.split(',')]
      elif opt == '--rawports':
        self.server_raw_ports = [(x == VIRTUAL_PN and x or int(x)) for x in arg.split(',')]
      elif opt in ('-h', '--host'): self.server_host = arg
      elif opt in ('-A', '--authdomain'): self.auth_domain = arg
      elif opt == '--authhelpurl': self.auth_help_url = arg
      elif opt == '--motd': self.motd = arg
      elif opt == '--noupgradeinfo': self.upgrade_info = []
      elif opt == '--upgradeinfo':
        version, tag, md5, human_url, file_url = arg.split(';')
        self.upgrade_info.append((version, tag, md5, human_url, file_url))
      elif opt in ('-f', '--isfrontend'):
        self.isfrontend = True
        global LOG_THRESHOLD
        LOG_THRESHOLD *= 4

      elif opt in ('-a', '--all'): self.require_all = True
      elif opt in ('-N', '--new'): self.servers_new_only = True
      elif opt in ('--socksify', '--torify'): 
        try:
          import socks
          (host, port) = arg.split(':')
          socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, int(port))
          self.socks_server = (host, port)
          # This increases the odds of unrelated requests getting lumped
          # together in the tunnel, which makes traffic analysis harder.
          global SEND_ALWAYS_BUFFERS
          SEND_ALWAYS_BUFFERS = True
        except Exception, e:
          raise ConfigError("Please instally SocksiPy: "
                            " http://code.google.com/p/socksipy-branch/")

        if opt == '--torify':
          self.servers_new_only = True  # Disable initial DNS lookups (leaks)
          self.servers_no_ping = True   # Disable front-end pings
          self.crash_report_url = None  # Disable crash reports
          socks.wrapmodule(urllib)      # Make DynDNS updates go via tor

      elif opt == '--ca_certs': self.ca_certs = arg
      elif opt == '--fe_certname': self.fe_certname.append(arg.lower())
      elif opt == '--frontend': self.servers_manual.append(arg)
      elif opt == '--frontends':
        count, domain, port = arg.split(':')
        self.servers_auto = (int(count), domain, int(port))

      elif opt in ('--errorurl', '-E'): self.error_url = arg
      elif opt == '--backend':
        protos, domain, bhost, bport, secret = arg.split(':')
        for proto in protos.split(','): 
          proto = proto.replace('/', '-')
          if '-' in proto:
            proto, port = proto.split('-')
            bid = '%s-%d:%s' % (proto.lower(), int(port), domain.lower())
          else:
            port = ''
            bid = '%s:%s' % (proto.lower(), domain.lower())

          backend = '%s:%s' % (bhost.lower(), bport)
          if bid in self.backends:
            raise ConfigError("Same backend/domain defined twice: %s" % bid)
          self.backends[bid] = (proto.lower(), port, domain.lower(),
                                backend, secret, BE_STATUS_UNKNOWN)

      elif opt == '--domain':
        protos, domain, secret = arg.split(':')
        if protos in ('*', ''): protos = ','.join(self.server_protos)
        for proto in protos.split(','): 
          bid = '%s:%s' % (proto, domain)
          if bid in self.backends:
            raise ConfigError("Same backend/domain defined twice: %s" % bid)
          self.backends[bid] = (proto, None, domain, None, secret,
                                BE_STATUS_UNKNOWN)

      elif opt == '--noprobes': self.no_probes = True
      elif opt == '--nofrontend': self.isfrontend = False
      elif opt == '--nodaemonize': self.daemonize = False
      elif opt == '--noall': self.require_all = False
      elif opt == '--nozchunks': self.disable_zchunks = True
      elif opt == '--sslzlib': self.enable_sslzlib = True
      elif opt == '--debugio':
        global DEBUG_IO
        DEBUG_IO = True
      elif opt == '--buffers': self.buffer_max = int(arg)
      elif opt == '--nocrashreport': self.crash_report_url = None
      elif opt == '--clean': pass
      elif opt == '--nopyopenssl': pass
      elif opt == '--noloop': self.main_loop = False

      elif opt == '--defaults':
        self.dyndns = (DYNDNS['pagekite.net'], {'user': '', 'pass': ''})
        self.servers_auto = (1, 'frontends.b5p.us', 443)
        #self.fe_certname = ['frontends.b5p.us', 'b5p.us']

      elif opt == '--settings':
        self.PrintSettings()
        sys.exit(0)

      else:
        self.HelpAndExit()

    return self

  def CheckConfig(self):
    if not self.servers_manual and not self.servers_auto and not self.isfrontend:
      if not self.servers:
        raise ConfigError('Nothing to do!  List some servers, or run me as one.')      
    return self
          
  def CheckAllTunnels(self, conns):
    missing = []
    for backend in self.backends:
      proto, domain = backend.split(':')
      if not conns.Tunnel(proto, domain):
        missing.append(domain)
    if missing:
      self.FallDown('No tunnel for %s' % missing, help=False) 

  def Ping(self, host, port):
    if self.servers_no_ping: return 0

    start = time.time() 
    try:
      fd = rawsocket(socket.AF_INET, socket.SOCK_STREAM)
      try:
        fd.settimeout(2.0) # Missing in Python 2.2
      except Exception:
        fd.setblocking(1)

      fd.connect((host, port))
      fd.send('PING / HTTP/1.0\r\n\r\n')
      fd.recv(1024)
      fd.close()

    except Exception, e:
      LogDebug('Ping %s:%s failed: %s' % (host, port, e))
      return 100000 

    elapsed = (time.time() - start)
    LogDebug('Pinged %s:%s: %f' % (host, port, elapsed))
    return elapsed

  def GetHostIpAddr(self, host):
    return socket.gethostbyname(host)

  def GetHostDetails(self, host):
    return socket.gethostbyname_ex(host)
 
  def ChooseFrontEnds(self):
    self.servers = []
    self.servers_preferred = []

    # Enable internal loopback
    if self.isfrontend:
      need_loopback = False
      for be in self.backends.values():
        if be[BE_BACKEND]:
          need_loopback = True
      if need_loopback:
        self.servers.append(LOOPBACK_FE)

    # Convert the hostnames into IP addresses...
    for server in self.servers_manual:
      (host, port) = server.split(':')
      try:
        ipaddr = self.GetHostIpAddr(host)
        server = '%s:%s' % (ipaddr, port)
        if server not in self.servers:
          self.servers.append(server)
          self.servers_preferred.append(ipaddr)
      except Exception, e:
        LogDebug('DNS lookup failed for %s' % host)

    # Lookup and choose from the auto-list (and our old domain).
    if self.servers_auto:
      (count, domain, port) = self.servers_auto

      # First, check for old addresses and always connect to those.
      if not self.servers_new_only:
        for bid in self.backends: 
          (proto, bdom) = bid.split(':')
          try:
            (hn, al, ips) = self.GetHostDetails(bdom)
            for ip in ips:
              server = '%s:%s' % (ip, port)
              if server not in self.servers: self.servers.append(server)
          except Exception, e:
            LogDebug('DNS lookup failed for %s' % bdom)

      try:
        (hn, al, ips) = socket.gethostbyname_ex(domain)
        times = [self.Ping(ip, port) for ip in ips]
      except Exception, e:
        LogDebug('Unreachable: %s, %s' % (domain, e))
        ips = times = []

      while count > 0 and ips:
        count -= 1
        mIdx = times.index(min(times)) 
        server = '%s:%s' % (ips[mIdx], port)
        if server not in self.servers:
          self.servers.append(server)
        if ips[mIdx] not in self.servers_preferred:
          self.servers_preferred.append(ips[mIdx])
        del times[mIdx]
        del ips[mIdx]

  def CreateTunnels(self, conns):
    live_servers = conns.TunnelServers()
    failures = 0
    connections = 0

    if self.backends:
      if not self.servers or len(self.servers) > len(live_servers):
        self.ChooseFrontEnds()

    for server in self.servers:
      if server not in live_servers:
        if server == LOOPBACK_FE:
          LoopbackTunnel.Loop(conns, self.backends)
        else:
          if Tunnel.BackEnd(server, self.backends, self.require_all, conns):
            Log([('connect', server)])
            connections += 1
          else:
            failures += 1
            LogInfo('Failed to connect', [('FE', server)])

    if self.dyndns:
      updates = {}
      ddns_fmt, ddns_args = self.dyndns

      for bid in self.backends.keys():
        proto, domain = bid.split(':')
        if bid in conns.tunnels:
          ips = []
          bips = []
          for tunnel in conns.tunnels[bid]:
            ip = tunnel.server_info[tunnel.S_NAME].split(':')[0]
            if not ip == LOOPBACK_HN:
              if not self.servers_preferred or ip in self.servers_preferred:
                ips.append(ip)
              else:
                bips.append(ip)
   
          if not ips: ips = bips

          if ips:
            iplist = ','.join(ips)
            payload = '%s:%s' % (domain, iplist)
            args = {}
            args.update(ddns_args)
            args.update({
              'domain': domain, 
              'ip': ips[0],
              'ips': iplist,
              'sign': signToken(secret=self.backends[bid][BE_SECRET],
                                payload=payload, length=100)
            })
            # FIXME: This may fail if different front-ends support different
            #        protocols. In practice, this should be rare.
            update = ddns_fmt % args
            if domain not in updates or len(update) < len(updates[domain]):
              updates[payload] = update

      last_updates = self.last_updates
      self.last_updates = []
      for update in updates:
        if update not in last_updates:
          try:
            result = ''.join(urllib.urlopen(updates[update]).readlines())
            self.last_updates.append(update)
            if result.startswith('good') or result.startswith('nochg'):
              Log([('dyndns', result), ('data', update)])
            else:
              LogInfo('DynDNS update failed: %s' % result, [('data', update)])
              failures += 1
          except Exception, e:
            LogInfo('DynDNS update failed: %s' % e, [('data', update)])
            failures += 1
      if not self.last_updates:
        self.last_updates = last_updates

    return failures

  def LogTo(self, filename, close_all=True, dont_close=[]):
    global Log

    if filename == 'memory':
      Log = LogToMemory
      filename = self.devnull

    elif filename == 'syslog':
      Log = LogSyslog
      filename = self.devnull
      syslog.openlog((sys.argv[0] or 'pagekite.py').split('/')[-1],
                     syslog.LOG_PID, syslog.LOG_DAEMON)

    if filename != 'stdio':
      global LogFile
      try:
        LogFile = fd = open(filename, "a", 0)
        os.dup2(fd.fileno(), sys.stdin.fileno())
        os.dup2(fd.fileno(), sys.stdout.fileno())
        os.dup2(fd.fileno(), sys.stderr.fileno())
      except Exception, e:
        raise ConfigError('%s' % e)

  def Daemonize(self):
    # Fork once...
    if os.fork() != 0: os._exit(0)

    # Fork twice...
    os.setsid()
    if os.fork() != 0: os._exit(0)

  def SelectLoop(self):
    global buffered_bytes

    conns = self.conns
    last_loop = time.time()

    self.looping = True
    iready, oready, eready = None, None, None
    while self.looping:
      isocks, osocks = conns.Readable(), conns.Blocked()
      try:
        if isocks or osocks:
          iready, oready, eready = select.select(isocks, osocks, [], 1.1)
        else:
          # Windoes does not seem to like empty selects, so we do this instead.
          time.sleep(0.5)
      except KeyboardInterrupt, e:
        raise KeyboardInterrupt()
      except Exception, e:
        LogError('Error in select: %s (%s/%s)' % (e, isocks, osocks))
        conns.CleanFds()
        last_loop -= 1

      now = time.time()
      if not iready and not oready:
        if (isocks or osocks) and (now < last_loop + 1):
          LogError('Spinning, pausing ...')
          time.sleep(0.1)

      if oready:
        for socket in oready:
          conn = conns.Connection(socket)
          if conn and not conn.Send([], try_flush=True):
#           LogDebug("Write error in main loop, closing %s" % conn)
            conns.Remove(conn)
            conn.Cleanup()

      if buffered_bytes < 1024 * self.buffer_max:
        throttle = None
      else:
        LogDebug("FIXME: Nasty pause to let buffers clear!")
        time.sleep(0.1)
        throttle = 1024

      if iready:
        for socket in iready:
          conn = conns.Connection(socket)
          if conn and not conn.ReadData(maxread=throttle):
#           LogDebug("Read error in main loop, closing %s" % conn)
            conns.Remove(conn)
            conn.Cleanup()

      for conn in conns.DeadConns():
        conns.Remove(conn)
        conn.Cleanup()

      last_loop = now

  def Loop(self):
    self.conns.start()
    if self.ui_httpd: self.ui_httpd.start()
    if self.tunnel_manager: self.tunnel_manager.start()

    try:
      epoll = select.epoll()
    except Exception, msg:
      epoll = None 

    if epoll: LogDebug("FIXME: Should try epoll!")
    self.SelectLoop()

  def Start(self):
    conns = self.conns = Connections(self)
    global Log

    # Log that we've started up
    config_report = [('started', sys.argv[0]), ('version', APPVER),
                     ('argv', ' '.join(sys.argv[1:])),
                     ('ca_certs', self.ca_certs)]
    for optf in self.rcfiles_loaded: config_report.append(('optfile', optf))
    Log(config_report)

    try:
      # Set up our listeners if we are a server.
      if self.isfrontend:
        for port in self.server_ports:
          Listener(self.server_host, port, conns)
        for port in self.server_raw_ports:
          if port != VIRTUAL_PN and port > 0:
            Listener(self.server_host, port, conns, connclass=RawConn)

      # Start the UI thread
      if self.ui_sspec:
        self.ui_httpd = HttpUiThread(self, conns,
                                     handler=self.ui_request_handler,
                                     server=self.ui_http_server,
                                     ssl_pem_filename = self.ui_pemfile)

      # Create the Tunnel Manager
      self.tunnel_manager = TunnelManager(self, conns)

    except Exception, e:
      Log = LogToFile
      FlushLogMemory()
      raise ConfigError(e)

    # Create log-file
    Log = LogToFile
    if self.logfile:
      keep_open = [s.fd.fileno() for s in conns.conns]
      if self.ui_httpd: keep_open.append(self.ui_httpd.httpd.socket.fileno())
      self.LogTo(self.logfile, dont_close=keep_open)

    # Flush in-memory log, if necessary
    FlushLogMemory()

    # Set up SIGHUP handler.
    if self.logfile or self.reloadfile:
      try:
        import signal
        def reopen(x,y):
          if self.logfile:
            self.LogTo(self.logfile, close_all=False)
            LogDebug('SIGHUP received, reopening: %s' % self.logfile)
          if self.reloadfile:
            self.ConfigureFromFile(self.reloadfile)
        signal.signal(signal.SIGHUP, reopen)
      except Exception:
        LogError('Warning: signal handler unavailable, logrotate will not work.')

    # Disable compression in OpenSSL
    if not self.enable_sslzlib:
      DisableSSLCompression()

    # Daemonize!
    if self.daemonize:
      self.Daemonize()

    # Create global secret
    globalSecret()

    # Create PID file
    if self.pidfile:
      pf = open(self.pidfile, 'w')
      pf.write('%s\n' % os.getpid())
      pf.close()

    # Do this after creating the PID and log-files.
    if self.daemonize: os.chdir('/')

    # Drop privileges, if we have any.
    if self.setgid: os.setgid(self.setgid)
    if self.setuid: os.setuid(self.setuid)
    if self.setuid or self.setgid:
      Log([('uid', os.getuid()), ('gid', os.getgid())])

    # Make sure we have what we need
    if self.require_all:
      self.CreateTunnels(conns)
      self.CheckAllTunnels(conns)

    # Finally, run our select/epoll loop.
    self.Loop()

    Log([('stopping', 'pagekite.py')])
    if self.ui_httpd: self.ui_httpd.quit()
    if self.tunnel_manager: self.tunnel_manager.quit()
    if self.conns:
      if self.conns.auth: self.conns.auth.quit()
      for conn in self.conns.conns: conn.Cleanup()


##[ Main ]#####################################################################

def Main(pagekite, configure):
  crashes = 1

  while True:
    pk = pagekite()
    try:
      try:
        try:
          configure(pk)
        except Exception, e:
          raise ConfigError(e)

        pk.Start()

      except (ConfigError, getopt.GetoptError), msg:
        pk.FallDown(msg)

      except KeyboardInterrupt, msg:
        pk.FallDown(None, help=False, noexit=True)
        return

    except SystemExit:
      sys.exit(0)

    except Exception, msg:
      traceback.print_exc(file=sys.stderr)

      if pk.crash_report_url:
        try:
          print 'Submitting crash report to %s' % pk.crash_report_url
          LogDebug(''.join(urllib.urlopen(pk.crash_report_url, 
                                          urllib.urlencode({ 
                                            'crash': traceback.format_exc() 
                                          })).readlines()))
        except Exception, e:
          print 'FAILED: %s' % e

      pk.FallDown(msg, help=False, noexit=pk.main_loop)

      # If we get this far, then we're looping. Clean up.
      sockets = pk.conns and pk.conns.Sockets() or []
      for fd in sockets: fd.close()

      # Exponential fall-back.
      LogDebug('Restarting in %d seconds...' % (2 ** crashes))
      time.sleep(2 ** crashes)
      crashes += 1
      if crashes > 9: crashes = 9

def Configure(pk):
  if '--appver' in sys.argv:
    print '%s' % APPVER
    sys.exit(0)

  if '--clean' not in sys.argv:
    if os.path.exists(pk.rcfile): pk.ConfigureFromFile()

  pk.Configure(sys.argv[1:])
  pk.CheckConfig()

if __name__ == '__main__':
  Main(PageKite, Configure)

# vi:ts=2 expandtab
