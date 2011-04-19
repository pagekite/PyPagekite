#!/usr/bin/python -u
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
#  - Create a derivative BaseHTTPServer which doesn't actually listen()
#    on a real socket, but instead communicates with the tunnel directly.
#  - Replace string concatenation ops with lists of buffers.
#
# Protocols:
#  - Make tunnel creation more stubborn (try multiple ports etc.)
#  - Add XMPP and incoming SMTP support.
#  - Tor entry point support? Is current SSL enough?
#  - Replace current tunnel auth scheme with SSL certificates.
#
# User interface:
#  - Enable (re)configuration from within HTTP UI.
#  - More human readable console output?
#
# Security:
#  - Add same-origin cookie enforcement to front-end. Or is that pointless
#    due to Javascript side-channels?
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
#    monitoring and static file serving.
#
# WARNING: The UI threading code assumes it is running in CPython, where the
#          GIL makes snooping across the thread-boundary relatively safe, even
#          without explicit locking. Beware!
#
###############################################################################
#
PROTOVER = '0.8'
APPVER = '0.3.99+github'
AUTHOR = 'Bjarni Runar Einarsson, http://bre.klaki.net/'
WWWHOME = 'http://pagekite.net/'
LICENSE_URL = 'http://www.gnu.org/licenses/agpl.html'
EXAMPLES = ("""\
    To make public a webserver running on localhost:
    $ pagekite.py NAME.pagekite.me                   # local port 80
    $ pagekite.py NAME.pagekite.me:3000              # local port 3000
    $ pagekite.py NAME.pagekite.me:built-in          # built-in HTTPD

    To make public HTTP and SSH servers:
    $ pagekite.py http:NAME.pagekite.me ssh:NAME.pagekite.me
    $ pagekite.py http,ssh:NAME.pagekite.me          # The same thing!
""")
MINIDOC = ("""\
>>> Welcome to pagekite.py v%s!

%s
    To sign up with PageKite.net or get advanced instructions:
    $ pagekite.py --signup
    $ pagekite.py --help

    If you request a kite which does not exist in your configuration file,
    the program will offer to help you sign up with http://pagekite.net/ and
    create it. Just choose whatever name you like and if it's available, it
    will be granted.
""") % (APPVER, EXAMPLES)
DOC = ("""\
pagekite.py is Copyright 2010, 2011, the Beanstalks Project ehf. 
     v%s                               http://pagekite.net/

This the reference implementation of the PageKite tunneling protocol,
both the front- and back-end. This following protocols are supported:

  HTTP      - HTTP 1.1 only, requires a valid HTTP Host: header
  HTTPS     - Recent versions of TLS only, requires the SNI extension.
  WEBSOCKET - Using the proposed Upgrade: WebSocket method.

Other protocols may be proxied by using "raw" back-ends and HTTP CONNECT.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License. For the full text of the
license, see: http://www.gnu.org/licenses/agpl-3.0.html

Usage:

  pagekite.py [options] [shortcuts]

Common Options:

 --clean                Skip loading the default configuration file.
 --signup               Interactively sign up for PageKite.net service.
 --defaults             Set defaults for use with PageKite.net service.

 --optfile=X    -o X    Read settings from file X. Default is ~/.pagekite.rc.
 --savefile=X   -S X    Read/write settings from file X.
 --settings             Dump the current settings to STDOUT, formatted as
                        an options file would be.

 --httpd=X:P    -H X:P  Enable the HTTP user interface on hostname X, port P.
 --webroot=X            Directory to serve as root of built-in HTTPD.
 --pemfile=X    -P X    Use X as a PEM key for the HTTPS UI.
 --httppass=X   -X X    Require password X to access the UI.

 --nozchunks            Disable zlib tunnel compression.
 --sslzlib              Enable zlib compression in OpenSSL.
 --buffers       N      Buffer at most N kB of back-end data before blocking.
 --logfile=F    -L F    Log to file F.
 --daemonize    -Z      Run as a daemon.
 --runas        -U U:G  Set UID:GID after opening our listening sockets.
 --pidfile=P    -I P    Write PID to the named file.
 --nocrashreport        Don't send anonymous crash reports to PageKite.net.
 --tls_default=N        Default name to use for SSL, if SNI and tracking fail.
 --tls_endpoint=N:F     Terminate SSL/TLS for name N, using key/cert from F.
 --errorurl=U  -E U     URL to redirect to when back-ends are not found.

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
                used as a wildcard for subdomains or protocols.

Back-end Options:

 --backend=proto:kitename:host:port:secret
                  Configure a back-end service on host:port, using protocol
                 proto and the given kite name as the public domain. As a
                special case, if host is 'localhost' and the word 'built-in'
              is used as a port number, pagekite.py's HTTP server will be used.

 --define_backend=...   Same as --backend, except not enabled by default.
 --frontends=N:X:P      Choose N front-ends from X (a DNS domain name), port P.
 --frontend=host:port   Connect to the named front-end server.
 --fe_certname=N        Connect using SSL, accepting valid certs for domain N.
 --ca_certs=PATH        Path to your trusted root SSL certificates file.

 --dyndns=X     -D X    Register changes with DynDNS provider X.  X can either
                       be simply the name of one of the 'built-in' providers,
                      or a URL format string for ad-hoc updating.

 --all          -a      Terminate early if any tunnels fail to register.
 --new          -N      Don't attempt to connect to the domain's old front-end.           
 --noprobes             Reject all probes for back-end liveness.
 --socksify=S:P         Connect via SOCKS server S, port P (requires socks.py)
 --torify=S:P           Same as socksify, but more paranoid.

About the configuration file:

    The configuration file contains the same options as are available to the
    command line, with the restriction that there be exactly one "option"
    per line.

    The leading '--' may also be omitted for readability, and for the same
    reason it is recommended to use the long form of the options in the
    configuration file (also, the short form may not always parse correctly).

    Blank lines and lines beginning with # (comments) are treated as comments
    and are ignored.  It is perfectly acceptable to have multiple configuration
    files, and configuration files can include other configuration files.

    NOTE: When using -o or --optfile on the command line, it is almost always
    advisable to use --clean as well, to suppress the default configuration.

Examples:

    Create a configuration file with default options, and then edit it.
    $ pagekite.py --defaults --settings > ~/.pagekite.rc
    $ vim ~/.pagekite.rc

    Run the built-in HTTPD.
    $ pagekite.py --defaults --httpd=localhost:9999
    $ firefox http://localhost:9999/

    Fly a PageKite on pagekite.net for somedomain.com, and register the
    new front-ends with the No-IP Dynamic DNS provider.
    $ pagekite.py \\
        --defaults \\
        --dyndns=user:pass@no-ip.com \\
        --backend=http:kitename.com:localhost:80:mygreatsecret

Shortcuts:

    A shortcut is simply the name of a kite, optionally prefixed by a
    protocol specification or followed by a local port number (the format
    is the same as for --backend= specifications as described above, using
    colons ':' as delimeters, except components may be omitted).

    When shortcuts are used, all defined back-ends are disabled except for
    those matching the list of shortcuts.

    If no match is found and the program is run interactively, the user
    will be prompted and given the option of signing up and/or creating a
    new kite using the PageKite.net service.

Shortcut examples:

"""+EXAMPLES) % APPVER

MAGIC_PREFIX = '/~:PageKite:~/'
MAGIC_PATH = '%sv%s' % (MAGIC_PREFIX, PROTOVER)
MAGIC_PATHS = (MAGIC_PATH, '/Beanstalk~Magic~Beans/0.2')

SERVICE_PROVIDER = 'PageKite.net'
SERVICE_DOMAINS = ('pagekite.me', )
SERVICE_XMLRPC = 'pk:http://pagekite.net/xmlrpc/'
SERVICE_TOS_URL = 'https://pagekite.net/support/terms/'

SERVICE_XMLRPC = 'pk:http://pagekite.net/xmlrpc/'

OPT_FLAGS = 'o:S:H:P:X:L:ZI:fA:R:h:p:aD:U:NE:'
OPT_ARGS = ['noloop', 'clean', 'nopyopenssl', 'nocrashreport',
            'signup', 'nullui', 'help',
            'optfile=', 'savefile=', 'service_xmlrpc=',
            'controlpanel', 'controlpass',
            'httpd=', 'pemfile=', 'httppass=', 'errorurl=', 'webroot=',
            'logfile=', 'daemonize', 'nodaemonize', 'runas=', 'pidfile=',
            'isfrontend', 'noisfrontend', 'settings', 'defaults', 'domain=',
            'authdomain=', 'register=', 'host=',
            'ports=', 'protos=', 'portalias=', 'rawports=',
            'tls_default=', 'tls_endpoint=', 'fe_certname=', 'ca_certs=',
            'backend=', 'define_backend=',
            'frontend=', 'frontends=', 'torify=', 'socksify=',
            'new', 'all', 'noall', 'dyndns=', 'nozchunks', 'sslzlib',
            'buffers=', 'noprobes']

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
BE_BHOST = 3
BE_BPORT = 4
BE_SECRET = 5
BE_STATUS = 6

BE_STATUS_OK = 100
BE_STATUS_BE_FAIL = 2
BE_STATUS_NO_TUNNEL = 1
BE_STATUS_DISABLED = -1
BE_STATUS_UNKNOWN = -2

BE_NONE = (None, None, None, None, None, '', BE_STATUS_UNKNOWN)

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
import cgi
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
import xmlrpclib
import zlib

import SocketServer
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import Cookie


##[ Conditional imports & compatibility magic! ]###############################

# Create our service-domain matching regexp
SERVICE_DOMAIN_RE = re.compile('\.(' + '|'.join(SERVICE_DOMAINS) + ')$')
SERVICE_SUBKITE_RE = re.compile(r'^[A-Za-z0-9_]+$')

# System logging on Unix
try:
  import syslog
except ImportError:
  pass

if not 'SHUT_RD' in dir(socket):
  socket.SHUT_RD = 0
  socket.SHUT_WR = 1
  socket.SHUT_RDWR = 2

# SSL/TLS strategy: prefer pyOpenSSL, as it comes with built-in Context
# objects. If that fails, look for Python 2.6+ native ssl support and 
# create a compatibility wrapper. If both fail, bomb with a ConfigError
# when the user tries to enable anything SSL-related.
SEND_MAX_BYTES = 16 * 1024
SEND_ALWAYS_BUFFERS = False
HAVE_SSL = False
try: 
  if '--nopyopenssl' in sys.argv:
    raise ImportError('pyOpenSSL disabled')

  from OpenSSL import SSL
  HAVE_SSL = True
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
    HAVE_SSL = True

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


if HAVE_SSL:
  class PageKiteXmlRpcTransport(xmlrpclib.SafeTransport):
    """Treat the XML-RPC host as a HTTP proxy for itself (SNI workaround)"""
    def make_connection(self, host):
      # FIXME: This is insecure by default, certs are unchecked.
      conn = xmlrpclib.SafeTransport.make_connection(self, host)
      try:
        # FIXME: This stuff will probably fail or be a no-op before Python 2.6,
        # making our connections unreliable. :-(  We need a more robust hack.
        host, extra_headers, x509 = self.get_host_info(host)
        conn._conn._tunnel_host = host
        conn._conn._tunnel_port = 443
        conn._conn._tunnel_headers = {}
      except:
        LogError('Warning, failed to configure HTTP tunnel for %s' % host)
      return conn

else:
  class PageKiteXmlRpcTransport(xmlrpclib.Transport): pass


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

class AuthError(Exception):
  pass


def HTTP_PageKiteRequest(server, backends, tokens=None, nozchunks=False,
                         tls=False, testtoken=None, replace=None):
  req = ['CONNECT PageKite:1 HTTP/1.0\r\n']

  if not nozchunks: req.append('X-PageKite-Features: ZChunks\r\n')
  if replace: req.append('X-PageKite-Replace: %s\r\n' % replace)
  if tls: req.append('X-PageKite-Features: TLS\r\n')
         
  tokens = tokens or {}
  for d in backends.keys():
    if (backends[d][BE_BHOST] and
        backends[d][BE_STATUS] != BE_STATUS_DISABLED):

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
LOG_LINE = 0
LOG_LENGTH = 300
LOG_THRESHOLD = 256 * 1024

def LogValues(values, testtime=None):
  global LOG_LINE
  words = [('ts', '%x' % (testtime or time.time())), ('ll', '%x' % LOG_LINE)]
  words.extend([(kv[0], ('%s' % kv[1]).replace('\t', ' ')
                                      .replace('\r', ' ')
                                      .replace('\n', ' ')
                                      .replace('; ', ', ')
                                      .strip()) for kv in values])
  wdict = dict(words)
  LOG_LINE += 1
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
    self.qc.acquire()
    while self.keep_running:
      now = int(time.time())
      if self.jobs:
        (requests, conn, callback) = self.jobs.pop(0)
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
            quota = self.conns.config.GetDomainQuota(proto, domain, srand,
                                                     token, sign,
                                                   check_token=(conn.quota is None))
            if not quota:
              results.append(('%s-Invalid' % prefix, what))
            elif self.conns.Tunnel(proto, domain):
              # FIXME: Allow multiple backends?
              results.append(('%s-Duplicate' % prefix, what))
            else:
              results.append(('%s-OK' % prefix, what))
              quotas.append(quota)

        results.append(('%s-SessionID' % prefix,
                        '%x:%s' % (now, sha1hex(session))))

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

  MIME_TYPES = {
    'txt': 'text/plain',
    'shtml': 'text/html',
    'html': 'text/html',
    'htm': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'jsonp': 'application/javascript',
    'png': 'image/png',
    'gif': 'image/gif',
    'jpg': 'image/jpeg',
    'jepg': 'image/jpeg',
    'DEFAULT': 'application/octet-stream'
  }
  TEMPLATE_RAW = ('%(body)s')
  TEMPLATE_JSONP = ('window.pkData = %s;')
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
    self.suppress_body = False
    if self.server.enable_ssl:
      self.connection = self.request
      self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
      self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)
    else:
      SimpleXMLRPCRequestHandler.setup(self)
 
  def log_message(self, format, *args):
    Log([('uireq', format % args)])

  def sendStdHdrs(self, header_list=[], cachectrl='private', mimetype='text/html'):
    self.send_header('Cache-Control', cachectrl)
    self.send_header('Content-Type', mimetype)
    for header in header_list:
      self.send_header(header[0], header[1])
    self.end_headers()

  def sendChunk(self, chunk):
    if self.chunked:
      self.wfile.write('%x\r\n' % len(chunk))
      self.wfile.write(chunk)
      self.wfile.write('\r\n')
    else:
      self.wfile.write(chunk)

  def sendEof(self):
    if self.chunked and not self.suppress_body: self.wfile.write('0\r\n\r\n')

  def sendResponse(self, message, code=200, msg='OK', mimetype='text/html',
                         header_list=[], chunked=False, length=None):
    self.log_request(code, message and len(message) or '-')
    self.wfile.write('HTTP/1.1 %s %s\n' % (code, msg))
    if code == 401:
      self.send_header('WWW-Authenticate',
                       'Basic realm=PK%d' % (time.time()/3600))

    self.chunked = chunked
    if chunked:
      self.send_header('Transfer-Encoding', 'chunked')
    else:
      if length:
        self.send_header('Content-Length', length)
      elif not chunked:
        self.send_header('Content-Length', len(message))

    self.sendStdHdrs(header_list=header_list, mimetype=mimetype)
    if message and not self.suppress_body:
      self.sendChunk(message)

  def checkUsernamePasswordAuth(self, username, password):
    if self.server.pkite.ui_password: 
      if password != self.server.pkite.ui_password: 
        raise AuthError("Invalid password")

  def checkRequestAuth(self, scheme, netloc, path, qs):
    if self.server.pkite.ui_password: 
      raise AuthError("checkRequestAuth not implemented")

  def checkPostAuth(self, scheme, netloc, path, qs, posted):
    if self.server.pkite.ui_password: 
      raise AuthError("checkRequestAuth not implemented")

  def performAuthChecks(self, scheme, netloc, path, qs):
    try:
      auth = self.headers.get('authorization')
      if auth:
        (how, ab64) = auth.split()
        if how.lower() == 'basic':
          (username, password) = base64.b64decode(ab64).split(':')
          self.checkUsernamePasswordAuth(username, password)
          return True

      self.checkRequestAuth(scheme, netloc, path, qs)
      return True

    except (ValueError, KeyError, AuthError), e:
      LogDebug('HTTP Auth failed: %s' % e)
    else:
      LogDebug('HTTP Auth failed: Unauthorized')

    self.sendResponse('<h1>Unauthorized</h1>\n', code=401, msg='Forbidden')
    return False

  def performPostAuthChecks(self, scheme, netloc, path, qs, posted):
    try:
      self.checkPostAuth(scheme, netloc, path, qs, posted)
      return True
    except AuthError:
      self.sendResponse('<h1>Unauthorized</h1>\n', code=401, msg='Forbidden')
      return False

  def do_PING(self):
    self.sendResponse('PONG\n', code=200, msg='PONG', mimetype='text/plain')

  def do_UNSUPPORTED(self):
    self.sendResponse('Unsupported request method.\n',
                      code=503, msg='Sorry', mimetype='text/plain')

  # Misc methods we don't support (yet)
  def do_OPTIONS(self): self.do_UNSUPPORTED()
  def do_DELETE(self): self.do_UNSUPPORTED()
  def do_PUT(self): self.do_UNSUPPORTED()

  def do_GET(self):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path) 
    qs = parse_qs(query)
    if not self.performAuthChecks(scheme, netloc, path, qs): return
    try:
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, None)
    except Exception, e:
      Log([('err', 'GET error at %s: %s' % (path, e))])
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')

  def do_HEAD(self):
    self.suppress_body = True
    self.do_GET()

  def do_POST(self):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    qs = parse_qs(query)
    if not self.performAuthChecks(scheme, netloc, path, qs): return

    posted = None
    try:
      ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
      if ctype == 'multipart/form-data':
        posted = cgi.parse_multipart(self.rfile, pdict)
      elif ctype == 'application/x-www-form-urlencoded':
        clength = int(self.headers.get('content-length'))
        posted = cgi.parse_qs(self.rfile.read(clength), 1)
      else:
        return SimpleXMLRPCRequestHandler.do_POST(self)
    except Exception, e:
      Log([('err', 'POST error at %s: %s' % (path, e))])
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')
      return

    if not self.performPostAuthChecks(scheme, netloc, path, qs, posted): return
    try:
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, posted)
    except Exception, e:
      Log([('err', 'POST error at %s: %s' % (path, e))])
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')

  def sendStaticFile(self, path, mimetype, shtml_vars=None):
    try:
      if path.find('..') >= 0: raise IOError("Evil")
      # FIXME: What about dynamic path mappings?
      full_path = '%s/%s' % (self.server.pkite.ui_webroot, path)
      for index in ('index.htm', 'index.html', 'index.shtml'):
        ipath = os.path.join(full_path, index)
        if os.path.exists(ipath):
          mimetype = 'text/html'
          full_path = ipath
          break
      if not full_path.endswith('.shtml'): shtml_vars = None
      rf = open(full_path, "rb")
      rf_stat = os.fstat(rf.fileno())
    except (IOError, OSError), e:
      return False

    headers = [ ]
    if not shtml_vars:
      # ETags for static content: we trust the file-system.
      etag = sha1hex(':'.join(['%s' % s for s in [full_path, rf_stat.st_mode,
                                   rf_stat.st_ino, rf_stat.st_dev,
                                   rf_stat.st_nlink, rf_stat.st_uid,
                                   rf_stat.st_gid, rf_stat.st_size,
                                   int(rf_stat.st_mtime),
                                   int(rf_stat.st_ctime)]]))[0:24]
      if etag == self.headers.get('if-none-match', None):
        rf.close()
        self.sendResponse('', code=304, msg='Not Modified', mimetype=mimetype)
        return True
      else:
        headers.append(('ETag', etag))

    # FIXME: Support ranges for resuming aborted transfers.

    self.sendResponse(None, mimetype=mimetype,
                            length=rf_stat.st_size,
                            chunked=(shtml_vars is not None),
                            header_list=headers)

    chunk_size = (shtml_vars and 1024 or 8) * 1024
    while not self.suppress_body:
      data = rf.read(chunk_size)
      if data == "": break
      if shtml_vars:
        self.sendChunk(data % shtml_vars)
      else:
        self.sendChunk(data)
    self.sendEof()
    rf.close()
    return True

  def getMimeType(self, path):
    try:
      ext = path.split('.')[-1].lower()
    except IndexError:
      ext = 'DIRECTORY'

    if ext in self.MIME_TYPES: return self.MIME_TYPES[ext]
    return self.MIME_TYPES['DEFAULT']

  def add_kite(self, path, qs):
    if path.find(self.server.secret) == -1:
      return {'mimetype': 'text/plain', 'body': 'Invalid secret'}

    pass

  def handleHttpRequest(self, scheme, netloc, path, params, query, frag,
                              qs, posted):
    data = {
      'prog': self.server.pkite.progname,
      'mimetype': self.getMimeType(path),
      'hostname': socket.gethostname() or 'Your Computer',
      'http_host': 'unknown',
      'code': 200,
      'body': '',
      'msg': 'OK',
      'now': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
      'ver': APPVER
    }
    for key in self.headers.keys():
      data['http_'+key.lower()] = self.headers.get(key)

    data['method'] = data.get('http_x-pagekite-proto', 'http').lower()

    if 'http_cookie' in data:
      cookies = Cookie.SimpleCookie(data['http_cookie'])
    else:
      cookies = {}

    if path == '/vars.txt':
      global gYamon
      data['body'] = gYamon.render_vars_text()

    elif path.startswith('/_pagekite/logout/'):
      parts = path.split('/')
      location = parts[3] or ('%s://%s/' % (data['method'], data['http_host']))
      self.sendResponse('\n', code=302, msg='Moved', header_list=[
                          ('Set-Cookie', 'pkite_token=; path=/'),
                          ('Location', location)
                        ])
      return

    elif path.startswith('/_pagekite/login/'):
      parts = path.split('/', 4)
      token = parts[3]
      location = parts[4] or ('%s://%s/_pagekite/' % (data['method'],
                                                      data['http_host']))
      if query: location += '?' + query
      if token == self.server.secret:
        self.sendResponse('\n', code=302, msg='Moved', header_list=[
                            ('Set-Cookie', 'pkite_token=%s; path=/' % token),
                            ('Location', location)
                          ])
      else:
        LogDebug("Invalid token, %s != %s" % (token, self.server.secret))
        self.sendResponse('<h1>Not found</h1>\n', code=404, msg='Missing')
      return

    elif path.startswith('/_pagekite/'):
      if not ('pkite_token' in cookies and cookies['pkite_token'].value == self.server.secret):
        self.sendResponse('<h1>Forbidden</h1>\n', code=403, msg='Forbidden')
        return

      if path == '/_pagekite/':
        if not self.sendStaticFile('/control.shtml', 'text/html', shtml_vars=data):
          self.sendResponse('<h1>Not found</h1>\n', code=404, msg='Missing')
        return
      elif path.startswith('/_pagekite/add_kite/'):
        data.update(self.add_kite(path, qs))
      elif path.endswith('/pagekite.rc'):
        data.update({'mimetype': 'application/octet-stream',
                     'body': '\n'.join(self.server.pkite.GenerateConfig())})
      elif path.endswith('/pagekite.rc.txt'):
        data.update({'mimetype': 'text/plain',
                     'body': '\n'.join(self.server.pkite.GenerateConfig())})
      elif path.endswith('/pagekite.cfg'):
        data.update({'mimetype': 'application/octet-stream',
                     'body': '\r\n'.join(self.server.pkite.GenerateConfig())})
      else:
        self.sendResponse('<h1>Not found</h1>\n', code=403, msg='Missing')
        return
    else:
      if not self.sendStaticFile(path, data['mimetype'], shtml_vars=data):
        self.sendResponse('<h1>Not found</h1>\n', code=404, msg='Missing')
      return

    if data['mimetype'] in ('application/octet-stream', 'text/plain'):
      response = self.TEMPLATE_RAW % data
    elif path.endswith('.jsonp'):
      response = self.TEMPLATE_JSONP % (data, )
    else:
      response = self.TEMPLATE_HTML % data

    self.sendResponse(response, msg=data['msg'],
                                code=data['code'],
                                mimetype=data['mimetype'],
                                chunked=False)
    self.sendEof()


class RemoteControlInterface(object):
  ACL_OPEN = ''
  ACL_READ = 'r'
  ACL_WRITE = 'w'

  def __init__(self, httpd, pkite, conns, yamon):
    self.httpd = httpd
    self.pkite = pkite
    self.conns = conns
    self.yamon = yamon
    self.modified = False

    # For now, nobody gets ACL_WRITE
    self.auth_tokens = {httpd.secret: self.ACL_READ}

    # Channels are in-memory logs which can be tailed over XML-RPC.
    # Javascript apps can create these for implementing chat etc.
    self.channels = {'LOG': {'access': self.ACL_READ, 'data': LOG}}

  def connections(self, auth_token):
    if self.ACL_READ not in self.auth_tokens.get(auth_token, self.ACL_OPEN):
      raise AuthError('Unauthorized')

    return [{'sid': c.sid,
             'dead': c.dead,
             'html': c.__html__()} for c in self.conns.conns]

  def add_kite(self, auth_token, kite_domain, kite_proto):
    if self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN):
      raise AuthError('Unauthorized')
    pass

  def get_kites(self, auth_token):
    if self.ACL_READ not in self.auth_tokens.get(auth_token, self.ACL_OPEN):
      raise AuthError('Unauthorized')

    kites = []
    for bid in self.pkite.backends:
      proto, domain = bid.split(':')
      fe_proto = proto.split('-')
      kite_info = {
        'id': bid,
        'domain': domain,
        'fe_proto': fe_proto[0],
        'fe_port': (len(fe_proto) > 1) and fe_proto[1] or '',
        'fe_secret': self.pkite.backends[bid][BE_SECRET],
        'be_proto': self.pkite.backends[bid][BE_PROTO],
        'backend': self.pkite.backends[bid][BE_BACKEND],
        'fe_list': [{'name': fe.server_name,
                     'tls': fe.using_tls,
                     'sid': fe.sid} for fe in self.conns.Tunnel(proto, domain)]
      }
      kites.append(kite_info)
    return kites

  def add_kite(self, auth_token,
               proto,
               fe_port, fe_domain,
               be_port, be_domain,
               shared_secret):
    if self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN):
      raise AuthError('Unauthorized')
    # FIXME
    
  def remove_kite(self, auth_token, kite_id):
    if self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN):
      raise AuthError('Unauthorized')

    if kite_id in self.pkite.backends:
      del self.pkite.backends[kite_id]
      Log([('reconfigured', '1'), ('removed', kite_id)])
      self.modified = True
    return self.get_kites(auth_token)

  def get_channel(self, auth_token, channel):
    req = self.channels.get(channel, {}).get('access', self.ACL_WRITE)
    if req not in self.auth_tokens.get(auth_token, self.ACL_OPEN):
      raise AuthError('Unauthorized')

    return self.channels.get(channel, {}).get('data', [])

  def get_channel_after(self, auth_token, channel, last_seen, timeout):
    chan = self.channels.get(channel, {})
    req = chan.get('access', self.ACL_OPEN)
    if req not in self.auth_tokens.get(auth_token, self.ACL_WRITE):
      raise AuthError('Unauthorized')

    last_seen = int(last_seen, 16)
    data = chan.get('data', [])

    # If our internal LOG_LINE counter is less than the count of the last seen
    # line at the remote end, then we've restarted and should send everything.
    if (last_seen == 0) or (LOG_LINE < last_seen): return data
    # FIXME: LOG_LINE global for all channels?  Is that suck?

    # Else, wait at least one second, AND wait for a new line to be added to
    # the log (or the timeout to expire).
    time.sleep(1)
    last_ll = data[-1]['ll']
    while (timeout > 0) and (data[-1]['ll'] == last_ll):
      time.sleep(1)
      timeout -= 1

    # Return everything the client hasn't already seen.
    return [ll for ll in data if int(ll['ll'], 16) > last_seen]


class UiHttpServer(SocketServer.ThreadingMixIn, SimpleXMLRPCServer):
  def __init__(self, sspec, pkite, conns,
               handler=UiRequestHandler,
               ssl_pem_filename=None):
    SimpleXMLRPCServer.__init__(self, sspec, handler)
    self.pkite = pkite
    self.conns = conns
    self.secret = pkite.ConfigSecret()

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
    gYamon.vset('version', APPVER)
    gYamon.vset('ssl_enabled', self.enable_ssl)
    gYamon.vset('errors', 0)
    gYamon.vset("bytes_all", 0)

    self.register_introspection_functions()
    self.register_instance(RemoteControlInterface(self, pkite, conns, gYamon))


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

  def __init__(self, fd=None, address=None, on_port=None, maxread=16000, ui=None):
    try:
      self.SetFD(fd or rawsocket(socket.AF_INET6, socket.SOCK_STREAM), six=True)
    except Exception:
      self.SetFD(fd or rawsocket(socket.AF_INET, socket.SOCK_STREAM))
    self.address = address
    self.on_port = on_port
    self.created = self.bytes_logged = time.time()
    self.dead = False
    self.ui = ui

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
      SELECTABLES[selectable_id] = self

    global gYamon
    self.countas = 'selectables_live'
    gYamon.vadd(self.countas, 1)
    gYamon.vadd('selectables', 1)

  def CountAs(self, what):
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
            '<b>Remote address</b>: %s<br>'
            '<b>Local address</b>: %s<br>'
            '<b>Bytes in / out</b>: %s / %s<br>'
            '<b>Created</b>: %s<br>'
            '<b>Status</b>: %s<br>'
            '\n') % (self.zw and ('level %d' % self.zlevel) or 'off',
                     self.dead and '-' or (obfuIp(peer[0]), peer[1]),
                     self.dead and '-' or (obfuIp(sock[0]), sock[1]),
                     fmt_size(self.all_in + self.read_bytes),
                     fmt_size(self.all_out + self.wrote_bytes),
                     time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.localtime(self.created)),
                     self.dead and 'dead' or 'alive')

  def ResetZChunks(self):
    if self.zw:
      self.zreset = True
      self.zw = zlib.compressobj(self.zlevel)

  def EnableZChunks(self, level=1):
    self.zlevel = level
    self.zw = zlib.compressobj(level)

  def SetFD(self, fd, six=False):
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

  def LogError(self, error, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    LogError(error, values)

  def LogDebug(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    LogDebug(message, values)

  def LogInfo(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    LogInfo(message, values)

  def LogTraffic(self, final=False):
    if self.wrote_bytes or self.read_bytes:
      now = time.time()
      self.all_out += self.wrote_bytes
      self.all_in += self.read_bytes

      if self.ui: self.ui.Status('traffic')

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

  def Cleanup(self):
    global buffered_bytes
    buffered_bytes -= len(self.write_blocked)
    self.write_blocked = ''

    if not self.dead:
      self.dead = True
      if self.fd: self.fd.close()
      self.LogTraffic(final=True)
      self.CountAs('selectables_dead')

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
      else:
        data = self.fd.recv(maxread)
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

  def Send(self, data, try_flush=False, bail_out=False):
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
#   print '>> %s\n%s\n' % (self, sdata[:80])
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
      self.conns.remove(s) 

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

  def __init__(self, fd=None, address=None, on_port=None, ui=None):
    Selectable.__init__(self, fd, address, on_port, ui=ui)
    self.leftovers = ''

  def __html__(self):
    return Selectable.__html__(self)

  def Cleanup(self):
    Selectable.Cleanup(self)

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

  def __init__(self, fd=None, address=None, on_port=None, ui=None):
    LineParser.__init__(self, fd, address, on_port, ui=ui)
    self.leftovers = ''
    self.might_be_tls = True
    self.is_tls = False
    self.my_tls = False

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

  def __init__(self, fd=None, address=None, on_port=None, ui=None):
    Selectable.__init__(self, fd, address, on_port, ui=ui)
    self.want_cbytes = 0
    self.want_bytes = 0
    self.compressed = False
    self.header = ''
    self.chunk = ''
    self.zr = zlib.decompressobj()

  def __html__(self):
    return Selectable.__html__(self)

  def Cleanup(self):
    Selectable.Cleanup(self)

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
    ChunkParser.__init__(self, ui=conns.config.ui)

    # We want to be sure to read the entire chunk at once, including
    # headers to save cycles, so we double the size we're willing to 
    # read here.
    self.maxread *= 2

    self.server_info = ['x.x.x.x:x', [], [], []]
    self.conns = conns
    self.users = {}
    self.zhistory = {}
    self.backends = {}
    self.rtt = 100000
    self.last_activity = time.time()
    self.last_ping = 0
    self.using_tls = False

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
      return None

    except socket.error, err:
      self.LogInfo('Discarding connection: %s' % err)
      return None

    self.CountAs('backends_live')
    self.SetConn(conn)
    conns.auth.check(requests, conn, lambda r: self.AuthCallback(conn, r))

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

    self.LogDebug('Ran out of quota? %s' % (results, ))
    return self
    # FIXME: We should let this run...

    self.LogInfo('Ran out of quota or account deleted, closing tunnel.')
    conns.Remove(self)
    self.Cleanup()
    return None

  def AuthCallback(self, conn, results):
    
    output = [HTTP_ResponseHeader(200, 'OK'),
              HTTP_Header('Transfer-Encoding', 'chunked'),
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
    if not self.Send(output):
      conn.LogDebug('No tunnels configured, closing connection.')
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
      except Exception:
        # This is sloppy, but the back-end will just connect somewhere else
        # instead, so laziness here should be fine.
        buf = None
      if buf is None or buf == '':
        LogDebug('Remote end closed connection.')
        return None
      data += buf
      self.read_bytes += len(buf)
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
      if (not self.Send(['CONNECT %s:443 HTTP/1.0\r\n\r\n' % commonName])
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
        self.using_tls = commonName
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
                                    replace=replace_sessionid))
        or not self.Flush(wait=True)):
      return None, None

    data = self._RecvHttpHeaders()
    if not data: return None, None

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
          sname = self.server_info[self.S_NAME]
          conns.config.ui.Notify('Connected to %s' % sname)
          conns.config.ui.Notify(' - Protocols: %s' % ', '.join(self.server_info[self.S_PROTOS]))
          conns.config.ui.Notify(' - Ports: %s' % ', '.join(self.server_info[self.S_PORTS]))
          if 'raw' in self.server_info[self.S_PROTOS]:
            conns.config.ui.Notify(' - Raw ports: %s' % ', '.join(self.server_info[self.S_RAW_PORTS]))

          for quota in parse.Header('X-PageKite-Quota'):
            self.quota = [int(quota), None, None]
            self.Log([('FE', sname), ('quota', quota)])
            qGB = 1024 * 1024
            conns.config.ui.Notify(('You have %.2f GB of quota left.'
                                    ) % (float(quota) / qGB),
                                   prefix=(int(quota) < qGB) and '!' or ' ')

          for request in parse.Header('X-PageKite-Invalid'):
            abort = True
            proto, domain, srand = request.split(':')
            self.Log([('FE', sname),
                      ('err', 'Rejected'),
                      ('proto', proto),
                      ('domain', domain)])
            conns.config.ui.Notify(('  Rejected: %s://%s'
                                    ) % (proto, domain), prefix='!')

          for request in parse.Header('X-PageKite-Duplicate'):
            abort = True
            proto, domain, srand = request.split(':')
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('err', 'Duplicate'),
                      ('proto', proto),
                      ('domain', domain)])
            conns.config.ui.Notify(('  Rejected: %s://%s (duplicate)'
                                    ) % (proto, domain), prefix='!')

          if not conns.config.disable_zchunks:
            for feature in parse.Header('X-PageKite-Features'):
              if feature == 'ZChunks': self.EnableZChunks(level=9)

          for request in parse.Header('X-PageKite-OK'):
            abort = False
            proto, domain, srand = request.split(':')
            conns.Tunnel(proto, domain, self)
            self.Log([('FE', sname),
                      ('proto', proto),
                      ('domain', domain)])
            if '-' in proto:
              proto, port = proto.split('-')
              conns.config.ui.Notify(('%s is front-end for: %s://%s:%s'
                                      ) % (sname, proto, domain, port))
            else:
              conns.config.ui.Notify(('%s is front-end for: %s://%s'
                                      ) % (sname, proto, domain))

        self.rtt = (time.time() - begin)
    

    except socket.error, e:
      return None

    except Exception, e:
      self.LogError('Server response parsing failed: %s' % e)
      return None

    if abort: return None

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
    return self.SendChunked('SID: %s\nEOF: %s%s\r\n\r\nBye!' % (sid,
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

  def Cleanup(self):
    for sid in self.users.keys(): self.CloseStream(sid)
    ChunkParser.Cleanup(self)

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
        bhost, bport = (be[BE_BHOST], be[BE_BPORT])
        # FIXME: Should vary probe by backend type
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
    self.conns.Remove(self)
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
        self.conns.config.ui.Notify(('You have %.2f GB of quota left.'
                                     ) % (float(self.quota[0]) / (1024*1024)))
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
        rTLS = (parse.Header('RTLS') or [''])[0].lower()
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
                                    remote_ip=rIp, remote_port=rPort, data=data)
            if proto in ('http', 'websocket'):
              if not conn:
                if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                                          HTTP_Unavailable('be', proto, host,
                                                           frame_url=self.conns.config.error_url) )):
                  return False
              elif rIp:
                add_headers = ('\nX-Forwarded-For: %s\r\n'
                               'X-PageKite-Port: %s\r\n'
                               'X-PageKite-Proto: %s\r\n'
                               ) % (rIp, port,
                                    # FIXME: Checking for port == 443 is wrong!
                                    (rTLS or (int(port) == 443)) and 'https' or 'http')
                req, rest = re.sub(r'(?mi)^x-forwarded-for', 'X-Old-Forwarded-For', data
                                   ).split('\n', 1) 
                data = ''.join([req, add_headers, rest])
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
    self.backend_count = 0
    if which == 'FE':
      for d in backends.keys():
        if backends[d][BE_BHOST]:
          proto, domain = d.split(':')
          self.conns.Tunnel(proto, domain, self)
          self.Log([('FE', self.server_info[self.S_NAME]),
                    ('proto', proto),
                    ('domain', domain)])
          self.backend_count += 1

  def Cleanup(self):
    other = self.other_end
    self.other_end = None
    if other and other.other_end: other.Cleanup()
    Tunnel.Cleanup(self)

  def Linkup(self, other):
    if self.backend_count > 0:
      self.other_end = other
      other.other_end = self
      return True
    else:
      LogDebug('Loopback not needed, going away.')
      other.Cleanup()
      self.Cleanup()
      return False

  def _Loop(conns, backends):
    return LoopbackTunnel(conns, 'FE', backends
                          ).Linkup(LoopbackTunnel(conns, 'BE', backends))

  Loop = staticmethod(_Loop)

  def Send(self, data):
    return self.other_end.ProcessData(''.join(data))


class UserConn(Selectable):
  """A Selectable representing a user's connection."""
  
  def __init__(self, address, ui=None):
    Selectable.__init__(self, address=address, ui=ui)
    self.tunnel = None

  def __html__(self):
    return ('<b>Tunnel</b>: <a href="/conn/%s">%s</a><br>'
            '%s') % (self.tunnel and self.tunnel.sid or '',
                     escape_html('%s' % (self.tunnel or '')),
                     Selectable.__html__(self))
 
  def CloseTunnel(self, tunnel_closed=False):
    self.ProcessTunnelEof(read_eof=True, write_eof=True)
    if self.tunnel and not tunnel_closed:
      self.tunnel.CloseStream(self.sid, stream_closed=True)
    self.tunnel = None

  def Cleanup(self):
    self.CloseTunnel()
    self.conns.Remove(self)
    Selectable.Cleanup(self)

  def _FrontEnd(conn, address, proto, host, on_port, body, conns):
    # This is when an external user connects to a server and requests a
    # web-page.  We have to give it to them!
    self = UserConn(address, ui=conns.config.ui)
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
      chunk_headers = [('RIP', self.address[0]),('RPort', self.address[1])]
      if conn.my_tls: chunk_headers.append(('RTLS', 1))

    if tunnels: self.tunnel = tunnels[0]
    if self.tunnel and self.tunnel.SendData(self, ''.join(body),
                                            host=host, proto=proto, port=on_port,
                                            chunk_headers=chunk_headers):
      self.Log([('domain', self.host), ('on_port', on_port), ('proto', self.proto), ('is', 'FE')])
      self.conns.Add(self)
      self.conns.TrackIP(address[0], host)
      # FIXME: Use the tracked data to detect & mitigate abuse?
      return self
    else:
      self.LogDebug('No back-end', [('on_port', on_port), ('proto', self.proto),
                                    ('domain', self.host), ('is', 'FE')])
      return None

  def _BackEnd(proto, host, sid, tunnel, on_port,
               remote_ip=None, remote_port=None, data=None):
    # This is when we open a backend connection, because a user asked for it.
    self = UserConn(None, ui=tunnel.conns.config.ui)
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

    if not backend or not backend[0]:
      self.ui.Notify(('%s <=> %s://%s:%s (FAIL: no server)'
                      ) % (remote_ip or 'unknown', proto, host, on_port),
                     prefix='?')

    # FIXME: Do access control interception HERE.
    #        Non-HTTP protocols will just get rejected if they don't match,
    #        for HTTP we will do a captive portal kind of thing.
    #        For HTTP we are guaranteed to have the initial HTTP request in
    #        `data`, so we should be able to parse that for cookies etc.

    if not backend:
      logInfo.append(('err', 'No back-end'))
      self.Log(logInfo)
      return None

    try:
      self.SetFD(rawsocket(socket.AF_INET, socket.SOCK_STREAM))
      try:
        self.fd.settimeout(2.0) # Missing in Python 2.2
      except Exception:
        self.fd.setblocking(1)

      sspec = list(backend)
      if len(sspec) == 1: sspec.append(80)
      self.fd.connect(tuple(sspec))

      self.fd.setblocking(0)

    except socket.error, err:
      logInfo.append(('socket_error', '%s' % err))
      self.ui.Notify(('%s <=> %s://%s:%s (FAIL: %s:%s is down)'
                      ) % (remote_ip or 'unknown', proto, host, on_port,
                           sspec[0], sspec[1]), prefix='!')
      self.Log(logInfo)
      Selectable.Cleanup(self)
      return None

    self.ui.Status('serving')
    self.ui.Notify(('%s <=> %s://%s:%s (OK: %s:%s)'
                    ) % (remote_ip or 'unknown', proto, host, on_port,
                         sspec[0], sspec[1]))
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
    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, read_eof=True)

    self.Shutdown(socket.SHUT_RD)
    self.read_eof = True
    return self.ProcessEof()

  def ProcessEofWrite(self, tell_tunnel=True):
    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, write_eof=True)

    if not self.write_blocked: self.Shutdown(socket.SHUT_WR)
    self.write_eof = True
    return self.ProcessEof()

  def Send(self, data, try_flush=False, bail_out=False):
    rv = Selectable.Send(self, data, try_flush=try_flush, bail_out=bail_out)
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
    MagicProtocolParser.__init__(self, fd, address, on_port, ui=conns.config.ui)
    self.peeking = True
    self.parser = HttpParser()
    self.conns = conns
    self.conns.Add(self)
    self.sid = -1

    self.host = None
    self.proto = None

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

          if cport in self.conns.config.server_raw_ports or VIRTUAL_PN in self.conns.config.server_raw_ports:
            if (('raw'+sid1) in tunnels) or (('raw'+sid2) in tunnels):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpParser()
              self.Send(HTTP_ConnectOK())
              return self.ProcessRaw(''.join(lines), self.host)

        except ValueError:
          pass

    if not done and self.parser.method == 'POST' and self.parser.path in MAGIC_PATHS:
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
    self.dead = True
    self.conns.Remove(self)

    # Break any circular references we might have
    self.parser = None
    self.conns = None

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
        self.my_tls = True
        return True

    if domains and domains[0] is not None:
      self.EatPeeked()
      if UserConn.FrontEnd(self, self.address,
                           'https', domains[0], self.on_port,
                           [data], self.conns) is None:
        return False

    # We are done!
    self.dead = True
    self.conns.Remove(self)

    # Break any circular references we might have
    self.parser = None
    self.conns = None
    return True

  def ProcessRaw(self, data, domain):
    if UserConn.FrontEnd(self, self.address,
                         'raw', domain, self.on_port,
                         [data], self.conns) is None:
      return False

    # We are done!
    self.dead = True
    self.conns.Remove(self)

    # Break any circular references we might have
    self.parser = None
    self.conns = None
    return True


class RawConn(Selectable):
  """This class is a raw/timed connection."""

  def __init__(self, fd, address, on_port, conns):
    Selectable.__init__(self, fd, address, on_port)
    domain = conns.LastIpDomain(address[0])
    if domain and UserConn.FrontEnd(self, address, 'raw', domain, on_port,
                                    [], conns):
      pass
    else:
      fd.close()



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
    check_interval = 5
    self.keep_running = True
    while self.keep_running:

      # Reconnect if necessary, randomized exponential fallback.
      problem = False
      if self.pkite.CreateTunnels(self.conns) > 0:
        check_interval += int(random.random()*check_interval)
        if check_interval > 300: check_interval = 300
        problem = True
        time.sleep(1)
      else:
        check_interval = 5

        # If all connected, make sure tunnels are really alive.
        if self.pkite.isfrontend:
          self.CheckTunnelQuotas(time.time())
          # FIXME: Front-ends should close dead back-end tunnels.
        else:
          self.pkite.ui.Status('flying')
          self.PingTunnels(time.time())

      tunnel_count = len(self.pkite.conns and
                         self.pkite.conns.TunnelServers() or [])
      tunnel_total = len(self.pkite.servers)
      if tunnel_count == 0:
        self.pkite.ui.Status('down',
                       message='Not connected to any front-ends, will retry...')
      elif tunnel_count < tunnel_total:
        self.pkite.ui.Status('flying',
                    message=('Only connected to %d/%d front-ends, will retry...'
                             ) % (tunnel_count, tunnel_total))
      elif problem:
        self.pkite.ui.Status('flying',
                      message='DynDNS updates may be incomplete, will retry...')

      for i in xrange(0, check_interval):
        if self.keep_running: time.sleep(1)


class NullUi(object):
  """This is a UI that always returns default values or raises errors."""

  WANTS_STDERR = False

  def __init__(self, welcome=None):
    self.in_wizard = False
    self.notify_history = {}
    self.status_tag = ''
    self.status_msg = ''
    self.welcome = welcome
    self.Splash()

  def Splash(self): pass

  def Welcome(self): pass
  def StartWizard(self, title): pass
  def EndWizard(self): pass
  def Spacer(self): pass

  def Browse(self, url):
    import webbrowser
    self.Tell(['Opening %s in your browser...' % url])
    webbrowser.open(url)

  def DefaultOrFail(self, question, default):
    if default is not None: return default
    raise ConfigError('Unanswerable question: %s' % question)

  def AskLogin(self, question, default=None, email=None,
               wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskEmail(self, question, default=None, pre=None,
               wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskYesNo(self, question, default=None, pre=None,
               wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def Tell(self, lines, error=False, back=None):
    if error:
      LogError(' '.join(lines))
      raise ConfigError(' '.join(lines))
    else:
      Log(['message', ' '.join(lines)])
      return True

  def Notify(self, message, prefix=' ', popup=False, now=None, alignright=''):
    if popup: Log([('info', '%s%s%s' % (message,
                                        alignright and ' ' or '',
                                        alignright))])

  def Status(self, tag, message=None): pass


class BasicUi(NullUi):
  """Stdio based user interface."""
 
  WANTS_STDERR = True
  EMAIL_RE = re.compile(r'^[a-z0-9!#$%&\'\*\+\/=?^_`{|}~-]+'
                         '(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@'
                         '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*'
                         '(?:[a-zA-Z]{2,4}|museum)$')

  def Notify(self, message, prefix=' ', popup=False, now=None, alignright=''):
    now = now or time.time()

    # We suppress duplicates that are either new or still on the screen.
    keys = self.notify_history.keys()
    if len(keys) > 20:
      for key in keys:
        if self.notify_history[key] < now-300:
          del self.notify_history[key]

    message = '%s' % message
    if message not in self.notify_history:
      self.notify_history[message] = now
      msg = '\r%s %s%s%s\n' % (prefix * 3, message,
                               ' ' * (75-len(message)-len(alignright)),
                               alignright)
      sys.stderr.write(msg)
      self.Status(self.status_tag, self.status_msg)

  def Status(self, tag, message=None):
    self.status_tag = tag
    self.status_msg = '%s' % (message or self.status_msg)
    if not self.in_wizard:
      if message:
        message = '%s' % message
        msg = '\r<<< pagekite.py [%s]%s %s%s\r' % (tag, ' ' * (8-len(tag)),
                                               message, ' ' * (52-len(message)))
      else:
        msg = '\r<<< pagekite.py [%s]%s\r' % (tag, ' ' * (8-len(tag)))
      sys.stderr.write(msg)
    if tag == 'exiting':
      sys.stderr.write('\n')

  def Welcome(self, pre=None):
    if self.in_wizard:
      sys.stderr.write('[H[J%s' % self.in_wizard)
    if self.welcome:
      sys.stderr.write('%s\n' % self.welcome)
      self.welcome = None
    if pre:
      sys.stderr.write('\n')
      for line in pre: sys.stderr.write('    %s\n' % line)

  def StartWizard(self, title):
    #sys.stderr.write('[H[J')
    self.Welcome()
    banner = '>>> %s' %  title
    banner = ('%s%s[CTRL+C = Cancel]\n') % (banner, ' ' * (62-len(banner)))
    self.in_wizard = banner
    self.tries = 200

  def Retry(self):
    self.tries -= 1
    return self.tries

  def EndWizard(self):
    self.in_wizard = None
    sys.stderr.write('\n')
    if os.getenv('USERPROFILE'):
      sys.stderr.write('\n<<< press ENTER to continue >>>\n')
      sys.stdin.readline()

  def Spacer(self):
    sys.stderr.write('\n')

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    while self.Retry():
      sys.stderr.write(' => %s ' % (question, ))
      answer = sys.stdin.readline().strip()
      if default and answer == '': return default
      if self.EMAIL_RE.match(answer): return answer
      if back is not None and answer == 'back': return back
    raise Exception('Too many tries')

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    def_email, def_pass = default or (email, None)
    sys.stderr.write('    %s\n' % (question, ))
    if not email:
      email = self.AskEmail('Your e-mail:', default=def_email, back=back)
      if email == back: return back

    import getpass
    sys.stderr.write(' => ')
    return (email, getpass.getpass() or def_pass)

  def AskYesNo(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    yn = ((default is True) and '[Y/n]'
          ) or ((default is False) and '[y/N]'
                ) or ('[y/n]')
    while self.Retry():
      sys.stderr.write(' => %s %s ' % (question, yn))
      answer = sys.stdin.readline().strip().lower()
      if default is not None and answer == '': answer = default and 'y' or 'n'
      if back is not None and answer.startswith('b'): return back
      if answer in ('y', 'n'): return (answer == 'y')
    raise Exception('Too many tries')

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    if len(domains) == 1:
      sys.stderr.write(('\n    (Note: the ending %s will be added for you.)'
                        ) % domains[0])
    else:
      sys.stderr.write('\n    Please use one of the following domains:\n')
      for domain in domains:
        sys.stderr.write('\n     %s' % domain)
      sys.stderr.write('\n')
    while self.Retry():
      sys.stderr.write('\n => %s ' % question)
      answer = sys.stdin.readline().strip().lower()
      if back is not None and answer == 'back':
        return back
      elif len(domains) == 1:
        answer = answer.replace(domains[0], '')
        if answer and SERVICE_SUBKITE_RE.match(answer):
          return answer+domains[0]
      else:
        for domain in domains:
          if answer.endswith(domain):
            answer = answer.replace(domain, '')
            if answer and SERVICE_SUBKITE_RE.match(answer):
              return answer+domain
      sys.stderr.write('    (Please only use characters A-Z, 0-9 and _.)')
    raise Exception('Too many tries')

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    sys.stderr.write('\n')
    for i in range(0, len(choices)):
      sys.stderr.write(('  %s %d) %s\n'
                        ) % ((default==i+1) and '*' or ' ', i+1, choices[i]))
    sys.stderr.write('\n')
    while self.Retry():
      d = default and (', default=%d' % default) or ''
      sys.stderr.write(' => %s [1-%d%s] ' % (question, len(choices), d))
      try:
        answer = sys.stdin.readline().strip()
        if back is not None and answer.startswith('b'): return back
        choice = int(answer or default)
        if choice > 0 and choice <= len(choices): return choice
      except (ValueError, IndexError):
        pass
    raise Exception('Too many tries')

  def Tell(self, lines, error=False, back=None):
    self.Welcome()
    sys.stderr.write('\n')
    for line in lines: sys.stderr.write('    %s\n' % line)
    if error: sys.stderr.write('\n')
    return True


class PageKite(object):
  """Configuration and master select loop."""

  def __init__(self, ui=None):
    self.progname = ((sys.argv[0] or 'pagekite.py').split('/')[-1]
                                                   .split('\\')[-1])
    self.isfrontend = False
    self.auth_domain = None
    self.server_host = ''
    self.server_ports = [80]
    self.server_raw_ports = []
    self.server_portalias = {}
    self.server_aliasport = {}
    self.server_protos = ['http', 'https', 'websocket', 'raw']

    self.tls_default = None
    self.tls_endpoints = {}
    self.fe_certname = []

    self.service_provider = SERVICE_PROVIDER
    self.service_xmlrpc = SERVICE_XMLRPC

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
    self.ui_webroot = None
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
    self.ui = ui or NullUi()

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
      self.ca_certs_default = sys.argv[0]
    self.ca_certs = self.ca_certs_default

  def SetServiceDefaults(self, clobber=True, check=False):
    def_dyndns    = (DYNDNS['pagekite.net'], {'user': '', 'pass': ''})
    def_frontends = (1, 'frontends.b5p.us', 443)
    def_ca_certs  = sys.argv[0]
    def_fe_certs  = ['frontends.b5p.us', 'b5p.us', 'pagekite.net']
    def_error_url = 'https://pagekite.net/offline/?'
    if check:
      return (self.dyndns == def_dyndns and
              self.servers_auto == def_frontends and
              self.error_url == def_error_url and
              self.ca_certs == def_ca_certs and
              (self.fe_certname == def_fe_certs or not HAVE_SSL))
    else:
      self.dyndns = (not clobber and self.dyndns) or def_dyndns
      self.servers_auto = (not clobber and self.servers_auto) or def_frontends
      self.error_url = (not clobber and self.error_url) or def_error_url
      self.ca_certs = def_ca_certs
      if HAVE_SSL: self.fe_certname.extend(def_fe_certs)
      return True

  def GenerateConfig(self, safe=False):
    config = [
      '####[ Current settings for pagekite.py v%s. ]####' % APPVER,
      '#',
      '# This file was auto-generated by pagekite.py.  Lines beginning',
      '# with a # are comments (like this one).  Aside from comments and',
      '# blank lines, each line in this file corrosponds to a single',
      '# command-line argument.  Note that order matters - especially',
      '# when including external configuration files with optfile=.',
      '#',
      '',
      '#/ HTTP control-panel settings',
      (self.ui_sspec and 'httpd=%s:%d' % self.ui_sspec
                      or '# httpd=host:port'),
      (self.ui_password and 'httppass=%s' % self.ui_password
                         or '# httppass=YOURSECRET'),
      (self.ui_pemfile and 'pemfile=%s' % self.ui_pemfile
                        or '# pemfile=/path/to/sslcert.pem'),
      '# webroot=/path/to/webroot/omitted/for/security/reasons/',
      (self.ui_webroot and safe and 'webroot=%s' % self.ui_webroot
                                 or '# webroot=/path/to/webroot/'),
      '', 
    ]

    if self.SetServiceDefaults(check=True):
      config.extend([
        '#/ Use service default settings',
        'defaults',
        '',
        '#/ Manual front-ends (optional)'
      ])
      if self.servers_manual:
        for server in self.servers_manual:
          config.append('frontend=%s' % server)
      else:
        config.append('# frontend=hostname:port')

    else:
      config.extend([
        '#/ Front-end and dynamic DNS settings',
        (self.servers_auto and 'frontends=%d:%s:%d' % self.servers_auto
                            or '#frontends=1:frontends.b5p.us:443')
      ])
      if self.servers_manual:
        for server in self.servers_manual:
          config.append('frontend=%s' % server)
      else:
        config.append('# frontend=hostname:port')
      for server in self.fe_certname:
        config.append('fe_certname=%s' % server)
      if self.ca_certs != self.ca_certs_default:
        config.append('ca_certs=%s' % self.ca_certs)
      else:
        config.append('# ca_certs=%s' % self.ca_certs)
      if self.dyndns:
        provider, args = self.dyndns
        for prov in DYNDNS:
          if DYNDNS[prov] == provider and prov != 'beanstalks.net':
            args['prov'] = prov
        if 'prov' not in args:
          args['prov'] = provider
        if args['pass']:
          config.append('dyndns=%(user)s:%(pass)s@%(prov)s' % args)
        elif args['user']:
          config.append('dyndns=%(user)s@%(prov)s' % args)
        else:
          config.append('dyndns=%(prov)s' % args)
      else:
        config.extend([
          '# dyndns=pagekite.net OR',
          '# dyndns=user:pass@dyndns.org OR',
          '# dyndns=user:pass@no-ip.com' ,
          '#',
          (self.error_url and ('errorurl=%s' % self.error_url) or '# errorurl=http://host/page/'),
        ])
      config.extend([
        '#/ Replace with this to just use service defaults:',
        '# defaults',
      ])

    config.extend([
      '',
      '#/ Your kites and local back-end servers',
      '#',
    ])
    bprinted = 0
    for bid in self.backends:
      be = self.backends[bid]
      if be[BE_BHOST]:
        config.append(('%s=%s:%s:%s:%s'
                       ) % ((be[BE_STATUS] == BE_STATUS_DISABLED
                             ) and 'define_backend' or 'backend',
                            bid, be[BE_BHOST], be[BE_BPORT], be[BE_SECRET]))
        bprinted += 1
    if bprinted == 0:
      config.append('# backend=http:YOU.pagekite.me:localhost:80:SECRET')
    config.extend([
      '#',
      '#/ More examples...',
      '# backend=ssh:YOU.pagekite.me:localhost:22:SECRET',
      '# backend=http/8080:YOU.pagekite.me:localhost:8080:SECRET',
      '# backend=https:YOU.pagekite.me:localhost:443:SECRET',
      '# backend=websocket:YOU.pagekite.me:localhost:8080:SECRET',
      '#/ This is how to define, but not activate by default...',
      '# define_backend=http:YOU.pagekite.me:localhost:4545:SECRET',
      '',
      '#/ Miscellaneous settings',
      (self.logfile   and 'logfile=%s' % self.logfile
                       or '# logfile=/path/to/file'),
      (self.servers_new_only and 'new' or '# new'),
      (self.require_all and 'all' or '# all'),
      (self.no_probes and 'noprobes' or '# noprobes'),
      (self.crash_report_url and '# nocrashreport' or 'nocrashreport'),
      'buffers=%s' % self.buffer_max,
      ''
    ])
    config.extend([
      '',
      '###[ The following stuff can usually be ignored. ]###',
      '',
      '#/ Save-files are never configured automatically for security reasons.',
      '# savefile=/path/to/savefile',
      (self.savefile and safe and 'savefile=%s' % self.savefile
                               or '# savefile=/path/to/savefile'),
      '',
      '#/ Front-end Options:',
      (self.isfrontend and 'isfrontend' or '# isfrontend')
    ])
    comment = (self.isfrontend and '' or '# ')
    config.extend([
      (self.server_host and '%shost=%s' % (comment, self.server_host)
                         or '# host=machine.domain.com'),
      '%sports=%s' % (comment, ','.join(['%s' % x for x in self.server_ports] or [])),
      '%sprotos=%s' % (comment, ','.join(['%s' % x for x in self.server_protos] or []))
    ])
    for pa in self.server_portalias:
      config.append('portalias=%s:%s' % (int(pa), int(self.server_portalias[pa])))
    config.extend([
      '%srawports=%s' % (comment, ','.join(['%s' % x for x in self.server_raw_ports] or [])),
      (self.auth_domain and '%sauthdomain=%s' % (comment, self.auth_domain)
                         or '# authdomain=foo.com')
    ])
    for bid in self.backends:
      be = self.backends[bid]
      if not be[BE_BHOST]:
        config.append('domain=%s:%s' % (bid, be[BE_SECRET]))
    config.extend([
      '# domain=http:*.pagekite.me:SECRET1',
      '# domain=http,https,websocket:THEM.pagekite.me:SECRET2',
      '',
    ])
    eprinted = 0
    config.append('#/ Domains we terminate SSL/TLS for natively, with key/cert-files')
    for ep in self.tls_endpoints:
      config.append('tls_endpoint=%s:%s' % (ep, self.tls_endpoints[ep][0]))
      eprinted += 1
    if eprinted == 0:
      config.append('# tls_endpoint=DOMAIN:PEM_FILE')
    config.extend([
      (self.tls_default and 'tls_default=%s' % self.tls_default
                         or '# tls_default=DOMAIN'),
      '',
      '#/ Systems administration settings:',
      (self.daemonize and 'daemonize' % self.logfile
                       or '# daemonize')
    ])
    if self.setuid and self.setgid:
      config.append('runas=%s:%s' % (self.setuid, self.setgid))
    elif self.setuid:
      config.append('runas=%s' % self.setuid)
    else:
      config.append('# runas=uid:gid')
    config.append(self.pidfile and 'pidfile=%s' % self.pidfile
                                or '# pidfile=/path/to/file')

    config.extend([
      '',
      '####[ End of pagekite.py configuration ]####',
      'END',
      ''
    ])
    return config

  def ConfigSecret(self, new=False):
    # This method returns a stable secret for the lifetime of this process.
    #
    # The secret depends on the active configuration as, reported by
    # GenerateConfig().  This lets external processes generate the same
    # secret and use the remote-control APIs as long as they can read the
    # *entire* config (which contains all the sensitive bits anyway).
    #
    if self.ui_httpd and self.ui_httpd.httpd and not new:
      return self.ui_httpd.httpd.secret
    else:
      return sha1hex('\n'.join(self.GenerateConfig()))

  def LoginPath(self, goto):
    return '/_pagekite/login/%s/%s' % (self.ConfigSecret(), goto)

  def LoginUrl(self, goto=''):
    return 'http%s://%s%s' % (self.ui_pemfile and 's' or '',
                              '%s:%s' % self.ui_sspec,
                              self.LoginPath(goto))

  def PrintSettings(self, safe=False):
    print '\n'.join(self.GenerateConfig(safe=safe))

  def SaveNewUserConfig(self):
    try:
      fd = open(self.rcfile, 'w')
      fd.write('\n'.join(self.GenerateConfig()))
      fd.close()
      self.ui.Tell(['Configuration saved to %s!' % self.rcfile])
      self.ui.Spacer()
      Log([('saved', 'Configuration saved to %s!' % self.rcfile)])
    except Exception, e:
      self.ui.Tell(['ERROR: Could not save to %s: %s' % (self.rcfile, e)])
      self.ui.Spacer()
      LogError('Could not save to %s: %s' % (self.rcfile, e))

  def FallDown(self, message, help=True, longhelp=False, noexit=False):
    if self.conns and self.conns.auth: self.conns.auth.quit()
    if self.ui_httpd: self.ui_httpd.quit()
    if self.tunnel_manager: self.tunnel_manager.quit()
    self.conns = self.ui_httpd = self.tunnel_manager = None
    if help or longhelp:
      print longhelp and DOC or MINIDOC
      print '*****'
    else:
      self.ui.Status('exiting', message=(message or 'Good-bye!'))
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

  def GetBackendData(self, proto, domain, recurse=True):
    backend = '%s:%s' % (proto.lower(), domain.lower())
    if backend in self.backends:
      if BE_STATUS_DISABLED != self.backends[backend][BE_STATUS]:
        return self.backends[backend]

    if recurse:
      dparts = domain.split('.')
      while len(dparts) > 1:
        dparts = dparts[1:]
        data = self.GetBackendData(proto, '.'.join(['*'] + dparts), recurse=False)
        if data: return data

    return None

  def GetBackendServer(self, proto, domain, recurse=True):
    backend = self.GetBackendData(proto, domain) or BE_NONE
    bhost, bport = (backend[BE_BHOST], backend[BE_BPORT])
    if bhost == '-' or not bhost: return None
    return (bhost, bport)

  def IsSignatureValid(self, sign, secret, proto, domain, srand, token):
    return checkSignature(sign=sign, secret=secret,
                          payload='%s:%s:%s:%s' % (proto, domain, srand, token))

  def LookupDomainQuota(self, lookup):
    if not lookup.endswith('.'): lookup += '.'
    ip = socket.gethostbyname(lookup)

    # If not an authentication error, quota should be encoded as an IP.
    if not ip.startswith(AUTH_ERRORS):
      o = [int(x) for x in ip.split('.')]
      return (((o[0]*256 + o[1])*256 + o[2])*256 + o[3])
  
    # Errors on real errors are final.
    if not ip.endswith(AUTH_ERR_USER_UNKNOWN): return None

    # User unknown, fall through to local test.
    return -1 

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
          return None

      except ValueError:
        LogError('Invalid port request: %s:%s' % (protoport, domain))
        return None
    else:
      proto, port = protoport, None

    if proto not in self.server_protos:
      LogInfo('Invalid proto request: %s:%s' % (protoport, domain))
      return None

    data = '%s:%s:%s' % (protoport, domain, srand)
    if (not token) or (not check_token) or checkSignature(sign=token, payload=data):
      if self.auth_domain:
        try:
          lookup = '.'.join([srand, token, sign, protoport, domain, self.auth_domain])
          rv = self.LookupDomainQuota(lookup)
          if rv is None or rv >= 0: return rv
        except Exception, e:
          # Lookup failed, fail open.
          LogError('Quota lookup failed: %s' % e)
          return -2

      secret = (self.GetBackendData(protoport, domain) or BE_NONE)[BE_SECRET]
      if not secret:
        secret = (self.GetBackendData(proto, domain) or BE_NONE)[BE_SECRET]
      if secret:
        if self.IsSignatureValid(sign, secret, protoport, domain, srand, token):
          return -1
        else:
          LogError('Invalid signature for: %s (%s)' % (domain, protoport))
          return None

    LogInfo('No authentication found for: %s (%s)' % (domain, protoport))
    return None

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

  def HelpAndExit(self, longhelp=False):
    print longhelp and DOC or MINIDOC
    sys.exit(0)

  def ArgToBackendSpecs(self, arg, status=BE_STATUS_UNKNOWN, secret=None):
    protos, fe_domain, be_host, be_port = '', '', '', ''

    # Interpret the argument into a specification of what we want.
    parts = arg.split(':')
    if len(parts) == 5:
      protos, fe_domain, be_host, be_port, secret = parts
    elif len(parts) == 4:
      protos, fe_domain, be_host, be_port = parts
    elif len(parts) == 3:
      protos, fe_domain, be_port = parts
    elif len(parts) == 2:
      try:
        if parts[1].startswith('built'):
          fe_domain, be_port = parts[0], parts[1]
        else:
          fe_domain, be_port = parts[0], int(parts[1])
      except:
        be_port = None
        protos, fe_domain = parts
    elif len(parts) == 1:
      fe_domain = parts[0]
    else:
      return {}

    # Allow http:// as a common typo instead of http:
    fe_domain = fe_domain.replace('/', '').lower()

    # Allow easy referencing of built-in HTTPD
    if be_port.startswith('built'):
      if not self.ui_sspec: self.ui_sspec = ('localhost', 9999)
      be_host, be_port = self.ui_sspec

    # Specs define what we are searching for...
    specs = []
    if protos:
      for proto in protos.replace('/', '-').lower().split(','):
        if proto == 'ssh':
          specs.append(['raw', '22', fe_domain, be_host, be_port or '22', secret]) 
        else:
          if '-' in proto:
            proto, port = proto.split('-')
          else:
            port = '' 
          specs.append([proto, port, fe_domain, be_host, be_port, secret]) 
    else:
      specs = [[None, '', fe_domain, be_host, be_port, secret]]

    backends = {}
    # For each spec, search through the existing backends and copy matches
    # or just shared secrets for partial matches.
    for proto, port, fdom, bhost, bport, sec in specs:
      matches = 0
      for bid in self.backends:
        be = self.backends[bid] 
        if fdom and fdom != be[BE_DOMAIN]: continue
        if not sec and be[BE_SECRET]: sec = be[BE_SECRET]
        if proto and proto != be[BE_PROTO]: continue
        if bhost and bhost.lower() != be[BE_BHOST]: continue
        if port and int(port) != be[BE_PORT]: continue
        if bport and int(bport) != be[BE_BPORT]: continue
        backends[bid] = be[:]
        matches += 1

      if matches == 0:
        proto = (proto or 'http')
        bhost = (bhost or 'localhost')
        bport = (bport or (proto == 'http' and 80)
                       or (proto == 'https' and 443))
        if port:
          bid = '%s-%d:%s' % (proto, int(port), fdom)
        else:
          bid = '%s:%s' % (proto, fdom)

        backends[bid] = [proto, port and int(port) or '', fdom,
                         bhost.lower(), int(bport), sec, status]

    return backends

  def Configure(self, argv):
    opts, args = getopt.getopt(argv, OPT_FLAGS, OPT_ARGS) 

    for opt, arg in opts:
      if opt in ('-o', '--optfile'): self.ConfigureFromFile(arg) 
      elif opt in ('-S', '--savefile'):
        if self.savefile: raise ConfigError('Multiple save-files!')
        self.ConfigureFromFile(arg)
        self.savefile = arg

      elif opt in ('-I', '--pidfile'): self.pidfile = arg
      elif opt in ('-L', '--logfile'): self.logfile = arg
      elif opt in ('-Z', '--daemonize'):
        self.daemonize = True
        self.ui = NullUi()
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
      elif opt == '--webroot': self.ui_webroot = arg

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
      elif opt == '--service_xmlrpc': self.service_xmlrpc = arg
      elif opt == '--frontend': self.servers_manual.append(arg)
      elif opt == '--frontends':
        count, domain, port = arg.split(':')
        self.servers_auto = (int(count), domain, int(port))

      elif opt in ('--errorurl', '-E'): self.error_url = arg
      elif opt in ('--backend', '--define_backend'):
        bes = self.ArgToBackendSpecs(arg, status=((opt == '--backend')
                                                  and BE_STATUS_UNKNOWN
                                                  or BE_STATUS_DISABLED))
        for bid in bes:
          if bid in self.backends:
            raise ConfigError("Same backend/domain defined twice: %s" % bid)
        self.backends.update(bes)

      elif opt == '--domain':
        protos, domain, secret = arg.split(':')
        if protos in ('*', ''): protos = ','.join(self.server_protos)
        for proto in protos.split(','): 
          bid = '%s:%s' % (proto, domain)
          if bid in self.backends:
            raise ConfigError("Same backend/domain defined twice: %s" % bid)
          self.backends[bid] = [proto, None, domain, None, None, secret,
                                BE_STATUS_UNKNOWN]

      elif opt == '--noprobes': self.no_probes = True
      elif opt == '--nofrontend': self.isfrontend = False
      elif opt == '--nodaemonize': self.daemonize = False
      elif opt == '--noall': self.require_all = False
      elif opt == '--nozchunks': self.disable_zchunks = True
      elif opt == '--nullui': self.ui = NullUi()
      elif opt == '--sslzlib': self.enable_sslzlib = True
      elif opt == '--buffers': self.buffer_max = int(arg)
      elif opt == '--nocrashreport': self.crash_report_url = None
      elif opt == '--clean': pass
      elif opt == '--nopyopenssl': pass
      elif opt == '--noloop': self.main_loop = False
      elif opt == '--defaults': self.SetServiceDefaults()
      elif opt == '--settings':
        self.PrintSettings(safe=True)
        sys.exit(0)

      elif opt == '--help':
        self.HelpAndExit(longhelp=True)

      elif opt == '--controlpanel':
        import webbrowser
        webbrowser.open(self.LoginUrl())
        sys.exit(0)

      elif opt == '--controlpass':
        print self.ConfigSecret()
        sys.exit(0)

      else:
        self.HelpAndExit()

    # Handle the user-friendly argument stuff and simple registration.

    just_these_backends = {}
    for arg in args:
      if not arg.startswith('-'):
        just_these_backends.update(self.ArgToBackendSpecs(arg))

    need_registration = {}
    for be in just_these_backends.values():
      if not be[BE_SECRET]: need_registration[be[BE_DOMAIN]] = True

    for domain in need_registration:
      result = self.RegisterNewKite(kitename=domain)
      if not result:
        raise ConfigError("Not sure what to do with %s, giving up." % domain)

      # Update the secrets...
      rdom, rsecret = result
      for be in just_these_backends.values():
        if be[BE_DOMAIN] == domain: be[BE_SECRET] = rsecret

      # Update the kite names themselves, if they changed.
      if rdom != domain:
        for bid in just_these_backends.keys():
          nbid = bid.replace(':'+domain, ':'+rdom)
          if nbid != bid:
            just_these_backends[nbid] = just_these_backends[bid]
            just_these_backends[nbid][BE_DOMAIN] = rdom
            del just_these_backends[bid]

    if just_these_backends.keys():
      for be in self.backends.values(): be[BE_STATUS] = BE_STATUS_DISABLED
      self.backends.update(just_these_backends)

    return self

  def GetServiceXmlRpc(self):
    service = self.service_xmlrpc
    if service.startswith('pk:http'):
      return xmlrpclib.ServerProxy(service.replace('pk:http', 'http'),
                                   PageKiteXmlRpcTransport(), None, False)
    else:
      return xmlrpclib.ServerProxy(self.service_xmlrpc, None, None, False)

  def _KiteInfo(self, kitename):
    is_service_domain = kitename and SERVICE_DOMAIN_RE.search(kitename)
    is_cname_for = is_cname_ready = False
    if kitename and not is_service_domain:
      try:
        (hn, al, ips) = socket.gethostbyname_ex(kitename)
        if hn != kitename and SERVICE_DOMAIN_RE.search(hn):
          is_cname_for = hn
      except:
        pass

    return is_service_domain, is_cname_for, is_cname_ready

  def RegisterNewKite(self, kitename=None, autoconfigure=False):
    if kitename:
      self.ui.StartWizard('Creating kite: %s' % kitename)
      is_service_domain, is_cname_for, is_cname_ready = self._KiteInfo(kitename)
    else:
      self.ui.StartWizard('Create your first kite!')
      is_service_domain = is_cname_for = is_cname_ready = False

    service = self.GetServiceXmlRpc()
    service_accounts = {}

    for be in self.backends.values():
      if SERVICE_DOMAIN_RE.search(be[BE_DOMAIN]):
        if be[BE_DOMAIN] == is_cname_for:
          is_cname_ready = True
        if be[BE_SECRET] not in service_accounts.values():
          service_accounts[be[BE_DOMAIN]] = be[BE_SECRET]
    service_account_list = service_accounts.keys()

    if service_account_list:
      state = ['choose_kite_account']
    else:
      state = ['use_service_question']
    history = []

    def Back():
      state[0] = history.pop(-1)
    def Goto(goto, back_skips_current=False):
      if not back_skips_current: history.append(state[0])
      state[0] = goto

    register = is_cname_for or kitename
    email = None
    while 'end' not in state:
      try:
        if 'use_service_question' in state:
          ch = self.ui.AskYesNo('Use the %s service?' % self.service_provider,
                                default=True, back=-1)
          if ch is True:
            self.SetServiceDefaults(clobber=False)
            if not kitename:
              Goto('service_signup_email')
            elif is_cname_for and is_cname_ready:
              register = kitename
              Goto('service_signup_email')
            elif is_service_domain:
              register = is_cname_for or kitename
              Goto('service_signup_email')
            else:
              Goto('service_signup_bad_domain')
          else:
            Goto('manual_abort')

        elif 'service_login_email' in state:
          p = None
          while not email or not p:
            (email, p) = self.ui.AskLogin('Please type in your %s account '
                                          'details.' % self.service_provider,
                                          email=email, back=(False, -1))
            if email and p:
              try:
                service_accounts[email] = service.getSharedSecret(email, p)
                # FIXME: Should get the list of preconfigured kites via. RPC
                #        so we don't try to create something that already
                #        exists?  Or should the RPC not just not complain?
                account = email
                Goto('create_kite')
              except:
                email = p = None
                if not self.ui.Tell(['Login failed! Try again?'], back=False):
                  Back()
            if email is False:
              Back()

        elif ('service_signup_bad_domain' in state or
              'service_login_bad_domain' in state):
          if is_cname_for:
            alternate = is_cname_for
            ch = self.ui.AskYesNo('Create both?',
                                  pre=['%s is a CNAME for %s.' % (kitename, is_cname_for)],
                                  default=True, back=-1)
          else:
            alternate = kitename.split('.')[-2]+'.'+SERVICE_DOMAINS[0]
            ch = self.ui.AskYesNo('Try to create %s instead?' % alternate,
                                  pre=['Sorry, %s is not a valid service domain.' % kitename],
                                  default=True, back=-1)
          if ch is True:
            register = alternate
            Goto(state[0].replace('bad_domain', 'email'))
          elif ch is False:
            register = alternate = kitename = False
            Goto('service_signup_kitename', back_skips_current=True)
          else:
            Back()

        elif 'service_signup_email' in state:
          email = self.ui.AskEmail('What is your e-mail address?', back=False)
          if email and register:
            Goto('service_signup')
          elif email:
            Goto('service_signup_kitename')
          else:
            Back()

        elif 'service_signup_kitename' in state:
          try:
            domains = service.getAvailableDomains(None, None)
          except:
            domains = ['.%s' % x for x in SERVICE_DOMAINS]

          ch = self.ui.AskKiteName(domains, 'Name your kite:', back=False)
          if ch:
            kitename = register = ch
            (is_service_domain, is_cname_for, is_cname_ready) = self._KiteInfo(ch)
            self.ui.StartWizard('Creating kite: %s' % kitename)
            Goto('service_signup')
          else:
            Back()

        elif 'service_signup' in state:
          ch = self.ui.AskMultipleChoice(['Yes, I agree!',
                                          'View Software License (AGPLv3).',
                                          'View PageKite.net Terms of Service.',
                                          'No, I do not accept these terms.'],
                                         'Your choice:',
                                         pre=['Do you accept the license and terms of service?'],
                                         default=1, back=False)
          if ch is False:
            Back()
          elif ch == 2:
            self.ui.Browse(LICENSE_URL)
          elif ch == 3:
            self.ui.Browse(SERVICE_TOS_URL)
          elif ch == 4:
            Goto('manual_abort')
          else:
            try:
              details = service.signUp(email, register)
              if details.get('secret', False):
                service_accounts[email] = details['secret']
                self.ui.Tell([
                  'Your kite, %s, is live!' % register,
                  '',
                  'NOTE: Your account still needs to be activated. Instructions',
                  'have been mailed to %s, please follow them ASAP. To' % email,
                  'avoid automated abuse, kites on unactivated %s'
                  ' accounts' % self.service_provider,
                  'can only be used for %d minutes.'
                  ' Activation makes them permanent.' % details['timeout'],
                ])
                # FIXME: Handle CNAMEs somehow?
                time.sleep(2) # Give the service side a moment to replicate...
                self.ui.EndWizard()
                if autoconfigure:
                  self.backends.update(self.ArgToBackendSpecs(register,
                                                      secret=details['secret']))
                return (register, details['secret'])
              else:
                error = details.get('error', 'unknown')
                if error == 'domaintaken':
                  self.ui.Tell([('Sorry, that domain (%s) is already taken.'
                                 ) % register], error=True)
                  Goto('abort')
                elif error == 'pleaselogin':
                  self.ui.Tell(['You already have an account, please log in.'])
                  Goto('service_login_email', back_skips_current=True)
                else:
                  self.ui.Tell(['Signup failed! (%s)' % error,
                                'Please try again later?'], error=True)
                  Goto('abort')
            except Exception, e:
              self.ui.Tell(['Signup failed! (%s)' % e,
                            'Please try again later?'], error=True)
              Goto('abort')

        elif 'choose_kite_account' in state:
          # FIXME: Make this a yes-no, just use the first account.
          choices = service_account_list[:]
          choices.append('Use another service provider')
          ch = self.ui.AskMultipleChoice(choices, 'Register with',
                                         pre=['Choose an account for this kite:'], 
                                         default=1)
          if ch == len(choices):
            Goto('manual_abort')
          else:
            account = choices[ch-1]
            Goto('create_kite')
 
        elif 'create_kite' in state:
          secret = service_accounts[account]
          cfgs = {}
          result = {}
          try:
            if is_cname_for and is_cname_ready:
              result = service.addCnameKite(account, secret, kitename)
              cfgs.update(self.ArgToBackendSpecs(kitename, secret=secret))
            else:
              result = service.addKite(account, secret, register)
              cfgs.update(self.ArgToBackendSpecs(register, secret=secret))
              if is_cname_for == register and 'error' not in result:
                result.update(service.addCnameKite(account, secret, kitename))
                cfgs.update(self.ArgToBackendSpecs(kitename, secret=secret))

            if 'error' in result:
              self.ui.Tell(['Oops, we had a problem: %s' % result['error'],
                            'Perhaps if you chose a different kite name?'],
                           error=True)
              Goto('abort')
            else:
              self.ui.Tell(['Success!  Time to fly some kites...', ''])
              self.ui.EndWizard()
              time.sleep(2) # Give the service side a moment to replicate...
              if autoconfigure: self.backends.update(cfgs)
              return (register or kitename, secret)

          except Exception, e:
            self.ui.Tell(['Oops! We had a problem: %s' % e,
                          'Please try again later?'], error=True)
            Goto('abort')

        elif 'manual_abort' in state:
          if self.ui.Tell(['Aborted!',
            'Please add information about your kites and front-ends',
            'to the configuration file: %s' % self.rcfile],
                          error=True, back=False) is False:
            Back()
          else:
            self.ui.EndWizard()
            sys.exit(1)

        elif 'abort' in state:
          self.ui.EndWizard()
          sys.exit(1)

        else:
          raise ConfigError('Unknown state: %s' % state)

      except KeyboardInterrupt:
        sys.stderr.write('\n')
        if history:
          Back()
        else:
          raise KeyboardInterrupt()

    self.ui.EndWizard()

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
      fd.send('HEAD / HTTP/1.0\r\n\r\n')
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
      for be in self.backends.values():
        if be[BE_BHOST]:
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
          if self.backends[bid][BE_STATUS] != BE_STATUS_DISABLED:
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
          self.ui.Status('connect', message='Connecting to front-end: %s' % server)
          if Tunnel.BackEnd(server, self.backends, self.require_all, conns):
            Log([('connect', server)])
            connections += 1
          else:
            failures += 1
            LogInfo('Failed to connect', [('FE', server)])
            self.ui.Notify('Failed to connect to %s' % server, prefix='!')

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
            self.ui.Status('dyndns', message='Updating Dynamic DNS records')
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

    if not failures:
      self.ui.Status('active', message='Kites are flying and all is well.')

    return failures

  def LogTo(self, filename, close_all=True, dont_close=[]):
    global Log

    if filename == 'memory':
      Log = LogToMemory
      filename = self.devnull

    elif filename == 'syslog':
      Log = LogSyslog
      filename = self.devnull
      syslog.openlog(self.progname, syslog.LOG_PID, syslog.LOG_DAEMON)

    else:
      Log = LogToFile

    # Try to open the file before we close everything, so errors don't get
    # squelched.
    try:
      open(filename, "a").close()
    except IOError, e:
      raise ConfigError('%s' % e)

    if filename != 'stdio':
      global LogFile
      try:
        LogFile = fd = open(filename, "a", 0)
        os.dup2(fd.fileno(), sys.stdin.fileno())
        os.dup2(fd.fileno(), sys.stdout.fileno())
        if not self.ui.WANTS_STDERR: os.dup2(fd.fileno(), sys.stderr.fileno())
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

  def Start(self, howtoquit='CTRL+C = Quit'):
    conns = self.conns = Connections(self)
    global Log

    # If we are going to spam stdout with ugly crap, then there is no point
    # attempting the fancy stuff. This also makes us backwards compatible
    # for the most part.
    if self.logfile == 'stdio': self.ui = NullUi()

    # Announce that we've started up!
    self.ui.Status('startup', message='Starting up...')
    self.ui.Notify(('Hello! This is %s v%s.'
                    ) % (self.progname, APPVER),
                    prefix='>', alignright='[%s]' % howtoquit)
    config_report = [('started', sys.argv[0]), ('version', APPVER),
                     ('argv', ' '.join(sys.argv[1:])),
                     ('ca_certs', self.ca_certs)]
    for optf in self.rcfiles_loaded: config_report.append(('optfile', optf))
    Log(config_report)

    if not HAVE_SSL:
      self.ui.Notify('SECURITY WARNING: No SSL support was found, tunnels are insecure!', prefix='!')
      self.ui.Notify('Please install either pyOpenSSL or python-ssl.',  prefix='!')

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

    # Preserve sane behavior when not run at the console.
    if not sys.stdout.isatty():
      Log = LogToFile

    # Create log-file
    if self.logfile:
      keep_open = [s.fd.fileno() for s in conns.conns]
      if self.ui_httpd: keep_open.append(self.ui_httpd.httpd.socket.fileno())
      self.LogTo(self.logfile, dont_close=keep_open)
      try:
        import signal
        def reopen(x,y):
          self.LogTo(self.logfile, close_all=False)
          LogDebug('SIGHUP received, reopening: %s' % self.logfile)
        signal.signal(signal.SIGHUP, reopen)
      except Exception:
        LogError('Warning: configure signal handler failed, logrotate will not work.')
    FlushLogMemory()

    # Disable compression in OpenSSL
    if not self.enable_sslzlib:
      DisableSSLCompression()

    # Daemonize!
    if self.daemonize:
      self.Daemonize()

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

def Main(pagekite, configure, uiclass=NullUi, progname=None, appver=APPVER):
  crashes = 1

  ui = uiclass()

  while True:
    pk = pagekite(ui=ui)
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

  if '--signup' in sys.argv:
    if pk.backends.keys() or pk.RegisterNewKite(autoconfigure=True):
      if pk.ui.AskYesNo('Save current configuration to %s?' % pk.rcfile,
                        default=(len(pk.backends.keys()) > 0)):
        pk.SaveNewUserConfig()
      pk.servers_new_only = True
  else:
    pk.CheckConfig()
      

if __name__ == '__main__':
  if sys.stdout.isatty():
    Main(PageKite, Configure, uiclass=BasicUi)
  else:
    Main(PageKite, Configure)


##[ CA Certificates ]##########################################################

CA_CERTS="""
StartCom Ltd.
=============
-----BEGIN CERTIFICATE-----
MIIFFjCCBH+gAwIBAgIBADANBgkqhkiG9w0BAQQFADCBsDELMAkGA1UEBhMCSUwxDzANBgNVBAgT
BklzcmFlbDEOMAwGA1UEBxMFRWlsYXQxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xGjAYBgNVBAsT
EUNBIEF1dGhvcml0eSBEZXAuMSkwJwYDVQQDEyBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhv
cml0eTEhMB8GCSqGSIb3DQEJARYSYWRtaW5Ac3RhcnRjb20ub3JnMB4XDTA1MDMxNzE3Mzc0OFoX
DTM1MDMxMDE3Mzc0OFowgbAxCzAJBgNVBAYTAklMMQ8wDQYDVQQIEwZJc3JhZWwxDjAMBgNVBAcT
BUVpbGF0MRYwFAYDVQQKEw1TdGFydENvbSBMdGQuMRowGAYDVQQLExFDQSBBdXRob3JpdHkgRGVw
LjEpMCcGA1UEAxMgRnJlZSBTU0wgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxITAfBgkqhkiG9w0B
CQEWEmFkbWluQHN0YXJ0Y29tLm9yZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA7YRgACOe
yEpRKSfeOqE5tWmrCbIvNP1h3D3TsM+x18LEwrHkllbEvqoUDufMOlDIOmKdw6OsWXuO7lUaHEe+
o5c5s7XvIywI6Nivcy+5yYPo7QAPyHWlLzRMGOh2iCNJitu27Wjaw7ViKUylS7eYtAkUEKD4/mJ2
IhULpNYILzUCAwEAAaOCAjwwggI4MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgHmMB0GA1Ud
DgQWBBQcicOWzL3+MtUNjIExtpidjShkjTCB3QYDVR0jBIHVMIHSgBQcicOWzL3+MtUNjIExtpid
jShkjaGBtqSBszCBsDELMAkGA1UEBhMCSUwxDzANBgNVBAgTBklzcmFlbDEOMAwGA1UEBxMFRWls
YXQxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xGjAYBgNVBAsTEUNBIEF1dGhvcml0eSBEZXAuMSkw
JwYDVQQDEyBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJARYS
YWRtaW5Ac3RhcnRjb20ub3JnggEAMB0GA1UdEQQWMBSBEmFkbWluQHN0YXJ0Y29tLm9yZzAdBgNV
HRIEFjAUgRJhZG1pbkBzdGFydGNvbS5vcmcwEQYJYIZIAYb4QgEBBAQDAgAHMC8GCWCGSAGG+EIB
DQQiFiBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAyBglghkgBhvhCAQQEJRYjaHR0
cDovL2NlcnQuc3RhcnRjb20ub3JnL2NhLWNybC5jcmwwKAYJYIZIAYb4QgECBBsWGWh0dHA6Ly9j
ZXJ0LnN0YXJ0Y29tLm9yZy8wOQYJYIZIAYb4QgEIBCwWKmh0dHA6Ly9jZXJ0LnN0YXJ0Y29tLm9y
Zy9pbmRleC5waHA/YXBwPTExMTANBgkqhkiG9w0BAQQFAAOBgQBscSXhnjSRIe/bbL0BCFaPiNhB
OlP1ct8nV0t2hPdopP7rPwl+KLhX6h/BquL/lp9JmeaylXOWxkjHXo0Hclb4g4+fd68p00UOpO6w
NnQt8M2YI3s3S9r+UZjEHjQ8iP2ZO1CnwYszx8JSFhKVU2Ui77qLzmLbcCOxgN8aIDjnfg==
-----END CERTIFICATE-----

StartCom Certification Authority
================================
-----BEGIN CERTIFICATE-----
MIIHyTCCBbGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEWMBQGA1UEChMN
U3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmlu
ZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDYwOTE3MTk0
NjM2WhcNMzYwOTE3MTk0NjM2WjB9MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRk
LjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMg
U3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQDBiNsJvGxGfHiflXu1M5DycmLWwTYgIiRezul38kMKogZkpMyONvg45iPwbm2xPN1y
o4UcodM9tDMr0y+v/uqwQVlntsQGfQqedIXWeUyAN3rfOQVSWff0G0ZDpNKFhdLDcfN1YjS6LIp/
Ho/u7TTQEceWzVI9ujPW3U3eCztKS5/CJi/6tRYccjV3yjxd5srhJosaNnZcAdt0FCX+7bWgiA/d
eMotHweXMAEtcnn6RtYTKqi5pquDSR3l8u/d5AGOGAqPY1MWhWKpDhk6zLVmpsJrdAfkK+F2PrRt
2PZE4XNiHzvEvqBTViVsUQn3qqvKv3b9bZvzndu/PWa8DFaqr5hIlTpL36dYUNk4dalb6kMMAv+Z
6+hsTXBbKWWc3apdzK8BMewM69KN6Oqce+Zu9ydmDBpI125C4z/eIT574Q1w+2OqqGwaVLRcJXrJ
osmLFqa7LH4XXgVNWG4SHQHuEhANxjJ/GP/89PrNbpHoNkm+Gkhpi8KWTRoSsmkXwQqQ1vp5Iki/
untp+HDH+no32NgN0nZPV/+Qt+OR0t3vwmC3Zzrd/qqc8NSLf3Iizsafl7b4r4qgEKjZ+xjGtrVc
UjyJthkqcwEKDwOzEmDyei+B26Nu/yYwl/WL3YlXtq09s68rxbd2AvCl1iuahhQqcvbjM4xdCUsT
37uMdBNSSwIDAQABo4ICUjCCAk4wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAa4wHQYDVR0OBBYE
FE4L7xqkQFulF2mHMMo0aEPQQa7yMGQGA1UdHwRdMFswLKAqoCiGJmh0dHA6Ly9jZXJ0LnN0YXJ0
Y29tLm9yZy9zZnNjYS1jcmwuY3JsMCugKaAnhiVodHRwOi8vY3JsLnN0YXJ0Y29tLm9yZy9zZnNj
YS1jcmwuY3JsMIIBXQYDVR0gBIIBVDCCAVAwggFMBgsrBgEEAYG1NwEBATCCATswLwYIKwYBBQUH
AgEWI2h0dHA6Ly9jZXJ0LnN0YXJ0Y29tLm9yZy9wb2xpY3kucGRmMDUGCCsGAQUFBwIBFilodHRw
Oi8vY2VydC5zdGFydGNvbS5vcmcvaW50ZXJtZWRpYXRlLnBkZjCB0AYIKwYBBQUHAgIwgcMwJxYg
U3RhcnQgQ29tbWVyY2lhbCAoU3RhcnRDb20pIEx0ZC4wAwIBARqBl0xpbWl0ZWQgTGlhYmlsaXR5
LCByZWFkIHRoZSBzZWN0aW9uICpMZWdhbCBMaW1pdGF0aW9ucyogb2YgdGhlIFN0YXJ0Q29tIENl
cnRpZmljYXRpb24gQXV0aG9yaXR5IFBvbGljeSBhdmFpbGFibGUgYXQgaHR0cDovL2NlcnQuc3Rh
cnRjb20ub3JnL3BvbGljeS5wZGYwEQYJYIZIAYb4QgEBBAQDAgAHMDgGCWCGSAGG+EIBDQQrFilT
dGFydENvbSBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOC
AgEAFmyZ9GYMNPXQhV59CuzaEE44HF7fpiUFS5Eyweg78T3dRAlbB0mKKctmArexmvclmAk8jhvh
3TaHK0u7aNM5Zj2gJsfyOZEdUauCe37Vzlrk4gNXcGmXCPleWKYK34wGmkUWFjgKXlf2Ysd6AgXm
vB618p70qSmD+LIU424oh0TDkBreOKk8rENNZEXO3SipXPJzewT4F+irsfMuXGRuczE6Eri8sxHk
fY+BUZo7jYn0TZNmezwD7dOaHZrzZVD1oNB1ny+v8OqCQ5j4aZyJecRDjkZy42Q2Eq/3JR44iZB3
fsNrarnDy0RLrHiQi+fHLB5LEUTINFInzQpdn4XBidUaePKVEFMy3YCEZnXZtWgo+2EuvoSoOMCZ
EoalHmdkrQYuL6lwhceWD3yJZfWOQ1QOq92lgDmUYMA0yZZwLKMS9R9Ie70cfmu3nZD0Ijuu+Pwq
yvqCUqDvr0tVk+vBtfAii6w0TiYiBKGHLHVKt+V9E9e4DGTANtLJL4YSjCMJwRuCO3NJo2pXh5Tl
1njFmUNj403gdy3hZZlyaQQaRwnmDwFWJPsfvw55qVguucQJAX6Vum0ABj6y6koQOdjQK/W/7HW/
lwLFCRsI3FU34oH7N4RDYiDK51ZLZer+bMEkkyShNOsF/5oirpt9P/FlUQqmMGqz9IgcgA38coro
g14=
-----END CERTIFICATE-----
"""
