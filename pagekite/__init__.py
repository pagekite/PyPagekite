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
#    monitoring and static file serving.
#
# WARNING: The UI threading code assumes it is running in CPython, where the
#          GIL makes snooping across the thread-boundary relatively safe, even
#          without explicit locking. Beware!
#
###############################################################################
#
PROTOVER = '0.8'
APPVER = '0.4.4c'
AUTHOR = 'Bjarni Runar Einarsson, http://bre.klaki.net/'
WWWHOME = 'http://pagekite.net/'
LICENSE_URL = 'http://www.gnu.org/licenses/agpl.html'
EXAMPLES = ("""\
    Basic usage, gives http://localhost:80/ a public name:
    $ pagekite.py NAME.pagekite.me

    To expose specific folders, files or use alternate local ports:
    $ pagekite.py +indexes /a/path/ NAME.pagekite.me   # built-in HTTPD
    $ pagekite.py *.html            NAME.pagekite.me   # built-in HTTPD
    $ pagekite.py 3000              NAME.pagekite.me   # http://localhost:3000/

    To expose multiple local servers (SSH and HTTP):
    $ pagekite.py ssh://NAME.pagekite.me AND 3000 http://NAME.pagekite.me
""")
MINIDOC = ("""\
>>> Welcome to pagekite.py v%s!

%s
    To sign up with PageKite.net or get advanced instructions:
    $ pagekite.py --signup
    $ pagekite.py --help

    If you request a kite which does not exist in your configuration file,
    the program will offer to help you sign up with http://pagekite.net/ and
    create it. Pick a name, any name!""") % (APPVER, EXAMPLES)
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
 --local=ports          Configure for local serving only (no remote front-end)

 --optfile=X    -o X    Read settings from file X. Default is ~/.pagekite.rc.
 --optdir=X     -O X    Read settings from *.rc in directory X.
 --savefile=X   -S X    Saved settings will be written to file X.
 --reloadfile=X         Re-read settings from X on SIGHUP.
 --autosave             Enable auto-saving.
 --noautosave           Disable auto-saving.
 --save                 Save this configuration.
 --settings             Dump the current settings to STDOUT, formatted as
                        an options file would be.

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
 --fingerpath=P         Path recipe for the httpfinger back-end proxy.
 --proxy=T:S:P          Connect using a chain of proxies (requires socks.py)
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

    A shortcut is simply the name of a kite following a list of zero or
    more 'things' to expose using that name.  Pagekite knows how to expose
    either servers running on localhost ports or directories and files
    using the built-in HTTP server.  If no list of things to expose is
    provided, the defaults for that kite are read from the configuration
    file or http://localhost:80/ used as a last-resort default.

    If a kite name is requested which does not already exist in the
    configuration file and program is run interactively, the user
    will be prompted and given the option of signing up and/or creating a
    new kite using the PageKite.net service.

    Multiple short-cuts can be specified on a single command-line,
    separated by the word 'AND' (note capital letters are required).
    This may cause problems if you have many files and folders by that
    name, but that should be relatively rare. :-)

Shortcut examples:

"""+EXAMPLES) % APPVER

MAGIC_PREFIX = '/~:PageKite:~/'
MAGIC_PATH = '%sv%s' % (MAGIC_PREFIX, PROTOVER)
MAGIC_PATHS = (MAGIC_PATH, '/Beanstalk~Magic~Beans/0.2')

SERVICE_PROVIDER = 'PageKite.net'
SERVICE_DOMAINS = ('pagekite.me', )
SERVICE_XMLRPC = 'http://pagekite.net/xmlrpc/'
SERVICE_TOS_URL = 'https://pagekite.net/support/terms/'

OPT_FLAGS = 'o:O:S:H:P:X:L:ZI:fA:R:h:p:aD:U:NE:'
OPT_ARGS = ['noloop', 'clean', 'nopyopenssl', 'nossl', 'nocrashreport',
            'nullui', 'remoteui', 'help', 'settings',
            'optfile=', 'optdir=', 'savefile=', 'reloadfile=',
            'autosave', 'noautosave',
            'signup', 'list', 'add', 'only', 'disable', 'remove', 'save',
            'service_xmlrpc=', 'controlpanel', 'controlpass',
            'httpd=', 'pemfile=', 'httppass=', 'errorurl=', 'webpath=',
            'logfile=', 'daemonize', 'nodaemonize', 'runas=', 'pidfile=',
            'isfrontend', 'noisfrontend', 'settings',
            'defaults', 'local=', 'domain=',
            'authdomain=', 'authhelpurl=', 'register=', 'host=',
            'noupgradeinfo', 'upgradeinfo=', 'motd=',
            'ports=', 'protos=', 'portalias=', 'rawports=',
            'tls_default=', 'tls_endpoint=',
            'fe_certname=', 'jakenoia', 'ca_certs=',
            'kitename=', 'kitesecret=',
            'backend=', 'define_backend=', 'be_config=', 'fingerpath=',
            'frontend=', 'frontends=', 'torify=', 'socksify=', 'proxy=',
            'new', 'all', 'noall', 'dyndns=', 'nozchunks', 'sslzlib',
            'buffers=', 'noprobes', 'debugio',
            # DEPRECATED:
            'webroot=', 'webaccess=', 'webindexes=']

DEBUG_IO = False
DEFAULT_CHARSET = 'utf-8'

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

WEB_POLICY_DEFAULT = 'default'
WEB_POLICY_PUBLIC = 'public'
WEB_POLICY_PRIVATE = 'private'
WEB_POLICY_OTP = 'otp'
WEB_POLICIES = (WEB_POLICY_DEFAULT, WEB_POLICY_PUBLIC,
                WEB_POLICY_PRIVATE, WEB_POLICY_OTP)

WEB_INDEX_ALL = 'all'
WEB_INDEX_ON = 'on'
WEB_INDEX_OFF = 'off'
WEB_INDEXTYPES = (WEB_INDEX_ALL, WEB_INDEX_ON, WEB_INDEX_OFF)

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
BE_STATUS_DISABLE_ONCE = -3
BE_INACTIVE = (BE_STATUS_DISABLED, BE_STATUS_DISABLE_ONCE)

BE_NONE = ['', '', None, None, None, '', BE_STATUS_UNKNOWN]

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
import httplib
import os
import random
import re
import select
import socket
rawsocket = socket.socket

import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib
import xmlrpclib
import zlib

import SocketServer
from CGIHTTPServer import CGIHTTPRequestHandler
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import Cookie

# This should be our socksipy
import sockschain as socks


##[ Conditional imports & compatibility magic! ]###############################

# Create our service-domain matching regexp
SERVICE_DOMAIN_RE = re.compile('\.(' + '|'.join(SERVICE_DOMAINS) + ')$')
SERVICE_SUBDOMAIN_RE = re.compile(r'^([A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$')

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
  import datetime
  ts_to_date = datetime.datetime.fromtimestamp
except ImportError:
  ts_to_date = str

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
SEND_ALWAYS_BUFFERS = False
SEND_MAX_BYTES = 16 * 1024

if socks.HAVE_PYOPENSSL:
  SSL = socks.SSL

elif socks.HAVE_SSL:
  SEND_ALWAYS_BUFFERS = True
  SEND_MAX_BYTES = 4 * 1024
  SSL = socks.SSL

else:
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
        raise ConfigError('Neither pyOpenSSL nor python 2.6+ '
                          'ssl modules found!')


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


# Enable system proxies
# This will all fail if we don't have PySocksipyChain available.
# FIXME: Move this code somewhere else?
socks.usesystemdefaults()
socks.wrapmodule(sys.modules[__name__])

if socks.HAVE_SSL:
  # Secure connections to pagekite.net in SSL tunnels.
  def_hop = socks.parseproxy('default')
  https_hop = socks.parseproxy('httpcs:pagekite.net:443')
  for dest in ('pagekite.net', 'up.pagekite.net', 'up.b5p.us'):
    socks.setproxy(dest, *def_hop)
    socks.addproxy(dest, *socks.parseproxy('http:%s:443' % dest))
    socks.addproxy(dest, *https_hop)
else:
  # FIXME: Should scream and shout about lack of security.
  pass


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
  YamonD = yamond.YamonD
except Exception:
  YamonD = MockYamonD


##[ PageKite.py code starts here! ]############################################

gSecret = None
def globalSecret():
  global gSecret
  if not gSecret:
    # This always works...
    gSecret = '%8.8x%s%8.8x' % (random.randint(0, 0x7FFFFFFE),
                                time.time(),
                                random.randint(0, 0x7FFFFFFE))

    # Next, see if we can augment that with some real randomness.
    try:
      newSecret = sha1hex(open('/dev/urandom').read(64) + gSecret)
      gSecret = newSecret
      LogDebug('Seeded signatures using /dev/urandom, hooray!')
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
    if (backends[d][BE_BHOST] and
        backends[d][BE_STATUS] not in BE_INACTIVE):

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
  if mimetype.startswith('text/') and ';' not in mimetype:
    mimetype += ('; charset=%s' % DEFAULT_CHARSET)
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

def HTTP_Unavailable(where, proto, domain, comment='', frame_url=None,
                     code=503, status='Unavailable', headers=None):
  if code == 401:
    headers = headers or []
    headers.append(HTTP_Header('WWW-Authenticate', 'Basic realm=PageKite'))
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
                          '</frameset></html>'], headers=headers)
  else:
    return HTTP_Response(code, status,
                         ['<html><body>', message, '</body></html>'],
                         headers=headers)

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

  #daemon = True

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


HTTP_METHODS = ['OPTIONS', 'CONNECT', 'GET', 'HEAD', 'POST', 'PUT', 'TRACE',
                'PROPFIND', 'PROPPATCH', 'MKCOL', 'DELETE', 'COPY', 'MOVE',
                'LOCK', 'UNLOCK', 'PING']
HTTP_VERSIONS = ['HTTP/1.0', 'HTTP/1.1']



##[ Protocol parsers! ]########################################################

class BaseLineParser(object):
  """Base protocol parser class."""

  PROTO = 'unknown'
  PROTOS = ['unknown']
  PARSE_UNKNOWN = -2
  PARSE_FAILED = -1
  PARSE_OK = 100

  def __init__(self, lines=None, state=PARSE_UNKNOWN, proto=PROTO):
    self.state = state
    self.protocol = proto
    self.lines = []
    self.domain = None
    self.last_parser = self
    if lines is not None:
      for line in lines:
        if not self.Parse(line): break

  def ParsedOK(self):
    return (self.state == self.PARSE_OK)

  def Parse(self, line):
    self.lines.append(line)
    return False

  def ErrorReply(self, port=None):
    return ''

class MagicLineParser(BaseLineParser):
  """Parse an unknown incoming connection request, line-by-line."""

  PROTO = 'magic'

  def __init__(self, lines=None, state=BaseLineParser.PARSE_UNKNOWN,
                     parsers=[]):
    self.parsers = [p() for p in parsers]
    BaseLineParser.__init__(self, lines, state, self.PROTO)
    if self.last_parser == self:
      self.last_parser = self.parsers[-1]

  def ParsedOK(self):
    return self.last_parser.ParsedOK()

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    self.last_parser = self.parsers[-1]
    for p in self.parsers[:]:
      if not p.Parse(line):
        LogDebug('Should remove %s' % p)
        self.parsers.remove(p)
        LogDebug('Parsers: %s' % self.parsers)
      elif p.ParsedOK():
        self.last_parser = p
        self.domain = p.domain
        self.protocol = p.protocol
        self.state = p.state
        self.parsers = [p]
        break

    if not self.parsers:
      LogDebug('No more parsers!')

    return (len(self.parsers) > 0)

class HttpLineParser(BaseLineParser):
  """Parse an HTTP request, line-by-line."""

  PROTO = 'http'
  PROTOS = ['http']
  IN_REQUEST = 11
  IN_HEADERS = 12
  IN_BODY = 13
  IN_RESPONSE = 14

  def __init__(self, lines=None, state=IN_REQUEST, testbody=False):
    self.method = None
    self.path = None
    self.version = None
    self.code = None
    self.message = None
    self.headers = []
    self.body_result = testbody
    BaseLineParser.__init__(self, lines, state, self.PROTO)

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

  def ParsedOK(self):
    return (self.state == self.IN_BODY)

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
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
      LogDebug('Parse failed: %s, %s, %s' % (self.state, err, self.lines))

    self.state = BaseLineParser.PARSE_FAILED
    return False

  def Header(self, header):
    return [h[1].strip() for h in self.headers if h[0] == header.lower()]

class FingerLineParser(BaseLineParser):
  """Parse an incoming Finger request, line-by-line."""

  PROTO = 'finger'
  PROTOS = ['finger', 'httpfinger']
  WANT_FINGER = 71

  def __init__(self, lines=None, state=WANT_FINGER):
    BaseLineParser.__init__(self, lines, state, self.PROTO)

  def ErrorReply(self, port=None):
    if port == 79:
      return ('PageKite wants to know, what domain?\n'
              'Try: finger user+domain@domain\n')
    else:
      return ''

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    if ' ' in line: return False
    if '+' in line:
      arg0, self.domain = line.strip().split('+', 1)
    elif '@' in line:
      arg0, self.domain = line.strip().split('@', 1)

    if self.domain:
      self.state = BaseLineParser.PARSE_OK
      self.lines[-1] = '%s\n' % arg0
      return True
    else:
      self.state = BaseLineParser.PARSE_FAILED
      return False

class IrcLineParser(BaseLineParser):
  """Parse an incoming IRC connection, line-by-line."""

  PROTO = 'irc'
  PROTOS = ['irc']
  WANT_USER = 61

  def __init__(self, lines=None, state=WANT_USER):
    self.seen = []
    BaseLineParser.__init__(self, lines, state, self.PROTO)

  def ErrorReply(self):
    return ':pagekite 451 :IRC Gateway requires user@HOST or nick@HOST\n'

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    if line in ('\n', '\r\n'): return True
    if self.state == IrcLineParser.WANT_USER:
      try:
        ocmd, arg = line.strip().split(' ', 1)
        cmd = ocmd.lower()
        self.seen.append(cmd)
        args = arg.split(' ')
        if cmd == 'pass':
          pass
        elif cmd in ('user', 'nick'):
          if '@' in args[0]:
            parts = args[0].split('@')
            self.domain = parts[-1]
            arg0 = '@'.join(parts[:-1])
          elif 'nick' in self.seen and 'user' in self.seen and not self.domain:
            raise Error('No domain found')

          if self.domain:
            self.state = BaseLineParser.PARSE_OK
            self.lines[-1] = '%s %s %s\n' % (ocmd, arg0, ' '.join(args[1:]))
        else:
          self.state = BaseLineParser.PARSE_FAILED
      except Exception, err:
        LogDebug('Parse failed: %s, %s, %s' % (self.state, err, self.lines))
        self.state = BaseLineParser.PARSE_FAILED

    return (self.state != BaseLineParser.PARSE_FAILED)


##[ Selectables ]##############################################################

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
                     ui=None, tracked=True, bind=None, backlog=100):
    self.fd = None

    try:
      self.SetFD(fd or rawsocket(socket.AF_INET6, socket.SOCK_STREAM), six=True)
      if bind:
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.fd.bind(bind)
        self.fd.listen(backlog)
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except:
      self.SetFD(fd or rawsocket(socket.AF_INET, socket.SOCK_STREAM))
      if bind:
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.fd.bind(bind)
        self.fd.listen(backlog)
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    self.address = address
    self.on_port = on_port
    self.created = self.bytes_logged = time.time()
    self.last_activity = 0
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
    self.logged = []
    global selectable_id
    selectable_id += 1
    selectable_id %= 0x10000
    self.sid = selectable_id
    self.alt_id = None

    if address:
      addr = address or ('x.x.x.x', 'x')
      self.log_id = 's%x/%s:%s' % (self.sid, obfuIp(addr[0]), addr[1])
    else:
      self.log_id = 's%x' % self.sid

    # Introspection
    global SELECTABLES
    if SELECTABLES is not None:
      SELECTABLES.append(self)

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
                     self.all_in + self.read_bytes,
                     self.all_out + self.wrote_bytes,
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
      self.LogTraffic(final=True)
    self.fd = None

  def SayHello(self):
    pass

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
      self.last_activity = time.time()
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
      if wait and len(self.write_blocked) > 0:
        time.sleep(0.1)
      LogDebug('Flushing...')
      loops -= 1

    if self.write_blocked: return False
    return True


class Connections(object):
  """A container for connections (Selectables), config and tunnel info."""

  def __init__(self, config):
    self.config = config
    self.ip_tracker = {}
    self.idle = []
    self.conns = []
    self.conns_by_id = {}
    self.tunnels = {}
    self.auth = None

  def start(self, auth_thread=None):
    self.auth = auth_thread or AuthThread(self)
    self.auth.start()

  def Add(self, conn, alt_id=None):
    self.idle.append(conn)
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
    if conn in self.idle:
      self.idle.remove(conn)
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
      try:
        dparts = domain.split('.')[1:]
        while len(dparts) > 1:
          wild_tid = '%s:*.%s' % (proto, '.'.join(dparts))
          if wild_tid in self.tunnels:
            return self.tunnels[wild_tid]
          dparts = dparts[1:]
      except:
        pass

      return []


class LineParser(Selectable):
  """A Selectable which parses the input as lines of text."""

  def __init__(self, fd=None, address=None, on_port=None,
                     ui=None, tracked=True):
    Selectable.__init__(self, fd, address, on_port, ui=ui, tracked=tracked)
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

  def __init__(self, fd=None, address=None, on_port=None, ui=None):
    LineParser.__init__(self, fd, address, on_port, ui=ui, tracked=False)
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
    ChunkParser.__init__(self, ui=conns.config.ui)

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
          if not conns.config.disable_zchunks:
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

    self.last_activity = time.time()
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
              HTTP_Header('Transfer-Encoding', 'chunked'),
              HTTP_Header('X-PageKite-Protos', ', '.join(['%s' % p
                            for p in self.conns.config.server_protos])),
              HTTP_Header('X-PageKite-Ports', ', '.join(
                            ['%s' % self.conns.config.server_portalias.get(p, p)
                             for p in self.conns.config.server_ports]))]

    if not self.conns.config.disable_zchunks:
      output.append(HTTP_Header('X-PageKite-Features', 'ZChunks'))

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

  def _RecvHttpHeaders(self, fd=None):
    data = ''
    fd = fd or self.fd
    while not data.endswith('\r\n\r\n') and not data.endswith('\n\n'):
      try:
        buf = fd.recv(1)
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

    sspec = server.split(':')
    if len(sspec) < 2: sspec = (sspec[0], 443)

    # Use chained SocksiPy to secure our communication.
    socks.DEBUG = (DEBUG_IO or socks.DEBUG) and LogDebug
    sock = socks.socksocket()
    if socks.HAVE_SSL:
      chain = ['default']
      if self.conns.config.fe_anon_tls_wrap:
        chain.append('ssl-anon:%s:%s' % (sspec[0], sspec[1]))
      if self.conns.config.fe_certname:
        chain.append('http:%s:%s' % (sspec[0], sspec[1]))
        chain.append('ssl:%s:443' % ','.join(self.conns.config.fe_certname))
      for hop in chain:
        sock.addproxy(*socks.parseproxy(hop))
    self.SetFD(sock)

    try:
      self.fd.settimeout(20.0) # Missing in Python 2.2
    except Exception:
      self.fd.setblocking(1)

    self.fd.connect((sspec[0], int(sspec[1])))
    replace_sessionid = self.conns.config.servers_sessionids.get(server, None)
    if (not self.Send(HTTP_PageKiteRequest(server,
                                         conns.config.backends,
                                       tokens,
                                     nozchunks=conns.config.disable_zchunks,
                                    replace=replace_sessionid), try_flush=True)
        or not self.Flush(wait=True)):
      return None, None

    data = self._RecvHttpHeaders()
    if not data: return None, None

    self.fd.setblocking(0)
    parse = HttpLineParser(lines=data.splitlines(),
                           state=HttpLineParser.IN_RESPONSE)

    return data, parse

  def _BackEnd(server, backends, require_all, conns):
    """This is the back-end end of a tunnel."""
    self = Tunnel(conns)
    self.backends = backends
    self.require_all = require_all
    self.server_info[self.S_NAME] = server
    abort = True
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
          conns.config.ui.Notify('Connecting to front-end %s ...' % sname,
                                 color=conns.config.ui.GREY)
          conns.config.ui.Notify(' - Protocols: %s' % ', '.join(self.server_info[self.S_PROTOS]),
                                 color=conns.config.ui.GREY)
          conns.config.ui.Notify(' - Ports: %s' % ', '.join(self.server_info[self.S_PORTS]),
                                 color=conns.config.ui.GREY)
          if 'raw' in self.server_info[self.S_PROTOS]:
            conns.config.ui.Notify(' - Raw ports: %s' % ', '.join(self.server_info[self.S_RAW_PORTS]),
                                   color=conns.config.ui.GREY)

          for quota in parse.Header('X-PageKite-Quota'):
            self.quota = [int(quota), None, None]
            self.Log([('FE', sname), ('quota', quota)])
            qGB = 1024 * 1024
            conns.config.ui.Notify(('You have %.2f GB of quota left.'
                                    ) % (float(quota) / qGB),
                                   prefix=(int(quota) < qGB) and '!' or ' ',
                                   color=conns.config.ui.MAGENTA)

          invalid_reasons = {}
          for request in parse.Header('X-PageKite-Invalid-Why'):
            # This is future-compatible, in that we can add more fields later.
            details = request.split(';')
            invalid_reasons[details[0]] = details[1]

          for request in parse.Header('X-PageKite-Invalid'):
            proto, domain, srand = request.split(':')
            reason = invalid_reasons.get(request, 'unknown')
            self.Log([('FE', sname),
                      ('err', 'Rejected'),
                      ('proto', proto),
                      ('reason', reason),
                      ('domain', domain)])
            conns.config.ui.Notify(('REJECTED: %s:%s (invalid or out of quota)'
                                    ) % (proto, domain),
                                   prefix='!', color=conns.config.ui.RED)

          for request in parse.Header('X-PageKite-Duplicate'):
            abort = True
            proto, domain, srand = request.split(':')
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('err', 'Duplicate'),
                      ('proto', proto),
                      ('domain', domain)])
            conns.config.ui.Notify(('REJECTED: %s:%s (duplicate)'
                                    ) % (proto, domain),
                                   prefix='!', color=conns.config.ui.YELLOW)

          if not conns.config.disable_zchunks:
            for feature in parse.Header('X-PageKite-Features'):
              if feature == 'ZChunks': self.EnableZChunks(level=9)

          ssl_available = {}
          for request in parse.Header('X-PageKite-SSL-OK'):
            ssl_available[request] = True

          for request in parse.Header('X-PageKite-OK'):
            abort = False
            proto, domain, srand = request.split(':')
            conns.Tunnel(proto, domain, self)
            if request in ssl_available:
              self.remote_ssl[(proto, domain)] = True
            self.Log([('FE', sname),
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
    if self.conns: self.conns.Remove(self)
    self.Cleanup()
    return True

  def ProcessEofWrite(self):
    return self.ProcessEofRead()

  def ProcessChunk(self, data):
    try:
      headers, data = data.split('\r\n\r\n', 1)
      parse = HttpLineParser(lines=headers.splitlines(),
                             state=HttpLineParser.IN_HEADERS)
    except ValueError:
      LogError('Tunnel::ProcessChunk: Corrupt packet!')
      return False

    try:
      if parse.Header('Quota'):
        if self.quota:
          self.quota[0] = int(parse.Header('Quota')[0])
        else:
          self.quota = [int(parse.Header('Quota')[0]), None, None]
        self.conns.config.ui.Notify(('You have %.2f GB of quota left.'
                                     ) % (float(self.quota[0]) / (1024*1024)),
                                    color=self.conns.config.ui.MAGENTA)
      if parse.Header('PING'): return self.SendPong()
      if parse.Header('ZRST') and not self.ResetZChunks(): return False
      if parse.Header('SPD') and not self.Throttle(parse): return False
      if parse.Header('NOOP'): return True
    except Exception, e:
      LogError('Tunnel::ProcessChunk: Corrupt chunk: %s' % e)
      return False

    proto = conn = sid = None
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
              if conn is None:
                if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                                          HTTP_Unavailable('be', proto, host,
                                       frame_url=self.conns.config.error_url))):
                  return False
              elif not conn:
                if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                                          HTTP_Unavailable('be', proto, host,
                                       frame_url=self.conns.config.error_url,
                                      code=401))):
                  return False
              elif rIp:
                add_headers = ('\nX-Forwarded-For: %s\r\n'
                               'X-PageKite-Port: %s\r\n'
                               'X-PageKite-Proto: %s\r\n'
                               ) % (rIp, port,
                                    # FIXME: Checking for port == 443 is wrong!
                                    ((rTLS or (int(port) == 443)) and 'https'
                                                                   or 'http'))
                rewritehost = conn.config.get('rewritehost', False)
                if rewritehost:
                  if rewritehost is True:
                    rewritehost = conn.backend[BE_BHOST]
                  for hdr in ('host', 'connection', 'keep-alive'):
                    data = re.sub(r'(?mi)^'+hdr, 'X-Old-'+hdr, data)
                  add_headers += ('Connection: close\r\n'
                                  'Host: %s\r\n') % rewritehost
                req, rest = re.sub(r'(?mi)^x-forwarded-for',
                                   'X-Old-Forwarded-For', data).split('\n', 1)
                data = ''.join([req, add_headers, rest])

            elif proto == 'httpfinger':
              # Rewrite a finger request to HTTP.
              try:
                firstline, rest = data.split('\n', 1)
                if conn.config.get('rewritehost', False):
                  rewritehost = conn.backend[BE_BHOST]
                else:
                  rewritehost = host
                if '%s' in self.conns.config.finger_path:
                  args =  (firstline.strip(), rIp, rewritehost, rest)
                else:
                  args =  (rIp, rewritehost, rest)
                data = ('GET '+self.conns.config.finger_path+' HTTP/1.1\r\n'
                        'X-Forwarded-For: %s\r\n'
                        'Connection: close\r\n'
                        'Host: %s\r\n\r\n%s') % args
              except Exception, e:
                self.LogError('Error formatting HTTP-Finger: %s' % e)
                conn = None

          if conn:
            self.users[sid] = conn

            if proto == 'httpfinger':
              conn.fd.setblocking(1)
              conn.Send(data, try_flush=True) or conn.Flush(wait=True)
              self._RecvHttpHeaders(fd=conn.fd)
              conn.fd.setblocking(0)
              data = ''

      if not conn:
        self.CloseStream(sid)
        if not self.SendStreamEof(sid): return False
      else:
        if not conn.Send(data, try_flush=True):
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
        if backends[d][BE_BHOST]:
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

  def __init__(self, address, ui=None):
    Selectable.__init__(self, address=address, ui=ui)
    self.tunnel = None
    self.conns = None
    self.backend = BE_NONE[:]
    self.config = {}

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
      self.backend = self.config = self.conns = None

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
      protos = ['http', 'https', 'websocket', 'raw', 'irc',
                'finger', 'httpfinger']
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
      if conn.my_tls: chunk_headers.append(('RTLS', 1))

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

  def _BackEnd(proto, host, sid, tunnel, on_port,
               remote_ip=None, remote_port=None, data=None):
    # This is when we open a backend connection, because a user asked for it.
    self = UserConn(None, ui=tunnel.conns.config.ui)
    self.sid = sid
    self.proto = proto
    self.host = host
    self.conns = tunnel.conns
    self.tunnel = tunnel
    failure = None

    # Try and find the right back-end. We prefer proto/port specifications
    # first, then the just the proto. If the protocol is WebSocket and no
    # tunnel is found, look for a plain HTTP tunnel.
    backend = None
    protos = [proto]
    if proto == 'probe': protos = ['http']
    if proto == 'websocket': protos.append('http')
    for p in protos:
      if not backend: backend, be = self.conns.config.GetBackendServer('%s-%s' % (p, on_port), host)
      if not backend: backend, be = self.conns.config.GetBackendServer(p, host)
      if not backend: backend, be = self.conns.config.GetBackendServer(p, CATCHALL_HN)

    logInfo = [
      ('on_port', on_port),
      ('proto', proto),
      ('domain', host),
      ('is', 'BE')
    ]
    if remote_ip: logInfo.append(('remote_ip', remote_ip))

    # Strip off useless IPv6 prefix, if this is an IPv4 address.
    if remote_ip.startswith('::ffff:') and ':' not in remote_ip[7:]:
      remote_ip = remote_ip[7:]

    if not backend or not backend[0]:
      self.ui.Notify(('%s - %s://%s:%s (FAIL: no server)'
                      ) % (remote_ip or 'unknown', proto, host, on_port),
                     prefix='?', color=self.ui.YELLOW)
    else:
      http_host = '%s/%s' % (be[BE_DOMAIN], be[BE_PORT] or '80')
      self.backend = be
      self.config = host_config = self.conns.config.be_config.get(http_host, {})

      # Access control interception: check remote IP addresses first.
      ip_keys = [k for k in host_config if k.startswith('ip/')]
      if ip_keys:
        k1 = 'ip/%s' % remote_ip
        k2 = '.'.join(k1.split('.')[:-1])
        if not (k1 in host_config or k2 in host_config):
          self.ui.Notify(('%s - %s://%s:%s (IP ACCESS DENIED)'
                          ) % (remote_ip or 'unknown', proto, host, on_port),
                         prefix='!', color=self.ui.YELLOW)
          logInfo.append(('forbidden-ip', '%s' % remote_ip))
          backend = None

      # Access control interception: check for HTTP Basic authentication.
      user_keys = [k for k in host_config if k.startswith('password/')]
      if user_keys:
        user, pwd, fail = None, None, True
        if proto in ('websocket', 'http'):
          parse = HttpLineParser(lines=data.splitlines())
          auth = parse.Header('Authorization')
          try:
            (how, ab64) = auth[0].strip().split()
            if how.lower() == 'basic':
              user, pwd = base64.decodestring(ab64).split(':')
          except:
            user = auth

          user_key = 'password/%s' % user
          if user and user_key in host_config:
            if host_config[user_key] == pwd:
              fail = False

        if fail:
          if DEBUG_IO: print '=== REQUEST\n%s\n===' % data
          self.ui.Notify(('%s - %s://%s:%s (USER ACCESS DENIED)'
                          ) % (remote_ip or 'unknown', proto, host, on_port),
                         prefix='!', color=self.ui.YELLOW)
          logInfo.append(('forbidden-user', '%s' % user))
          backend = None
          failure = ''

    if not backend:
      logInfo.append(('err', 'No back-end'))
      self.Log(logInfo)
      self.Cleanup(close=False)
      return failure

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
      self.ui.Notify(('%s - %s://%s:%s (FAIL: %s:%s is down)'
                      ) % (remote_ip or 'unknown', proto, host, on_port,
                           sspec[0], sspec[1]),
                     prefix='!', color=self.ui.YELLOW)
      self.Log(logInfo)
      self.Cleanup(close=False)
      return None

    sspec = (sspec[0], sspec[1])
    be_name = (sspec == self.conns.config.ui_sspec) and 'builtin' or ('%s:%s' % sspec)
    self.ui.Status('serving')
    self.ui.Notify(('%s < %s://%s:%s (%s)'
                    ) % (remote_ip or 'unknown', proto, host, on_port, be_name))
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
    MagicProtocolParser.__init__(self, fd, address, on_port, ui=conns.config.ui)
    self.peeking = True

    # Set up our parser chain.
    self.parsers = [HttpLineParser]
    if IrcLineParser.PROTO in conns.config.server_protos:
      self.parsers.append(IrcLineParser)
    if FingerLineParser.PROTO in conns.config.server_protos:
      self.parsers.append(FingerLineParser)
    self.parser = MagicLineParser(parsers=self.parsers)

    self.conns = conns
    self.conns.Add(self)
    self.sid = -1

    self.host = None
    self.proto = None
    self.said_hello = False

  def Cleanup(self, close=True):
    if self.conns: self.conns.Remove(self)
    MagicProtocolParser.Cleanup(self, close=close)
    self.conns = self.parser = None

  def SayHello(self):
    if self.said_hello:
      return
    else:
      self.said_hello = True

    if self.on_port in (25, 125, ):
      # FIXME: We don't actually support SMTP yet and 125 is bogus.
      self.Send(['220 ready ESMTP PageKite Magic Proxy\n'], try_flush=True)

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
    if not self.parser.ParsedOK(): return True

    self.parser = self.parser.last_parser
    if self.parser.protocol == HttpLineParser.PROTO:
      # HTTP has special cases, including CONNECT etc.
      return self.ProcessParsedHttp(line, lines)
    else:
      return self.ProcessParsedMagic(self.parser.PROTOS, line, lines)

  def ProcessParsedMagic(self, protos, line, lines):
    for proto in protos:
      if UserConn.FrontEnd(self, self.address,
                           proto, self.parser.domain, self.on_port,
                           self.parser.lines + lines, self.conns) is not None:
        self.Cleanup(close=False)
        return True

    self.Send([self.parser.ErrorReply(port=self.on_port)], try_flush=True)
    self.Cleanup()
    return False

  def ProcessParsedHttp(self, line, lines):
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

          # These allow explicit CONNECTs to direct http(s) or raw backends.
          # If no match is found, we fall through to default HTTP processing.

          if cport in (80, 8080):
            if (('http'+sid1) in tunnels) or (
                ('http'+sid2) in tunnels):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpLineParser()
              self.Send(HTTP_ConnectOK(), try_flush=True)
              return True

          if cport == 443:
            if (('https'+sid1) in tunnels) or (
                ('https'+sid2) in tunnels) or (
                chost in self.conns.config.tls_endpoints):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpLineParser()
              self.Send(HTTP_ConnectOK(), try_flush=True)
              return self.ProcessTls(''.join(lines), chost)

          if (cport in self.conns.config.server_raw_ports or
              VIRTUAL_PN in self.conns.config.server_raw_ports):
            for raw in ('raw', 'finger'):
              if ((raw+sid1) in tunnels) or ((raw+sid2) in tunnels):
                (self.on_port, self.host) = (cport, chost)
                self.parser = HttpLineParser()
                self.Send(HTTP_ConnectOK(), try_flush=True)
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
          self.Send(HTTP_NoFeConnection(),
                    try_flush=True)
        else:
          self.Send(HTTP_Unavailable('fe', self.proto, self.host,
                                     frame_url=self.conns.config.error_url),
                    try_flush=True)

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
        self.fd = socks.SSL_Connect(ctx, self.fd,
                                    accepted=True, server_side=True)
        self.peeking = False
        self.is_tls = False
        self.my_tls = True
        return True

    if domains and domains[0] is not None:
      if UserConn.FrontEnd(self, self.address,
                           'https', domains[0], self.on_port,
                           [data], self.conns) is not None:
        # We are done!
        self.EatPeeked()
        self.Cleanup(close=False)
        return True
      else:
        # If we know how to terminate the TLS/SSL, do so!
        ctx = self.conns.config.GetTlsEndpointCtx(domains[0])
        if ctx:
          self.fd = socks.SSL_Connect(ctx, self.fd,
                                      accepted=True, server_side=True)
          self.peeking = False
          self.is_tls = False
          return True
        else:
          return False

    return False

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
    Selectable.__init__(self, bind=(host, port), backlog=backlog)
    self.Log([('listen', '%s:%s' % (host, port))])
    conns.config.ui.Notify(' - Listening on %s:%s' % (host or '*', port))

    self.connclass = connclass
    self.port = port
    self.last_activity = self.created + 1
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


class HttpUiThread(threading.Thread):
  """Handle HTTP UI in a separate thread."""

  daemon = True

  def __init__(self, pkite, conns,
               server=None, handler=None, ssl_pem_filename=None):
    threading.Thread.__init__(self)
    if not (server and handler):
      self.serve = False
      return

    self.ui_sspec = pkite.ui_sspec
    self.httpd = server(self.ui_sspec, pkite, conns,
                        handler=handler,
                        ssl_pem_filename=ssl_pem_filename)
    self.httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.ui_sspec = pkite.ui_sspec = (self.ui_sspec[0],
                                      self.httpd.socket.getsockname()[1])
    self.serve = True

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



class TunnelManager(threading.Thread):
  """Create new tunnels as necessary or kill idle ones."""

  daemon = True

  def __init__(self, pkite, conns):
    threading.Thread.__init__(self)
    self.pkite = pkite
    self.conns = conns

  def CheckIdleConns(self, now):
    active = []
    for conn in self.conns.idle:
      if conn.last_activity:
        active.append(conn)
      elif conn.created < now - 10:
        LogDebug('Removing idle connection: %s' % conn)
        self.conns.Remove(conn)
        conn.Cleanup()
      elif conn.created < now - 1:
        conn.SayHello()
    for conn in active:
      self.conns.idle.remove(conn)

  def CheckTunnelQuotas(self, now):
    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        tunnel.RecheckQuota(self.conns, when=now)

  def PingTunnels(self, now):
    dead = {}
    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        grace = max(40, len(tunnel.write_blocked)/(tunnel.write_speed or 0.001))
        if tunnel.last_activity == 0:
          pass
        elif tunnel.last_activity < tunnel.last_ping-(5+grace):
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
    self.explained = False
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
          for tid in self.conns.tunnels:
            proto, domain = tid.split(':')
            if '-' in proto:
              proto, port = proto.split('-')
            else:
              port = ''
            self.pkite.ui.Notify(('Flying: %s://%s%s/'
                                  ) % (proto, domain, port and ':'+port or ''),
                                 prefix='~<>', color=self.pkite.ui.CYAN)

        if len(self.pkite.backends.keys()):
          self.pkite.ui.Status('flying')
          for tid in self.conns.tunnels:
            be = self.pkite.backends.get(tid)
            if be and be[BE_STATUS] not in BE_INACTIVE:
              domain = be[BE_DOMAIN]
              port = be[BE_PORT]
              proto = be[BE_PROTO]

              # Do we have auto-SSL at the front-end?
              protoport = (port and ('%s-%s' % (proto, port)) or proto)
              tunnels = self.conns.Tunnel(protoport, domain)
              if proto == 'http' and tunnels:
                proto = 'https'
                for t in tunnels:
                  if (protoport, domain) not in t.remote_ssl: proto = 'http'

              prox = (proto == 'raw') and ' (HTTP proxied)' or ''
              if proto == 'raw' and port in ('22', 22): proto = 'ssh'
              url = '%s://%s%s' % (proto, domain, port and (':%s' % port) or '')
              self.pkite.ui.Notify(('Flying %s:%s as %s/%s'
                                    ) % (be[BE_BHOST], be[BE_BPORT], url, prox),
                                    prefix='~<>', color=self.pkite.ui.CYAN)
              domainp = '%s/%s' % (domain, port or '80')
              if (self.pkite.ui_sspec and
                  domainp in self.pkite.ui_paths and
                  be[BE_BHOST] == self.pkite.ui_sspec[0] and
                  be[BE_BPORT] == self.pkite.ui_sspec[1]):
                dpaths = self.pkite.ui_paths[domainp]
                for dp in sorted(dpaths.keys()):
                  self.pkite.ui.Notify(' - %s%s' % (url, dp),
                                       color=self.pkite.ui.BLUE)

          self.PingTunnels(time.time())

      tunnel_count = len(self.pkite.conns and
                         self.pkite.conns.TunnelServers() or [])
      tunnel_total = len(self.pkite.servers)
      if tunnel_count == 0:
        if self.pkite.isfrontend:
          self.pkite.ui.Status('idle', message='Waiting for back-ends.')
        else:
          self.pkite.ui.Status('down', color=self.pkite.ui.RED,
                       message='Not connected to any front-ends, will retry...')
      elif tunnel_count < tunnel_total:
        self.pkite.ui.Status('flying', color=self.pkite.ui.YELLOW,
                    message=('Only connected to %d/%d front-ends, will retry...'
                             ) % (tunnel_count, tunnel_total))
      elif problem:
        self.pkite.ui.Status('flying', color=self.pkite.ui.YELLOW,
                      message='DynDNS updates may be incomplete, will retry...')

      for i in xrange(0, check_interval):
        if self.keep_running:
          time.sleep(1)
          if self.pkite.isfrontend:
            self.CheckIdleConns(time.time())


class NullUi(object):
  """This is a UI that always returns default values or raises errors."""

  WANTS_STDERR = False

  def __init__(self, welcome=None):
    if sys.platform in ('win32', 'os2', 'os2emx'):
      self.CLEAR = '\n\n'
      self.NORM = self.WHITE = self.GREY = self.GREEN = self.YELLOW = ''
      self.BLUE = self.RED = self.MAGENTA = self.CYAN = ''
    else:
      self.CLEAR = '\033[H\033[J'
      self.NORM = '\033[0m'
      self.WHITE = '\033[1m'
      self.GREY =  '\033[0m' #'\033[30;1m'
      self.RED = '\033[31;1m'
      self.GREEN = '\033[32;1m'
      self.YELLOW = '\033[33;1m'
      self.BLUE = '\033[34;1m'
      self.MAGENTA = '\033[35;1m'
      self.CYAN = '\033[36;1m'

    self.in_wizard = False
    self.wizard_tell = None
    self.last_tick = 0
    self.notify_history = {}
    self.status_tag = ''
    self.status_col = self.NORM
    self.status_msg = ''
    self.welcome = welcome
    self.tries = 200
    self.Splash()

  def Splash(self): pass

  def Welcome(self): pass
  def StartWizard(self, title): pass
  def EndWizard(self): pass
  def Spacer(self): pass

  def Browse(self, url):
    import webbrowser
    self.Tell(['Opening %s in your browser...' % url], error=True)
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

  def Notify(self, message, prefix=' ',
             popup=False, color=None, now=None, alignright=''):
    if popup: Log([('info', '%s%s%s' % (message,
                                        alignright and ' ' or '',
                                        alignright))])

  def Status(self, tag, message=None, color=None): pass

  def ExplainError(self, error, title, subject=None):
    if error == 'pleaselogin':
      self.Tell([title, 'You already have an account. Log in to continue.'
                 ], error=True)
    elif error == 'email':
      self.Tell([title, 'Invalid e-mail address. Please try again?'
                 ], error=True)
    elif error == 'honey':
      self.Tell([title, 'Hmm. Somehow, you triggered the spam-filter.'
                 ], error=True)
    elif error in ('domaintaken', 'domain', 'subdomain'):
      self.Tell([title, 'Sorry, that domain (%s) is unavailable.' % subject
                 ], error=True)
    elif error == 'checkfailed':
      self.Tell([title, 'That domain (%s) is not correctly set up.' % subject
                 ], error=True)
    else:
      self.Tell([title, 'Error code: %s' % error, 'Try again later?'
                 ], error=True)


class PageKite(object):
  """Configuration and master select loop."""

  def __init__(self, ui=None, http_handler=None, http_server=None):
    self.progname = ((sys.argv[0] or 'pagekite.py').split('/')[-1]
                                                   .split('\\')[-1])
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
    self.server_protos = ['http', 'https', 'websocket', 'irc',
                          'finger', 'httpfinger', 'raw']

    self.tls_default = None
    self.tls_endpoints = {}
    self.fe_certname = []
    self.fe_anon_tls_wrap = False

    self.service_provider = SERVICE_PROVIDER
    self.service_xmlrpc = SERVICE_XMLRPC

    self.daemonize = False
    self.pidfile = None
    self.logfile = None
    self.setuid = None
    self.setgid = None
    self.ui_request_handler = http_handler
    self.ui_http_server = http_server
    self.ui_httpd = None
    self.ui_sspec = None
    self.ui_socket = None
    self.ui_password = None
    self.ui_pemfile = None
    self.ui_magic_file = '.pagekite.magic'
    self.ui_paths = {}
    self.be_config = {}
    self.disable_zchunks = False
    self.enable_sslzlib = False
    self.buffer_max = 1024
    self.error_url = None
    self.finger_path = '/~%s/.finger'

    self.tunnel_manager = None
    self.client_mode = 0

    self.proxy_server = None
    self.require_all = False
    self.no_probes = False
    self.servers = []
    self.servers_manual = []
    self.servers_auto = None
    self.servers_new_only = False
    self.servers_no_ping = False
    self.servers_preferred = []
    self.servers_sessionids = {}

    self.kitename = ''
    self.kitesecret = ''
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
    self.autosave = 0
    self.reloadfile = None
    self.added_kites = False
    self.ui = ui or NullUi()

    self.save = 0
    self.kite_add = False
    self.kite_only = False
    self.kite_disable = False
    self.kite_remove = False

    # Searching for our configuration file!  We prefer the documented
    # 'standard' locations, but if nothing is found there and something local
    # exists, use that instead.
    try:
      if sys.platform in ('win32', 'os2', 'os2emx'):
        self.rcfile = os.path.join(os.path.expanduser('~'), 'pagekite.cfg')
        self.devnull = 'nul'
      else:
        # Everything else
        self.rcfile = os.path.join(os.path.expanduser('~'), '.pagekite.rc')
        self.devnull = '/dev/null'

    except Exception, e:
      # The above stuff may fail in some cases, e.g. on Android in SL4A.
      self.rcfile = 'pagekite.cfg'
      self.devnull = '/dev/null'

    # Look for CA Certificates. If we don't find them in the host OS,
    # we assume there might be something good in the program itself.
    self.ca_certs_default = '/etc/ssl/certs/ca-certificates.crt'
    if not os.path.exists(self.ca_certs_default):
      self.ca_certs_default = sys.argv[0]
    self.ca_certs = self.ca_certs_default

  def SetLocalSettings(self, ports):
    self.isfrontend = True
    self.servers_auto = None
    self.servers_manual = []
    self.server_ports = ports
    self.backends = self.ArgToBackendSpecs('http:localhost:localhost:builtin:-')

  def SetServiceDefaults(self, clobber=True, check=False):
    def_dyndns    = (DYNDNS['pagekite.net'], {'user': '', 'pass': ''})
    def_frontends = (1, 'frontends.b5p.us', 443)
    def_ca_certs  = sys.argv[0]
    def_fe_certs  = ['b5p.us', 'frontends.b5p.us', 'pagekite.net']
    def_error_url = 'https://pagekite.net/offline/?'
    if check:
      return (self.dyndns == def_dyndns and
              self.servers_auto == def_frontends and
              self.error_url == def_error_url and
              self.ca_certs == def_ca_certs and
              (self.fe_certname == def_fe_certs or not socks.HAVE_SSL))
    else:
      self.dyndns = (not clobber and self.dyndns) or def_dyndns
      self.servers_auto = (not clobber and self.servers_auto) or def_frontends
      self.error_url = (not clobber and self.error_url) or def_error_url
      self.ca_certs = def_ca_certs
      if socks.HAVE_SSL:
        for cert in def_fe_certs:
          if cert not in self.fe_certname:
            self.fe_certname.append(cert)
        self.fe_certname.sort()
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
      '#/ Built-in HTTPD settings',
      (self.ui_sspec and 'httpd=%s:%d' % self.ui_sspec
                      or '# httpd=host:port'),
      (self.ui_password and 'httppass=%s' % self.ui_password
                         or '# httppass=YOURSECRET'),
      (self.ui_pemfile and 'pemfile=%s' % self.ui_pemfile
                        or '# pemfile=/path/to/sslcert.pem'),
    ]
    for http_host in sorted(self.ui_paths.keys()):
      for path in sorted(self.ui_paths[http_host].keys()):
        p = self.ui_paths[http_host][path]
        config.append('webpath=%s:%s:%s:%s' % (http_host, path, p[0], p[1]))
    config.append('')

    if self.SetServiceDefaults(check=True):
      config.extend([
        '#/ Use service default settings',
        'defaults',
        '',
        '#/ Manual front-ends (optional)'
      ])
      if self.servers_manual:
        for server in sorted(self.servers_manual):
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
        for server in sorted(self.servers_manual):
          config.append('frontend=%s' % server)
      else:
        config.append('# frontend=hostname:port')
      for server in sorted(self.fe_certname):
        config.append('fe_certname=%s' % server)
      if self.ca_certs != self.ca_certs_default:
        config.append('ca_certs=%s' % self.ca_certs)
      else:
        config.append('# ca_certs=%s' % self.ca_certs)
      if self.dyndns:
        provider, args = self.dyndns
        for prov in sorted(DYNDNS.keys()):
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
          (self.finger_path and ('fingerpath=%s' % self.finger_path) or '# fingerpath=/~%s/.finger'),
        ])
      config.extend([
        '#/ Replace with this to just use service defaults:',
        '# defaults',
      ])

    config.extend([
      '',
      '#/ Your kites and local back-end servers',
      '#',
      (self.kitename and ('kitename=%s' % self.kitename) or '#kitename=NAME'),
      (self.kitesecret and ('kitesecret=%s' % self.kitesecret) or '#kitesecret=SECRET'),
      '#',
    ])
    bprinted = 0
    for bid in sorted(self.backends.keys()):
      be = self.backends[bid]
      proto, domain = bid.split(':')
      if be[BE_BHOST]:
        config.append(('%s=%s:%s:%s:%s:%s'
                       ) % ((be[BE_STATUS] == BE_STATUS_DISABLED
                             ) and 'define_backend' or 'backend',
                   proto, ((domain == self.kitename) and '@kitename' or domain),
              be[BE_BHOST], be[BE_BPORT],
         (be[BE_SECRET] == self.kitesecret) and '@kitesecret' or be[BE_SECRET]))
        bprinted += 1
    if bprinted == 0:
      config.append('# backend=http:YOU.pagekite.me:localhost:80:SECRET')
    for http_host in sorted(self.be_config.keys()):
      for key in sorted(self.be_config[http_host].keys()):
        config.append('be_config=%s:%s:%s' % (http_host, key,
                                              self.be_config[http_host][key]))
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
      (self.savefile and safe and 'savefile=%s' % self.savefile
                               or '# savefile=/path/to/savefile'),
      (self.autosave and 'autosave' or '# autosave'),
      '',
      '#/ Front-end Options:',
      (self.isfrontend and 'isfrontend' or '# isfrontend')
    ])
    comment = ((not self.isfrontend) and '# ' or '')
    config.extend([
      (self.server_host and '%shost=%s' % (comment, self.server_host)
                         or '# host=machine.domain.com'),
      '%sports=%s' % (comment, ','.join(['%s' % x for x in sorted(self.server_ports)] or [])),
      '%sprotos=%s' % (comment, ','.join(['%s' % x for x in sorted(self.server_protos)] or []))
    ])
    for pa in self.server_portalias:
      config.append('portalias=%s:%s' % (int(pa), int(self.server_portalias[pa])))
    config.extend([
      '%srawports=%s' % (comment or (not self.server_raw_ports) and '# ' or '',
                         ','.join(['%s' % x for x in sorted(self.server_raw_ports)] or [])),
      (self.auth_domain and '%sauthdomain=%s' % (comment, self.auth_domain)
                         or '# authdomain=foo.com')
    ])
    for bid in sorted(self.backends.keys()):
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
    for ep in sorted(self.tls_endpoints.keys()):
      config.append('tls_endpoint=%s:%s' % (ep, self.tls_endpoints[ep][0]))
      eprinted += 1
    if eprinted == 0:
      config.append('# tls_endpoint=DOMAIN:PEM_FILE')
    config.extend([
      (self.tls_default and 'tls_default=%s' % self.tls_default
                         or '# tls_default=DOMAIN'),
      '',
      '#/ Systems administration settings:',
      (self.daemonize and 'daemonize'
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

  def ListKites(self):
    self.ui.welcome = '>>> ' + self.ui.WHITE + 'Your kites:' + self.ui.NORM
    message = []
    for bid in sorted(self.backends.keys()):
      be = self.backends[bid]
      be_be = (be[BE_BHOST], be[BE_BPORT])
      backend = (be_be == self.ui_sspec) and 'builtin' or '%s:%s' % be_be
      if '-' in be[BE_PROTO]:
        fe_proto, fe_port = be[BE_PROTO].split('-', 1)
      else:
        fe_proto, fe_port = be[BE_PROTO], ''

      frontend = '%s://%s%s%s' % (fe_proto, be[BE_DOMAIN],
                                  fe_port and ':' or '', fe_port)

      if be[BE_STATUS] == BE_STATUS_DISABLED:
        color = self.ui.GREY
        status = '(disabled)'
      else:
        color = self.ui.NORM
        status = (fe_proto == 'raw') and '(HTTP proxied)' or ''
      message.append(''.join([color, backend, ' ' * (19-len(backend)),
                              frontend, ' ' * (42-len(frontend)), status]))
    message.append(self.ui.NORM)
    self.ui.Tell(message)

  def PrintSettings(self, safe=False):
    print '\n'.join(self.GenerateConfig(safe=safe))

  def SaveUserConfig(self):
    self.savefile = self.savefile or self.rcfile
    try:
      fd = open(self.savefile, 'w')
      fd.write('\n'.join(self.GenerateConfig(safe=True)))
      fd.close()
      self.ui.Tell(['Settings saved to: %s' % self.savefile])
      self.ui.Spacer()
      Log([('saved', 'Settings saved to: %s' % self.savefile)])
    except Exception, e:
      self.ui.Tell(['ERROR: Could not save to %s: %s' % (self.savefile, e)])
      self.ui.Spacer()
      LogError('Could not save to %s: %s' % (self.savefile, e))

  def FallDown(self, message, help=True, longhelp=False, noexit=False):
    if self.conns and self.conns.auth: self.conns.auth.quit()
    if self.ui_httpd: self.ui_httpd.quit()
    if self.tunnel_manager: self.tunnel_manager.quit()
    self.conns = self.ui_httpd = self.tunnel_manager = None
    if help or longhelp:
      print longhelp and DOC or MINIDOC
      print '***'
    else:
      self.ui.Status('exiting', message=(message or 'Good-bye!'))
    if message: print 'Error: %s' % message
    if DEBUG_IO: traceback.print_exc(file=sys.stderr)
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
      if self.backends[backend][BE_STATUS] not in BE_INACTIVE:
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
    if bhost == '-' or not bhost: return None, None
    return (bhost, bport), backend

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

      secret = (self.GetBackendData(protoport, domain) or BE_NONE)[BE_SECRET]
      if not secret:
        secret = (self.GetBackendData(proto, domain) or BE_NONE)[BE_SECRET]
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

  def ConfigureFromDirectory(self, dirname):
    for fn in sorted(os.listdir(dirname)):
      if not fn.startswith('.') and fn.endswith('.rc'):
        self.ConfigureFromFile(os.path.join(dirname, fn))

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
      if parts[1].startswith('built') or ('.' in parts[0] and
                                          os.path.exists(parts[1])):
        fe_domain, be_port = parts[0], parts[1]
        protos = 'http'
      else:
        try:
          fe_domain, be_port = parts[0], '%s' % int(parts[1])
          protos = 'http'
        except:
          be_port = ''
          protos, fe_domain = parts
    elif len(parts) == 1:
      fe_domain = parts[0]
    else:
      return {}

    # Allow http:// as a common typo instead of http:
    fe_domain = fe_domain.replace('/', '').lower()

    # Allow easy referencing of built-in HTTPD
    if be_port.startswith('built'):
      self.BindUiSspec()
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
            if len(parts) == 1:
              port = '*'
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
        if proto and (proto != be[BE_PROTO]): continue
        if bhost and (bhost.lower() != be[BE_BHOST]): continue
        if bport and (int(bport) != be[BE_BHOST]): continue
        if port and (port != '*') and (int(port) != be[BE_PORT]): continue
        backends[bid] = be[:]
        backends[bid][BE_STATUS] = status
        matches += 1

      if matches == 0:
        proto = (proto or 'http')
        bhost = (bhost or 'localhost')
        bport = (bport or (proto in ('http', 'httpfinger', 'websocket') and 80)
                       or (proto == 'irc' and 6667)
                       or (proto == 'https' and 443)
                       or (proto == 'finger' and 79))
        if port:
          bid = '%s-%d:%s' % (proto, int(port), fdom)
        else:
          bid = '%s:%s' % (proto, fdom)

        backends[bid] = BE_NONE[:]
        backends[bid][BE_PROTO] = proto
        backends[bid][BE_PORT] = port and int(port) or ''
        backends[bid][BE_DOMAIN] = fdom
        backends[bid][BE_BHOST] = bhost.lower()
        backends[bid][BE_BPORT] = int(bport)
        backends[bid][BE_SECRET] = sec
        backends[bid][BE_STATUS] = status

    return backends

  def BindUiSspec(self):
    # Create the UI thread
    if self.ui_httpd:
      self.ui_httpd.httpd.socket.close()
    self.ui_sspec = self.ui_sspec or ('localhost', 0)
    self.ui_httpd = HttpUiThread(self, self.conns,
                                 handler=self.ui_request_handler,
                                 server=self.ui_http_server,
                                 ssl_pem_filename = self.ui_pemfile)
    return self.ui_sspec

  def Configure(self, argv):
    self.conns = self.conns or Connections(self)
    opts, args = getopt.getopt(argv, OPT_FLAGS, OPT_ARGS)

    for opt, arg in opts:
      if opt in ('-o', '--optfile'):
        self.ConfigureFromFile(arg)
      elif opt in ('-O', '--optdir'):
        self.ConfigureFromDirectory(arg)
      elif opt == '--reloadfile':
        self.ConfigureFromFile(arg)
        self.reloadfile = arg
      elif opt in ('-S', '--savefile'):
        if self.savefile: raise ConfigError('Multiple save-files!')
        self.savefile = arg
      elif opt == '--autosave':
        self.autosave = True
      elif opt == '--noautosave':
        self.autosave = False
      elif opt == '--save':
        self.save = True
      elif opt == '--only':
        self.save = self.kite_only = True
        if self.kite_remove or self.kite_add or self.kite_disable:
          raise ConfigError('One change at a time please!')
      elif opt == '--add':
        self.save = self.kite_add = True
        if self.kite_remove or self.kite_only or self.kite_disable:
          raise ConfigError('One change at a time please!')
      elif opt == '--remove':
        self.save = self.kite_remove = True
        if self.kite_add or self.kite_only or self.kite_disable:
          raise ConfigError('One change at a time please!')
      elif opt == '--disable':
        self.save = self.kite_disable = True
        if self.kite_add or self.kite_only or self.kite_remove:
          raise ConfigError('One change at a time please!')
      elif opt == '--list': pass

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
          self.ui_sspec = (host, 0)

      elif opt == '--webpath':
        host, path, policy, fpath = arg.split(':', 3)

        # Defaults...
        path = path or os.path.normpath(fpath)
        host = host or '*'
        policy = policy or WEB_POLICY_DEFAULT

        if policy not in WEB_POLICIES:
          raise ConfigError('Policy must be one of: %s' % WEB_POLICIES)
        elif os.path.isdir(fpath):
          if not path.endswith('/'): path += '/'

        hosti = self.ui_paths.get(host, {})
        hosti[path] = (policy or 'public', os.path.abspath(fpath))
        self.ui_paths[host] = hosti

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
      elif opt in ('--proxy', '--socksify', '--torify'):
        if opt == '--proxy':
          socks.setdefaultproxy()
          for proxy in arg.split(','):
            socks.adddefaultproxy(*socks.parseproxy(proxy))
        else:
          (host, port) = arg.split(':')
          socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, int(port))

        if not self.proxy_server:
          # Make DynDNS updates go via the proxy.
          socks.wrapmodule(urllib)
          self.proxy_server = arg
        else:
          self.proxy_server += ',' + arg

        if opt == '--torify':
          self.servers_new_only = True  # Disable initial DNS lookups (leaks)
          self.servers_no_ping = True   # Disable front-end pings
          self.crash_report_url = None  # Disable crash reports

          # This increases the odds of unrelated requests getting lumped
          # together in the tunnel, which makes traffic analysis harder.
          global SEND_ALWAYS_BUFFERS
          SEND_ALWAYS_BUFFERS = True

      elif opt == '--ca_certs': self.ca_certs = arg
      elif opt == '--jakenoia': self.fe_anon_tls_wrap = True
      elif opt == '--fe_certname':
        cert = arg.lower()
        if cert not in self.fe_certname: self.fe_certname.append(cert)
        self.fe_certname.sort()
      elif opt == '--service_xmlrpc': self.service_xmlrpc = arg
      elif opt == '--frontend': self.servers_manual.append(arg)
      elif opt == '--frontends':
        count, domain, port = arg.split(':')
        self.servers_auto = (int(count), domain, int(port))

      elif opt in ('--errorurl', '-E'): self.error_url = arg
      elif opt == '--fingerpath': self.finger_path = arg
      elif opt == '--kitename': self.kitename = arg
      elif opt == '--kitesecret': self.kitesecret = arg
      elif opt in ('--backend', '--define_backend'):
        bes = self.ArgToBackendSpecs(arg.replace('@kitesecret', self.kitesecret)
                                        .replace('@kitename', self.kitename),
                                     status=((opt == '--backend')
                                             and BE_STATUS_UNKNOWN
                                             or BE_STATUS_DISABLED))
        for bid in bes:
          if not self.kitename:
            self.kitename = bes[bid][BE_DOMAIN]
            self.kitesecret = bes[bid][BE_SECRET]
          if bid in self.backends:
            raise ConfigError("Same backend/domain defined twice: %s" % bid)
        self.backends.update(bes)
      elif opt == '--be_config':
        host, key, val = arg.split(':', 2)
        if key.startswith('user/'): key = key.replace('user/', 'password/')
        hostc = self.be_config.get(host, {})
        hostc[key] = {'True': True, 'False': False, 'None': None}.get(val, val)
        self.be_config[host] = hostc

      elif opt == '--domain':
        protos, domain, secret = arg.split(':')
        if protos in ('*', ''): protos = ','.join(self.server_protos)
        for proto in protos.split(','):
          bid = '%s:%s' % (proto, domain)
          if bid in self.backends:
            raise ConfigError("Same backend/domain defined twice: %s" % bid)
          self.backends[bid] = BE_NONE[:]
          self.backends[bid][BE_PROTO] = proto
          self.backends[bid][BE_DOMAIN] = domain
          self.backends[bid][BE_SECRET] = secret
          self.backends[bid][BE_STATUS] = BE_STATUS_UNKNOWN

      elif opt == '--noprobes': self.no_probes = True
      elif opt == '--nofrontend': self.isfrontend = False
      elif opt == '--nodaemonize': self.daemonize = False
      elif opt == '--noall': self.require_all = False
      elif opt == '--nozchunks': self.disable_zchunks = True
      elif opt == '--nullui': self.ui = NullUi()
      elif opt == '--remoteui':
        import pagekite.remoteui
        self.ui = pagekite.remoteui.RemoteUi()
      elif opt == '--sslzlib': self.enable_sslzlib = True
      elif opt == '--debugio':
        global DEBUG_IO
        DEBUG_IO = True
      elif opt == '--buffers': self.buffer_max = int(arg)
      elif opt == '--nocrashreport': self.crash_report_url = None
      elif opt == '--noloop': self.main_loop = False
      elif opt == '--local':
        self.SetLocalSettings([int(p) for p in arg.split(',')])
        if not 'localhost' in args: args.append('localhost')
      elif opt == '--defaults': self.SetServiceDefaults()
      elif opt in ('--clean', '--nopyopenssl', '--nossl', '--settings',
                   '--webaccess', '--webindexes',
                   '--webroot', '--signup'): pass
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

    # Make sure these are configured before we try and do XML-RPC stuff.
    socks.DEBUG = (DEBUG_IO or socks.DEBUG) and LogDebug
    if self.ca_certs: socks.setdefaultcertfile(self.ca_certs)

    # Handle the user-friendly argument stuff and simple registration.

    just_these_backends = {}
    just_these_webpaths = {}
    just_these_be_configs = {}
    argsets = []
    while 'AND' in args:
      argsets.append(args[0:args.index('AND')])
      args[0:args.index('AND')+1] = []
    if args:
      argsets.append(args)

    for args in argsets:
      # Extract the config options first...
      be_config = [p for p in args if p.startswith('+')]
      args = [p for p in args if not p.startswith('+')]

      fe_spec = args.pop()
      if os.path.exists(fe_spec):
        raise ConfigError('Is a local file: %s' % fe_spec)

      be_paths = []
      be_path_prefix = ''
      if len(args) == 0:
        be_spec = ''
      elif len(args) == 1:
        if '*' in args[0] or '?' in args[0]:
          if sys.platform in ('win32', 'os2', 'os2emx'):
            be_paths = [args[0]]
            be_spec = 'builtin'
        elif os.path.exists(args[0]):
          be_paths = [args[0]]
          be_spec = 'builtin'
        else:
          be_spec = args[0]
      else:
        be_spec = 'builtin'
        be_paths = args[:]

      be_proto = 'http' # A sane default...
      if be_spec == '':
        be = None
      else:
        be = be_spec.replace('/', '').split(':')
        if be[0].lower() in ('http', 'https', 'httpfinger', 'finger', 'ssh',
                             'irc'):
          be_proto = be.pop(0)
          if len(be) < 2:
            be.append({'http': '80', 'https': '443', 'irc': '6667',
                       'httpfinger': '80', 'finger': '79',
                       'ssh': '22'}[be_proto])
        if len(be) > 2:
          raise ConfigError('Bad back-end definition: %s' % be_spec)
        if len(be) < 2:
          be = ['localhost', be[0]]

      # Extract the path prefix from the fe_spec
      fe_urlp = fe_spec.split('/', 3)
      if len(fe_urlp) == 4:
        fe_spec = '/'.join(fe_urlp[:3])
        be_path_prefix = '/' + fe_urlp[3]

      fe = fe_spec.replace('/', '').split(':')
      if len(fe) == 3:
        fe = ['%s-%s' % (fe[0], fe[2]), fe[1]]
      elif len(fe) == 2:
        try:
          fe = ['%s-%s' % (be_proto, int(fe[1])), fe[0]]
        except ValueError:
          pass
      elif len(fe) == 1 and be:
        fe = [be_proto, fe[0]]

      # Do our own globbing on Windows
      if sys.platform in ('win32', 'os2', 'os2emx'):
        import glob
        new_paths = []
        for p in be_paths:
          new_paths.extend(glob.glob(p))
        be_paths = new_paths

      for f in be_paths:
        if not os.path.exists(f):
          raise ConfigError('File or directory not found: %s' % f)

      spec = ':'.join(fe)
      if be: spec += ':' + ':'.join(be)
      specs = self.ArgToBackendSpecs(spec)
      just_these_backends.update(specs)

      spec = specs[specs.keys()[0]]
      http_host = '%s/%s' % (spec[BE_DOMAIN], spec[BE_PORT] or '80')
      if be_config:
        # Map the +foo=bar values to per-site config settings.
        host_config = just_these_be_configs.get(http_host, {})
        for cfg in be_config:
          if '=' in cfg:
            key, val = cfg[1:].split('=', 1)
          elif cfg.startswith('+no'):
            key, val = cfg[3:], False
          else:
            key, val = cfg[1:], True
          if ':' in key:
            raise ConfigError('Please do not use : in web config keys.')
          if key.startswith('user/'): key = key.replace('user/', 'password/')
          host_config[key] = val
        just_these_be_configs[http_host] = host_config

      if be_paths:
        host_paths = just_these_webpaths.get(http_host, {})
        host_config = just_these_be_configs.get(http_host, {})
        rand_seed = '%s:%x' % (specs[specs.keys()[0]][BE_SECRET],
                               time.time()/3600)

        first = (len(host_paths.keys()) == 0) or be_path_prefix
        paranoid = host_config.get('hide', False)
        set_root = host_config.get('root', True)
        if len(be_paths) == 1:
          skip = 0
        else:
          skip = len(os.path.dirname(os.path.commonprefix(be_paths)+'X'))

        for path in be_paths:
          phead, ptail = os.path.split(path)
          if paranoid:
            if path.endswith('/'): path = path[0:-1]
            webpath = '%s/%s' % (sha1hex(rand_seed+os.path.dirname(path))[0:9],
                                  os.path.basename(path))
          elif (first and set_root and os.path.isdir(path)):
            webpath = ''
          elif (os.path.isdir(path) and
                not path.startswith('.') and
                not os.path.isabs(path)):
            webpath = path[skip:] + '/'
          elif path == '.':
            webpath = ''
          else:
            webpath = path[skip:]
          while webpath.endswith('/.'):
            webpath = webpath[:-2]
          host_paths[(be_path_prefix + '/' + webpath).replace('///', '/'
                                                    ).replace('//', '/')
                     ] = (WEB_POLICY_DEFAULT, os.path.abspath(path))
          first = False
        just_these_webpaths[http_host] = host_paths

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
      if self.kite_add:
        self.backends.update(just_these_backends)
      elif self.kite_remove:
        for bid in just_these_backends:
          be = self.backends[bid]
          if be[BE_PROTO] == 'http':
            http_host = '%s/%s' % (be[BE_DOMAIN], be[BE_PORT] or '80')
            if http_host in self.ui_paths: del self.ui_paths[http_host]
            if http_host in self.be_config: del self.be_config[http_host]
          del self.backends[bid]
      elif self.kite_disable:
        for bid in just_these_backends:
          self.backends[bid][BE_STATUS] = BE_STATUS_DISABLED
      elif self.kite_only:
        for be in self.backends.values(): be[BE_STATUS] = BE_STATUS_DISABLED
        self.backends.update(just_these_backends)
      else:
        # Nothing explictly requested: 'only' behavior with a twist;
        # If kites are new, don't make disables persist on save.
        for be in self.backends.values():
          be[BE_STATUS] = (need_registration and BE_STATUS_DISABLE_ONCE
                                              or BE_STATUS_DISABLED)
        self.backends.update(just_these_backends)

      self.ui_paths.update(just_these_webpaths)
      self.be_config.update(just_these_be_configs)

    return self

  def GetServiceXmlRpc(self):
    service = self.service_xmlrpc
    return xmlrpclib.ServerProxy(self.service_xmlrpc, None, None, False)

  def _KiteInfo(self, kitename):
    is_service_domain = kitename and SERVICE_DOMAIN_RE.search(kitename)
    is_subdomain_of = is_cname_for = is_cname_ready = False

    if is_service_domain:
      parts = kitename.split('.')
      if '-' in parts[0]:
        parts[0] = '-'.join(parts[0].split('-')[1:])
        is_subdomain_of = '.'.join(parts)
      elif len(parts) > 3:
        is_subdomain_of = '.'.join(parts[1:])

    elif kitename:
      try:
        (hn, al, ips) = socket.gethostbyname_ex(kitename)
        if hn != kitename and SERVICE_DOMAIN_RE.search(hn):
          is_cname_for = hn
      except:
        pass

    return is_subdomain_of, is_service_domain, is_cname_for, is_cname_ready

  def RegisterNewKite(self, kitename=None, autoconfigure=False):
    if kitename:
      self.ui.StartWizard('Creating kite: %s' % kitename)
      (is_subdomain_of, is_service_domain,
       is_cname_for, is_cname_ready) = self._KiteInfo(kitename)
    else:
      self.ui.StartWizard('Create your first kite!')
      is_subdomain_of = is_service_domain = False
      is_cname_for = is_cname_ready = False

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
      if kitename:
        state = ['choose_kite_account']
      else:
        state = ['manual_abort']
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
              if is_subdomain_of:
                Goto('service_signup_is_subdomain')
              else:
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
                self.ui.Tell(['Login failed! Try again?'], error=True)
            if email is False:
              Back()

        elif ('service_signup_is_subdomain' in state):
          ch = self.ui.AskYesNo('Use this name?',
                                pre=[('WARNING: %s is a sub-domain!'
                                      ) % kitename, '',
         'This process will FAIL if you have not already registered the parent',
                                     'domain: %s' % is_subdomain_of],
                                default=True, back=-1)
          if ch is True:
            if email:
              Goto('service_signup')
            else:
              Goto('service_signup_email')
          elif ch is False:
            Goto('service_signup_kitename')
          else:
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
            (is_subdomain_of, is_service_domain,
             is_cname_for, is_cname_ready) = self._KiteInfo(ch)
            self.ui.StartWizard('Creating kite: %s' % kitename)
            if is_subdomain_of:
              Goto('service_signup_is_subdomain')
            elif email:
              Goto('service_signup')
            else:
              Goto('service_signup_email')
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
                  'IMPORTANT NOTE:',
                  'An activation link has been mailed to: %s' % email,
                  'Unverified accounts are deactivated after '
                  '%s minutes.' % details['timeout'],
                ])
                # FIXME: Handle CNAMEs somehow?
                time.sleep(2) # Give the service side a moment to replicate...
                self.ui.EndWizard()
                if autoconfigure:
                  self.backends.update(self.ArgToBackendSpecs(register,
                                                      secret=details['secret']))
                self.added_kites = True
                return (register, details['secret'])
              else:
                error = details.get('error', 'unknown')
            except Exception, e:
              error = '%s' % e

            if error == 'pleaselogin':
              self.ui.ExplainError(error,
                                   '%s log-in required.' % self.service_provider,
                                   subject=register)
              Goto('service_login_email', back_skips_current=True)
            elif error == 'email':
              self.ui.ExplainError(error, 'Signup failed!', subject=register)
              Goto('service_login_email', back_skips_current=True)
            elif error == 'domain':
              self.ui.ExplainError(error, 'Invalid domain!', subject=register)
              Goto('service_signup_kitename', back_skips_current=True)
            else:
              print 'FIXME!  Error is %s' % error
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
          subject = None
          cfgs = {}
          result = {}
          error = None
          try:
            if is_cname_for and is_cname_ready:
              subject = kitename
              result = service.addCnameKite(account, secret, kitename)
              cfgs.update(self.ArgToBackendSpecs(kitename, secret=secret))
            else:
              subject = register
              result = service.addKite(account, secret, register)
              cfgs.update(self.ArgToBackendSpecs(register, secret=secret))
              if is_cname_for == register and 'error' not in result:
                subject = kitename
                result.update(service.addCnameKite(account, secret, kitename))
                cfgs.update(self.ArgToBackendSpecs(kitename, secret=secret))
            error = result.get('error', None)
          except Exception, e:
            error = '%s' % e

          if error:
            self.ui.ExplainError(error, 'Kite creation failed!',
                                 subject=subject)
            Goto('abort')
          else:
            self.ui.Tell(['Success!'])
            self.ui.EndWizard()
            time.sleep(2) # Give the service side a moment to replicate...
            if autoconfigure: self.backends.update(cfgs)
            self.added_kites = True
            return (register or kitename, secret)


        elif 'manual_abort' in state:
          if self.ui.Tell(['Aborted!', '',
            'Please manually add information about your kites and front-ends',
            'to the configuration file: %s' % self.rcfile],
                          error=True, back=False) is False:
            Back()
          else:
            self.ui.EndWizard()
            sys.exit(0)

        elif 'abort' in state:
          self.ui.EndWizard()
          sys.exit(0)

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
    if self.ui_sspec: self.BindUiSspec()
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
      need_loopback = False
      for be in self.backends.values():
        if be[BE_BHOST]:
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
          self.ui.Status('connect', color=self.ui.YELLOW,
                         message='Connecting to front-end: %s' % server)
          if Tunnel.BackEnd(server, self.backends, self.require_all, conns):
            Log([('connect', server)])
            connections += 1
          else:
            failures += 1
            LogInfo('Failed to connect', [('FE', server)])
            self.ui.Notify('Failed to connect to %s' % server,
                           prefix='!', color=self.ui.YELLOW)

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
            self.ui.Status('dyndns', color=self.ui.YELLOW,
                                     message='Updating DNS...')
            result = ''.join(urllib.urlopen(updates[update]).readlines())
            self.last_updates.append(update)
            if result.startswith('good') or result.startswith('nochg'):
              Log([('dyndns', result), ('data', update)])
            else:
              LogInfo('DynDNS update failed: %s' % result, [('data', update)])
              failures += 1
          except Exception, e:
            LogInfo('DynDNS update failed: %s' % e, [('data', update)])
            traceback.print_exc(file=sys.stderr)
            failures += 1
      if not self.last_updates:
        self.last_updates = last_updates

    if not failures:
      self.ui.Status('active', color=self.ui.GREEN,
                               message='Kites are flying and all is well.')

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

    global LogFile
    if filename in ('stdio', 'stdout'):
      sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
      sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)
      LogFile = sys.stdout
    else:
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
    conns = self.conns = self.conns or Connections(self)
    global Log

    # If we are going to spam stdout with ugly crap, then there is no point
    # attempting the fancy stuff. This also makes us backwards compatible
    # for the most part.
    if self.logfile == 'stdio': self.ui = NullUi()

    # Announce that we've started up!
    self.ui.Status('startup', message='Starting up...')
    self.ui.Notify(('Hello! This is %s v%s.'
                    ) % (self.progname, APPVER),
                    prefix='>', color=self.ui.GREEN,
                    alignright='[%s]' % howtoquit)
    config_report = [('started', sys.argv[0]), ('version', APPVER),
                     ('platform', sys.platform),
                     ('argv', ' '.join(sys.argv[1:])),
                     ('ca_certs', self.ca_certs)]
    for optf in self.rcfiles_loaded:
      config_report.append(('optfile_%s' % optf, 'ok'))
    Log(config_report)

    if not socks.HAVE_SSL:
      self.ui.Notify('SECURITY WARNING: No SSL support was found, tunnels are insecure!',
                     prefix='!', color=self.ui.WHITE)
      self.ui.Notify('Please install either pyOpenSSL or python-ssl.',
                     prefix='!', color=self.ui.WHITE)

    # Create global secret
    self.ui.Status('startup', message='Collecting entropy for a secure secret...')
    LogInfo('Collecting entropy for a secure secret.')
    globalSecret()
    self.ui.Status('startup', message='Starting up...')

    try:

      # Set up our listeners if we are a server.
      if self.isfrontend:
        self.ui.Notify('This is a PageKite front-end server.')
        for port in self.server_ports:
          Listener(self.server_host, port, conns)
        for port in self.server_raw_ports:
          if port != VIRTUAL_PN and port > 0:
            Listener(self.server_host, port, conns, connclass=RawConn)

      # Create the Tunnel Manager
      self.tunnel_manager = TunnelManager(self, conns)

    except Exception, e:
      self.LogTo('stdio')
      FlushLogMemory()
      if DEBUG_IO: traceback.print_exc(file=sys.stderr)
      raise ConfigError('Configuring listeners: %s ' % e)

    # Configure logging
    if self.logfile:
      keep_open = [s.fd.fileno() for s in conns.conns]
      if self.ui_httpd: keep_open.append(self.ui_httpd.httpd.socket.fileno())
      self.LogTo(self.logfile, dont_close=keep_open)

    elif not sys.stdout.isatty():
      # Preserve sane behavior when not run at the console.
      self.LogTo('stdio')

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
    if socks.HAVE_SSL and not self.enable_sslzlib:
      socks.DisableSSLCompression()

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

def Main(pagekite, configure, uiclass=NullUi,
                              progname=None, appver=APPVER,
                              http_handler=None, http_server=None):
  crashes = 1

  ui = uiclass()

  while True:
    pk = pagekite(ui=ui, http_handler=http_handler, http_server=http_server)
    try:
      try:
        try:
          configure(pk)
        except SystemExit, status:
          sys.exit(status)
        except Exception, e:
          raise ConfigError(e)

        pk.Start()

      except (ConfigError, getopt.GetoptError), msg:
        pk.FallDown(msg)

      except KeyboardInterrupt, msg:
        pk.FallDown(None, help=False, noexit=True)
        return

    except SystemExit, status:
      sys.exit(status)

    except Exception, msg:
      traceback.print_exc(file=sys.stderr)

      if pk.crash_report_url:
        try:
          print 'Submitting crash report to %s' % pk.crash_report_url
          LogDebug(''.join(urllib.urlopen(pk.crash_report_url,
                                          urllib.urlencode({
                                            'platform': sys.platform,
                                            'appver': APPVER,
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

  if '--clean' not in sys.argv and '--help' not in sys.argv:
    if os.path.exists(pk.rcfile): pk.ConfigureFromFile()

  pk.Configure(sys.argv[1:])

  if '--settings' in sys.argv:
    pk.PrintSettings(safe=True)
    sys.exit(0)

  if not pk.backends.keys():
    friendly_mode = sys.platform in ('win32', 'os2', 'os2emx',
                                     'darwin', 'darwin1', 'darwin2')
    if '--signup' in sys.argv or friendly_mode:
      pk.RegisterNewKite(autoconfigure=True)
    if friendly_mode: pk.save = True

  pk.CheckConfig()

  if pk.added_kites:
    if (pk.autosave or pk.save or
        pk.ui.AskYesNo('Save settings to %s?' % pk.rcfile,
                       default=(len(pk.backends.keys()) > 0))):
      pk.SaveUserConfig()
    pk.servers_new_only = True
  elif pk.save:
    pk.SaveUserConfig()

  if ('--list' in sys.argv or
      pk.kite_add or pk.kite_remove or pk.kite_only or pk.kite_disable):
    pk.ListKites()
    sys.exit(0)


