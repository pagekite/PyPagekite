#!/usr/bin/python2
#
# NOTE: This is a compilation of multiple Python files.
#       See below for details on individual segments.
#
import base64, imp, os, sys, StringIO, zlib

__FILES = {}
__os_path_exists = os.path.exists
__builtin_open = open

def __comb_open(filename, *args, **kwargs):
  if filename in __FILES:
    return StringIO.StringIO(__FILES[filename])
  else:
    return __builtin_open(filename, *args, **kwargs)

def __comb_exists(filename, *args, **kwargs):
  if filename in __FILES:
    return True
  else:
    return __os_path_exists(filename, *args, **kwargs)

open = __comb_open
os.path.exists = __comb_exists
sys.path[0:0] = ['.SELF/']


###############################################################################
__FILES[".SELF/sockschain/__init__.py"] = """\
#!/usr/bin/python
\"\"\"SocksiPy - Python SOCKS module.
Version 2.00

Copyright 2011 Bjarni R. Einarsson. All rights reserved.
Copyright 2006 Dan-Haim. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Dan Haim nor the names of his contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY DAN HAIM \"AS IS\" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL DAN HAIM OR HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMANGE.


This module provides a standard socket-like interface for Python
for tunneling connections through SOCKS proxies.

\"\"\"

\"\"\"

Refactored to allow proxy chaining and use as a command-line netcat-like
tool by Bjarni R. Einarsson (http://bre.klaki.net/) for use with PageKite
(http://pagekite.net/).

Minor modifications made by Christopher Gilbert (http://motomastyle.com/)
for use in PyLoris (http://pyloris.sourceforge.net/)

Minor modifications made by Mario Vilas (http://breakingcode.wordpress.com/)
mainly to merge bug fixes found in Sourceforge

\"\"\"

import base64, errno, os, socket, sys, select, struct, threading
DEBUG = False
#def DEBUG(foo): print foo


##[ SSL compatibility code ]##################################################

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


def SSL_CheckName(commonName, digest, valid_names):
    pairs = [(commonName, '%s/%s' % (commonName, digest))]
    valid = 0

    if commonName.startswith('*.'):
        commonName = commonName[1:].lower()
        for name in valid_names:
            name = name.split('/')[0].lower()
            if ('.'+name).endswith(commonName):
                pairs.append((name, '%s/%s' % (name, digest)))

    for commonName, cNameDigest in pairs:
        if ((commonName in valid_names) or (cNameDigest in valid_names)):
            valid += 1

    if DEBUG: DEBUG(('*** Cert score: %s (%s ?= %s)'
                     ) % (valid, pairs, valid_names))
    return valid


HAVE_SSL = False
HAVE_PYOPENSSL = False
TLS_CA_CERTS = \"/etc/ssl/certs/ca-certificates.crt\"
try:
    if '--nopyopenssl' in sys.argv or '--nossl' in sys.argv:
        raise ImportError('pyOpenSSL disabled')

    from OpenSSL import SSL
    HAVE_SSL = HAVE_PYOPENSSL = True

    def SSL_Connect(ctx, sock,
                    server_side=False, accepted=False, connected=False,
                    verify_names=None):
        if DEBUG: DEBUG('*** TLS is provided by pyOpenSSL')
        if verify_names:
            def vcb(conn, x509, errno, depth, rc):
                if errno != 0: return False
                if depth != 0: return True
                return (SSL_CheckName(x509.get_subject().commonName.lower(),
                                      x509.digest('sha1').replace(':',''),
                                      verify_names) > 0)
            ctx.set_verify(SSL.VERIFY_PEER |
                           SSL.VERIFY_FAIL_IF_NO_PEER_CERT, vcb)
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
        if '--nossl' in sys.argv:
            raise ImportError('SSL disabled')

        import ssl
        HAVE_SSL = True

        class SSL(object):
            SSLv23_METHOD = ssl.PROTOCOL_SSLv23
            SSLv3_METHOD = ssl.PROTOCOL_SSLv3
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
                    self.ciphers = None
                def use_privatekey_file(self, fn):
                    self.privatekey_file = fn
                def use_certificate_chain_file(self, fn):
                    self.certchain_file = fn
                def set_cipher_list(self, ciphers):
                    self.ciphers = ciphers
                def load_verify_locations(self, pemfile, capath=None):
                    self.ca_certs = pemfile

        def SSL_CheckPeerName(fd, names):
            cert = fd.getpeercert()
            certhash = sha1hex(fd.getpeercert(binary_form=True))
            if not cert: return None
            valid = 0
            for field in cert['subject']:
                if field[0][0].lower() == 'commonname':
                    valid += SSL_CheckName(field[0][1].lower(), certhash, names)

            if 'subjectAltName' in cert:
                for field in cert['subjectAltName']:
                    if field[0].lower() == 'dns':
                        name = field[1].lower()
                        valid += SSL_CheckName(field[1].lower(),
                                               certhash, names)
            return (valid > 0)

        def SSL_Connect(ctx, sock,
                        server_side=False, accepted=False, connected=False,
                        verify_names=None):
            if DEBUG: DEBUG('*** TLS is provided by native Python ssl')
            reqs = (verify_names and ssl.CERT_REQUIRED or ssl.CERT_NONE)
            try:
                fd = ssl.wrap_socket(sock, keyfile=ctx.privatekey_file,
                                           certfile=ctx.certchain_file,
                                           cert_reqs=reqs,
                                           ca_certs=ctx.ca_certs,
                                           do_handshake_on_connect=False,
                                           ssl_version=ctx.method,
                                           ciphers=ctx.ciphers,
                                           server_side=server_side)
            except:
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
                    raise SSL.Error(('Cert not in %s (%s)'
                                     ) % (verify_names, reqs))
            return fd

    except ImportError:
        class SSL(object):
            # Mock to let our try/except clauses below not fail.
            class Error(Exception): pass
            class SysCallError(Exception): pass
            class WantWriteError(Exception): pass
            class ZeroReturnError(Exception): pass


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
            ssllib = sorted(glob.glob(\"/usr/lib/libssl.so.*\"))[0]
            openssl = ctypes.CDLL(ssllib, ctypes.RTLD_GLOBAL)

        openssl.SSL_COMP_get_compression_methods.restype = ctypes.c_void_p
        openssl.sk_zero.argtypes = [ctypes.c_void_p]
        openssl.sk_zero(openssl.SSL_COMP_get_compression_methods())
    except Exception:
        if DEBUG: DEBUG('disableSSLCompression: Failed')


##[ SocksiPy itself ]#########################################################

PROXY_TYPE_DEFAULT = -1
PROXY_TYPE_NONE = 0
PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3
PROXY_TYPE_SSL = 4
PROXY_TYPE_SSL_WEAK = 5
PROXY_TYPE_SSL_ANON = 6
PROXY_TYPE_TOR = 7
PROXY_TYPE_HTTPS = 8
PROXY_TYPE_HTTP_CONNECT = 9
PROXY_TYPE_HTTPS_CONNECT = 10

PROXY_SSL_TYPES = (PROXY_TYPE_SSL, PROXY_TYPE_SSL_WEAK,
                   PROXY_TYPE_SSL_ANON, PROXY_TYPE_HTTPS,
                   PROXY_TYPE_HTTPS_CONNECT)
PROXY_HTTP_TYPES = (PROXY_TYPE_HTTP, PROXY_TYPE_HTTPS)
PROXY_HTTPC_TYPES = (PROXY_TYPE_HTTP_CONNECT, PROXY_TYPE_HTTPS_CONNECT)
PROXY_SOCKS5_TYPES = (PROXY_TYPE_SOCKS5, PROXY_TYPE_TOR)
PROXY_DEFAULTS = {
    PROXY_TYPE_NONE: 0,
    PROXY_TYPE_DEFAULT: 0,
    PROXY_TYPE_HTTP: 8080,
    PROXY_TYPE_HTTP_CONNECT: 8080,
    PROXY_TYPE_SOCKS4: 1080,
    PROXY_TYPE_SOCKS5: 1080,
    PROXY_TYPE_TOR: 9050,
}
PROXY_TYPES = {
  'none': PROXY_TYPE_NONE,
  'default': PROXY_TYPE_DEFAULT,
  'defaults': PROXY_TYPE_DEFAULT,
  'http': PROXY_TYPE_HTTP,
  'httpc': PROXY_TYPE_HTTP_CONNECT,
  'socks': PROXY_TYPE_SOCKS5,
  'socks4': PROXY_TYPE_SOCKS4,
  'socks4a': PROXY_TYPE_SOCKS4,
  'socks5': PROXY_TYPE_SOCKS5,
  'tor': PROXY_TYPE_TOR,
}

if HAVE_SSL:
    PROXY_DEFAULTS.update({
        PROXY_TYPE_HTTPS: 443,
        PROXY_TYPE_HTTPS_CONNECT: 443,
        PROXY_TYPE_SSL: 443,
        PROXY_TYPE_SSL_WEAK: 443,
        PROXY_TYPE_SSL_ANON: 443,
    })
    PROXY_TYPES.update({
        'https': PROXY_TYPE_HTTPS,
        'httpcs': PROXY_TYPE_HTTPS_CONNECT,
        'ssl': PROXY_TYPE_SSL,
        'ssl-anon': PROXY_TYPE_SSL_ANON,
        'ssl-weak': PROXY_TYPE_SSL_WEAK,
    })

P_TYPE = 0
P_HOST = 1
P_PORT = 2
P_RDNS = 3
P_USER = 4
P_PASS = P_CACERTS = 5
P_CERTS = 6

DEFAULT_ROUTE = '*'
_proxyroutes = { }
_orgsocket = socket.socket
_orgcreateconn = getattr(socket, 'create_connection', None)
try:
  _thread_locals = threading.local()
  def _thread_local(): return _thread_locals

except AttributeError:
  # Pre 2.4, we have to implement our own.
  _thread_local_dict = {}
  class Storage(object): pass
  def _thread_local():
    tid = str(threading.currentThread())
    if not tid in _thread_local_dict: _thread_local_dict[tid] = Storage()
    return _thread_local_dict[tid]


class ProxyError(Exception): pass
class GeneralProxyError(ProxyError): pass
class Socks5AuthError(ProxyError): pass
class Socks5Error(ProxyError): pass
class Socks4Error(ProxyError): pass
class HTTPError(ProxyError): pass

_generalerrors = (\"success\",
    \"invalid data\",
    \"not connected\",
    \"not available\",
    \"bad proxy type\",
    \"bad input\")

_socks5errors = (\"succeeded\",
    \"general SOCKS server failure\",
    \"connection not allowed by ruleset\",
    \"Network unreachable\",
    \"Host unreachable\",
    \"Connection refused\",
    \"TTL expired\",
    \"Command not supported\",
    \"Address type not supported\",
    \"Unknown error\")

_socks5autherrors = (\"succeeded\",
    \"authentication is required\",
    \"all offered authentication methods were rejected\",
    \"unknown username or invalid password\",
    \"unknown error\")

_socks4errors = (\"request granted\",
    \"request rejected or failed\",
    \"request rejected because SOCKS server cannot connect to identd on the client\",
    \"request rejected because the client program and identd report different user-ids\",
    \"unknown error\")


def parseproxy(arg):
    # This silly function will do a quick-and-dirty parse of our argument
    # into a proxy specification array. It lets people omit stuff.
    args = arg.replace('/', '').split(':')
    args[0] = PROXY_TYPES[args[0] or 'http']

    if (len(args) in (3, 4, 5)) and ('@' in args[2]):
        # Re-order http://user:pass@host:port/ => http:host:port:user:pass
        pwd, host = args[2].split('@')
        user = args[1]
        args[1:3] = [host]
        if len(args) == 2: args.append(PROXY_DEFAULTS[args[0]])
        if len(args) == 3: args.append(False)
        args.extend([user, pwd])
    elif (len(args) in (2, 3, 4)) and ('@' in args[1]):
        user, host = args[1].split('@')
        args[1] = host
        if len(args) == 2: args.append(PROXY_DEFAULTS[args[0]])
        if len(args) == 3: args.append(False)
        args.append(user)

    if len(args) == 2: args.append(PROXY_DEFAULTS[args[0]])
    if len(args) > 2: args[2] = int(args[2])

    if args[P_TYPE] in PROXY_SSL_TYPES:
      names = (args[P_HOST] or '').split(',')
      args[P_HOST] = names[0]
      while len(args) <= P_CERTS:
        args.append((len(args) == P_RDNS) and True or None)
      args[P_CERTS] = (len(names) > 1) and names[1:] or names

    return args

def addproxy(dest, proxytype=None, addr=None, port=None, rdns=True,
                   username=None, password=None, certnames=None):
    global _proxyroutes
    route = _proxyroutes.get(dest.lower(), None)
    proxy = (proxytype, addr, port, rdns, username, password, certnames)
    if route is None:
        route = _proxyroutes.get(DEFAULT_ROUTE, [])[:]
    route.append(proxy)
    _proxyroutes[dest.lower()] = route
    if DEBUG: DEBUG('Routes are: %s' % (_proxyroutes, ))

def setproxy(dest, *args, **kwargs):
    global _proxyroutes
    dest = dest.lower()
    if args:
      _proxyroutes[dest] = []
      return addproxy(dest, *args, **kwargs)
    else:
      if dest in _proxyroutes:
        del _proxyroutes[dest.lower()]

def setdefaultcertfile(path):
    global TLS_CA_CERTS
    TLS_CA_CERTS = path

def setdefaultproxy(*args, **kwargs):
    \"\"\"setdefaultproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
    Sets a default proxy which all further socksocket objects will use,
    unless explicitly changed.
    \"\"\"
    if args and args[P_TYPE] == PROXY_TYPE_DEFAULT:
        raise ValueError(\"Circular reference to default proxy.\")
    return setproxy(DEFAULT_ROUTE, *args, **kwargs)

def adddefaultproxy(*args, **kwargs):
    if args and args[P_TYPE] == PROXY_TYPE_DEFAULT:
        raise ValueError(\"Circular reference to default proxy.\")
    return addproxy(DEFAULT_ROUTE, *args, **kwargs)

def usesystemdefaults():
    import os

    no_proxy = ['localhost', 'localhost.localdomain', '127.0.0.1']
    no_proxy.extend(os.environ.get('NO_PROXY',
                                   os.environ.get('NO_PROXY',
                                                  '')).split(','))
    for host in no_proxy:
        setproxy(host, PROXY_TYPE_NONE)

    for var in ('ALL_PROXY', 'HTTPS_PROXY', 'http_proxy'):
        val = os.environ.get(var.lower(), os.environ.get(var, None))
        if val:
            setdefaultproxy(*parseproxy(val))
            os.environ[var] = ''
            return

def sockcreateconn(*args, **kwargs):
    _thread_local().create_conn = args[0]
    try:
      rv = _orgcreateconn(*args, **kwargs)
      return rv
    finally:
      del(_thread_local().create_conn)

class socksocket(socket.socket):
    \"\"\"socksocket([family[, type[, proto]]]) -> socket object
    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET, type=SOCK_STREAM and proto=0.
    \"\"\"

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        self.__sock = _orgsocket(family, type, proto)
        self.__proxy = None
        self.__proxysockname = None
        self.__proxypeername = None
        self.__makefile_refs = 0
        self.__buffer = ''
        self.__negotiating = False
        self.__override = ['addproxy', 'setproxy',
                           'getproxysockname', 'getproxypeername',
                           'close', 'connect', 'getpeername', 'makefile',
                           'recv'] #, 'send', 'sendall']

    def __getattribute__(self, name):
        if name.startswith('_socksocket__'):
          return object.__getattribute__(self, name)
        elif name in self.__override:
          return object.__getattribute__(self, name)
        else:
          return getattr(object.__getattribute__(self, \"_socksocket__sock\"),
                         name)

    def __setattr__(self, name, value):
        if name.startswith('_socksocket__'):
          return object.__setattr__(self, name, value)
        else:
          return setattr(object.__getattribute__(self, \"_socksocket__sock\"),
                         name, value)

    def __recvall(self, count):
        \"\"\"__recvall(count) -> data
        Receive EXACTLY the number of bytes requested from the socket.
        Blocks until the required number of bytes have been received or a
        timeout occurs.
        \"\"\"
        self.__sock.setblocking(1)
        try:
            self.__sock.settimeout(20)
        except:
            # Python 2.2 compatibility hacks.
            pass

        data = self.recv(count)
        while len(data) < count:
            d = self.recv(count-len(data))
            if d == '':
                raise GeneralProxyError((0, \"connection closed unexpectedly\"))
            data = data + d
        return data

    def close(self):
        if self.__makefile_refs < 1:
            self.__sock.close()
        else:
            self.__makefile_refs -= 1

    def makefile(self, mode='r', bufsize=-1):
        self.__makefile_refs += 1
        try:
            return socket._fileobject(self, mode, bufsize, close=True)
        except TypeError:
            # Python 2.2 compatibility hacks.
            return socket._fileobject(self, mode, bufsize)

    def addproxy(self, proxytype=None, addr=None, port=None, rdns=True, username=None, password=None, certnames=None):
        \"\"\"setproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
        Sets the proxy to be used.
        proxytype -    The type of the proxy to be used. Three types
                are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -        The address of the server (IP or DNS).
        port -        The port of the server. Defaults to 1080 for SOCKS
                servers and 8080 for HTTP proxy servers.
        rdns -        Should DNS queries be preformed on the remote side
                (rather than the local side). The default is True.
                Note: This has no effect with SOCKS4 servers.
        username -    Username to authenticate with to the server.
                The default is no authentication.
        password -    Password to authenticate with to the server.
                Only relevant when username is also provided.
        \"\"\"
        proxy = (proxytype, addr, port, rdns, username, password, certnames)
        if not self.__proxy: self.__proxy = []
        self.__proxy.append(proxy)

    def setproxy(self, *args, **kwargs):
        \"\"\"setproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
           (see addproxy)
        \"\"\"
        self.__proxy = []
        self.addproxy(*args, **kwargs)

    def __negotiatesocks5(self, destaddr, destport, proxy):
        \"\"\"__negotiatesocks5(self, destaddr, destport, proxy)
        Negotiates a connection through a SOCKS5 server.
        \"\"\"
        # First we'll send the authentication packages we support.
        if (proxy[P_USER]!=None) and (proxy[P_PASS]!=None):
            # The username/password details were supplied to the
            # setproxy method so we support the USERNAME/PASSWORD
            # authentication (in addition to the standard none).
            self.sendall(struct.pack('BBBB', 0x05, 0x02, 0x00, 0x02))
        else:
            # No username/password were entered, therefore we
            # only support connections with no authentication.
            self.sendall(struct.pack('BBB', 0x05, 0x01, 0x00))
        # We'll receive the server's response to determine which
        # method was selected
        chosenauth = self.__recvall(2)
        if chosenauth[0:1] != chr(0x05).encode():
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        # Check the chosen authentication method
        if chosenauth[1:2] == chr(0x00).encode():
            # No authentication is required
            pass
        elif chosenauth[1:2] == chr(0x02).encode():
            # Okay, we need to perform a basic username/password
            # authentication.
            self.sendall(chr(0x01).encode() +
                         chr(len(proxy[P_USER])) + proxy[P_USER] +
                         chr(len(proxy[P_PASS])) + proxy[P_PASS])
            authstat = self.__recvall(2)
            if authstat[0:1] != chr(0x01).encode():
                # Bad response
                self.close()
                raise GeneralProxyError((1, _generalerrors[1]))
            if authstat[1:2] != chr(0x00).encode():
                # Authentication failed
                self.close()
                raise Socks5AuthError((3, _socks5autherrors[3]))
            # Authentication succeeded
        else:
            # Reaching here is always bad
            self.close()
            if chosenauth[1] == chr(0xFF).encode():
                raise Socks5AuthError((2, _socks5autherrors[2]))
            else:
                raise GeneralProxyError((1, _generalerrors[1]))
        # Now we can request the actual connection
        req = struct.pack('BBB', 0x05, 0x01, 0x00)
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = socket.inet_aton(destaddr)
            req = req + chr(0x01).encode() + ipaddr
        except socket.error:
            # Well it's not an IP number,  so it's probably a DNS name.
            if proxy[P_RDNS]:
                # Resolve remotely
                ipaddr = None
                req = req + (chr(0x03).encode() +
                             chr(len(destaddr)).encode() + destaddr)
            else:
                # Resolve locally
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
                req = req + chr(0x01).encode() + ipaddr
        req = req + struct.pack(\">H\", destport)
        self.sendall(req)
        # Get the response
        resp = self.__recvall(4)
        if resp[0:1] != chr(0x05).encode():
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        elif resp[1:2] != chr(0x00).encode():
            # Connection failed
            self.close()
            if ord(resp[1:2])<=8:
                raise Socks5Error((ord(resp[1:2]),
                                   _socks5errors[ord(resp[1:2])]))
            else:
                raise Socks5Error((9, _socks5errors[9]))
        # Get the bound address/port
        elif resp[3:4] == chr(0x01).encode():
            boundaddr = self.__recvall(4)
        elif resp[3:4] == chr(0x03).encode():
            resp = resp + self.recv(1)
            boundaddr = self.__recvall(ord(resp[4:5]))
        else:
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        boundport = struct.unpack(\">H\", self.__recvall(2))[0]
        self.__proxysockname = (boundaddr, boundport)
        if ipaddr != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def getproxysockname(self):
        \"\"\"getsockname() -> address info
        Returns the bound IP address and port number at the proxy.
        \"\"\"
        return self.__proxysockname

    def getproxypeername(self):
        \"\"\"getproxypeername() -> address info
        Returns the IP and port number of the proxy.
        \"\"\"
        return _orgsocket.getpeername(self)

    def getpeername(self):
        \"\"\"getpeername() -> address info
        Returns the IP address and port number of the destination
        machine (note: getproxypeername returns the proxy)
        \"\"\"
        return self.__proxypeername

    def __negotiatesocks4(self, destaddr, destport, proxy):
        \"\"\"__negotiatesocks4(self, destaddr, destport, proxy)
        Negotiates a connection through a SOCKS4 server.
        \"\"\"
        # Check if the destination address provided is an IP address
        rmtrslv = False
        try:
            ipaddr = socket.inet_aton(destaddr)
        except socket.error:
            # It's a DNS name. Check where it should be resolved.
            if proxy[P_RDNS]:
                ipaddr = struct.pack(\"BBBB\", 0x00, 0x00, 0x00, 0x01)
                rmtrslv = True
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
        # Construct the request packet
        req = struct.pack(\">BBH\", 0x04, 0x01, destport) + ipaddr
        # The username parameter is considered userid for SOCKS4
        if proxy[P_USER] != None:
            req = req + proxy[P_USER]
        req = req + chr(0x00).encode()
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if rmtrslv:
            req = req + destaddr + chr(0x00).encode()
        self.sendall(req)
        # Get the response from the server
        resp = self.__recvall(8)
        if resp[0:1] != chr(0x00).encode():
            # Bad data
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        if resp[1:2] != chr(0x5A).encode():
            # Server returned an error
            self.close()
            if ord(resp[1:2]) in (91, 92, 93):
                self.close()
                raise Socks4Error((ord(resp[1:2]), _socks4errors[ord(resp[1:2]) - 90]))
            else:
                raise Socks4Error((94, _socks4errors[4]))
        # Get the bound address/port
        self.__proxysockname = (socket.inet_ntoa(resp[4:]),
                                struct.unpack(\">H\", resp[2:4])[0])
        if rmtrslv != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def __getproxyauthheader(self, proxy):
        if proxy[P_USER] and proxy[P_PASS]:
          auth = proxy[P_USER] + \":\" + proxy[P_PASS]
          return \"Proxy-Authorization: Basic %s\\r\\n\" % base64.b64encode(auth)
        else:
          return \"\"

    def __stop_http_negotiation(self):
        buf = self.__buffer
        host, port, proxy = self.__negotiating
        self.__buffer = self.__negotiating = None
        self.__override.remove('send')
        self.__override.remove('sendall')
        return (buf, host, port, proxy)

    def recv(self, count):
        if self.__negotiating:
            # If the calling code tries to read before negotiating is done,
            # assume this is not HTTP, bail and attempt HTTP CONNECT.
            if DEBUG: DEBUG(\"*** Not HTTP, failing back to HTTP CONNECT.\")
            buf, host, port, proxy = self.__stop_http_negotiation()
            self.__negotiatehttpconnect(host, port, proxy)
            self.__sock.sendall(buf)
        while True:
            try:
                return self.__sock.recv(count)
            except SSL.SysCallError:
                return ''
            except SSL.WantReadError:
                pass

    def send(self, *args, **kwargs):
        if self.__negotiating:
            self.__buffer += args[0]
            self.__negotiatehttpproxy()
        else:
            return self.__sock.send(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        if self.__negotiating:
            self.__buffer += args[0]
            self.__negotiatehttpproxy()
        else:
            return self.__sock.sendall(*args, **kwargs)

    def __negotiatehttp(self, destaddr, destport, proxy):
        \"\"\"__negotiatehttpproxy(self, destaddr, destport, proxy)
        Negotiates a connection through an HTTP proxy server.
        \"\"\"
        if destport in (21, 22, 23, 25, 109, 110, 143, 220, 443, 993, 995):
            # Go straight to HTTP CONNECT for anything related to e-mail,
            # SSH, telnet, FTP, SSL, ...
            self.__negotiatehttpconnect(destaddr, destport, proxy)
        else:
            if DEBUG: DEBUG('*** Transparent HTTP proxy mode...')
            self.__negotiating = (destaddr, destport, proxy)
            self.__override.extend(['send', 'sendall'])

    def __negotiatehttpproxy(self):
        \"\"\"__negotiatehttp(self, destaddr, destport, proxy)
        Negotiates an HTTP request through an HTTP proxy server.
        \"\"\"
        buf = self.__buffer
        host, port, proxy = self.__negotiating

        # If our buffer is tiny, wait for data.
        if len(buf) <= 3: return

        # If not HTTP, fall back to HTTP CONNECT.
        if buf[0:3].lower() not in ('get', 'pos', 'hea',
                                    'put', 'del', 'opt', 'pro'):
            if DEBUG: DEBUG(\"*** Not HTTP, failing back to HTTP CONNECT.\")
            self.__stop_http_negotiation()
            self.__negotiatehttpconnect(host, port, proxy)
            self.__sock.sendall(buf)
            return

        # Have we got the end of the headers?
        if buf.find('\\r\\n\\r\\n'.encode()) != -1:
            CRLF = '\\r\\n'
        elif buf.find('\\n\\n'.encode()) != -1:
            CRLF = '\\n'
        else:
            # Nope
            return

        # Remove our send/sendall hooks.
        self.__stop_http_negotiation()

        # Format the proxy request.
        host += ':%d' % port
        headers = buf.split(CRLF)
        for hdr in headers:
            if hdr.lower().startswith('host: '): host = hdr[6:]
        req = headers[0].split(' ', 1)
        headers[0] = '%s http://%s%s' % (req[0], host, req[1])
        headers[1] = self.__getproxyauthheader(proxy) + headers[1]

        # Send it!
        if DEBUG: DEBUG(\"*** Proxy request:\\n%s***\" % CRLF.join(headers))
        self.__sock.sendall(CRLF.join(headers).encode())

    def __negotiatehttpconnect(self, destaddr, destport, proxy):
        \"\"\"__negotiatehttp(self, destaddr, destport, proxy)
        Negotiates an HTTP CONNECT through an HTTP proxy server.
        \"\"\"
        # If we need to resolve locally, we do this now
        if not proxy[P_RDNS]:
            addr = socket.gethostbyname(destaddr)
        else:
            addr = destaddr
        self.__sock.sendall((\"CONNECT \"
                             + addr + \":\" + str(destport) + \" HTTP/1.1\\r\\n\"
                             + self.__getproxyauthheader(proxy)
                             + \"Host: \" + destaddr + \"\\r\\n\\r\\n\"
                             ).encode())
        # We read the response until we get \"\\r\\n\\r\\n\" or \"\\n\\n\"
        resp = self.__recvall(1)
        while (resp.find(\"\\r\\n\\r\\n\".encode()) == -1 and
               resp.find(\"\\n\\n\".encode()) == -1):
            resp = resp + self.__recvall(1)
        # We just need the first line to check if the connection
        # was successful
        statusline = resp.splitlines()[0].split(\" \".encode(), 2)
        if statusline[0] not in (\"HTTP/1.0\".encode(), \"HTTP/1.1\".encode()):
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        try:
            statuscode = int(statusline[1])
        except ValueError:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if statuscode != 200:
            self.close()
            raise HTTPError((statuscode, statusline[2]))
        self.__proxysockname = (\"0.0.0.0\", 0)
        self.__proxypeername = (addr, destport)

    def __get_ca_ciphers(self):
        return 'HIGH:MEDIUM:!MD5'

    def __get_ca_anon_ciphers(self):
        return 'aNULL'

    def __get_ca_certs(self):
        return TLS_CA_CERTS

    def __negotiatessl(self, destaddr, destport, proxy,
                       weak=False, anonymous=False):
        \"\"\"__negotiatessl(self, destaddr, destport, proxy)
        Negotiates an SSL session.
        \"\"\"
        ssl_version = SSL.SSLv3_METHOD
        want_hosts = ca_certs = self_cert = None
        ciphers = self.__get_ca_ciphers()
        if anonymous:
            # Insecure and use anon ciphers - this is just camoflage
            ciphers = self.__get_ca_anon_ciphers()
        elif not weak:
            # This is normal, secure mode.
            self_cert = proxy[P_USER] or None
            ca_certs  = proxy[P_CACERTS] or self.__get_ca_certs() or None
            want_hosts = proxy[P_CERTS] or [proxy[P_HOST]]

        try:
            ctx = SSL.Context(ssl_version)
            ctx.set_cipher_list(ciphers)
            if self_cert:
                ctx.use_certificate_chain_file(self_cert)
                ctx.use_privatekey_file(self_cert)
            if ca_certs and want_hosts:
                ctx.load_verify_locations(ca_certs)

            self.__sock.setblocking(1)
            self.__sock = SSL_Connect(ctx, self.__sock,
                                      connected=True, verify_names=want_hosts)
        except:
            if DEBUG: DEBUG('*** SSL problem: %s/%s/%s' % (sys.exc_info(),
                                                           self.__sock,
                                                           want_hosts))
            raise

        self.__encrypted = True
        if DEBUG: DEBUG('*** Wrapped %s:%s in %s' % (destaddr, destport,
                                                     self.__sock))

    def __default_route(self, dest):
        route = _proxyroutes.get(str(dest).lower(), [])[:]
        if not route or route[0][P_TYPE] == PROXY_TYPE_DEFAULT:
            route[0:1] = _proxyroutes.get(DEFAULT_ROUTE, [])
        while route and route[0][P_TYPE] == PROXY_TYPE_DEFAULT:
            route.pop(0)
        return route

    def connect(self, destpair):
        \"\"\"connect(self, despair)
        Connects to the specified destination through a chain of proxies.
        destpar - A tuple of the IP/DNS address and the port number.
        (identical to socket's connect).
        To select the proxy servers use setproxy() and chainproxy().
        \"\"\"
        if DEBUG: DEBUG('*** Connect: %s / %s' % (destpair, self.__proxy))
        destpair = getattr(_thread_local(), 'create_conn', destpair)

        # Do a minimal input check first
        if ((not type(destpair) in (list, tuple)) or
            (len(destpair) < 2) or (type(destpair[0]) != type('')) or
            (type(destpair[1]) != int)):
            raise GeneralProxyError((5, _generalerrors[5]))

        if self.__proxy:
            proxy_chain = self.__proxy
            default_dest = destpair[0]
        else:
            proxy_chain = self.__default_route(destpair[0])
            default_dest = DEFAULT_ROUTE

        for proxy in proxy_chain:
            if (proxy[P_TYPE] or PROXY_TYPE_NONE) not in PROXY_DEFAULTS:
                raise GeneralProxyError((4, _generalerrors[4]))

        chain = proxy_chain[:]
        chain.append([PROXY_TYPE_NONE, destpair[0], destpair[1]])
        if DEBUG: DEBUG('*** Chain: %s' % (chain, ))

        first = True
        result = None
        while chain:
            proxy = chain.pop(0)

            if proxy[P_TYPE] == PROXY_TYPE_DEFAULT:
                chain[0:0] = self.__default_route(default_dest)
                if DEBUG: DEBUG('*** Chain: %s' % chain)
                continue

            if proxy[P_PORT] != None:
                portnum = proxy[P_PORT]
            else:
                portnum = PROXY_DEFAULTS[proxy[P_TYPE] or PROXY_TYPE_NONE]

            if first and proxy[P_HOST]:
                if DEBUG: DEBUG('*** Connect: %s:%s' % (proxy[P_HOST], portnum))
                result = self.__sock.connect((proxy[P_HOST], portnum))

            if chain:
                nexthop = (chain[0][P_HOST] or '', int(chain[0][P_PORT] or 0))

                if proxy[P_TYPE] in PROXY_SSL_TYPES:
                    if DEBUG: DEBUG('*** TLS/SSL Setup: %s' % (nexthop, ))
                    self.__negotiatessl(nexthop[0], nexthop[1], proxy,
                      weak=(proxy[P_TYPE] == PROXY_TYPE_SSL_WEAK),
                      anonymous=(proxy[P_TYPE] == PROXY_TYPE_SSL_ANON))

                if proxy[P_TYPE] in PROXY_HTTPC_TYPES:
                    if DEBUG: DEBUG('*** HTTP CONNECT: %s' % (nexthop, ))
                    self.__negotiatehttpconnect(nexthop[0], nexthop[1], proxy)

                elif proxy[P_TYPE] in PROXY_HTTP_TYPES:
                    if len(chain) > 1:
                        # Chaining requires HTTP CONNECT.
                        if DEBUG: DEBUG('*** HTTP CONNECT: %s' % (nexthop, ))
                        self.__negotiatehttpconnect(nexthop[0], nexthop[1],
                                                    proxy)
                    else:
                        # If we are last in the chain, do transparent magic.
                        if DEBUG: DEBUG('*** HTTP PROXY: %s' % (nexthop, ))
                        self.__negotiatehttp(nexthop[0], nexthop[1], proxy)

                if proxy[P_TYPE] in PROXY_SOCKS5_TYPES:
                    if DEBUG: DEBUG('*** SOCKS5: %s' % (nexthop, ))
                    self.__negotiatesocks5(nexthop[0], nexthop[1], proxy)

                elif proxy[P_TYPE] == PROXY_TYPE_SOCKS4:
                    if DEBUG: DEBUG('*** SOCKS4: %s' % (nexthop, ))
                    self.__negotiatesocks4(nexthop[0], nexthop[1], proxy)

                elif proxy[P_TYPE] == PROXY_TYPE_NONE:
                    if first and nexthop[0] and nexthop[1]:
                         if DEBUG: DEBUG('*** Connect: %s:%s' % nexthop)
                         result = self.__sock.connect(nexthop)
                    else:
                         raise GeneralProxyError((4, _generalerrors[4]))

            first = False

        if DEBUG: DEBUG('*** Connected! (%s)' % result)
        return result

def wrapmodule(module):
    \"\"\"wrapmodule(module)
    Attempts to replace a module's socket library with a SOCKS socket.
    This will only work on modules that import socket directly into the
    namespace; most of the Python Standard Library falls into this category.
    \"\"\"
    module.socket.socket = socksocket
    module.socket.create_connection = sockcreateconn


## Netcat-like proxy-chaining tools follow ##

def netcat(s, i, o, keep_open=''):
    if hasattr(o, 'buffer'): o = o.buffer
    try:
        in_fileno = i.fileno()
        isel = [s, i]
        obuf, sbuf, oselo, osels = [], [], [], []
        while isel:
            in_r, out_r, err_r = select.select(isel, oselo+osels, isel, 1000)

#           print 'In:%s Out:%s Err:%s' % (in_r, out_r, err_r)
            if s in in_r:
                obuf.append(s.recv(4096))
                oselo = [o]
                if len(obuf[-1]) == 0:
                    if DEBUG: DEBUG('EOF(s, in)')
                    isel.remove(s)

            if o in out_r:
                o.write(obuf[0])
                if len(obuf) == 1:
                    if len(obuf[0]) == 0:
                        if DEBUG: DEBUG('CLOSE(o)')
                        o.close()
                        if i in isel and 'i' not in keep_open:
                            isel.remove(i)
                            i.close()
                    else:
                        o.flush()
                    obuf, oselo = [], []
                else:
                    obuf.pop(0)

            if i in in_r:
                sbuf.append(os.read(in_fileno, 4096))
                osels = [s]
                if len(sbuf[-1]) == 0:
                    if DEBUG: DEBUG('EOF(i)')
                    isel.remove(i)

            if s in out_r:
                s.send(sbuf[0])
                if len(sbuf) == 1:
                    if len(sbuf[0]) == 0:
                        if s in isel and 's' not in keep_open:
                            if DEBUG: DEBUG('CLOSE(s)')
                            isel.remove(s)
                            s.close()
                        else:
                            if DEBUG: DEBUG('SHUTDOWN(s, WR)')
                            s.shutdown(socket.SHUT_WR)
                    sbuf, osels = [], []
                else:
                    sbuf.pop(0)

        for data in sbuf: s.sendall(data)
        for data in obuf: o.write(data)

    except:
        if DEBUG: DEBUG(\"Disconnected: %s\" % (sys.exc_info(), ))

    i.close()
    s.close()
    o.close()

def __proxy_connect_netcat(hostname, port, chain, keep_open):
    try:
        s = socksocket(socket.AF_INET, socket.SOCK_STREAM)
        for proxy in chain:
            s.addproxy(*proxy)
        s.connect((hostname, port))
    except:
        sys.stderr.write('Error: %s\\n' % (sys.exc_info(), ))
        return False
    netcat(s, sys.stdin, sys.stdout, keep_open)
    return True

def __make_proxy_chain(args):
    chain = []
    for arg in args:
        chain.append(parseproxy(arg))
    return chain

def DebugPrint(text):
  print(text)

def Main():
    keep_open = 's'
    try:
        args = sys.argv[1:]
        if '--wait' in args:
            keep_open = 'si'
            args.remove('--wait')
        if '--nowait' in args:
            keep_open = ''
            args.remove('--nowait')
        if '--debug' in args:
            global DEBUG
            DEBUG = DebugPrint
            args.remove('--debug')
        for arg in ('--nopyopenssl', '--nossl'):
            while arg in args:
                args.remove(arg)

        usesystemdefaults()

        dest_host, dest_port = args.pop().split(':', 1)
        dest_port = int(dest_port)
        chain = __make_proxy_chain(args)
    except:
        DebugPrint('Error: %s' % (sys.exc_info(), ))
        sys.stderr.write(('Usage: %s '
                          '[<proto:proxy:port> [<proto:proxy:port> ...]] '
                          '<host:port>\\n') % os.path.basename(sys.argv[0]))
        sys.exit(1)

    try:
        if not __proxy_connect_netcat(dest_host, dest_port, chain, keep_open):
            sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == \"__main__\":
    Main()

"""
sys.modules["sockschain"] = imp.new_module("sockschain")
sys.modules["sockschain"].open = __comb_open
exec __FILES[".SELF/sockschain/__init__.py"] in sys.modules["sockschain"].__dict__


###############################################################################
__FILES[".SELF/pagekite/__init__.py"] = """\
#!/usr/bin/python -u
LICENSE = \"\"\"\\
pagekite.py, Copyright 2010, 2011, the Beanstalks Project ehf.
                                   and Bjarni Runar Einarsson

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

\"\"\"
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
APPVER = '0.4.6a'
AUTHOR = 'Bjarni Runar Einarsson, http://bre.klaki.net/'
WWWHOME = 'http://pagekite.net/'
LICENSE_URL = 'http://www.gnu.org/licenses/agpl.html'
EXAMPLES = (\"\"\"\\
    Basic usage, gives http://localhost:80/ a public name:
    $ pagekite.py NAME.pagekite.me

    To expose specific folders, files or use alternate local ports:
    $ pagekite.py +indexes /a/path/ NAME.pagekite.me   # built-in HTTPD
    $ pagekite.py *.html            NAME.pagekite.me   # built-in HTTPD
    $ pagekite.py 3000              NAME.pagekite.me   # http://localhost:3000/

    To expose multiple local servers (SSH and HTTP):
    $ pagekite.py ssh://NAME.pagekite.me AND 3000 http://NAME.pagekite.me
\"\"\")
MINIDOC = (\"\"\"\\
>>> Welcome to pagekite.py v%s!

%s
    To sign up with PageKite.net or get advanced instructions:
    $ pagekite.py --signup
    $ pagekite.py --help

    If you request a kite which does not exist in your configuration file,
    the program will offer to help you sign up with http://pagekite.net/ and
    create it. Pick a name, any name!\"\"\") % (APPVER, EXAMPLES)
DOC = (\"\"\"\\
pagekite.py is Copyright 2010, 2011, the Beanstalks Project ehf.
     v%s                               http://pagekite.net/

This the reference implementation of the PageKite tunneling protocol,
both the front- and back-end. This following protocols are supported:

  HTTP      - HTTP 1.1 only, requires a valid HTTP Host: header
  HTTPS     - Recent versions of TLS only, requires the SNI extension.
  WEBSOCKET - Using the proposed Upgrade: WebSocket method.

Other protocols may be proxied by using \"raw\" back-ends and HTTP CONNECT.

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
 --motd=/path/to/motd   Send the contents of this file to new back-ends.
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
 --delete_backend=...   Delete a given back-end.
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
    command line, with the restriction that there be exactly one \"option\"
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
    $ pagekite.py \\\\
        --defaults \\\\
        --dyndns=user:pass@no-ip.com \\\\
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

\"\"\"+EXAMPLES) % APPVER

MAGIC_PREFIX = '/~:PageKite:~/'
MAGIC_PATH = '%sv%s' % (MAGIC_PREFIX, PROTOVER)
MAGIC_PATHS = (MAGIC_PATH, '/Beanstalk~Magic~Beans/0.2')

SERVICE_PROVIDER = 'PageKite.net'
SERVICE_DOMAINS = ('pagekite.me', )
SERVICE_XMLRPC = 'http://pagekite.net/xmlrpc/'
SERVICE_TOS_URL = 'https://pagekite.net/support/terms/'

OPT_FLAGS = 'o:O:S:H:P:X:L:ZI:fA:R:h:p:aD:U:NE:'
OPT_ARGS = ['noloop', 'clean', 'nopyopenssl', 'nossl', 'nocrashreport',
            'nullui', 'remoteui', 'uiport=', 'help', 'settings',
            'optfile=', 'optdir=', 'savefile=', 'reloadfile=',
            'autosave', 'noautosave', 'friendly',
            'signup', 'list', 'add', 'only', 'disable', 'remove', 'save',
            'service_xmlrpc=', 'controlpanel', 'controlpass',
            'httpd=', 'pemfile=', 'httppass=', 'errorurl=', 'webpath=',
            'logfile=', 'daemonize', 'nodaemonize', 'runas=', 'pidfile=',
            'isfrontend', 'noisfrontend', 'settings',
            'defaults', 'local=', 'domain=',
            'authdomain=', 'motd=', 'register=', 'host=',
            'noupgradeinfo', 'upgradeinfo=',
            'ports=', 'protos=', 'portalias=', 'rawports=',
            'tls_default=', 'tls_endpoint=',
            'fe_certname=', 'jakenoia', 'ca_certs=',
            'kitename=', 'kitesecret=', 'fingerpath=',
            'backend=', 'define_backend=', 'be_config=', 'delete_backend',
            'frontend=', 'frontends=', 'torify=', 'socksify=', 'proxy=',
            'new', 'all', 'noall', 'dyndns=', 'nozchunks', 'sslzlib',
            'buffers=', 'noprobes', 'debugio',
            # DEPRECATED:
            'webroot=', 'webaccess=', 'webindexes=']

DEBUG_IO = False
DEFAULT_CHARSET = 'utf-8'
DEFAULT_BUFFER_MAX = 1024

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

BE_STATUS_REMOTE_SSL   = 0x0010000
BE_STATUS_OK           = 0x0001000
BE_STATUS_ERR_DNS      = 0x0000100
BE_STATUS_ERR_BE       = 0x0000010
BE_STATUS_ERR_TUNNEL   = 0x0000001
BE_STATUS_ERR_ANY      = 0x0000fff
BE_STATUS_UNKNOWN      = 0
BE_STATUS_DISABLED     = 0x8000000
BE_STATUS_DISABLE_ONCE = 0x4000000
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
SERVICE_DOMAIN_RE = re.compile('\\.(' + '|'.join(SERVICE_DOMAINS) + ')$')
SERVICE_SUBDOMAIN_RE = re.compile(r'^([A-Za-z0-9_-]+\\.)*[A-Za-z0-9_-]+$')

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

YamonD = MockYamonD
gYamon = YamonD(())


class MockPageKiteXmlRpc:
  def __init__(self, config):
    self.config = config

  def getSharedSecret(self, email, p):
    for be in self.config.backends.values():
      if be[BE_SECRET]: return be[BE_SECRET]

  def getAvailableDomains(self, a, b):
    return ['.%s' % x for x in SERVICE_DOMAINS]

  def signUp(self, a, b):
    return {
      'secret': self.getSharedSecret(a, b)
    }

  def addCnameKite(self, a, s, k): return {}
  def addKite(self, a, s, k): return {}


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
  \"\"\"
  This will generate a random token with a signature which could only have come
  from this server.  If a token is provided, it is re-signed so the original
  can be compared with what we would have generated, for verification purposes.

  If a timestamp is provided it will be embedded in the signature to a
  resolution of 10 minutes, and the signature will begin with the letter 't'

  Note: This is only as secure as random.randint() is random.
  \"\"\"
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
  \"\"\"
  Check a signature for validity. When using timestamped signatures, we only
  accept signatures from the current and previous windows.
  \"\"\"
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
  req = ['CONNECT PageKite:1 HTTP/1.0\\r\\n',
         'X-PageKite-Version: %s\\r\\n' % APPVER]

  if not nozchunks: req.append('X-PageKite-Features: ZChunks\\r\\n')
  if replace: req.append('X-PageKite-Replace: %s\\r\\n' % replace)
  if tls: req.append('X-PageKite-Features: TLS\\r\\n')

  tokens = tokens or {}
  for d in backends.keys():
    if (backends[d][BE_BHOST] and
        backends[d][BE_SECRET] and
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

      req.append('X-PageKite: %s:%s\\r\\n' % (data, sign))

  req.append('\\r\\n')
  return ''.join(req)

def HTTP_ResponseHeader(code, title, mimetype='text/html'):
  if mimetype.startswith('text/') and ';' not in mimetype:
    mimetype += ('; charset=%s' % DEFAULT_CHARSET)
  return ('HTTP/1.1 %s %s\\r\\nContent-Type: %s\\r\\nPragma: no-cache\\r\\n'
          'Expires: 0\\r\\nCache-Control: no-store\\r\\nConnection: close'
          '\\r\\n') % (code, title, mimetype)

def HTTP_Header(name, value):
  return '%s: %s\\r\\n' % (name, value)

def HTTP_StartBody():
  return '\\r\\n'

def HTTP_ConnectOK():
  return 'HTTP/1.0 200 Connection Established\\r\\n\\r\\n'

def HTTP_ConnectBad():
  return 'HTTP/1.0 503 Sorry\\r\\n\\r\\n'

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
                     '<p>The ', proto.upper(),' <a href=\"', WWWHOME, '\">',
                     '<i>PageKite</i></a> for <b>', domain,
                     '</b> is unavailable at the moment.</p>',
                     '<p>Please try again later.</p><!-- ', comment, ' -->'])
  if frame_url:
    if '?' in frame_url:
      frame_url += '&where=%s&proto=%s&domain=%s' % (where.upper(), proto, domain)
    return HTTP_Response(code, status,
                         ['<html><frameset cols=\"*\">',
                          '<frame target=\"_top\" src=\"', frame_url, '\" />',
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
  global LOG_LINE, LOG_LAST_TIME
  now = int(testtime or time.time())
  words = [('ts', '%x' % now),
           ('t',  '%s' % datetime.datetime.fromtimestamp(now).isoformat()),
           ('ll', '%x' % LOG_LINE)]
  words.extend([(kv[0], ('%s' % kv[1]).replace('\\t', ' ')
                                      .replace('\\r', ' ')
                                      .replace('\\n', ' ')
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
  LogFile.write('\\n')

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
  \"\"\"Handle authentication work in a separate thread.\"\"\"

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
    try:
      self.join()
    except RuntimeError:
      pass

  def run(self):
    self.keep_running = True
    while self.keep_running:
      try:
        self._run()
      except Exception, e:
        LogError('AuthThread died: %s' % e)
        time.sleep(5)
    LogDebug('AuthThread: done')

  def _run(self):
    self.qc.acquire()
    while self.keep_running:
      now = int(time.time())
      if self.jobs:
        (requests, conn, callback) = self.jobs.pop(0)
        if DEBUG_IO: print '=== AUTH REQUESTS\\n%s\\n===' % requests
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
              if not reason: reason = 'quota'
              results.append(('%s-Invalid' % prefix, what))
              results.append(('%s-Invalid-Why' % prefix,
                              '%s;%s' % (what, reason)))
              Log([('rejected', domain),
                   ('quota', quota),
                   ('reason', reason)])
            elif self.conns.Tunnel(proto, domain):
              # FIXME: Allow multiple backends?
              results.append(('%s-Duplicate' % prefix, what))
              Log([('rejected', domain),
                   ('duplicate', 'yes')])
            else:
              results.append(('%s-OK' % prefix, what))
              quotas.append(quota)
              if (proto.startswith('http') and
                  self.conns.config.GetTlsEndpointCtx(domain)):
                results.append(('%s-SSL-OK' % prefix, what))

        results.append(('%s-SessionID' % prefix,
                        '%x:%s' % (now, sha1hex(session))))
        results.append(('%s-Misc' % prefix, urllib.urlencode({
                          'motd': (self.conns.config.motd_message or ''),
                        })))
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

        if DEBUG_IO: print '=== AUTH RESULTS\\n%s\\n===' % results
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
  \"\"\"Base protocol parser class.\"\"\"

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
  \"\"\"Parse an unknown incoming connection request, line-by-line.\"\"\"

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
        self.parsers.remove(p)
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
  \"\"\"Parse an HTTP request, line-by-line.\"\"\"

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
    if line in ('', '\\r', '\\n', '\\r\\n'):
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
  \"\"\"Parse an incoming Finger request, line-by-line.\"\"\"

  PROTO = 'finger'
  PROTOS = ['finger', 'httpfinger']
  WANT_FINGER = 71

  def __init__(self, lines=None, state=WANT_FINGER):
    BaseLineParser.__init__(self, lines, state, self.PROTO)

  def ErrorReply(self, port=None):
    if port == 79:
      return ('PageKite wants to know, what domain?\\n'
              'Try: finger user+domain@domain\\n')
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
      self.lines[-1] = '%s\\n' % arg0
      return True
    else:
      self.state = BaseLineParser.PARSE_FAILED
      return False

class IrcLineParser(BaseLineParser):
  \"\"\"Parse an incoming IRC connection, line-by-line.\"\"\"

  PROTO = 'irc'
  PROTOS = ['irc']
  WANT_USER = 61

  def __init__(self, lines=None, state=WANT_USER):
    self.seen = []
    BaseLineParser.__init__(self, lines, state, self.PROTO)

  def ErrorReply(self):
    return ':pagekite 451 :IRC Gateway requires user@HOST or nick@HOST\\n'

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    if line in ('\\n', '\\r\\n'): return True
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
            self.lines[-1] = '%s %s %s\\n' % (ocmd, arg0, ' '.join(args[1:]))
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
  \"\"\"A wrapper around a socket, for use with select.\"\"\"

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
            '\\n') % (self.zw and ('level %d' % self.zlevel) or 'off',
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
      gYamon.vadd(\"bytes_all\", self.wrote_bytes
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
        if DEBUG_IO: print '<== IN (peeked)\\n%s\\n===' % data
      else:
        data = self.fd.recv(maxread)
        if DEBUG_IO: print '<== IN\\n%s\\n===' % data
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

    self.last_activity = time.time()
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
        if DEBUG_IO: print '==> OUT\\n%s\\n===' % sending[:sent_bytes]
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
        return self.Send(['%xZ%x%s\\r\\n%s' % (len(sdata), len(zdata), rst, zdata)])
      except zlib.error:
        LogError('Error compressing, resetting ZChunks.')
        self.ResetZChunks()

    return self.Send(['%x%s\\r\\n%s' % (len(sdata), rst, sdata)])

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
  \"\"\"A container for connections (Selectables), config and tunnel info.\"\"\"

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
    try:
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
    except ValueError:
      # Let's not asplode if another thread races us for this.
      pass

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
  \"\"\"A Selectable which parses the input as lines of text.\"\"\"

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
      if line.endswith('\\n'):
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
SSL_CLIENTHELLO = '\\x80'

# FIXME: XMPP support
class MagicProtocolParser(LineParser):
  \"\"\"A Selectable which recognizes HTTP, TLS or XMPP preambles.\"\"\"

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
      prefix, words, data = data.split('\\r\\n', 2)
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
    if proto in ('http', 'http2', 'http3', 'websocket'):
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
  \"\"\"A Selectable which parses the input as chunks.\"\"\"

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
      if self.header.find('\\r\\n') < 0:
        if self.read_eof: return self.ProcessEofRead()
        return True
      try:
        size, data = self.header.split('\\r\\n', 1)
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
        # FIXME: This blows the stack from time to time.  We need a loop
        #        or better yet, to just process more in a subsequent
        #        iteration of the main select() loop.
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
  \"\"\"A Selectable representing a PageKite tunnel.\"\"\"

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
    \"\"\"This is what the front-end does when a back-end requests a new tunnel.\"\"\"
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
      output.append('%s: %s\\r\\n' % r)

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
    while not data.endswith('\\r\\n\\r\\n') and not data.endswith('\\n\\n'):
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
    if DEBUG_IO: print '<== IN (headers)\\n%s\\n===' % data
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
    \"\"\"This is the back-end end of a tunnel.\"\"\"
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
          conns.config.ui.NotifyServer(self, self.server_info)

          for misc in parse.Header('X-PageKite-Misc'):
            args = parse_qs(misc)
            logdata = [('FE', sname)]
            for arg in args:
              logdata.append((arg, args[arg][0]))
            Log(logdata)
            if 'motd' in args and args['motd'][0]:
              conns.config.ui.NotifyMOTD(sname, args['motd'][0])

          for quota in parse.Header('X-PageKite-Quota'):
            self.quota = [int(quota), None, None]
            self.Log([('FE', sname), ('quota', quota)])
            conns.config.ui.NotifyQuota(float(quota))

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
            conns.config.ui.NotifyKiteRejected(proto, domain, reason, crit=True)
            conns.config.SetBackendStatus(domain, proto,
                                          add=BE_STATUS_ERR_TUNNEL)

          for request in parse.Header('X-PageKite-Duplicate'):
            abort = True
            proto, domain, srand = request.split(':')
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('err', 'Duplicate'),
                      ('proto', proto),
                      ('domain', domain)])
            conns.config.ui.NotifyKiteRejected(proto, domain, 'duplicate')
            conns.config.SetBackendStatus(domain, proto,
                                          add=BE_STATUS_ERR_TUNNEL)

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
            status = BE_STATUS_OK
            if request in ssl_available:
              status |= BE_STATUS_REMOTE_SSL
              self.remote_ssl[(proto, domain)] = True
            self.Log([('FE', sname),
                      ('proto', proto),
                      ('domain', domain),
                      ('ssl', (request in ssl_available))])
            conns.config.SetBackendStatus(domain, proto, add=status)

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
    self.last_activity = time.time()

    return self

  FrontEnd = staticmethod(_FrontEnd)
  BackEnd = staticmethod(_BackEnd)

  def SendData(self, conn, data, sid=None, host=None, proto=None, port=None,
                                 chunk_headers=None):
    sid = int(sid or conn.sid)
    if conn: self.users[sid] = conn
    if not sid in self.zhistory: self.zhistory[sid] = [0, 0]

    sending = ['SID: %s\\r\\n' % sid]
    if proto: sending.append('Proto: %s\\r\\n' % proto)
    if host: sending.append('Host: %s\\r\\n' % host)
    if port:
      porti = int(port)
      if porti in self.conns.config.server_portalias:
        sending.append('Port: %s\\r\\n' % self.conns.config.server_portalias[porti])
      else:
        sending.append('Port: %s\\r\\n' % port)
    if chunk_headers:
      for ch in chunk_headers: sending.append('%s: %s\\r\\n' % ch)
    sending.append('\\r\\n')
    sending.append(data)

    return self.SendChunked(sending, zhistory=self.zhistory[sid])

  def SendStreamEof(self, sid, write_eof=False, read_eof=False):
    return self.SendChunked('SID: %s\\r\\nEOF: 1%s%s\\r\\n\\r\\nBye!' % (sid,
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
    return self.SendChunked('NOOP: 1\\r\\nZRST: 1\\r\\n\\r\\n!', compress=False)

  def SendPing(self):
    self.last_ping = int(time.time())
    self.LogDebug(\"Ping\", [('host', self.server_info[self.S_NAME])])
    return self.SendChunked('NOOP: 1\\r\\nPING: 1\\r\\n\\r\\n!', compress=False)

  def SendPong(self):
    return self.SendChunked('NOOP: 1\\r\\n\\r\\n!', compress=False)

  def SendQuota(self):
    return self.SendChunked('NOOP: 1\\r\\nQuota: %s\\r\\n\\r\\n!' % self.quota[0],
                            compress=False)

  def SendThrottle(self, sid, write_speed):
    return self.SendChunked('NOOP: 1\\r\\nSID: %s\\r\\nSPD: %d\\r\\n\\r\\n!' % (
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
      headers, data = data.split('\\r\\n\\r\\n', 1)
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
        self.conns.config.ui.Notify(('You have %.2f MB of quota left.'
                                     ) % (float(self.quota[0]) / 1024),
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
              if not self.SendChunked('SID: %s\\r\\n\\r\\n%s' % (
                                        sid, HTTP_NoFeConnection() )):
                return False
            elif self.Probe(host):
              LogDebug('Responding to probe for %s: good' % host)
              if not self.SendChunked('SID: %s\\r\\n\\r\\n%s' % (
                                        sid, HTTP_GoodBeConnection() )):
                return False
            else:
              LogDebug('Responding to probe for %s: back-end down' % host)
              if not self.SendChunked('SID: %s\\r\\n\\r\\n%s' % (
                                        sid, HTTP_NoBeConnection() )):
                return False
          else:
            conn = UserConn.BackEnd(proto, host, sid, self, port,
                                    remote_ip=rIp, remote_port=rPort, data=data)
            if proto in ('http', 'http2', 'http3', 'websocket'):
              if conn is None:
                if not self.SendChunked('SID: %s\\r\\n\\r\\n%s' % (sid,
                                          HTTP_Unavailable('be', proto, host,
                                       frame_url=self.conns.config.error_url))):
                  return False
              elif not conn:
                if not self.SendChunked('SID: %s\\r\\n\\r\\n%s' % (sid,
                                          HTTP_Unavailable('be', proto, host,
                                       frame_url=self.conns.config.error_url,
                                      code=401))):
                  return False
              elif rIp:
                add_headers = ('\\nX-Forwarded-For: %s\\r\\n'
                               'X-PageKite-Port: %s\\r\\n'
                               'X-PageKite-Proto: %s\\r\\n'
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
                  add_headers += ('Connection: close\\r\\n'
                                  'Host: %s\\r\\n') % rewritehost
                req, rest = re.sub(r'(?mi)^x-forwarded-for',
                                   'X-Old-Forwarded-For', data).split('\\n', 1)
                data = ''.join([req, add_headers, rest])

            elif proto == 'httpfinger':
              # Rewrite a finger request to HTTP.
              try:
                firstline, rest = data.split('\\n', 1)
                if conn.config.get('rewritehost', False):
                  rewritehost = conn.backend[BE_BHOST]
                else:
                  rewritehost = host
                if '%s' in self.conns.config.finger_path:
                  args =  (firstline.strip(), rIp, rewritehost, rest)
                else:
                  args =  (rIp, rewritehost, rest)
                data = ('GET '+self.conns.config.finger_path+' HTTP/1.1\\r\\n'
                        'X-Forwarded-For: %s\\r\\n'
                        'Connection: close\\r\\n'
                        'Host: %s\\r\\n\\r\\n%s') % args
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
  \"\"\"A Tunnel which just loops back to this process.\"\"\"

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
  \"\"\"A Selectable representing a user's connection.\"\"\"

  def __init__(self, address, ui=None):
    Selectable.__init__(self, address=address, ui=ui)
    self.tunnel = None
    self.conns = None
    self.backend = BE_NONE[:]
    self.config = {}
    # UserConn objects are considered active immediately
    self.last_activity = time.time()

  def __html__(self):
    return ('<b>Tunnel</b>: <a href=\"/conn/%s\">%s</a><br>'
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
      elif proto == 'http': protos.extend(['http2', 'http3'])

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
      if proto.startswith('http'):
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
    # tunnel is found, look for a plain HTTP tunnel.  Fallback hosts can
    # be registered using the http2/3/4 protocols.
    backend = None

    if proto == 'http': protos = [proto, 'http2', 'http3']
    elif proto == 'probe': protos = ['http', 'http2', 'http3']
    elif proto == 'websocket': protos = [proto, 'http', 'http2', 'http3']
    else: protos = [proto]

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
        if proto in ('websocket', 'http', 'http2', 'http3'):
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
          if DEBUG_IO: print '=== REQUEST\\n%s\\n===' % data
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
  \"\"\"This class is a connection which we're not sure what is yet.\"\"\"

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
      self.Send(['220 ready ESMTP PageKite Magic Proxy\\n'], try_flush=True)

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
      self.Send('PONG %s\\r\\n\\r\\n' % self.parser.path)
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
                ('http'+sid2) in tunnels) or (
                ('http2'+sid1) in tunnels) or (
                ('http2'+sid2) in tunnels) or (
                ('http3'+sid1) in tunnels) or (
                ('http3'+sid2) in tunnels):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpLineParser()
              self.Send(HTTP_ConnectOK(), try_flush=True)
              return True

          whost = chost
          if '.' in whost:
            whost = '*.' + '.'.join(whost.split('.')[1:])

          if cport == 443:
            if (('https'+sid1) in tunnels) or (
                ('https'+sid2) in tunnels) or (
                chost in self.conns.config.tls_endpoints) or (
                whost in self.conns.config.tls_endpoints):
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
          self.my_tls = True
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


class UiConn(LineParser):

  STATE_PASSWORD = 0
  STATE_LIVE     = 1

  def __init__(self, fd, address, on_port, conns):
    LineParser.__init__(self, fd=fd, address=address, on_port=on_port)
    self.state = self.STATE_PASSWORD

    self.conns = conns
    self.conns.Add(self)
    self.lines = []
    self.qc = threading.Condition()

    self.challenge = sha1hex('%s%8.8x' % (globalSecret(),
                                          random.randint(0, 0x7FFFFFFD)+1))
    self.expect = signToken(token=self.challenge,
                            secret=self.conns.config.ConfigSecret(),
                            payload=self.challenge,
                            length=1000)
    LogDebug('Expecting: %s' % self.expect)
    self.Send('PageKite? %s\\r\\n' % self.challenge)


  def readline(self):
    self.qc.acquire()
    while not self.lines: self.qc.wait()
    line = self.lines.pop(0)
    self.qc.release()
    return line

  def write(self, data):
    self.conns.config.ui_wfile.write(data)
    self.Send(data)

  def Cleanup(self):
    self.conns.config.ui.wfile = self.conns.config.ui_wfile
    self.conns.config.ui.rfile = self.conns.config.ui_rfile
    self.lines = self.conns.config.ui_conn = None
    self.conns = None
    LineParser.Cleanup(self)

  def Disconnect(self):
    self.Send('Goodbye')
    self.Cleanup()

  def ProcessLine(self, line, lines):
    if self.state == self.STATE_LIVE:
      self.qc.acquire()
      self.lines.append(line)
      self.qc.notify()
      self.qc.release()
      return True
    elif self.state == self.STATE_PASSWORD:
      if line.strip() == self.expect:
        if self.conns.config.ui_conn: self.conns.config.ui_conn.Disconnect()
        self.conns.config.ui_conn = self
        self.conns.config.ui.wfile = self
        self.conns.config.ui.rfile = self
        self.state = self.STATE_LIVE
        self.Send('OK!\\r\\n')
        return True
      else:
        self.Send('Sorry.\\r\\n')
        return False
    else:
      return False


class RawConn(Selectable):
  \"\"\"This class is a raw/timed connection.\"\"\"

  def __init__(self, fd, address, on_port, conns):
    Selectable.__init__(self, fd, address, on_port)
    self.my_tls = False
    self.is_tls = False

    domain = conns.LastIpDomain(address[0])
    if domain and UserConn.FrontEnd(self, address, 'raw', domain, on_port,
                                    [], conns):
      self.Cleanup(close=False)
    else:
      self.Cleanup()


class Listener(Selectable):
  \"\"\"This class listens for incoming connections and accepts them.\"\"\"

  def __init__(self, host, port, conns, backlog=100,
                     connclass=UnknownConn, quiet=False):
    Selectable.__init__(self, bind=(host, port), backlog=backlog)
    self.Log([('listen', '%s:%s' % (host, port))])
    if not quiet:
      conns.config.ui.Notify(' - Listening on %s:%s' % (host or '*', port))

    self.connclass = connclass
    self.port = port
    self.last_activity = self.created + 1
    self.conns = conns
    self.conns.Add(self)

  def __str__(self):
    return '%s port=%s' % (Selectable.__str__(self), self.port)

  def __html__(self):
    return '<p>Listening on port %s for %s</p>' % (self.port, self.connclass)

  def ReadData(self, maxread=None):
    try:
      client, address = self.fd.accept()
      if client:
        self.Log([('accept', '%s:%s' % (obfuIp(address[0]), address[1]))])
        uc = self.connclass(client, address, self.port, self.conns)
        return True

    except IOError, err:
      if err.errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogDebug('Listener::ReadData: error: %s (%s)' % (err, err.errno))

    except socket.error, (errno, msg):
      if errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogInfo('Listener::ReadData: error: %s (errno=%s)' % (msg, errno))

    except Exception, e:
      LogDebug('Listener::ReadData: %s' % e)

    return False


class HttpUiThread(threading.Thread):
  \"\"\"Handle HTTP UI in a separate thread.\"\"\"

  daemon = True

  def __init__(self, pkite, conns,
               server=None, handler=None, ssl_pem_filename=None):
    threading.Thread.__init__(self)
    if not (server and handler):
      self.serve = False
      self.httpd = None
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
    except IOError:
      pass
    try:
      self.join()
    except RuntimeError:
      try:
        if self.httpd and self.httpd.socket:
          self.httpd.socket.close()
      except IOError:
        pass

  def run(self):
    while self.serve:
      try:
        self.httpd.handle_request()
      except KeyboardInterrupt:
        self.serve = False
      except Exception, e:
        LogInfo('HTTP UI caught exception: %s' % e)
    if self.httpd: self.httpd.socket.close()
    LogDebug('HttpUiThread: done')


class UiCommunicator(threading.Thread):
  \"\"\"Listen for interactive commands.\"\"\"

  def __init__(self, config, conns):
    threading.Thread.__init__(self)
    self.looping = False
    self.config = config
    self.conns = conns
    LogDebug('UiComm: Created')

  def run(self):
    self.looping = True
    while self.looping:
      if not self.config or not self.config.ui.ALLOWS_INPUT:
        time.sleep(1)
        continue

      line = ''
      try:
        i, o, e = select.select([self.config.ui.rfile], [], [], 1)
        if not i: continue
      except:
        pass

      if self.config:
        line = self.config.ui.rfile.readline().strip()
        if line: self.Parse(line)

    LogDebug('UiCommunicator: done')

  def Reconnect(self):
    if self.config.tunnel_manager:
      self.config.ui.Status('reconfig')
      self.config.tunnel_manager.CloseTunnels()
      self.config.tunnel_manager.HurryUp()

  def Parse(self, line):
    try:
      command, args = line.split(': ', 1)
      LogDebug('UiComm: %s(%s)' % (command, args))

      if args.lower() == 'none': args = None
      elif args.lower() == 'true': args = True
      elif args.lower() == 'false': args = False

      if command == 'exit':
        self.config.keep_looping = False
        self.config.main_loop = False
      elif command == 'restart':
        self.config.keep_looping = False
        self.config.main_loop = True
      elif command == 'config':
        command = 'change settings'
        self.config.Configure(['--%s' % args])
      elif command == 'enablekite':
        command = 'enable kite'
        if args and args in self.config.backends:
          self.config.backends[args][BE_STATUS] = BE_STATUS_UNKNOWN
          self.Reconnect()
        else:
          raise Exception('No such kite: %s' % args)
      elif command == 'disablekite':
        command = 'disable kite'
        if args and args in self.config.backends:
          self.config.backends[args][BE_STATUS] = BE_STATUS_DISABLED
          self.Reconnect()
        else:
          raise Exception('No such kite: %s' % args)
      elif command == 'delkite':
        command = 'remove kite'
        if args and args in self.config.backends:
          del self.config.backends[args]
          self.Reconnect()
        else:
          raise Exception('No such kite: %s' % args)
      elif command == 'addkite':
        command = 'create new kite'
        args = (args or '').strip().split() or ['']
        if self.config.RegisterNewKite(kitename=args[0],
                                       autoconfigure=True, ask_be=True):
          self.Reconnect()
      elif command == 'save':
        command = 'save configuration'
        self.config.SaveUserConfig(quiet=(args == 'quietly'))

    except ValueError:
      LogDebug('UiComm: bogus: %s' % line)
    except SystemExit:
      self.config.keep_looping = False
      self.config.main_loop = False
    except:
      LogDebug('UiComm: %s' % (sys.exc_info(), ))
      self.config.ui.Tell(['Oops!', '', 'Failed to %s, details:' % command,
                           '', '%s' % (sys.exc_info(), )], error=True)

  def quit(self):
    self.looping = False
    self.conns = None
    try:
      self.join()
    except RuntimeError:
      pass


class TunnelManager(threading.Thread):
  \"\"\"Create new tunnels as necessary or kill idle ones.\"\"\"

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

  def CloseTunnels(self):
    close = []
    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        close.append(tunnel)
    for tunnel in close:
      Log([('closing', tunnel.server_info[tunnel.S_NAME])])
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
        if DEBUG_IO: traceback.print_exc(file=sys.stderr)
        time.sleep(5)
    LogDebug('TunnelManager: done')

  def _run(self):
    self.check_interval = 5
    while self.keep_running:

      # Reconnect if necessary, randomized exponential fallback.
      problem = False
      if self.pkite.CreateTunnels(self.conns) > 0:
        self.check_interval += int(1+random.random()*self.check_interval)
        if self.check_interval > 300: self.check_interval = 300
        problem = True
        time.sleep(1)
      else:
        self.check_interval = 5

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
            self.pkite.ui.NotifyFlyingFE(proto, port, domain)

        self.PingTunnels(time.time())

      self.pkite.ui.StartListingBackEnds()
      for bid in self.pkite.backends:
        be = self.pkite.backends[bid]
        # Do we have auto-SSL at the front-end?
        protoport, domain = bid.split(':', 1)
        tunnels = self.conns.Tunnel(protoport, domain)
        if be[BE_PROTO] in ('http', 'http2', 'http3') and tunnels:
          has_ssl = True
          for t in tunnels:
            if (protoport, domain) not in t.remote_ssl: has_ssl = False
        else:
          has_ssl = False

        # Get list of webpaths...
        domainp = '%s/%s' % (domain, be[BE_PORT] or '80')
        if (self.pkite.ui_sspec and
            be[BE_BHOST] == self.pkite.ui_sspec[0] and
            be[BE_BPORT] == self.pkite.ui_sspec[1]):
          builtin = True
          dpaths = self.pkite.ui_paths.get(domainp, {})
        else:
          builtin = False
          dpaths = {}

        self.pkite.ui.NotifyBE(bid, be, has_ssl, dpaths, is_builtin=builtin)
      self.pkite.ui.EndListingBackEnds()

      if self.pkite.isfrontend:
        self.pkite.LoadMOTD()

      tunnel_count = len(self.pkite.conns and
                         self.pkite.conns.TunnelServers() or [])
      tunnel_total = len(self.pkite.servers)
      if tunnel_count == 0:
        if self.pkite.isfrontend:
          self.pkite.ui.Status('idle', message='Waiting for back-ends.')
        elif tunnel_total == 0:
          self.pkite.ui.Status('down', color=self.pkite.ui.GREY,
                       message='No kites ready to fly.  Boring...')
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
      else:
        self.pkite.ui.Status('flying', color=self.pkite.ui.GREEN,
                                   message='Kites are flying and all is well.')

      for i in xrange(0, self.check_interval):
        if self.keep_running:
          time.sleep(1)
          if i > self.check_interval: break
          if self.pkite.isfrontend:
            self.CheckIdleConns(time.time())

  def HurryUp(self):
    self.check_interval = 0


class NullUi(object):
  \"\"\"This is a UI that always returns default values or raises errors.\"\"\"

  DAEMON_FRIENDLY = True
  ALLOWS_INPUT = False
  WANTS_STDERR = False
  REJECTED_REASONS = {
    'quota': 'You are out of quota',
    'nodays': 'Your subscription has expired',
    'noquota': 'You are out of quota',
    'noconns': 'You are flying too many kites',
    'unauthorized': 'Invalid account or shared secret'
  }

  def __init__(self, welcome=None, wfile=sys.stderr, rfile=sys.stdin):
    if sys.platform in ('win32', 'os2', 'os2emx'):
      self.CLEAR = '\\n\\n'
      self.NORM = self.WHITE = self.GREY = self.GREEN = self.YELLOW = ''
      self.BLUE = self.RED = self.MAGENTA = self.CYAN = ''
    else:
      self.CLEAR = '\\033[H\\033[J'
      self.NORM = '\\033[0m'
      self.WHITE = '\\033[1m'
      self.GREY =  '\\033[0m' #'\\033[30;1m'
      self.RED = '\\033[31;1m'
      self.GREEN = '\\033[32;1m'
      self.YELLOW = '\\033[33;1m'
      self.BLUE = '\\033[34;1m'
      self.MAGENTA = '\\033[35;1m'
      self.CYAN = '\\033[36;1m'

    self.wfile = wfile
    self.rfile = rfile

    self.in_wizard = False
    self.wizard_tell = None
    self.last_tick = 0
    self.notify_history = {}
    self.status_tag = ''
    self.status_col = self.NORM
    self.status_msg = ''
    self.welcome = welcome
    self.tries = 200
    self.server_info = None
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

  def AskYesNo(self, question, default=None, pre=None, yes='Yes', no='No',
               wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskBackends(self, kitename, protos, ports, rawports, question, pre=[],
                  default=None, wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def Working(self, message): pass

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

  def NotifyMOTD(self, frontend, message):
    pass

  def NotifyKiteRejected(self, proto, domain, reason, crit=False):
    if reason in self.REJECTED_REASONS:
      reason = self.REJECTED_REASONS[reason]
    self.Notify('REJECTED: %s:%s (%s)' % (proto, domain, reason),
                prefix='!', color=(crit and self.RED or self.YELLOW))

  def NotifyServer(self, obj, server_info):
    self.server_info = server_info
    self.Notify('Connecting to front-end %s ...' % server_info[obj.S_NAME],
                color=self.GREY)
    self.Notify(' - Protocols: %s' % ' '.join(server_info[obj.S_PROTOS]),
                color=self.GREY)
    self.Notify(' - Ports: %s' % ' '.join(server_info[obj.S_PORTS]),
                color=self.GREY)
    if 'raw' in server_info[obj.S_PROTOS]:
      self.Notify(' - Raw ports: %s' % ' '.join(server_info[obj.S_RAW_PORTS]),
                  color=self.GREY)

  def NotifyQuota(self, quota):
    qMB = 1024
    self.Notify('You have %.2f MB of quota left.' % (quota / qMB),
                prefix=(int(quota) < qMB) and '!' or ' ',
                color=self.MAGENTA)

  def NotifyFlyingFE(self, proto, port, domain, be=None):
    self.Notify(('Flying: %s://%s%s/'
                 ) % (proto, domain, port and ':'+port or ''),
                prefix='~<>', color=self.CYAN)

  def StartListingBackEnds(self): pass
  def EndListingBackEnds(self): pass

  def NotifyBE(self, bid, be, has_ssl, dpaths, is_builtin=False):
    domain, port, proto = be[BE_DOMAIN], be[BE_PORT], be[BE_PROTO]
    prox = (proto == 'raw') and ' (HTTP proxied)' or ''
    if proto == 'raw' and port in ('22', 22): proto = 'ssh'
    url = '%s://%s%s' % (proto, domain, port and (':%s' % port) or '')

    if be[BE_STATUS] == BE_STATUS_UNKNOWN: return
    if be[BE_STATUS] & BE_STATUS_OK:
      if be[BE_STATUS] & BE_STATUS_ERR_ANY:
        status = 'Trying'
        color = self.YELLOW
        prefix = '   '
      else:
        status = 'Flying'
        color = self.CYAN
        prefix = '~<>'
    else:
      return

    self.Notify(('%s %s:%s as %s/%s'
                 ) % (status, be[BE_BHOST], be[BE_BPORT], url, prox),
                prefix=prefix, color=color)

    if status == 'Flying':
      for dp in sorted(dpaths.keys()):
        self.Notify(' - %s%s' % (url, dp), color=self.BLUE)

  def Status(self, tag, message=None, color=None): pass

  def ExplainError(self, error, title, subject=None):
    if error == 'pleaselogin':
      self.Tell([title, '', 'You already have an account. Log in to continue.'
                 ], error=True)
    elif error == 'email':
      self.Tell([title, '', 'Invalid e-mail address. Please try again?'
                 ], error=True)
    elif error == 'honey':
      self.Tell([title, '', 'Hmm. Somehow, you triggered the spam-filter.'
                 ], error=True)
    elif error in ('domaintaken', 'domain', 'subdomain'):
      self.Tell([title, '',
                 'Sorry, that domain (%s) is unavailable.' % subject
                 ], error=True)
    elif error == 'checkfailed':
      self.Tell([title, '',
                 'That domain (%s) is not correctly set up.' % subject
                 ], error=True)
    elif error == 'network':
      self.Tell([title, '',
                 'There was a problem communicating with %s.' % subject, '',
                 'Please verify that you have a working'
                 ' Internet connection and try again!'
                 ], error=True)
    else:
      self.Tell([title, 'Error code: %s' % error, 'Try again later?'
                 ], error=True)


class PageKite(object):
  \"\"\"Configuration and master select loop.\"\"\"

  def __init__(self, ui=None, http_handler=None, http_server=None):
    self.progname = ((sys.argv[0] or 'pagekite.py').split('/')[-1]
                                                   .split('\\\\')[-1])
    self.ui = ui or NullUi()
    self.ui_request_handler = http_handler
    self.ui_http_server = http_server
    self.ResetConfiguration()

  def ResetConfiguration(self):
    self.isfrontend = False
    self.upgrade_info = []
    self.auth_domain = None
    self.motd = None
    self.motd_message = None
    self.server_host = ''
    self.server_ports = [80]
    self.server_raw_ports = []
    self.server_portalias = {}
    self.server_aliasport = {}
    self.server_protos = ['http', 'http2', 'http3', 'https', 'websocket',
                          'irc', 'finger', 'httpfinger', 'raw']

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
    self.ui_httpd = None
    self.ui_sspec_cfg = None
    self.ui_sspec = None
    self.ui_socket = None
    self.ui_password = None
    self.ui_pemfile = None
    self.ui_magic_file = '.pagekite.magic'
    self.ui_paths = {}
    self.be_config = {}
    self.disable_zchunks = False
    self.enable_sslzlib = False
    self.buffer_max = DEFAULT_BUFFER_MAX
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
    self.last_loop = 0
    self.keep_looping = True
    self.main_loop = True

    self.crash_report_url = '%scgi-bin/crashes.pl' % WWWHOME
    self.rcfile_recursion = 0
    self.rcfiles_loaded = []
    self.savefile = None
    self.autosave = 0
    self.reloadfile = None
    self.added_kites = False
    self.ui_wfile = sys.stderr
    self.ui_rfile = sys.stdin
    self.ui_port = None
    self.ui_conn = None
    self.ui_comm = None

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
      '###[ Current settings for pagekite.py v%s. ]#########' % APPVER,
      '#',
      '## NOTE: This file may be rewritten/reordered by pagekite.py.',
      '#',
      '',
    ]

    if not self.kitename:
      for be in self.backends.values():
        if not self.kitename or len(self.kitename) < len(be[BE_DOMAIN]):
          self.kitename = be[BE_DOMAIN]
          self.kitesecret = be[BE_SECRET]

    new = not (self.kitename or self.kitesecret or self.backends)
    def p(vfmt, value, dval):
      return '%s%s' % (value and value != dval
                             and ('', vfmt % value) or ('# ', vfmt % dval))

    if self.kitename or self.kitesecret or new:
      config.extend([
        '##[ Default kite and account details ]##',
        p('kitename=%s', self.kitename, 'NAME'),
        p('kitesecret=%s', self.kitesecret, 'SECRET'),
        ''
      ])

    if self.SetServiceDefaults(check=True):
      config.extend([
        '##[ Front-end settings: use service defaults ]##',
        'defaults',
        ''
      ])
      if self.servers_manual:
        config.append('##[ Manual front-ends ]##')
        for server in sorted(self.servers_manual):
          config.append('frontend=%s' % server)
        config.append('')
    else:
      if not self.servers_auto and not self.servers_manual:
        new = True
        config.extend([
          '##[ Use this to just use service defaults ]##',
          '# defaults',
          ''
        ])
      config.append('##[ Custom front-end and dynamic DNS settings ]##')
      if self.servers_auto:
        config.append('frontends=%d:%s:%d' % self.servers_auto)
      if self.servers_manual:
        for server in sorted(self.servers_manual):
          config.append('frontend=%s' % server)
      if not self.servers_auto and not self.servers_manual:
        new = True
        config.append('# frontends=N:hostname:port')
        config.append('# frontend=hostname:port')

      for server in sorted(self.fe_certname):
        config.append('fe_certname=%s' % server)
      if self.ca_certs != self.ca_certs_default:
        config.append('ca_certs=%s' % self.ca_certs)

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
        new = True
        config.extend([
          '# dyndns=pagekite.net OR',
          '# dyndns=user:pass@dyndns.org OR',
          '# dyndns=user:pass@no-ip.com' ,
          '#',
          p('errorurl=%s', self.error_url, 'http://host/page/'),
          p('fingerpath=%s', self.finger_path, '/~%s/.finger'),
          '',
        ])

    if self.ui_sspec or self.ui_password or self.ui_pemfile:
      config.extend([
        '##[ Built-in HTTPD settings ]##',
        p('httpd=%s:%s', self.ui_sspec_cfg, ('host', 'port'))
      ])
      if self.ui_password: config.append('httppass=%s' % self.ui_password)
      if self.ui_pemfile: config.append('pemfile=%s' % self.pemfile)
      for http_host in sorted(self.ui_paths.keys()):
        for path in sorted(self.ui_paths[http_host].keys()):
          up = self.ui_paths[http_host][path]
          config.append('webpath=%s:%s:%s:%s' % (http_host, path, up[0], up[1]))
      config.append('')

    config.append('##[ Back-ends and local services ]##')
    bprinted = 0
    for bid in sorted(self.backends.keys()):
      be = self.backends[bid]
      proto, domain = bid.split(':')
      if be[BE_BHOST]:
        be_spec = (be[BE_BHOST], be[BE_BPORT])
        config.append(('%s=%s:%s:%s:%s'
                       ) % ((be[BE_STATUS] == BE_STATUS_DISABLED
                             ) and 'define_backend' or 'backend',
                   proto, ((domain == self.kitename) and '@kitename' or domain),
         (be_spec == self.ui_sspec) and 'localhost:builtin' or ('%s:%s' % be_spec),
         (be[BE_SECRET] == self.kitesecret) and '@kitesecret' or be[BE_SECRET]))
        bprinted += 1
    if bprinted == 0:
      config.append('# No back-ends!  How boring!')
    for http_host in sorted(self.be_config.keys()):
      for key in sorted(self.be_config[http_host].keys()):
        config.append('be_config=%s:%s:%s' % (http_host, key,
                                              self.be_config[http_host][key]))
    config.append('')

    if bprinted == 0:
      new = True
      config.extend([
        '##[ Back-end examples ... ]##',
        '#',
        '# backend=http:YOU.pagekite.me:localhost:80:SECRET',
        '# backend=ssh:YOU.pagekite.me:localhost:22:SECRET',
        '# backend=http/8080:YOU.pagekite.me:localhost:8080:SECRET',
        '# backend=https:YOU.pagekite.me:localhost:443:SECRET',
        '# backend=websocket:YOU.pagekite.me:localhost:8080:SECRET',
        '#',
        '# define_backend=http:YOU.pagekite.me:localhost:4545:SECRET',
        ''
      ])

    if self.isfrontend or new:
      config.extend([
        '##[ Front-end Options ]##',
        (self.isfrontend and 'isfrontend' or '# isfrontend')
      ])
      comment = ((not self.isfrontend) and '# ' or '')
      config.extend([
        p('host=%s', self.isfrontend and self.server_host, 'machine.domain.com'),
        '%sports=%s' % (comment, ','.join(['%s' % x for x in sorted(self.server_ports)] or [])),
        '%sprotos=%s' % (comment, ','.join(['%s' % x for x in sorted(self.server_protos)] or []))
      ])
      for pa in self.server_portalias:
        config.append('portalias=%s:%s' % (int(pa), int(self.server_portalias[pa])))
      config.extend([
        '%srawports=%s' % (comment or (not self.server_raw_ports) and '# ' or '',
                           ','.join(['%s' % x for x in sorted(self.server_raw_ports)] or [VIRTUAL_PN])),
        p('authdomain=%s', self.isfrontend and self.auth_domain, 'foo.com'),
        p('motd=%s', self.isfrontend and self.motd, '/path/to/motd.txt')
      ])
      dprinted = 0
      for bid in sorted(self.backends.keys()):
        be = self.backends[bid]
        if not be[BE_BHOST]:
          config.append('domain=%s:%s' % (bid, be[BE_SECRET]))
          dprinted += 1
      if not dprinted:
        new = True
        config.extend([
          '# domain=http:*.pagekite.me:SECRET1',
          '# domain=http,https,websocket:THEM.pagekite.me:SECRET2',
          '',
        ])

      eprinted = 0
      config.append('##[ Domains we terminate SSL/TLS for natively, with key/cert-files ]##')
      for ep in sorted(self.tls_endpoints.keys()):
        config.append('tls_endpoint=%s:%s' % (ep, self.tls_endpoints[ep][0]))
        eprinted += 1
      if eprinted == 0:
        new = True
        config.append('# tls_endpoint=DOMAIN:PEM_FILE')
      config.extend([
        p('tls_default=%s', self.tls_default, 'DOMAIN'),
        '',
      ])

    config.extend([
      '',
      '###[ Anything below this line can usually be ignored. ]#########',
      '',
      '##[ Miscellaneous settings ]##',
      p('logfile=%s', self.logfile, '/path/to/file'),
      p('buffers=%s', self.buffer_max, DEFAULT_BUFFER_MAX),
      (self.servers_new_only is True) and 'new' or '# new',
      (self.require_all and 'all' or '# all'),
      (self.no_probes and 'noprobes' or '# noprobes'),
      (self.crash_report_url and '# nocrashreport' or 'nocrashreport'),
      p('savefile=%s', safe and self.savefile, '/path/to/savefile'),
      (self.autosave and 'autosave' or '# autosave'),
      '',
    ])

    if self.daemonize or self.setuid or self.setgid or self.pidfile or new:
      config.extend([
        '##[ Systems administration settings ]##',
        (self.daemonize and 'daemonize' or '# daemonize')
      ])
      if self.setuid and self.setgid:
        config.append('runas=%s:%s' % (self.setuid, self.setgid))
      elif self.setuid:
        config.append('runas=%s' % self.setuid)
      else:
        new = True
        config.append('# runas=uid:gid')
      config.append(p('pidfile=%s', self.pidfile, '/path/to/file'))

    config.extend([
      '',
      '###[ End of pagekite.py configuration ]#########',
      'END',
      ''
    ])
    if not new:
      config = [l for l in config if not l.startswith('# ')]
      clean_config = []
      for i in range(0, len(config)-1):
        if i > 0 and (config[i].startswith('#') or config[i] == ''):
          if config[i+1] != '' or clean_config[-1].startswith('#'):
            clean_config.append(config[i])
        else:
          clean_config.append(config[i])
      clean_config.append(config[-1])
      return clean_config
    else:
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
      return sha1hex('\\n'.join(self.GenerateConfig()))

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
      fe_port = be[BE_PORT] or ''
      frontend = '%s://%s%s%s' % (be[BE_PROTO], be[BE_DOMAIN],
                                  fe_port and ':' or '', fe_port)

      if be[BE_STATUS] == BE_STATUS_DISABLED:
        color = self.ui.GREY
        status = '(disabled)'
      else:
        color = self.ui.NORM
        status = (be[BE_PROTO] == 'raw') and '(HTTP proxied)' or ''
      message.append(''.join([color, backend, ' ' * (19-len(backend)),
                              frontend, ' ' * (42-len(frontend)), status]))
    message.append(self.ui.NORM)
    self.ui.Tell(message)

  def PrintSettings(self, safe=False):
    print '\\n'.join(self.GenerateConfig(safe=safe))

  def SaveUserConfig(self, quiet=False):
    self.savefile = self.savefile or self.rcfile
    try:
      fd = open(self.savefile, 'w')
      fd.write('\\n'.join(self.GenerateConfig(safe=True)))
      fd.close()
      if not quiet:
        self.ui.Tell(['Settings saved to: %s' % self.savefile])
        self.ui.Spacer()
      Log([('saved', 'Settings saved to: %s' % self.savefile)])
    except Exception, e:
      self.ui.Tell(['Could not save to %s: %s' % (self.savefile, e)],
                   error=True)
      self.ui.Spacer()

  def FallDown(self, message, help=True, longhelp=False, noexit=False):
    if self.conns and self.conns.auth: self.conns.auth.quit()
    if self.ui_httpd: self.ui_httpd.quit()
    if self.ui_comm: self.ui_comm.quit()
    if self.tunnel_manager: self.tunnel_manager.quit()
    self.keep_looping = False
    self.conns = self.ui_httpd = self.ui_comm = self.tunnel_manager = None
    if help or longhelp:
      print longhelp and DOC or MINIDOC
      print '***'
    else:
      self.ui.Status('exiting', message=(message or 'Good-bye!'))
    if message: print 'Error: %s' % message
    if DEBUG_IO: traceback.print_exc(file=sys.stderr)
    if not noexit:
      self.main_loop = False
      sys.exit(1)

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

  def SetBackendStatus(self, domain, proto='', add=None, sub=None):
    match = '%s:%s' % (proto, domain)
    for bid in self.backends:
      if bid == match or (proto == '' and bid.endswith(match)):
        status = self.backends[bid][BE_STATUS]
        if add: self.backends[bid][BE_STATUS] |= add
        if sub and (status & sub): self.backends[bid][BE_STATUS] -= sub
        Log([('bid', bid),
             ('status', '0x%x' % self.backends[bid][BE_STATUS])])

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
    if DEBUG_IO: print '=== AUTH LOOKUP\\n%s\\n===' % lookup
    (hn, al, ips) = socket.gethostbyname_ex(lookup)
    if DEBUG_IO: print 'hn=%s\\nal=%s\\nips=%s\\n' % (hn, al, ips)

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
    if ((not token) or
        (not check_token) or
        checkSignature(sign=token, payload=data)):

      secret = (self.GetBackendData(protoport, domain) or BE_NONE)[BE_SECRET]
      if not secret:
        secret = (self.GetBackendData(proto, domain) or BE_NONE)[BE_SECRET]

      if secret:
        if self.IsSignatureValid(sign, secret, protoport, domain, srand, token):
          return (-1, None)
        elif not self.auth_domain:
          LogError('Invalid signature for: %s (%s)' % (domain, protoport))
          return (None, auth_error_type or 'signature')

      if self.auth_domain:
        try:
          lookup = '.'.join([srand, token, sign, protoport, domain, self.auth_domain])
          (rv, auth_error_type) = self.LookupDomainQuota(lookup)
          if rv is None or rv >= 0:
            return (rv, auth_error_type)
        except Exception, e:
          # Lookup failed, fail open.
          LogError('Quota lookup failed: %s' % e)
          return (-2, None)

    LogInfo('No authentication found for: %s (%s)' % (domain, protoport))
    return (None, auth_error_type or 'unauthorized')

  def ConfigureFromFile(self, filename=None, data=None):
    if not filename: filename = self.rcfile

    if self.rcfile_recursion > 25:
      raise ConfigError('Nested too deep: %s' % filename)

    self.rcfiles_loaded.append(filename)
    optfile = data or open(filename)
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
      if (parts[1] == 'builtin') or ('.' in parts[0] and
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
    if be_port == 'builtin':
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

  def BindUiSspec(self, force=False):
    # Create the UI thread
    if self.ui_httpd and self.ui_httpd.httpd:
      if not force: return self.ui_sspec
      self.ui_httpd.httpd.socket.close()

    self.ui_sspec = self.ui_sspec or ('localhost', 0)
    self.ui_httpd = HttpUiThread(self, self.conns,
                                 handler=self.ui_request_handler,
                                 server=self.ui_http_server,
                                 ssl_pem_filename = self.ui_pemfile)
    return self.ui_sspec

  def LoadMOTD(self):
    if self.motd:
      try:
        f = open(self.motd, 'r')
        self.motd_message = ''.join(f.readlines()).strip()[:8192]
        f.close()
      except (OSError, IOError):
        pass

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
        if not self.ui.DAEMON_FRIENDLY: self.ui = NullUi()
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
          self.ui_sspec = self.ui_sspec_cfg = (host, int(parts[1]))
        else:
          self.ui_sspec = self.ui_sspec_cfg = (host, 0)

      elif opt == '--nowebpath':
        host, path = arg.split(':', 1)
        if host in self.ui_paths and path in self.ui_paths[host]:
          del self.ui_paths[host][path]
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
        elif arg:
          if arg in DYNDNS: arg = DYNDNS[arg]
          self.dyndns = (arg, {'user': '', 'pass': ''})
        else:
          self.dyndns = None

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
      elif opt == '--motd':
        self.motd = arg
        self.LoadMOTD()
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
        if arg == '':
          self.fe_certname = []
        else:
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
                                     status=((opt != '--backend')
                                             and BE_STATUS_DISABLED
                                             or BE_STATUS_UNKNOWN))
        for bid in bes:
          if bid in self.backends:
            raise ConfigError(\"Same backend/domain defined twice: %s\" % bid)
          if not self.kitename:
            self.kitename = bes[bid][BE_DOMAIN]
            self.kitesecret = bes[bid][BE_SECRET]
        self.backends.update(bes)
      elif opt == '--be_config':
        host, key, val = arg.split(':', 2)
        if key.startswith('user/'): key = key.replace('user/', 'password/')
        hostc = self.be_config.get(host, {})
        hostc[key] = {'True': True, 'False': False, 'None': None}.get(val, val)
        self.be_config[host] = hostc
      elif opt == '--delete_backend':
        bes = self.ArgToBackendSpecs(arg)
        for bid in bes:
          if bid in self.backends:
            del self.backends[bid]

      elif opt == '--domain':
        protos, domain, secret = arg.split(':')
        if protos in ('*', ''): protos = ','.join(self.server_protos)
        for proto in protos.split(','):
          bid = '%s:%s' % (proto, domain)
          if bid in self.backends:
            raise ConfigError(\"Same backend/domain defined twice: %s\" % bid)
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
      elif opt == '--uiport': self.ui_port = int(arg)
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
                   '--webroot', '--signup', '--friendly'): pass
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
    return self.ParseFriendlyBackendSpecs(args)

  def ParseFriendlyBackendSpecs(self, args):
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

      fe_spec = (args.pop().replace('@kitesecret', self.kitesecret)
                           .replace('@kitename', self.kitename))
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
        if be[0].lower() in ('http', 'http2', 'http3', 'https',
                             'httpfinger', 'finger', 'ssh', 'irc'):
          be_proto = be.pop(0)
          if len(be) < 2:
            be.append({'http': '80', 'http2': '80', 'http3': '80',
                       'https': '443', 'irc': '6667',
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
      if not be[BE_SECRET]:
        if self.kitesecret and be[BE_DOMAIN] == self.kitename:
          be[BE_SECRET] = self.kitesecret
        else:
          need_registration[be[BE_DOMAIN]] = True

    for domain in need_registration:
      result = self.RegisterNewKite(kitename=domain)
      if not result:
        raise ConfigError(\"Not sure what to do with %s, giving up.\" % domain)

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
          if be[BE_PROTO] in ('http', 'http2', 'http3'):
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
    if service == 'mock':
      return MockPageKiteXmlRpc(self)
    else:
      return xmlrpclib.ServerProxy(self.service_xmlrpc, None, None, False)

  def _KiteInfo(self, kitename):
    is_service_domain = kitename and SERVICE_DOMAIN_RE.search(kitename)
    is_subdomain_of = is_cname_for = is_cname_ready = False
    secret = None

    for be in self.backends.values():
      if be[BE_SECRET] and (be[BE_DOMAIN] == kitename):
        secret = be[BE_SECRET]

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

    return (secret, is_subdomain_of, is_service_domain,
            is_cname_for, is_cname_ready)

  def RegisterNewKite(self, kitename=None, first=False,
                            ask_be=False, autoconfigure=False):
    registered = False
    if kitename:
      (secret, is_subdomain_of, is_service_domain,
       is_cname_for, is_cname_ready) = self._KiteInfo(kitename)
      if secret:
        self.ui.StartWizard('Updating kite: %s' % kitename)
        registered = True
      else:
        self.ui.StartWizard('Creating kite: %s' % kitename)
    else:
      if first:
        self.ui.StartWizard('Create your first kite')
      else:
        self.ui.StartWizard('Creating a new kite')
      is_subdomain_of = is_service_domain = False
      is_cname_for = is_cname_ready = False

    # This is the default...
    be_specs = ['http:%s:localhost:80']

    service = self.GetServiceXmlRpc()
    service_accounts = {}
    if self.kitename and self.kitesecret:
      service_accounts[self.kitename] = self.kitesecret

    for be in self.backends.values():
      if SERVICE_DOMAIN_RE.search(be[BE_DOMAIN]):
        if be[BE_DOMAIN] == is_cname_for:
          is_cname_ready = True
        if be[BE_SECRET] not in service_accounts.values():
          service_accounts[be[BE_DOMAIN]] = be[BE_SECRET]
    service_account_list = service_accounts.keys()

    if registered:
      state = ['choose_backends']
    if service_account_list:
      state = ['choose_kite_account']
    else:
      state = ['use_service_question']
    history = []

    def Goto(goto, back_skips_current=False):
      if not back_skips_current: history.append(state[0])
      state[0] = goto
    def Back():
      if history:
        state[0] = history.pop(-1)
      else:
        Goto('abort')

    register = is_cname_for or kitename
    account = email = None
    while 'end' not in state:
      try:
        if 'use_service_question' in state:
          ch = self.ui.AskYesNo('Use the service?',
                                pre=['<b>Welcome to PageKite!</b>',
                                     '',
                                     'Please answer a few quick questions to',
                                     'create your first kite.',
                                     '',
                                     'By continuing, you agree to play nice',
                                     'and abide by the Terms of Service at:',
                                     '- <a href=\"%s\">%s</a>' % (SERVICE_TOS_URL, SERVICE_TOS_URL)],
                                default=True, back=-1, no='Abort')
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
                # FIXME: Shut up if parent is already in local config!
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
            (email, p) = self.ui.AskLogin('Please log on ...', pre=[
                                            'By logging on to %s,' % self.service_provider,
                                            'you will be able to use this kite',
                                            'with your pre-existing account.'
                                          ], email=email, back=(email, False))
            if email and p:
              try:
                self.ui.Working('Logging on to your account')
                service_accounts[email] = service.getSharedSecret(email, p)
                # FIXME: Should get the list of preconfigured kites via. RPC
                #        so we don't try to create something that already
                #        exists?  Or should the RPC not just not complain?
                account = email
                Goto('create_kite')
              except:
                email = p = None
                self.ui.Tell(['Login failed! Try again?'], error=True)
            if p is False:
              Back()
              break

        elif ('service_signup_is_subdomain' in state):
          ch = self.ui.AskYesNo('Use this name?',
                                pre=['%s is a sub-domain.' % kitename, '',
                                     '<b>NOTE:</b> This process will fail if you',
                                     'have not already registered the parent',
                                     'domain, %s.' % is_subdomain_of],
                                default=True, back=-1)
          if ch is True:
            if account:
              Goto('create_kite')
            elif email:
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
          email = self.ui.AskEmail('<b>What is your e-mail address?</b>',
                                   pre=['We need to be able to contact you',
                                        'now and then with news about the',
                                        'service and your account.',
                                        '',
                                        'Your details will be kept private.'],
                                   back=False)
          if email and register:
            Goto('service_signup')
          elif email:
            Goto('service_signup_kitename')
          else:
            Back()

        elif ('service_signup_kitename' in state or
              'service_ask_kitename' in state):
          try:
            self.ui.Working('Fetching list of available domains')
            domains = service.getAvailableDomains(None, None)
          except:
            domains = ['.%s' % x for x in SERVICE_DOMAINS]

          ch = self.ui.AskKiteName(domains, 'Name this kite:',
                                 pre=['Your kite name becomes the public name',
                                      'of your personal server or web-site.',
                                      '',
                                      'Names are provided on a first-come,',
                                      'first-serve basis. You can create more',
                                      'kites with different names later on.'],
                                 back=False)
          if ch:
            kitename = register = ch
            (secret, is_subdomain_of, is_service_domain,
             is_cname_for, is_cname_ready) = self._KiteInfo(ch)
            if secret:
              self.ui.StartWizard('Updating kite: %s' % kitename)
              registered = True
            else:
              self.ui.StartWizard('Creating kite: %s' % kitename)
            Goto('choose_backends')
          else:
            Back()

        elif 'choose_backends' in state:
          if ask_be and autoconfigure:
            skip = False
            ch = self.ui.AskBackends(kitename, ['http'], ['80'], [],
                                     'Enable which service?', back=False, pre=[
                                  'You control which of your files or servers',
                                  'PageKite exposes to the Internet. ',
                                     ], default=','.join(be_specs))
            if ch:
              be_specs = ch.split(',')
          else:
            skip = ch = True

          if ch:
            if registered:
              Goto('create_kite', back_skips_current=skip)
            elif is_subdomain_of:
              Goto('service_signup_is_subdomain', back_skips_current=skip)
            elif account:
              Goto('create_kite', back_skips_current=skip)
            elif email:
              Goto('service_signup', back_skips_current=skip)
            else:
              Goto('service_signup_email', back_skips_current=skip)
          else:
            Back()

        elif 'service_signup' in state:
          try:
            self.ui.Working('Signing up')
            details = service.signUp(email, register)
            if details.get('secret', False):
              service_accounts[email] = details['secret']
              self.ui.AskYesNo('Continue?', pre=[
                '<b>Your kite is ready to fly!</b>',
                '',
                '<b>Note:</b> To complete the signup process,',
                'check your e-mail (and spam folders) for',
                'activation instructions. You can give',
                'PageKite a try first, but un-activated',
                'accounts are disabled after %d minutes.' % details['timeout'],
              ], yes='Finish', no=False, default=True)
              self.ui.EndWizard()
              if autoconfigure:
                print 'Backends: %s (register=%s)' % (be_specs, register)
                for be_spec in be_specs:
                  self.backends.update(self.ArgToBackendSpecs(
                                                    be_spec % register,
                                                    secret=details['secret']))
              self.added_kites = True
              return (register, details['secret'])
            else:
              error = details.get('error', 'unknown')
          except IOError:
            error = 'network'
          except:
            error = '%s' % (sys.exc_info(), )

          if error == 'pleaselogin':
            #self.ui.ExplainError(error,
            #                     '%s log-in required.' % self.service_provider,
            #                     subject=register)
            Goto('service_login_email', back_skips_current=True)
          elif error == 'email':
            self.ui.ExplainError(error, 'Signup failed!', subject=register)
            Goto('service_login_email', back_skips_current=True)
          elif error in ('domain', 'domaintaken', 'subdomain'):
            register, kitename = None, None
            self.ui.ExplainError(error, 'Invalid domain!', subject=register)
            Goto('service_signup_kitename', back_skips_current=True)
          elif error == 'network':
            self.ui.ExplainError(error, 'Network error!', subject=self.service_provider)
            Goto('service_signup', back_skips_current=True)
          else:
            self.ui.ExplainError(error, 'Unknown problem!')
            print 'FIXME!  Error is %s' % error
            Goto('abort')

        elif 'choose_kite_account' in state:
          choices = service_account_list[:]
          choices.append('Use another service provider')
          justdoit = (len(service_account_list) == 1)
          if justdoit:
            ch = 1
          else:
            ch = self.ui.AskMultipleChoice(choices, 'Register with',
                                       pre=['Choose an account for this kite:'],
                                           default=1)
          account = choices[ch-1]
          if ch == len(choices):
            Goto('manual_abort')
          elif kitename:
            Goto('choose_backends', back_skips_current=justdoit)
          else:
            Goto('service_ask_kitename', back_skips_current=justdoit)

        elif 'create_kite' in state:
          secret = service_accounts[account]
          subject = None
          cfgs = {}
          result = {}
          error = None
          try:
            if registered and kitename and secret:
              pass
            elif is_cname_for and is_cname_ready:
              self.ui.Working('Creating your kite')
              subject = kitename
              result = service.addCnameKite(account, secret, kitename)
              time.sleep(2) # Give the service side a moment to replicate...
            else:
              self.ui.Working('Creating your kite')
              subject = register
              result = service.addKite(account, secret, register)
              time.sleep(2) # Give the service side a moment to replicate...
              for be_spec in be_specs:
                cfgs.update(self.ArgToBackendSpecs(be_spec % register,
                                                   secret=secret))
              if is_cname_for == register and 'error' not in result:
                subject = kitename
                result.update(service.addCnameKite(account, secret, kitename))

            error = result.get('error', None)
            if not error:
              for be_spec in be_specs:
                cfgs.update(self.ArgToBackendSpecs(be_spec % kitename,
                                                   secret=secret))
          except Exception, e:
            error = '%s' % e

          if error:
            self.ui.ExplainError(error, 'Kite creation failed!',
                                 subject=subject)
            Goto('abort')
          else:
            self.ui.Tell(['Success!'])
            self.ui.EndWizard()
            if autoconfigure: self.backends.update(cfgs)
            self.added_kites = True
            return (register or kitename, secret)

        elif 'manual_abort' in state:
          if self.ui.Tell(['Aborted!', '',
            'Please manually add information about your',
            'kites and front-ends to the configuration file:',
            '', ' %s' % self.rcfile],
                          error=True, back=False) is False:
            Back()
          else:
            self.ui.EndWizard()
            if self.ui.ALLOWS_INPUT: return None
            sys.exit(0)

        elif 'abort' in state:
          self.ui.EndWizard()
          if self.ui.ALLOWS_INPUT: return None
          sys.exit(0)

        else:
          raise ConfigError('Unknown state: %s' % state)

      except KeyboardInterrupt:
        sys.stderr.write('\\n')
        if history:
          Back()
        else:
          raise KeyboardInterrupt()

    self.ui.EndWizard()
    return None

  def CheckConfig(self):
    if self.ui_sspec: self.BindUiSspec()
    if not self.servers_manual and not self.servers_auto and not self.isfrontend:
      if not self.servers and not self.ui.ALLOWS_INPUT:
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
      fd.send('HEAD / HTTP/1.0\\r\\n\\r\\n')
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

  def GetActiveBackends(self):
    active = []
    for bid in self.backends:
      (proto, bdom) = bid.split(':')
      if (self.backends[bid][BE_STATUS] not in BE_INACTIVE and
          self.backends[bid][BE_SECRET] and
          not bdom.startswith('*')):
        active.append(bid)
    return active

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
        for bid in self.GetActiveBackends():
          (proto, bdom) = bid.split(':')
          try:
            (hn, al, ips) = self.GetHostDetails(bdom)
            for ip in ips:
              if not ip.startswith('127.'):
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

    if len(self.GetActiveBackends()) > 0:
      if not self.servers or len(self.servers) > len(live_servers):
        self.ChooseFrontEnds()
    else:
      self.servers_preferred = []
      self.servers = []

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
              self.SetBackendStatus(update.split(':')[0],
                                    sub=BE_STATUS_ERR_DNS)
            else:
              LogInfo('DynDNS update failed: %s' % result, [('data', update)])
              self.SetBackendStatus(update.split(':')[0],
                                    add=BE_STATUS_ERR_DNS)
              failures += 1
          except Exception, e:
            LogInfo('DynDNS update failed: %s' % e, [('data', update)])
            if DEBUG_IO: traceback.print_exc(file=sys.stderr)
            self.SetBackendStatus(update.split(':')[0],
                                  add=BE_STATUS_ERR_DNS)
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
      syslog.openlog(self.progname, syslog.LOG_PID, syslog.LOG_DAEMON)

    else:
      Log = LogToFile

    global LogFile
    if filename in ('stdio', 'stdout'):
      try:
        LogFile = os.fdopen(sys.stdout.fileno(), 'w', 0)
      except:
        LogFile = sys.stdout
    else:
      try:
        LogFile = fd = open(filename, \"a\", 0)
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
    self.last_loop = time.time()

    iready, oready, eready = None, None, None
    while self.keep_looping:
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
        self.last_loop -= 1

      now = time.time()
      if not iready and not oready:
        if (isocks or osocks) and (now < self.last_loop + 1):
          LogError('Spinning, pausing ...')
          time.sleep(0.1)

      if oready:
        for socket in oready:
          conn = conns.Connection(socket)
          if conn and not conn.Send([], try_flush=True):
#           LogDebug(\"Write error in main loop, closing %s\" % conn)
            conns.Remove(conn)
            conn.Cleanup()

      if buffered_bytes < 1024 * self.buffer_max:
        throttle = None
      else:
        LogDebug(\"FIXME: Nasty pause to let buffers clear!\")
        time.sleep(0.1)
        throttle = 1024

      if iready:
        for socket in iready:
          conn = conns.Connection(socket)
          if conn and not conn.ReadData(maxread=throttle):
#           LogDebug(\"Read error in main loop, closing %s\" % conn)
            conns.Remove(conn)
            conn.Cleanup()

      for conn in conns.DeadConns():
        conns.Remove(conn)
        conn.Cleanup()

      self.last_loop = now

  def Loop(self):
    self.conns.start()
    if self.ui_httpd: self.ui_httpd.start()
    if self.tunnel_manager: self.tunnel_manager.start()
    if self.ui_comm: self.ui_comm.start()

    try:
      epoll = select.epoll()
    except Exception, msg:
      epoll = None

    if epoll: LogDebug(\"FIXME: Should try epoll!\")
    self.SelectLoop()

  def Start(self, howtoquit='CTRL+C = Quit'):
    conns = self.conns = self.conns or Connections(self)
    global Log

    # If we are going to spam stdout with ugly crap, then there is no point
    # attempting the fancy stuff. This also makes us backwards compatible
    # for the most part.
    if self.logfile == 'stdio':
      if not self.ui.DAEMON_FRIENDLY: self.ui = NullUi()

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

    # Create the UI Communicator
    self.ui_comm = UiCommunicator(self, conns)

    try:

      # Set up our listeners if we are a server.
      if self.isfrontend:
        self.ui.Notify('This is a PageKite front-end server.')
        for port in self.server_ports:
          Listener(self.server_host, port, conns)
        for port in self.server_raw_ports:
          if port != VIRTUAL_PN and port > 0:
            Listener(self.server_host, port, conns, connclass=RawConn)

      if self.ui_port:
        Listener('127.0.0.1', self.ui_port, conns, connclass=UiConn)

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
      pf.write('%s\\n' % os.getpid())
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

    self.ui.Status('exiting', message='Stopping...')
    Log([('stopping', 'pagekite.py')])
    if self.ui_httpd: self.ui_httpd.quit()
    if self.ui_comm: self.ui_comm.quit()
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

    # No exception, do we keep looping?
    if not pk.main_loop: return

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

  if not pk.backends.keys() and (not pk.kitesecret or not pk.kitename):
    friendly_mode = (('--friendly' in sys.argv) or
                     (sys.platform in ('win32', 'os2', 'os2emx',
                                       'darwin', 'darwin1', 'darwin2')))
    if '--signup' in sys.argv or friendly_mode:
      pk.RegisterNewKite(autoconfigure=True, first=True)
    if friendly_mode: pk.save = True

  pk.CheckConfig()

  if pk.added_kites:
    if (pk.autosave or pk.save or
        pk.ui.AskYesNo('Save settings to %s?' % pk.rcfile,
                       default=(len(pk.backends.keys()) > 0))):
      pk.SaveUserConfig()
    pk.servers_new_only = 'Once'
  elif pk.save:
    pk.SaveUserConfig(quiet=True)

  if ('--list' in sys.argv or
      pk.kite_add or pk.kite_remove or pk.kite_only or pk.kite_disable):
    pk.ListKites()
    sys.exit(0)


"""
sys.modules["pagekite"] = imp.new_module("pagekite")
sys.modules["pagekite"].open = __comb_open
exec __FILES[".SELF/pagekite/__init__.py"] in sys.modules["pagekite"].__dict__


###############################################################################
__FILES[".SELF/pagekite/basicui.py"] = """\
import re, sys, time
import pagekite
from pagekite import NullUi

HTML_BR_RE = re.compile(r'<(br|/p|/li|/tr|/h\\d)>\\s*')
HTML_LI_RE = re.compile(r'<li>\\s*')
HTML_NBSP_RE = re.compile(r'&nbsp;')
HTML_TAGS_RE = re.compile(r'<[^>\\s][^>]*>')

def clean_html(text):
  return HTML_LI_RE.sub(' * ',
          HTML_NBSP_RE.sub('_',
           HTML_BR_RE.sub('\\n', text)))

def Q(text):
  return HTML_TAGS_RE.sub('', clean_html(text))


class BasicUi(NullUi):
  \"\"\"Stdio based user interface.\"\"\"

  DAEMON_FRIENDLY = False
  WANTS_STDERR = True
  EMAIL_RE = re.compile(r'^[a-z0-9!#$%&\\'\\*\\+\\/=?^_`{|}~-]+'
                         '(?:\\.[a-z0-9!#$%&\\'*+/=?^_`{|}~-]+)*@'
                         '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)*'
                         '(?:[a-zA-Z]{2,4}|museum)$')
  def Notify(self, message, prefix=' ',
             popup=False, color=None, now=None, alignright=''):
    now = int(now or time.time())
    color = color or self.NORM

    # We suppress duplicates that are either new or still on the screen.
    keys = self.notify_history.keys()
    if len(keys) > 20:
      for key in keys:
        if self.notify_history[key] < now-300:
          del self.notify_history[key]

    message = '%s' % message
    if message not in self.notify_history:

      # Display the time now and then.
      if (not alignright and
          (now >= (self.last_tick + 60)) and
          (len(message) < 68)):
        try:
          self.last_tick = now
          d = datetime.datetime.fromtimestamp(now)
          alignright = '[%2.2d:%2.2d]' % (d.hour, d.minute)
        except:
          pass # Fails on Python 2.2

      self.notify_history[message] = now
      msg = '\\r%s %s%s%s%s%s\\n' % ((prefix * 3)[0:3], color, message, self.NORM,
                                   ' ' * (75-len(message)-len(alignright)),
                                   alignright)
      self.wfile.write(msg)
      self.Status(self.status_tag, self.status_msg)

  def NotifyMOTD(self, frontend, motd_message):
    self.Notify('Message of the day:', prefix=' ++', color=self.WHITE)
    lc = 1
    for line in Q(motd_message).splitlines():
      self.Notify((line.strip() or ' ' * (lc+2)))
      lc += 1
    self.Notify(' ' * (lc+2), alignright='[from %s]' % frontend)

  def Status(self, tag, message=None, color=None):
    self.status_tag = tag
    self.status_col = color or self.status_col or self.NORM
    self.status_msg = '%s' % (message or self.status_msg)
    if not self.in_wizard:
      message = self.status_msg
      msg = ('\\r << pagekite.py [%s]%s %s%s%s\\r%s'
             ) % (tag, ' ' * (8-len(tag)),
                  self.status_col, message, ' ' * (52-len(message)), self.NORM)
      self.wfile.write(msg)
    if tag == 'exiting':
      self.wfile.write('\\n')

  def Welcome(self, pre=None):
    if self.in_wizard:
      self.wfile.write('%s%s%s' % (self.CLEAR, self.WHITE, self.in_wizard))
    if self.welcome:
      self.wfile.write('%s\\r%s\\n' % (self.NORM, Q(self.welcome)))
      self.welcome = None
    if self.in_wizard and self.wizard_tell:
      self.wfile.write('\\n%s\\r' % self.NORM)
      for line in self.wizard_tell: self.wfile.write('*** %s\\n' % Q(line))
      self.wizard_tell = None
    if pre:
      self.wfile.write('\\n%s\\r' % self.NORM)
      for line in pre: self.wfile.write('    %s\\n' % Q(line))
    self.wfile.write('\\n%s\\r' % self.NORM)

  def StartWizard(self, title):
    self.Welcome()
    banner = '>>> %s' %  title
    banner = ('%s%s[CTRL+C = Cancel]\\n') % (banner, ' ' * (62-len(banner)))
    self.in_wizard = banner
    self.tries = 200

  def Retry(self):
    self.tries -= 1
    return self.tries

  def EndWizard(self):
    if self.wizard_tell: self.Welcome()
    self.in_wizard = None
    if sys.platform in ('win32', 'os2', 'os2emx'):
      self.wfile.write('\\n<<< press ENTER to continue >>>\\n')
      self.rfile.readline()

  def Spacer(self):
    self.wfile.write('\\n')

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    if welcome: self.Welcome(pre)
    while self.Retry():
      self.wfile.write(' => %s ' % (Q(question), ))
      answer = self.rfile.readline().strip()
      if default and answer == '': return default
      if self.EMAIL_RE.match(answer): return answer
      if back is not None and answer == 'back': return back
    raise Exception('Too many tries')

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)

    def_email, def_pass = default or (email, None)
    self.wfile.write('    %s\\n' % (Q(question), ))

    if not email:
      email = self.AskEmail('Your e-mail:',
                            default=def_email, back=back, welcome=False)
      if email == back: return back

    import getpass
    self.wfile.write(' => ')
    return (email, getpass.getpass() or def_pass)

  def AskYesNo(self, question, default=None, pre=[], yes='yes', no='no',
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    yn = ((default is True) and '[Y/n]'
          ) or ((default is False) and '[y/N]'
                ) or ('[y/n]')
    while self.Retry():
      self.wfile.write(' => %s %s ' % (Q(question), yn))
      answer = self.rfile.readline().strip().lower()
      if default is not None and answer == '': answer = default and 'y' or 'n'
      if back is not None and answer.startswith('b'): return back
      if answer in ('y', 'n'): return (answer == 'y')
    raise Exception('Too many tries')

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    if len(domains) == 1:
      self.wfile.write(('\\n    (Note: the ending %s will be added for you.)'
                        ) % domains[0])
    else:
      self.wfile.write('\\n    Please use one of the following domains:\\n')
      for domain in domains:
        self.wfile.write('\\n     *%s' % domain)
      self.wfile.write('\\n')
    while self.Retry():
      self.wfile.write('\\n => %s ' % Q(question))
      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back':
        return back
      elif len(domains) == 1:
        answer = answer.replace(domains[0], '')
        if answer and pagekite.SERVICE_SUBDOMAIN_RE.match(answer):
          return answer+domains[0]
      else:
        for domain in domains:
          if answer.endswith(domain):
            answer = answer.replace(domain, '')
            if answer and pagekite.SERVICE_SUBDOMAIN_RE.match(answer):
              return answer+domain
      self.wfile.write('    (Please only use characters A-Z, 0-9, - and _.)')
    raise Exception('Too many tries')

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    for i in range(0, len(choices)):
      self.wfile.write(('  %s %d) %s\\n'
                        ) % ((default==i+1) and '*' or ' ', i+1, choices[i]))
    self.wfile.write('\\n')
    while self.Retry():
      d = default and (', default=%d' % default) or ''
      self.wfile.write(' => %s [1-%d%s] ' % (Q(question), len(choices), d))
      try:
        answer = self.rfile.readline().strip()
        if back is not None and answer.startswith('b'): return back
        choice = int(answer or default)
        if choice > 0 and choice <= len(choices): return choice
      except (ValueError, IndexError):
        pass
    raise Exception('Too many tries')

  def Tell(self, lines, error=False, back=None):
    if self.in_wizard:
      self.wizard_tell = lines
    else:
      self.Welcome()
      for line in lines: self.wfile.write('    %s\\n' % line)
      if error: self.wfile.write('\\n')
      return True

  def Working(self, message):
    self.Tell([message])
"""
sys.modules["pagekite.basicui"] = imp.new_module("pagekite.basicui")
sys.modules["pagekite.basicui"].open = __comb_open
sys.modules["pagekite"].basicui = sys.modules["pagekite.basicui"]
exec __FILES[".SELF/pagekite/basicui.py"] in sys.modules["pagekite.basicui"].__dict__


###############################################################################
__FILES[".SELF/pagekite/remoteui.py"] = """\
import re, sys, time
import pagekite
from pagekite import NullUi

class RemoteUi(NullUi):
  \"\"\"Stdio based user interface for interacting with other processes.\"\"\"

  DAEMON_FRIENDLY = True
  ALLOWS_INPUT = True
  WANTS_STDERR = True
  EMAIL_RE = re.compile(r'^[a-z0-9!#$%&\\'\\*\\+\\/=?^_`{|}~-]+'
                         '(?:\\.[a-z0-9!#$%&\\'*+/=?^_`{|}~-]+)*@'
                         '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)*'
                         '(?:[a-zA-Z]{2,4}|museum)$')

  def __init__(self, welcome=None, wfile=sys.stderr, rfile=sys.stdin):
    NullUi.__init__(self, welcome=welcome, wfile=wfile, rfile=rfile)
    self.CLEAR = ''
    self.NORM = self.WHITE = self.GREY = self.GREEN = self.YELLOW = ''
    self.BLUE = self.RED = self.MAGENTA = self.CYAN = ''

  def StartListingBackEnds(self):
    self.wfile.write('begin_be_list\\n')

  def EndListingBackEnds(self):
    self.wfile.write('end_be_list\\n')

  def NotifyBE(self, bid, be, has_ssl, dpaths, is_builtin=False, now=None):
    domain = be[pagekite.BE_DOMAIN]
    port = be[pagekite.BE_PORT]
    proto = be[pagekite.BE_PROTO]
    prox = (proto == 'raw') and ' (HTTP proxied)' or ''
    if proto == 'raw' and port in ('22', 22): proto = 'ssh'
    url = '%s://%s%s' % (proto, domain, port and (':%s' % port) or '')

    message = (' be_status:'
               ' status=%x; bid=%s; domain=%s; port=%s; proto=%s;'
               ' bhost=%s; bport=%s%s%s'
               '\\n') % (be[pagekite.BE_STATUS], bid, domain, port, proto,
                        be[pagekite.BE_BHOST], be[pagekite.BE_BPORT],
                        has_ssl and '; ssl=1' or '',
                        is_builtin and '; builtin=1' or '')
    self.wfile.write(message)

    for path in dpaths:
      message = (' be_path: domain=%s; port=%s; path=%s; policy=%s; src=%s\\n'
                 ) % (domain, port or 80, path,
                      dpaths[path][0], dpaths[path][1])
      self.wfile.write(message)

  def Notify(self, message, prefix=' ',
             popup=False, color=None, now=None, alignright=''):
    message = '%s' % message
    self.wfile.write('notify: %s\\n' % message)

  def NotifyMOTD(self, frontend, message):
    self.wfile.write('motd: %s %s\\n' % (frontend,
                                        message.replace('\\n', '  ')))

  def Status(self, tag, message=None, color=None):
    self.status_tag = tag
    self.status_msg = '%s' % (message or self.status_msg)
    if message:
      self.wfile.write('status_msg: %s\\n' % message)
    if tag:
      self.wfile.write('status_tag: %s\\n' % tag)

  def Welcome(self, pre=None):
    self.wfile.write('welcome: %s\\n' % (pre or '').replace('\\n', '  '))

  def StartWizard(self, title):
    self.wfile.write('start_wizard: %s\\n' % title)

  def Retry(self):
    self.tries -= 1
    if self.tries < 0:
      raise Exception('Too many tries')
    return self.tries

  def EndWizard(self):
    self.wfile.write('end_wizard: done\\n')

  def Spacer(self):
    pass

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    while self.Retry():
      self.wfile.write('begin_ask_email\\n')
      if pre:
        self.wfile.write(' preamble: %s\\n' % '\\n'.join(pre).replace('\\n', '  '))
      if default:
        self.wfile.write(' default: %s\\n' % default)
      self.wfile.write(' question: %s\\n' % (question or '').replace('\\n', '  '))
      self.wfile.write(' expect: email\\n')
      self.wfile.write('end_ask_email\\n')

      answer = self.rfile.readline().strip()
      if self.EMAIL_RE.match(answer): return answer
      if back is not None and answer == 'back': return back

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_login\\n')
      if pre:
        self.wfile.write(' preamble: %s\\n' % '\\n'.join(pre).replace('\\n', '  '))
      if email:
        self.wfile.write(' default: %s\\n' % email)
      self.wfile.write(' question: %s\\n' % (question or '').replace('\\n', '  '))
      self.wfile.write(' expect: email\\n')
      self.wfile.write(' expect: password\\n')
      self.wfile.write('end_ask_login\\n')

      answer_email = self.rfile.readline().strip()
      if back is not None and answer_email == 'back': return back

      answer_pass = self.rfile.readline().strip()
      if back is not None and answer_pass == 'back': return back

      if self.EMAIL_RE.match(answer_email) and answer_pass:
        return (answer_email, answer_pass)

  def AskYesNo(self, question, default=None, pre=[], yes='Yes', no='No',
               wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_yesno\\n')
      if yes:
        self.wfile.write(' yes: %s\\n' % yes)
      if no:
        self.wfile.write(' no: %s\\n' % no)
      if pre:
        self.wfile.write(' preamble: %s\\n' % '\\n'.join(pre).replace('\\n', '  '))
      if default:
        self.wfile.write(' default: %s\\n' % default)
      self.wfile.write(' question: %s\\n' % (question or '').replace('\\n', '  '))
      self.wfile.write(' expect: yesno\\n')
      self.wfile.write('end_ask_yesno\\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer in ('y', 'n'): return (answer == 'y')
      if answer == str(default).lower(): return default

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_kitename\\n')
      if pre:
        self.wfile.write(' preamble: %s\\n' % '\\n'.join(pre).replace('\\n', '  '))
      for domain in domains:
        self.wfile.write(' domain: %s\\n' % domain)
      if default:
        self.wfile.write(' default: %s\\n' % default)
      self.wfile.write(' question: %s\\n' % (question or '').replace('\\n', '  '))
      self.wfile.write(' expect: kitename\\n')
      self.wfile.write('end_ask_kitename\\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer:
        for d in domains:
          if answer.endswith(d) or answer.endswith(d): return answer
        return answer+domains[0]

  def AskBackends(self, kitename, protos, ports, rawports, question, pre=[],
                  default=None, wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_backends\\n')
      if pre:
        self.wfile.write(' preamble: %s\\n' % '\\n'.join(pre).replace('\\n', '  '))
      count = 0
      if self.server_info:
        protos = self.server_info[pagekite.Tunnel.S_PROTOS]
        ports = self.server_info[pagekite.Tunnel.S_PORTS]
        rawports = self.server_info[pagekite.Tunnel.S_RAW_PORTS]
      self.wfile.write(' kitename: %s\\n' % kitename)
      self.wfile.write(' protos: %s\\n' % ', '.join(protos))
      self.wfile.write(' ports: %s\\n' % ', '.join(ports))
      self.wfile.write(' rawports: %s\\n' % ', '.join(rawports))
      if default:
        self.wfile.write(' default: %s\\n' % default)
      self.wfile.write(' question: %s\\n' % (question or '').replace('\\n', '  '))
      self.wfile.write(' expect: backends\\n')
      self.wfile.write('end_ask_backends\\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      return answer

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_multiplechoice\\n')
      if pre:
        self.wfile.write(' preamble: %s\\n' % '\\n'.join(pre).replace('\\n', '  '))
      count = 0
      for choice in choices:
        count += 1
        self.wfile.write(' choice_%d: %s\\n' % (count, choice))
      if default:
        self.wfile.write(' default: %s\\n' % default)
      self.wfile.write(' question: %s\\n' % (question or '').replace('\\n', '  '))
      self.wfile.write(' expect: choice_index\\n')
      self.wfile.write('end_ask_multiplechoice\\n')

      answer = self.rfile.readline().strip().lower()
      try:
        ch = int(answer)
        if ch > 0 and ch <= len(choices): return ch
      except:
        pass
      if back is not None and answer == 'back': return back

  def Tell(self, lines, error=False, back=None):
    dialog = error and 'error' or 'message'
    self.wfile.write('tell_%s: %s\\n' % (dialog, '  '.join(lines)))

  def Working(self, message):
    self.wfile.write('working: %s\\n' % message)

"""
sys.modules["pagekite.remoteui"] = imp.new_module("pagekite.remoteui")
sys.modules["pagekite.remoteui"].open = __comb_open
sys.modules["pagekite"].remoteui = sys.modules["pagekite.remoteui"]
exec __FILES[".SELF/pagekite/remoteui.py"] in sys.modules["pagekite.remoteui"].__dict__


###############################################################################
__FILES[".SELF/pagekite/yamond.py"] = """\
#!/usr/bin/python -u
#
# yamond.py, Copyright 2010, The Beanstalks Project ehf.
#                            http://beanstalks-project.net/
#
# This is a class implementing a flexible metric-store and an HTTP
# thread for browsing the numbers.
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
  \"\"\"Handle HTTP in a separate thread.\"\"\"

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
      data.append('%s: %s\\n' % (var, self.values[var]))

    for lname in self.lists:
      (elems, offset, list) = self.lists[lname]
      l = list[offset:]
      l.extend(list[:offset])
      data.append('%s: %s\\n' % (lname, ' '.join(['%s' % x for x in l])))

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

"""
sys.modules["pagekite.yamond"] = imp.new_module("pagekite.yamond")
sys.modules["pagekite.yamond"].open = __comb_open
sys.modules["pagekite"].yamond = sys.modules["pagekite.yamond"]
exec __FILES[".SELF/pagekite/yamond.py"] in sys.modules["pagekite.yamond"].__dict__


###############################################################################
__FILES[".SELF/pagekite/httpd.py"] = """\
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
###############################################################################
import base64
import cgi
from cgi import escape as escape_html
import os
import re
import socket
import sys
import tempfile
import threading
import time
import traceback
import urllib

import SocketServer
from CGIHTTPServer import CGIHTTPRequestHandler
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import Cookie

import pagekite
import sockschain as socks


##[ Conditional imports & compatibility magic! ]###############################

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


##[ PageKite HTTPD code starts here! ]#########################################


class AuthError(Exception):
  pass


def fmt_size(count):
  if count > 2*(1024*1024*1024):
    return '%dGB' % (count / (1024*1024*1024))
  if count > 2*(1024*1024):
    return '%dMB' % (count / (1024*1024))
  if count > 2*(1024):
    return '%dKB' % (count / 1024)
  return '%dB' % count


class CGIWrapper(CGIHTTPRequestHandler):
  def __init__(self, request, path_cgi):
    self.path = path_cgi
    self.cgi_info = (os.path.dirname(path_cgi),
                     os.path.basename(path_cgi))
    self.request = request
    self.server = request.server
    self.command = request.command
    self.headers = request.headers
    self.client_address = ('unknown', 0)
    self.rfile = request.rfile
    self.wfile = tempfile.TemporaryFile()

  def translate_path(self, path): return path

  def send_response(self, code, message):
    self.wfile.write('X-Response-Code: %s\\r\\n' % code)
    self.wfile.write('X-Response-Message: %s\\r\\n' % message)

  def send_error(self, code, message):
    return self.send_response(code, message)

  def Run(self):
    self.run_cgi()
    self.wfile.seek(0)
    return self.wfile


class UiRequestHandler(SimpleXMLRPCRequestHandler):

  # Make all paths/endpoints legal, we interpret them below.
  rpc_paths = ( )

  E403 = { 'code': '403', 'msg': 'Missing', 'mimetype': 'text/html',
           'title': '403 Not found',
           'body': '<p>File or directory not found. Sorry!</p>' }
  E404 = { 'code': '404', 'msg': 'Not found', 'mimetype': 'text/html',
           'title': '404 Not found',
           'body': '<p>File or directory not found. Sorry!</p>' }

  MIME_TYPES = {
    '3gp': 'video/3gpp',            'aac': 'audio/aac',
    'atom': 'application/atom+xml', 'avi': 'video/avi',
    'bmp': 'image/bmp',             'bz2': 'application/x-bzip2',
    'c': 'text/plain',              'cpp': 'text/plain',
    'css': 'text/css',
    'conf': 'text/plain',           'cfg': 'text/plain',
    'dtd': 'application/xml-dtd',   'doc': 'application/msword',
    'gif': 'image/gif',             'gz': 'application/x-gzip',
    'h': 'text/plain',              'hpp': 'text/plain',
    'htm': 'text/html',             'html': 'text/html',
    'hqx': 'application/mac-binhex40',
    'java': 'text/plain',           'jar': 'application/java-archive',
    'jpg': 'image/jpeg',            'jpeg': 'image/jpeg',
    'js': 'application/javascript',
    'json': 'application/json',     'jsonp': 'application/javascript',
    'log': 'text/plain',
    'md': 'text/plain',            'midi': 'audio/x-midi',
    'mov': 'video/quicktime',      'mpeg': 'video/mpeg',
    'mp2': 'audio/mpeg',           'mp3': 'audio/mpeg',
    'm4v': 'video/mp4',            'mp4': 'video/mp4',
    'm4a': 'audio/mp4',
    'ogg': 'audio/vorbis',
    'pdf': 'application/pdf',      'ps': 'application/postscript',
    'pl': 'text/plain',            'png': 'image/png',
    'ppt': 'application/vnd.ms-powerpoint',
    'py': 'text/plain',            'pyw': 'text/plain',
    'pk-shtml': 'text/html',       'pk-js': 'application/javascript',
    'rc': 'text/plain',            'rtf': 'application/rtf',
    'rss': 'application/rss+xml',  'sgml': 'text/sgml',
    'sh': 'text/plain',            'shtml': 'text/plain',
    'svg': 'image/svg+xml',        'swf': 'application/x-shockwave-flash',
    'tar': 'application/x-tar',    'tgz': 'application/x-tar',
    'tiff': 'image/tiff',          'txt': 'text/plain',
    'wav': 'audio/wav',
    'xml': 'application/xml',      'xls': 'application/vnd.ms-excel',
    'xrdf': 'application/xrds+xml','zip': 'application/zip',
    'DEFAULT': 'application/octet-stream'
  }
  TEMPLATE_RAW = ('%(body)s')
  TEMPLATE_JSONP = ('window.pkData = %s;')
  TEMPLATE_HTML = ('<html><head>\\n'
               '<link rel=\"stylesheet\" media=\"screen, screen\"'
                ' href=\"%(method)s://pagekite.net/css/pagekite.css\"'
                ' type=\"text/css\" title=\"Default stylesheet\" />\\n'
               '<title>%(title)s - %(prog)s v%(ver)s</title>\\n'
              '</head><body>\\n'
               '<h1>%(title)s</h1>\\n'
               '<div id=body>%(body)s</div>\\n'
               '<div id=footer><hr><i>Powered by <b>pagekite.py'
                ' v%(ver)s</b> and'
                ' <a href=\"'+ pagekite.WWWHOME +'\"><i>PageKite.net</i></a>.<br>'
                'Local time is %(now)s.</i></div>\\n'
              '</body></html>\\n')

  def setup(self):
    self.suppress_body = False
    if self.server.enable_ssl:
      self.connection = self.request
      self.rfile = socket._fileobject(self.request, \"rb\", self.rbufsize)
      self.wfile = socket._fileobject(self.request, \"wb\", self.wbufsize)
    else:
      SimpleXMLRPCRequestHandler.setup(self)

  def log_message(self, format, *args):
    pagekite.Log([('uireq', format % args)])

  def send_header(self, header, value):
    self.wfile.write('%s: %s\\r\\n' % (header, value))

  def end_headers(self):
    self.wfile.write('\\r\\n')

  def sendStdHdrs(self, header_list=[], cachectrl='private',
                                        mimetype='text/html'):
    if mimetype.startswith('text/') and ';' not in mimetype:
      mimetype += ('; charset=%s' % pagekite.DEFAULT_CHARSET)
    self.send_header('Cache-Control', cachectrl)
    self.send_header('Content-Type', mimetype)
    for header in header_list:
      self.send_header(header[0], header[1])
    self.end_headers()

  def sendChunk(self, chunk):
    if self.chunked:
      if pagekite.DEBUG_IO: print '<== SENDING CHUNK ===\\n%s\\n' % chunk
      self.wfile.write('%x\\r\\n' % len(chunk))
      self.wfile.write(chunk)
      self.wfile.write('\\r\\n')
    else:
      if pagekite.DEBUG_IO: print '<== SENDING ===\\n%s\\n' % chunk
      self.wfile.write(chunk)

  def sendEof(self):
    if self.chunked and not self.suppress_body: self.wfile.write('0\\r\\n\\r\\n')

  def sendResponse(self, message, code=200, msg='OK', mimetype='text/html',
                         header_list=[], chunked=False, length=None):
    self.log_request(code, message and len(message) or '-')
    self.wfile.write('HTTP/1.1 %s %s\\r\\n' % (code, msg))
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
        self.send_header('Content-Length', len(message or ''))

    self.sendStdHdrs(header_list=header_list, mimetype=mimetype)
    if message and not self.suppress_body:
      self.sendChunk(message)

  def needPassword(self):
    if self.server.pkite.ui_password: return True
    userkeys = [k for k in self.host_config.keys() if k.startswith('password/')]
    return userkeys

  def checkUsernamePasswordAuth(self, username, password):
    userkey = 'password/%s' % username
    if userkey in self.host_config:
      if self.host_config[userkey] == password:
        return

    if (self.server.pkite.ui_password and
        password == self.server.pkite.ui_password):
      return

    if self.needPassword():
      raise AuthError(\"Invalid password\")

  def checkRequestAuth(self, scheme, netloc, path, qs):
    if self.needPassword():
      raise AuthError(\"checkRequestAuth not implemented\")

  def checkPostAuth(self, scheme, netloc, path, qs, posted):
    if self.needPassword():
      raise AuthError(\"checkPostAuth not implemented\")

  def performAuthChecks(self, scheme, netloc, path, qs):
    try:
      auth = self.headers.get('authorization')
      if auth:
        (how, ab64) = auth.strip().split()
        if how.lower() == 'basic':
          (username, password) = base64.decodestring(ab64).split(':')
          self.checkUsernamePasswordAuth(username, password)
          return True

      self.checkRequestAuth(scheme, netloc, path, qs)
      return True

    except (ValueError, KeyError, AuthError), e:
      pagekite.LogDebug('HTTP Auth failed: %s' % e)
    else:
      pagekite.LogDebug('HTTP Auth failed: Unauthorized')

    self.sendResponse('<h1>Unauthorized</h1>\\n', code=401, msg='Forbidden')
    return False

  def performPostAuthChecks(self, scheme, netloc, path, qs, posted):
    try:
      self.checkPostAuth(scheme, netloc, path, qs, posted)
      return True
    except AuthError:
      self.sendResponse('<h1>Unauthorized</h1>\\n', code=401, msg='Forbidden')
      return False

  def do_UNSUPPORTED(self):
    self.sendResponse('Unsupported request method.\\n',
                      code=503, msg='Sorry', mimetype='text/plain')

  # Misc methods we don't support (yet)
  def do_OPTIONS(self): self.do_UNSUPPORTED()
  def do_DELETE(self): self.do_UNSUPPORTED()
  def do_PUT(self): self.do_UNSUPPORTED()

  def getHostInfo(self):
    http_host = self.headers.get('HOST', self.headers.get('host', 'unknown'))
    if http_host == 'unknown' or (http_host.startswith('localhost:') and
                http_host.replace(':', '/') not in self.server.pkite.be_config):
      http_host = None
      for bid in sorted(self.server.pkite.backends.keys()):
        be = self.server.pkite.backends[bid]
        if (be[pagekite.BE_BPORT] == self.server.pkite.ui_sspec[1] and
            be[pagekite.BE_STATUS] not in pagekite.BE_INACTIVE):
          http_host = '%s:%s' % (be[pagekite.BE_DOMAIN],
                                 be[pagekite.BE_PORT] or 80)
    if not http_host:
      if self.server.pkite.be_config.keys():
        http_host = sorted(self.server.pkite.be_config.keys()
                           )[0].replace('/', ':')
      else:
        http_host = 'unknown'
    self.http_host = http_host
    self.host_config = self.server.pkite.be_config.get((':' in http_host
                                                           and http_host
                                                            or http_host+':80'
                                                        ).replace(':', '/'), {})

  def do_GET(self, command='GET'):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    qs = parse_qs(query)
    self.getHostInfo()
    self.post_data = None
    self.command = command
    if not self.performAuthChecks(scheme, netloc, path, qs): return
    try:
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, None)
    except Exception, e:
      pagekite.Log([('err', 'GET error at %s: %s' % (path, e))])
      if pagekite.DEBUG_IO: print '=== ERROR\\n%s\\n===' % traceback.format_exc()
      self.sendResponse('<h1>Internal Error</h1>\\n', code=500, msg='Error')

  def do_HEAD(self):
    self.suppress_body = True
    self.do_GET(command='HEAD')

  def do_POST(self, command='POST'):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    qs = parse_qs(query)
    self.getHostInfo()
    self.command = command

    if not self.performAuthChecks(scheme, netloc, path, qs): return

    posted = None
    self.post_data = tempfile.TemporaryFile()
    self.old_rfile = self.rfile
    try:
      # First, buffer the POST data to a file...
      clength = cleft = int(self.headers.get('content-length'))
      while cleft > 0:
        rbytes = min(64*1024, cleft)
        self.post_data.write(self.rfile.read(rbytes))
        cleft -= rbytes

      # Juggle things so the buffering is invisble.
      self.post_data.seek(0)
      self.rfile = self.post_data

      ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
      if ctype == 'multipart/form-data':
        self.post_data.seek(0)
        posted = cgi.parse_multipart(self.rfile, pdict)
      elif ctype == 'application/x-www-form-urlencoded':
        if clength >= 50*1024*1024:
          raise Exception((\"Refusing to parse giant posted query \"
                           \"string (%s bytes).\") % clength)
        posted = cgi.parse_qs(self.rfile.read(clength), 1)
      elif self.host_config.get('xmlrpc', False):
        # We wrap the XMLRPC request handler in _BEGIN/_END in order to
        # expose the request environment to the RPC functions.
        RCI = self.server.RCI
        return RCI._END(SimpleXMLRPCRequestHandler.do_POST(RCI._BEGIN(self)))

      self.post_data.seek(0)
    except Exception, e:
      pagekite.Log([('err', 'POST error at %s: %s' % (path, e))])
      self.sendResponse('<h1>Internal Error</h1>\\n', code=500, msg='Error')
      self.rfile = self.old_rfile
      self.post_data = None
      return

    if not self.performPostAuthChecks(scheme, netloc, path, qs, posted): return
    try:
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, posted)
    except Exception, e:
      pagekite.Log([('err', 'POST error at %s: %s' % (path, e))])
      self.sendResponse('<h1>Internal Error</h1>\\n', code=500, msg='Error')

    self.rfile = self.old_rfile
    self.post_data = None

  def openCGI(self, full_path, path, shtml_vars):
    cgi_file = CGIWrapper(self, full_path).Run()
    lines = cgi_file.read(32*1024).splitlines(True)
    if '\\r\\n' in lines: lines = lines[0:lines.index('\\r\\n')+1]
    elif '\\n' in lines: lines = lines[0:lines.index('\\n')+1]
    else: lines.append('')

    header_list = []
    response_code = 200
    response_message = 'OK'
    response_mimetype = 'text/html'
    for line in lines[:-1]:
      key, val = line.strip().split(': ', 1)
      if key == 'X-Response-Code':
        response_code = val
      elif key == 'X-Response-Message':
        response_message = val
      elif key.lower() == 'content-type':
        response_mimetype = val
      elif key.lower() == 'location':
        response_code = 302
        header_list.append((key, val))
      else:
        header_list.append((key, val))

    self.sendResponse(None, code=response_code,
                            msg=response_message,
                            mimetype=response_mimetype,
                            chunked=True, header_list=header_list)
    cgi_file.seek(sum([len(l) for l in lines]))
    return cgi_file

  def renderIndex(self, full_path, files=None):
    files = files or [(f, os.path.join(full_path, f))
                      for f in sorted(os.listdir(full_path))]

    # Remove dot-files and PageKite metadata files
    if self.host_config.get('indexes') != pagekite.WEB_INDEX_ALL:
      files = [f for f in files if not (f[0].startswith('.') or
                                        f[0].startswith('_pagekite'))]

    fhtml = ['<table>']
    if files:
      for (fn, fpath) in files:
        fmimetype = self.getMimeType(fn)
        try:
          fsize = os.path.getsize(fpath) or ''
        except OSError:
          fsize = 0
        ops = [ ]
        if os.path.isdir(fpath):
          fclass = ['dir']
          if not fn.endswith('/'): fn += '/'
          qfn = urllib.quote(fn)
        else:
          qfn = urllib.quote(fn)
          fn = os.path.basename(fn)
          fclass = ['file']
          ops.append('download')
          if (fmimetype.startswith('text/') or
              (fmimetype == 'application/octet-stream' and fsize < 512000)):
            ops.append('view')
        (unused, ext) = os.path.splitext(fn)
        if ext:
          fclass.append(ext.replace('.', 'ext_'))
        fclass.append('mime_%s' % fmimetype.replace('/', '_'))

        ophtml = ', '.join([('<a class=\"%s\" href=\"%s?%s=/%s\">%s</a>'
                             ) % (op, qfn, op, qfn, op)
                            for op in sorted(ops)])
        try:
          mtime = full_path and int(os.path.getmtime(fpath) or time.time())
        except OSError:
          mtime = int(time.time())
        fhtml.append(('<tr class=\"%s\">'
                       '<td class=\"ops\">%s</td>'
                       '<td class=\"size\">%s</td>'
                       '<td class=\"mtime\">%s</td>'
                       '<td class=\"name\"><a href=\"%s\">%s</a></td>'
                      '</tr>'
                      ) % (' '.join(fclass), ophtml, fsize,
                           str(ts_to_date(mtime)), qfn,
                           fn.replace('<', '&lt;'),
                      ))
    else:
      fhtml.append('<tr><td><i>empty</i></td></tr>')
    fhtml.append('</table>')
    return ''.join(fhtml)

  def sendStaticPath(self, path, mimetype, shtml_vars=None):
    pkite = self.server.pkite
    is_shtml, is_cgi, is_dir = False, False, False
    index_list = None
    try:
      path = urllib.unquote(path)
      if path.find('..') >= 0: raise IOError(\"Evil\")

      paths = pkite.ui_paths
      def_paths = paths.get('*', {})
      http_host = self.http_host
      if ':' not in http_host: http_host += ':80'
      host_paths = paths.get(http_host.replace(':', '/'), {})
      path_parts = path.split('/')
      path_rest = []
      full_path = ''
      root_path = ''
      while len(path_parts) > 0 and not full_path:
        pf = '/'.join(path_parts)
        pd = pf+'/'
        m = None
        if   pf in host_paths: m = host_paths[pf]
        elif pd in host_paths: m = host_paths[pd]
        elif pf in def_paths: m = def_paths[pf]
        elif pd in def_paths: m = def_paths[pd]
        if m:
          policy = m[0]
          root_path = m[1]
          full_path = os.path.join(root_path, *path_rest)
        else:
          path_rest.insert(0, path_parts.pop())

      if full_path:
        is_dir = os.path.isdir(full_path)
      else:
        if not self.host_config.get('indexes', False): return False
        if self.host_config.get('hide', False): return False

        # Generate pseudo-index
        ipath = path
        if not ipath.endswith('/'): ipath += '/'
        plen = len(ipath)
        index_list = [(p[plen:], host_paths[p][1]) for p
                                                   in sorted(host_paths.keys())
                                                   if p.startswith(ipath)]
        if not index_list: return False

        full_path = ''
        mimetype = 'text/html'
        is_dir = True

      if is_dir and not path.endswith('/'):
        self.sendResponse('\\n', code=302, msg='Moved', header_list=[
                            ('Location', '%s/' % path)
                          ])
        return True

      indexes = ['index.html', 'index.htm', '_pagekite.html']

      dynamic_suffixes = []
      if self.host_config.get('pk-shtml'):
        indexes[0:0] = ['index.pk-shtml']
        dynamic_suffixes = ['.pk-shtml', '.pk-js']

      cgi_suffixes = []
      cgi_config = self.host_config.get('cgi', False)
      if cgi_config:
        if cgi_config == True: cgi_config = 'cgi'
        for suffix in cgi_config.split(','):
          indexes[0:0] = ['index.%s' % suffix]
          cgi_suffixes.append('.%s' % suffix)

      for index in indexes:
        ipath = os.path.join(full_path, index)
        if os.path.exists(ipath):
          mimetype = 'text/html'
          full_path = ipath
          is_dir = False
          break

      self.chunked = False
      rf_stat = rf_size = None
      if full_path:
        if is_dir:
          mimetype = 'text/html'
          rf_size = rf = None
          rf_stat = os.stat(full_path)
        else:
          for s in dynamic_suffixes:
            if full_path.endswith(s): is_shtml = True
          for s in cgi_suffixes:
            if full_path.endswith(s): is_cgi = True
          if not is_shtml and not is_cgi: shtml_vars = None
          rf = open(full_path, \"rb\")
          try:
            rf_stat = os.fstat(rf.fileno())
            rf_size = rf_stat.st_size
          except:
            self.chunked = True
    except (IOError, OSError), e:
      return False

    headers = [ ]
    if rf_stat and not (is_dir or is_shtml or is_cgi):
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

      # FIXME: Support ranges for resuming aborted transfers?

    if is_cgi:
      self.chunked = True
      rf = self.openCGI(full_path, path, shtml_vars)
    else:
      self.sendResponse(None, mimetype=mimetype,
                              length=rf_size,
                              chunked=self.chunked or (shtml_vars is not None),
                              header_list=headers)

    chunk_size = (is_shtml and 1024 or 16) * 1024
    if rf:
      while not self.suppress_body:
        data = rf.read(chunk_size)
        if data == \"\": break
        if is_shtml and shtml_vars:
          self.sendChunk(data % shtml_vars)
        else:
          self.sendChunk(data)
      rf.close()

    elif shtml_vars and not self.suppress_body:
      shtml_vars['title'] = '//%s%s' % (shtml_vars['http_host'], path)
      if self.host_config.get('indexes') in (True, pagekite.WEB_INDEX_ON,
                                                   pagekite.WEB_INDEX_ALL):
        shtml_vars['body'] = self.renderIndex(full_path, files=index_list)
      else:
        shtml_vars['body'] = ('<p><i>Directory listings disabled and</i> '
                              'index.html <i>not found.</i></p>')
      self.sendChunk(self.TEMPLATE_HTML % shtml_vars)

    self.sendEof()
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
      'http_host': self.http_host,
      'query_string': query,
      'code': 200,
      'body': '',
      'msg': 'OK',
      'now': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
      'ver': pagekite.APPVER
    }
    for key in self.headers.keys():
      data['http_'+key.lower()] = self.headers.get(key)

    if 'download' in qs:
      data['mimetype'] = 'application/octet-stream'
      # Would be nice to set Content-Disposition too.
    elif 'view' in qs:
      data['mimetype'] = 'text/plain'

    data['method'] = data.get('http_x-pagekite-proto', 'http').lower()

    if 'http_cookie' in data:
      cookies = Cookie.SimpleCookie(data['http_cookie'])
    else:
      cookies = {}

    # Do we expose the built-in console?
    console = self.host_config.get('console', False)

    if path == self.host_config.get('yamon', False):
      data['body'] = pagekite.gYamon.render_vars_text()

    elif console and path.startswith('/_pagekite/logout/'):
      parts = path.split('/')
      location = parts[3] or ('%s://%s/' % (data['method'], data['http_host']))
      self.sendResponse('\\n', code=302, msg='Moved', header_list=[
                          ('Set-Cookie', 'pkite_token=; path=/'),
                          ('Location', location)
                        ])
      return

    elif console and path.startswith('/_pagekite/login/'):
      parts = path.split('/', 4)
      token = parts[3]
      location = parts[4] or ('%s://%s/_pagekite/' % (data['method'],
                                                      data['http_host']))
      if query: location += '?' + query
      if token == self.server.secret:
        self.sendResponse('\\n', code=302, msg='Moved', header_list=[
                            ('Set-Cookie', 'pkite_token=%s; path=/' % token),
                            ('Location', location)
                          ])
        return
      else:
        pagekite.LogDebug(\"Invalid token, %s != %s\" % (token,
                                                       self.server.secret))
        data.update(self.E404)

    elif console and path.startswith('/_pagekite/'):
      if not ('pkite_token' in cookies and cookies['pkite_token'].value == self.server.secret):
        self.sendResponse('<h1>Forbidden</h1>\\n', code=403, msg='Forbidden')
        return

      if path == '/_pagekite/':
        if not self.sendStaticPath('%s/control.pk-shtml' % console, 'text/html',
                                   shtml_vars=data):
          self.sendResponse('<h1>Not found</h1>\\n', code=404, msg='Missing')
        return
      elif path.startswith('/_pagekite/quitquitquit/'):
        self.sendResponse('<h1>Kaboom</h1>\\n', code=500, msg='Asplode')
        self.wfile.flush()
        os._exit(2)
      elif path.startswith('/_pagekite/add_kite/'):
        data.update(self.add_kite(path, qs))
      elif path.endswith('/pagekite.rc'):
        data.update({'mimetype': 'application/octet-stream',
                     'body': '\\n'.join(self.server.pkite.GenerateConfig())})
      elif path.endswith('/pagekite.rc.txt'):
        data.update({'mimetype': 'text/plain',
                     'body': '\\n'.join(self.server.pkite.GenerateConfig())})
      elif path.endswith('/pagekite.cfg'):
        data.update({'mimetype': 'application/octet-stream',
                     'body': '\\r\\n'.join(self.server.pkite.GenerateConfig())})
      else:
        data.update(self.E403)
    else:
      if self.sendStaticPath(path, data['mimetype'], shtml_vars=data):
        return
      data.update(self.E404)

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

    self.lock = threading.Lock()
    self.request = None

    # For now, nobody gets ACL_WRITE
    self.auth_tokens = {httpd.secret: self.ACL_READ}

    # Channels are in-memory logs which can be tailed over XML-RPC.
    # Javascript apps can create these for implementing chat etc.
    self.channels = {'LOG': {'access': self.ACL_READ,
                             'tokens': self.auth_tokens,
                             'data': pagekite.LOG}}

  def _BEGIN(self, request_object):
    self.lock.acquire()
    self.request = request_object
    return request_object

  def _END(self, rv=None):
    if self.request:
      self.request = None
      self.lock.release()
    return rv

  def connections(self, auth_token):
    if (not self.request.host_config.get('console', False) or
        self.ACL_READ not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')

    return [{'sid': c.sid,
             'dead': c.dead,
             'html': c.__html__()} for c in self.conns.conns]

  def add_kite(self, auth_token, kite_domain, kite_proto):
    if (not self.request.host_config.get('console', False) or
        self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')
    pass

  def get_kites(self, auth_token):
    if (not self.request.host_config.get('console', False) or
        self.ACL_READ not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
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
    if (not self.request.host_config.get('console', False) or
        self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')
    # FIXME

  def remove_kite(self, auth_token, kite_id):
    if (not self.request.host_config.get('console', False) or
        self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')

    if kite_id in self.pkite.backends:
      del self.pkite.backends[kite_id]
      pagekite.Log([('reconfigured', '1'), ('removed', kite_id)])
      self.modified = True
    return self.get_kites(auth_token)

  def mk_channel(self, auth_token, channel):
    if not self.request.host_config.get('channels', False):
      raise AuthError('Unauthorized')

    chid = '%s/%s' % (self.request.http_host, channel)
    if chid in self.channels:
      raise Error('Exists')
    else:
      self.channels[chid] = {'access': self.ACL_WRITE,
                             'tokens': {auth_token: self.ACL_WRITE},
                             'data': []}
      return self.append_channel(auth_token, channel, {'created': channel})

  def get_channel(self, auth_token, channel):
    if not self.request.host_config.get('channels', False):
      raise AuthError('Unauthorized')

    chan = self.channels.get('%s/%s' % (self.request.http_host, channel),
                             self.channels.get(channel, {}))
    req = chan.get('access', self.ACL_WRITE)
    if req not in chan.get('tokens', self.auth_tokens).get(auth_token,
                                                           self.ACL_OPEN):
      raise AuthError('Unauthorized')

    return chan.get('data', [])

  def append_channel(self, auth_token, channel, values):
    data = self.get_channel(auth_token, channel)
    global LOG_LINE
    values.update({'ts': '%x' % time.time(), 'll': '%x' % LOG_LINE})
    LOG_LINE += 1
    data.append(values)
    return values

  def get_channel_after(self, auth_token, channel, last_seen, timeout):
    data = self.get_channel(auth_token, channel)
    last_seen = int(last_seen, 16)

    # line at the remote end, then we've restarted and should send everything.
    if (last_seen == 0) or (LOG_LINE < last_seen): return data
    # FIXME: LOG_LINE global for all channels?  Is that suck?

    # We are about to get sleepy, so release our environment lock.
    self._END()

    # If our internal LOG_LINE counter is less than the count of the last seen
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

    self.server_name = sspec[0]
    self.server_port = sspec[1]

    if ssl_pem_filename:
      ctx = pagekite.SSL.Context(pagekite.SSL.SSLv3_METHOD)
      ctx.use_privatekey_file (ssl_pem_filename)
      ctx.use_certificate_chain_file(ssl_pem_filename)
      self.socket = pagekite.SSL_Connect(ctx, socket.socket(self.address_family,
                                                            self.socket_type),
                                         server_side=True)
      self.server_bind()
      self.server_activate()
      self.enable_ssl = True
    else:
      self.enable_ssl = False

    try:
      from pagekite import yamond
      pagekite.YamonD = yamond.YamonD
    except:
      pass

    gYamon = pagekite.gYamon = pagekite.YamonD(sspec)
    gYamon.vset('started', int(time.time()))
    gYamon.vset('version', pagekite.APPVER)
    gYamon.vset('httpd_ssl_enabled', self.enable_ssl)
    gYamon.vset('errors', 0)
    gYamon.vset(\"bytes_all\", 0)

    self.RCI = RemoteControlInterface(self, pkite, conns, gYamon)
    self.register_introspection_functions()
    self.register_instance(self.RCI)


"""
sys.modules["pagekite.httpd"] = imp.new_module("pagekite.httpd")
sys.modules["pagekite.httpd"].open = __comb_open
sys.modules["pagekite"].httpd = sys.modules["pagekite.httpd"]
exec __FILES[".SELF/pagekite/httpd.py"] in sys.modules["pagekite.httpd"].__dict__


###############################################################################
#!/usr/bin/python
import sys
import pagekite as pk
import pagekite.httpd as httpd

if __name__ == "__main__":
  if sys.stdout.isatty():
    import pagekite.basicui
    uiclass = pagekite.basicui.BasicUi
  else:
    uiclass = pk.NullUi

  pk.Main(pk.PageKite, pk.Configure,
          uiclass=uiclass,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)


##############################################################################
CERTS="""\
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


#EOF#

