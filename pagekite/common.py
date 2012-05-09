#!/usr/bin/python
"""
Constants and global program state.
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

PROTOVER = '0.8'
APPVER = '0.4.6b+github'
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
 --authdomain=D:X       Use X as a remote authentication domain for *.D.
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

 --service_on=proto:kitename:host:port:secret
                  Configure a back-end service on host:port, using protocol
                 proto and the given kite name as the public domain. As a
                special case, if host is 'localhost' and the word 'built-in'
              is used as a port number, pagekite.py's HTTP server will be used.

 --service_off=...      Same as --service, except not enabled by default.
 --service_delete=...   Delete a given service.
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
 --watch=N              Display proxied data (higher N = more verbosity)

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

    Fly a kite on pagekite.net for somedomain.com, and register the
    public IP address with the No-IP Dynamic DNS provider.
    $ pagekite.py \\
        --defaults \\
        --dyndns=user:pass@no-ip.com \\
        --service_on=http:kitename.com:localhost:80:mygreatsecret

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
SERVICE_CERTS = ['b5p.us', 'frontends.b5p.us', 'pagekite.net', 'pagekite.me',
                 'pagekite.com', 'pagekite.org', 'testing.is', '302.is']

OPT_FLAGS = 'o:O:S:H:P:X:L:ZI:fA:R:h:p:aD:U:NE:'
OPT_ARGS = ['noloop', 'clean', 'nopyopenssl', 'nossl', 'nocrashreport',
            'nullui', 'remoteui', 'uiport=', 'help', 'settings',
            'optfile=', 'optdir=', 'savefile=',
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
            'backend=', 'define_backend=', 'be_config=', 'delete_backend=',
            'service_on=', 'service_off=', 'service_cfg=', 'service_delete=',
            'frontend=', 'frontends=', 'torify=', 'socksify=', 'proxy=',
            'new', 'all', 'noall', 'dyndns=', 'nozchunks', 'sslzlib',
            'buffers=', 'noprobes', 'debugio', 'watch=',
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

# Create our service-domain matching regexp
import re
SERVICE_DOMAIN_RE = re.compile('\.(' + '|'.join(SERVICE_DOMAINS) + ')$')
SERVICE_SUBDOMAIN_RE = re.compile(r'^([A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$')


class ConfigError(Exception):
  """This error gets thrown on configuration errors."""

class ConnectError(Exception):
  """This error gets thrown on connection errors."""


##[ Ugly fugly globals ]#######################################################

# The global Yamon is used for measuring internal state for monitoring
gYamon = None

# Status of our buffers...
buffered_bytes = 0



