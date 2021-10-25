"""
Constants and global program state.
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
import random
import time

PROTOVER = '0.8'
APPVER = '1.5.2.201011'
AUTHOR = 'Bjarni Runar Einarsson, http://bre.klaki.net/'
WWWHOME = 'https://pagekite.net/'
LICENSE_URL = 'http://www.gnu.org/licenses/agpl.html'

MAGIC_PREFIX = '/~:PageKite:~/'
MAGIC_PATH = '%sv%s' % (MAGIC_PREFIX, PROTOVER)
MAGIC_PATHS = (MAGIC_PATH, '/Beanstalk~Magic~Beans/0.2')
MAGIC_UUID = '%x-%x-%s' % (random.randint(0, 0xfffffff), int(time.time()), APPVER)

SERVICE_PROVIDER = 'PageKite.net'
SERVICE_DOMAINS = ('pagekite.me', '302.is', 'testing.is', 'kazz.am')
SERVICE_DOMAINS_SIGNUP = ('pagekite.me',)
SERVICE_XMLRPC = 'http://pagekite.net/xmlrpc/'
SERVICE_TOS_URL = 'https://pagekite.net/humans.txt'
SERVICE_CERTS = ['b5p.us', 'frontends.b5p.us', 'pagekite.net', 'pagekite.me',
                 'pagekite.com', 'pagekite.org', 'testing.is', '302.is']

# Places to search for the CA Certificate bundle
OS_CA_CERTS = (
  "/etc/pki/tls/certs/ca-bundle.crt",                  # Fedora/RHEL
  "/etc/ssl/certs/ca-certificates.crt",                # Debian/Ubuntu/Gentoo etc.
  "/etc/ssl/ca-bundle.pem",                            # OpenSUSE
  "/etc/pki/tls/cacert.pem",                           # OpenELEC
  "/etc/ssl/cert.pem",                                 # OpenBSD
  "/usr/local/share/certs/ca-root-nss.crt",            # FreeBSD/DragonFly
  "/usr/local/etc/openssl/cert.pem",                   # OS X (Homebrew)
  "/opt/local/etc/openssl/cert.pem",                   # OS X (Ports?)
  "/data/data/com.termux/files/usr/etc/tls/cert.pem")  # Android-Termux

CURL_CA_CERTS = 'https://curl.haxx.se/ca/cacert.pem'


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

# This is how many bytes we are willing to read per cycle.
MAX_READ_BYTES = (16 * 1024) - 128  # Under 16kB, because OpenSSL
MAX_READ_TUNNEL_X = 3.1             # 3x above, + fudge factor

# Higher values save CPU and prevent individual tunnels
# from hogging all our resources, but hurt latency and
# reduce per-tunnel throughput.
SELECT_LOOP_MIN_MS = 5

# Re-evaluate our choice of frontends every 45-60 minutes.
FE_PING_INTERVAL = (45 * 60) + random.randint(0, 900)

# This is a global count of disconnect errors; we use this
# to adjust the ping interval over time.
DISCONNECTS = []

PING_INTERVAL_MIN     = 20
PING_INTERVAL         = 116  # Not quite 2 minutes... :-)
PING_INTERVAL_DEFAULT = 116
PING_INTERVAL_MOBILE  = 1800
PING_INTERVAL_MAX     = 1800
PING_GRACE_DEFAULT    = 40
PING_GRACE_MIN        = 5

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
  'whitelabel': ('http://dnsup.%s/'
                 '?hostname=%%(domain)s&myip=%%(ips)s&sign=%%(sign)s'),
  'whitelabels': ('https://dnsup.%s/'
                  '?hostname=%%(domain)s&myip=%%(ips)s&sign=%%(sign)s'),
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

class BugFoundError(Exception):
  """Throw this anywhere a bug is detected and we want a crash."""


##[ Ugly fugly globals ]#######################################################

# The global Yamon is used for measuring internal state for monitoring
gYamon = None

# Status of our buffers...
buffered_bytes = [0]
