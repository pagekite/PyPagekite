#!/usr/bin/python
"""
The program manual!
"""
import re
import time

from common import *
from compat import ts_to_iso

MAN_NAME = ("""\
    pagekite.py - Make localhost servers publicly visible.
""")
MAN_SYNOPSIS = ("""\
    <b>pagekite.py</b> [<a>--options</a>] [<a>service</a>] <a>kite-name</a> [<a>+flags</a>]
""")
MAN_DESCRIPTION = ("""\
    PageKite is a system for exposing <tt>localhost</tt> servers to the
    public Internet.  It is most commonly used to make local web servers or
    SSH servers publicly visible, although almost any TCP-based protocol can
    work if the client knows how to use an HTTP proxy.

    PageKite uses a combination of tunnels and reverse proxies to compensate
    for the fact that <tt>localhost</tt> usually does not have a public IP
    address and is often subject to adverse network conditions, including
    aggressive firewalls and multiple layers of NAT.

    This program implements both ends of the tunnel: the local "back-end"
    and the remote "front-end" reverse-proxy relay.  For convenience,
    <b>pagekite.py</b> also includes a basic HTTP server for quickly exposing
    files and directories to the World Wide Web for casual sharing and
    collaboration.
""")
MAN_EXAMPLES = ("""\
    <pre>Basic usage, gives <tt>http://localhost:80/</tt> a public name:
    $ pagekite.py NAME.pagekite.me

    To expose specific folders, files or use alternate local ports:
    $ pagekite.py /a/path/ NAME.pagekite.me +indexes  # built-in HTTPD
    $ pagekite.py *.html   NAME.pagekite.me           # built-in HTTPD
    $ pagekite.py 3000     NAME.pagekite.me           # HTTPD on 3000

    To expose multiple local servers (SSH and HTTP):
    $ pagekite.py ssh://NAME.pagekite.me AND 3000 NAME.pagekite.me</pre>
""")
MAN_KITES = ("""\
    The most comman usage of <b>pagekite.py</b> is as a back-end, where it
    is used to expose local services to the outside world.

    Examples of services are: a local HTTP server, a local SSH server,
    a folder or a file.

    As illustrated above, one simply tells the program which local services
    to expose to the world and which names to use.  If a kite name is
    requested which does not already exist in the configuration file and
    program is run interactively, the user will be prompted and given the
    option of signing up and/or creating a new kite using the <b>pagekite.net</b>
    service.

    Multiple services and kites can be specified on a single command-line,
    separated by the word 'AND' (note capital letters are required).
    This may cause problems if you have many files and folders by that
    name, but that should be relatively rare. :-)

    The options <b>--list</b>, <b>--add</b>, <b>--disable</b> and \
<b>--remove</b> can be used to
    manipulate the kites in your configuration, if you prefer not to edit
    the file by hand.
""")
MAN_FLAGS = ("""\
    Flags are used to tune the behavior of a particular kite, for example
    by enabling access controls or specific features of the built-in HTTP
    server.
""")
MAN_FLAGS_COMMON = ("""\
    +ip</b>/<a>1.2.3.4     __Enable connections only from this IP address.
    +ip</b>/<a>1.2.3       __Enable connections only from this /24 netblock.
""")
MAN_FLAGS_HTTP = ("""\
    +password</b>/<a>name</b>=<a>pass
            Require a username and password (HTTP Basic Authentication)

    +rewritehost   __Rewrite the incoming Host: header
""")
MAN_FLAGS_BUILTIN = ("""\
    +indexes       __Enable directory indexes.
    +indexes</b>=<a>all   __Enable directory indexes including hidden (dot-) files.
    +hide          __Obfuscate URLs of shared files.

    +cgi</b>=<a>list
            A list of extensions, for which files should be treated as
            CGI scripts (example: <tt>+cgi=cgi,pl,sh</tt>).
""")
MAN_OPTIONS = ("""\
    The full power of <b>pagekite.py</b> lies in the numerous options which
    can be specified on the command line or in a configuration file (see below).

    Note that many options, especially the service and domain definitions,
    are additive and if given multiple options the program will attempt to
    obey them all.  Options are processed in order and if they are not
    additive then the last option will override all preceding ones.

    Although <b>pagekite.py</b> accepts a great many options, most of the
    time the program defaults will Just Work.
""")
MAN_OPT_COMMON = ("""\
    --clean         __Skip loading the default configuration file.
    --signup        __Interactively sign up for PageKite.net service.
    --defaults      __Set defaults for use with PageKite.net service.
    --nocrashreport __Don't send anonymous crash reports to pagekite.net.
""")
MAN_OPT_BACKEND = ("""\
    --list          __List all configured kites.
    --add           __Add (or enable) the following kites, save config.
    --remove        __Remove the following kites, save config.
    --disable       __Disable the following kites, save config.
    --only          __Disable all but the following kites, save config.
    --watch</b>=<a>N       __Display proxied data (higher N = more verbosity).

    --local</b>=<a>ports   __Configure for local serving only (no remote front-end).

    --proxy</b>=<a>type</a>:<a>server</a>:<a>port<a>,\
 <b>--socksify</b>=<a>server</a>:<a>port,\
 <b>--torify</b>=<a>server</a>:<a>port
            Connect to the front-ends using a chain of proxies, a single SOCKS
            proxy or the Tor anonymity network.  The type can be any of
            'ssl', 'http' or 'socks5'.

    --service_on</b>=<a>proto</a>:<a>kitename</a>:<a>host</a>:<a>port</a>:<a>secret
            Explicit configuration for a service kite.  Generally kites are
            created on the command-line using the service short-hand
            described above, but this syntax is used in the config file.

    --service_off</b>=<a>proto</a>:<a>kitename</a>:<a>host</a>:<a>port</a>:<a>secret
            Same as --service, except disabled by default.

    --service_cfg</b>=<a>...</a>, <b>--webpath</b>=<a>...
            These options are used in the configuration file to store service
            and flag settings (see above). These are both likely to change in
            the near future, so please just pretend you didn't notice them.

    --frontend</b>=<a>host</a>:<a>port
            Connect to the named front-end server. If this option is repeated,
            multiple connections will be made.

    --frontends</b>=<a>num</a>:<a>dns-name</a>:<a>port
            Choose <a>num</a> front-ends from the A records of a DNS domain
            name, using the given port number. Default behavior is to probe
            all addresses and use the fastest one.

    --fe_certname</b>=<a>domain
            Connect using SSL, accepting valid certs for this domain. If
            this option is repeated, any of the named certificates will be
            accepted, but the first will be preferred.

    --ca_certs</b>=<a>/path/to/file
            Path to your trusted root SSL certificates file.

    --dyndns</b>=<a>X
            Register changes with DynDNS provider X.  X can either be simply
            the name of one of the 'built-in' providers, or a URL format
            string for ad-hoc updating.

    --all           __Terminate early if any tunnels fail to register.
    --new           __Don't attempt to connect to any kites' old front-ends.
    --fingerpath</b>=<a>P  __Path recipe for the httpfinger back-end proxy.
    --noprobes      __Reject all probes for service state.
""")
MAN_OPT_FRONTEND = ("""\
    --isfrontend    __Enable front-end operation.

    --domain</b>=<a>proto,proto2,pN</a>:<a>domain</a>:<a>secret
            Accept tunneling requests for the named protocols and specified
            domain, using the given secret.  A * may be used as a wildcard for
            subdomains or protocols.

    --authdomain</b>=<a>auth-domain,\
 <b>--authdomain</b>=<a>target-domain</a>:<a>auth-domain
            Use <i>auth-domain</a> as a remote authentication server for the
            DNS-based authetication protocol.  If no <i>target-domain</i>
            is given, use this as the default authentication method.

    --motd</b>=<a>/path/to/motd
            Send the contents of this file to new back-ends as a
            "message of the day".

    --host</b>=<a>hostname __Listen on the given hostname only.
    --ports</b>=<a>list    __Listen on a comma-separated list of ports.
    --portalias</b>=<a>A:B __Report port A as port B to backends.
    --protos</b>=<a>list   __Accept the listed protocols for tunneling.

    --rawports</b>=<a>list
            Listen for raw connections these ports. The string '%s'
            allows arbitrary ports in HTTP CONNECT.

    --tls_default</b>=<a>name
            Default name to use for SSL, if SNI (Server Name Indication)
            is missing from incoming HTTPS connections.

    --tls_endpoint</b>=<a>name</a>:<a>/path/to/file
            Terminate SSL/TLS for a name using key/cert from a file.
""")
MAN_OPT_SYSTEM = ("""\
    --optfile</b>=<a>/path/to/file
            Read settings from file X. Default is <tt>~/.pagekite.rc</tt>.

    --optdir</b>=<a>/path/to/directory
            Read settings from <tt>/path/to/directory/*.rc</tt>, in
            lexicographical order.

    --savefile</b>=<a>/path/to/file
            Saved settings will be written to this file.

    --save          __Save the current configuration to the savefile.

    --settings
            Dump the current settings to STDOUT, formatted as a configuration
            file would be.

    --httpd</b>=<a>X</a>:<a>P    __Enable the HTTP user interface on hostname X, port P.
    --pemfile</b>=<a>X    __Use X as a PEM key for the HTTPS UI.
    --httppass</b>=<a>X   __Require password X to access the UI.

    --nozchunks    __Disable zlib tunnel compression.
    --sslzlib      __Enable zlib compression in OpenSSL.
    --buffers</b>=<a>N    __Buffer at most N kB of data before blocking.
    --logfile</b>=<a>F    __Log to file F.
    --daemonize    __Run as a daemon.
    --runas</b>=<a>U</a>:<a>G    __Set UID:GID after opening our listening sockets.
    --pidfile</b>=<a>P    __Write PID to the named file.
    --errorurl</b>=<a>U   __URL to redirect to when back-ends are not found.
""")
MAN_CONFIG_FILES = ("""\
    The <b>pagekite.py</b> configuration file lives in different places,
    depending on your operating system and how you are using it.

    If you are using the program as a command-line utility, it will
    load its configuration from a file in your home directory.  The file is
    named <tt>.pagekite.rc</tt> on Unix systems (including Mac OS X), or
    <tt>pagekite.cfg</tt> on Windows.

    If you are using <b>pagekite.py</b> as a system-daemon which starts up
    when your computer boots, it is generally configured to load settings
    from <tt>/etc/pagekite.d/*.rc</tt> (in lexicographical order).

    In all cases, the configuration files contain one or more of the same
    options as are described above, with the difference that at most one
    option may be present on each line, and the parser is more tolerant of
    white-space.  The leading '--' may also be omitted for readability and
    blank lines and lines beginning with '#' are treated as comments.

    <b>NOTE:</b> When using <b>-o</b>, <b>--optfile</b> or <b>--optdir</b> on the command line,
    it is advisable to use <b>--clean</b> to suppress the default configuration.
""")
MAN_LICENSE = """\
    Copyright 2010-2012, the Beanstalks Project ehf. and Bjarni R. Einarsson.

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at
    your option) any later version.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
    License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see: <http://www.gnu.org/licenses/>
"""
MAN_SEE_ALSO = ("""\
    lapcat(1), <http://pagekite.org/>, <https://pagekite.net/>
""")
MAN_AUTHOR = ("""\
    Bjarni R. Einarsson <http://bre.klaki.net/>
""")

MANUAL = (
  ('SH', 'Name', MAN_NAME),
  ('SH', 'Synopsis', MAN_SYNOPSIS),
  ('SH', 'Description', MAN_DESCRIPTION),
  ('SH', 'Basic examples', MAN_EXAMPLES),
  ('SH', 'Services and kites', MAN_KITES),
  ('SH', 'Flags', MAN_FLAGS),
  ('SS', 'Common flags', MAN_FLAGS_COMMON),
  ('SS', 'HTTP protocol flags', MAN_FLAGS_HTTP),
  ('SS', 'Built-in HTTPD flags', MAN_FLAGS_BUILTIN),
  ('SH', 'Options', MAN_OPTIONS),
  ('SS', 'Common options', MAN_OPT_COMMON),
  ('SS', 'Back-end options', MAN_OPT_BACKEND),
  ('SS', 'Front-end options', MAN_OPT_FRONTEND),
  ('SS', 'System options', MAN_OPT_SYSTEM),
  ('SH', 'Configuration files', MAN_CONFIG_FILES),
  ('SH', 'See Also', MAN_SEE_ALSO),
  ('SH', 'Author', MAN_AUTHOR),
  ('SH', 'Copyright and license', MAN_LICENSE),
)

def clean_text(text):
  return re.sub('</?(tt|i)>', '`',
                re.sub('</?(a|b|pre)>', '', text.replace(' __', '   ')))


MINIDOC = ("""\
>>> Welcome to pagekite.py v%s!

%s
    To sign up with PageKite.net or get advanced instructions:
    $ pagekite.py --signup
    $ pagekite.py --help

    If you request a kite which does not exist in your configuration file,
    the program will offer to help you sign up with https://pagekite.net/
    and create it.  Pick a name, any name!\
""") % (APPVER, clean_text(MAN_EXAMPLES))

def DOC():
  doc = ''
  for h, section, text in MANUAL:
    doc += '%s\n\n%s\n' % (h == 'SH' and section.upper() or '  '+section,
                           clean_text(text))
  return doc

def MAN(pname=None):
  man = ("""\
.\\" This man page is autogenerated from the pagekite.py built-in manual.
.TH PAGEKITE "1" "%s" "https://pagekite.net/" "Awesome Commands"
.nh
.ad l
""") % ts_to_iso(time.time()).split('T')[0]
  for h, section, text in MANUAL:
    man += ('.%s %s\n\n%s\n\n'
            ) % (h, h == 'SH' and section.upper() or section,
                 re.sub('\n +', '\n', '\n'+text.strip())
                   .replace('\n--', '\n.TP\n\\fB--')
                   .replace('\n+', '\n.TP\n\\fB+')
                   .replace(' __', '\\fR\n')
                   .replace('-', '\\-')
                   .replace('<pre>', '\n.nf\n').replace('</pre>', '\n.fi\n')
                   .replace('<b>', '\\fB').replace('</b>', '\\fR')
                   .replace('<a>', '\\fI').replace('</a>', '\\fR')
                   .replace('<i>', '\\fI').replace('</i>', '\\fR')
                   .replace('<tt>', '\\fI').replace('</tt>', '\\fR'))
  if pname: man = man.replace('pagekite.py', pname)
  return man

if __name__ == '__main__':
  import sys
  if '--nopy' in sys.argv:
    pname = 'pagekite'
  else:
    pname = None

  if '--man' in sys.argv:
    print MAN(pname)
  elif '--minidoc' in sys.argv:
    print MINIDOC
  else:
    print DOC()
