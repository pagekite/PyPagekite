#!/usr/bin/env python
"""
The program manual!
"""
import os
import re
import time

from common import *
from compat import ts_to_iso

MAN_NAME = ("""\
    pagekite.py - Make localhost servers publicly visible
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

    A service is exposed by describing it on the command line, along with the
    desired public kite name. If a kite name is requested which does not already
    exist in the configuration file and program is run interactively, the user
    will be prompted and given the option of signing up and/or creating a new
    kite using the <b>pagekite.net</b> service.

    Multiple services and kites can be specified on a single command-line,
    separated by the word 'AND' (note capital letters are required).
    This may cause problems if you have many files and folders by that
    name, but that should be relatively rare. :-)
""")
MAN_KITE_EXAMPLES = ("""\
    The options <b>--list</b>, <b>--add</b>, <b>--disable</b> and \
<b>--remove</b> can be used to
    manipulate the kites and service definitions in your configuration file,
    if you prefer not to edit it by hand.  Examples:

    <pre>Adding new kites
    $ pagekite.py --add /a/path/ NAME.pagekite.me +indexes
    $ pagekite.py --add 80 OTHER-NAME.pagekite.me

    To display the current configuration
    $ pagekite.py --list

    Disable or delete kites (--add re-enables)
    $ pagekite.py --disable OTHER-NAME.pagekite.me
    $ pagekite.py --remove NAME.pagekite.me</pre>
""")
MAN_FLAGS = ("""\
    Flags are used to tune the behavior of a particular kite, for example
    by enabling access controls or specific features of the built-in HTTP
    server.
""")
MAN_FLAGS_COMMON = ("""\
    +ip</b>/<a>1.2.3.4</a>     __Enable connections only from this IP address.
    +ip</b>/<a>1.2.3</a>       __Enable connections only from this /24 netblock.
""")
MAN_FLAGS_HTTP = ("""\
    +password</b>/<a>name</a>=<a>pass</a>
            Require a username and password (HTTP Basic Authentication)

    +rewritehost</b>    __Rewrite the incoming Host: header.
    +rewritehost</b>=<a>N</a>  __Replace Host: header value with N.
    +rawheaders</b>     __Do not rewrite (or add) any HTTP headers at all.
    +insecure</b>       __Allow access to phpMyAdmin, /admin, etc. (per kite).
""")
MAN_FLAGS_BUILTIN = ("""\
    +indexes        __Enable directory indexes.
    +indexes</b>=<a>all</a>    __Enable directory indexes including hidden (dot-) files.
    +hide           __Obfuscate URLs of shared files.
    +uploads        __Accept file uploads.
    +uploads</b>=<a>RE</a>     __Accept uploads to paths matching regexp RE.
    +ul_filenames</b>=<a>P</a> __Upload naming policy. P = overwrite, keep or rename

    +cgi</b>=<a>list</a>
            A list of extensions, for which files should be treated as
            CGI scripts (example: <tt>+cgi=cgi,pl,sh</tt>).

    +photobackup</b>=<a>password</a>
            Enable built-in PhotoBackup server with the given password.
            See https://photobackup.github.io/ for details.
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
    --signup        __Interactively sign up for pagekite.net service.
    --defaults      __Set defaults for use with pagekite.net service.
    --whitelabel=D  __Set defaults for pagekite.net white-labels.
    --whitelabels=D __Set defaults for pagekite.net white-labels (with TLS).
    --nocrashreport __Don't send anonymous crash reports to pagekite.net.
""")
MAN_OPT_BACKEND = ("""\
    --shell         __Run PageKite in an interactive shell.
    --nullui        __Silent UI for scripting. Assumes Yes on all questions.

    --list          __List all configured kites.
    --add           __Add (or enable) the following kites, save config.
    --remove        __Remove the following kites, save config.
    --disable       __Disable the following kites, save config.
    --only          __Disable all but the following kites, save config.

    --insecure      __Allow access to phpMyAdmin, /admin, etc. (global).

    --local</b>=<a>ports</a>   __Configure for local serving only (no remote front-end).
    --watch</b>=<a>N</a>       __Display proxied data (higher N = more verbosity).

    --noproxy       __Ignore system (or config file) proxy settings.

    --proxy</b>=<a>type</a>:<a>server</a>:<a>port</a>,\
 <b>--socksify</b>=<a>server</a>:<a>port</a>,\
 <b>--torify</b>=<a>server</a>:<a>port</a> __
            Connect to the front-ends using SSL, an HTTP proxy, a SOCKS proxy,
            or the Tor anonymity network.  The type can be any of 'ssl', 'http'
            or 'socks5'.  The server name can either be a plain hostname,
            user@hostname or user:password@hostname.  For SSL connections the
            user part may be a path to a client cert PEM file.  If multiple
            proxies are defined, they will be chained one after another.

    --service_on</b>=<a>proto</a>:<a>kitename</a>:<a>host</a>:<a>port</a>:<a>secret</a> __
            Explicit configuration for a service kite.  Generally kites are
            created on the command-line using the service short-hand
            described above, but this syntax is used in the config file.

    --service_off</b>=<a>proto</a>:<a>kitename</a>:<a>host</a>:<a>port</a>:<a>secret</a> __
            Same as --service_on, except disabled by default.

    --service_cfg</b>=<a>...</a>, <b>--webpath</b>=<a>...</a> __
            These options are used in the configuration file to store service
            and flag settings (see above). These are both likely to change in
            the near future, so please just pretend you didn't notice them.

    --frontend</b>=<a>host</a>:<a>port</a> __
            Connect to the named front-end server. If this option is repeated,
            multiple connections will be made.

    --frontends</b>=<a>num</a>:<a>dns-name</a>:<a>port</a> __
            Choose <a>num</a> front-ends from the A records of a DNS domain
            name, using the given port number. Default behavior is to probe
            all addresses and use the fastest one.

    --nofrontend</b>=<a>ip</a>:<a>port</a> __
            Never connect to the named front-end server. This can be used to
            exclude some front-ends from auto-configuration.

    --fe_certname</b>=<a>domain</a> __
            Connect using SSL, accepting valid certs for this domain. If
            this option is repeated, any of the named certificates will be
            accepted, but the first will be preferred.

    --fe_nocertcheck</b> __
            Connect using SSL/TLS, but do not verify the remote certificate.
            This is largely insecure but still thwarts passive attacks and
            prevents routers and firewalls from corrupting the PageKite tunnel.

    --ca_certs</b>=<a>/path/to/file</a> __
            Path to your trusted root SSL certificates file.

    --dyndns</b>=<a>X</a> __
            Register changes with DynDNS provider X.  X can either be simply
            the name of one of the 'built-in' providers, or a URL format
            string for ad-hoc updating.

    --keepalive</b>=<a>N</a> __
            Force traffic over idle tunnels every N seconds, to cope with
            firewalls that kill idle TCP connections. Backend only: if set
            to "auto" (the default), the interval will be adjusted
            automatically in response to disconnects.

    --all           __Terminate early if any tunnels fail to register.
    --new           __Don't attempt to connect to any kites' old front-ends.
    --fingerpath</b>=<a>P</a>  __Path recipe for the httpfinger back-end proxy.
    --noprobes      __Reject all probes for service state.
""")
MAN_OPT_FRONTEND = ("""\
    --isfrontend    __Enable front-end operation.

    --domain</b>=<a>proto,proto2,pN</a>:<a>domain</a>:<a>secret</a> __
            Accept tunneling requests for the named protocols and specified
            domain, using the given secret.  A * may be used as a wildcard
            for subdomains or protocols. This is for static configurations,
            for dynamic access controls use the `--authdomain` mechanism.

    --authdomain</b>=<a>DNS-suffix</a>,\
 <b>--authdomain</b>=<a>/path/to/app</a>,\
 <b>--authdomain</b>=<a>kite-domain</a>:<a>DNS-suffix</a>,\
 <b>--authdomain</b>=<a>kite-domain</a>:<a>/path/to/app</a> __
            Use <a>DNS-suffix</a> for remote DNS-based authentication of
            incoming tunnel requests, or invoke an external application
            for this purpose.  If no <i>kite-domain</i> is given, use
            this as the default authentication method.  See the section
            below on tunnel authentication for further details.  In order
            for the app path to be recognized as such, it must contain at
            least one / character.

    --motd</b>=<a>/path/to/motd</a> __
            Send the contents of this file to new back-ends as a
            "message of the day".

    --host</b>=<a>hostname</a> __Listen on the given hostname only.
    --ports</b>=<a>list</a>    __Listen on a comma-separated list of ports.
    --portalias</b>=<a>A:B</a> __Report port A as port B to backends (because firewalls).
    --protos</b>=<a>list</a>   __Accept the listed protocols for tunneling.

    --rawports</b>=<a>list</a> __
            Listen for raw connections these ports. The string '%s'
            allows arbitrary ports in HTTP CONNECT.

    --ratelimit_ips</b>=<a>IPs/seconds</a>,\
 <b>--ratelimit_ips</b>=<a>kitename</a>:<a>IPs/seconds</a> __
            Limit how many different IP addresses can request data from
            a tunnel within a given window of time, e.g. 5/3600. This is
            useful as either a crude form of DDoS mitigation, or as a
            mechanism to make public kite services unusable for phishing.
            Note that limits are enforced per-tunnel (not per kite), and
            tunnels serving multiple kites will use the settings of the
            strictest kite.

    --accept_acl_file</b>=<a>/path/to/file</a> __
            Consult an external access control file before accepting an
            incoming connection. Quick'n'dirty for mitigating abuse. The
            format is one rule per line: `rule policy comment` where a
            rule is an IP or regexp and policy is 'allow' or 'deny'.

    --client_acl</b>=<a>policy</a>:<a>regexp</a>,\
 <b>--tunnel_acl</b>=<a>policy</a>:<a>regexp</a> __
            Add a client connection or tunnel access control rule.
            Policies should be 'allow' or 'deny', the regular expression
            should be written to match IPv4 or IPv6 addresses.  If defined,
            access rules are checkd in order and if none matches, incoming
            connections will be rejected.

    --tls_default</b>=<a>name</a> __
            Default name to use for SSL, if SNI (Server Name Indication)
            is missing from incoming HTTPS connections.

    --tls_endpoint</b>=<a>name</a>:<a>/path/to/file</a> __
            Terminate SSL/TLS for a name using key/cert from a file.
""")
MAN_OPT_SYSTEM = ("""\
    --optfile</b>=<a>/path/to/file</a> __
            Read settings from file X. Default is <tt>~/.pagekite.rc</tt>.

    --optdir</b>=<a>/path/to/directory</a> __
            Read settings from <tt>/path/to/directory/*.rc</tt>, in
            lexicographical order.

    --savefile</b>=<a>/path/to/file</a> __
            Saved settings will be written to this file.

    --save          __Save the current configuration to the savefile.

    --settings</b> __
            Dump the current settings to STDOUT, formatted as a configuration
            file would be.

    --nopyopenssl  __Avoid use of the pyOpenSSL library (not in config file)
    --nossl        __Avoid use SSL entirely (not allowed in config file)

    --nozchunks    __Disable zlib tunnel compression.
    --sslzlib      __Enable zlib compression in OpenSSL.
    --buffers</b>=<a>N</a>    __Buffer at most N kB of data before blocking.
    --logfile</b>=<a>F</a>    __Log to file F, <tt>stdio</tt> means standard output.
    --daemonize    __Run as a daemon.
    --runas</b>=<a>U</a>:<a>G</a>    __Set UID:GID after opening our listening sockets.
    --pidfile</b>=<a>P</a>    __Write PID to the named file.
    --errorurl</b>=<a>U</a>   __URL to redirect to when back-ends are not found.
    --errorurl</b>=<a>D:U</a> __Custom error URL for domain D.

    --selfsign</b> __
            Configure the built-in HTTP daemon for HTTPS, first generating a
            new self-signed certificate using <b>openssl</b> if necessary.

    --httpd</b>=<a>X</a>:<a>P</a>,\
 <b>--httppass</b>=<a>X</a>,\
 <b>--pemfile</b>=<a>X</a> __
            Configure the built-in HTTP daemon.  These options are likely to
            change in the near future, please pretend you didn't see them.
""")
MAN_CONFIG_FILES = ("""\
    If you are using <b>pagekite.py</b> as a command-line utility, it will
    load its configuration from a file in your home directory.  The file is
    named <tt>.pagekite.rc</tt> on Unix systems (including Mac OS X), or
    <tt>pagekite.cfg</tt> on Windows.

    If you are using <b>pagekite.py</b> as a system-daemon which starts up
    when your computer boots, it is generally configured to load settings
    from <tt>/etc/pagekite.d/*.rc</tt> (in lexicographical order).

    In both cases, the configuration files contain one or more of the same
    options as are used on the command line, with the difference that at most
    one option may be present on each line, and the parser is more tolerant of
    white-space.  The leading '--' may also be omitted for readability and
    blank lines and lines beginning with '#' are treated as comments.

    <b>NOTE:</b> When using <b>-o</b>, <b>--optfile</b> or <b>--optdir</b> on the command line,
    it is advisable to use <b>--clean</b> to suppress the default configuration.
""")
MAN_SECURITY = ("""\
    Please keep in mind, that whenever exposing a server to the public
    Internet, it is important to think about security. Hacked webservers are
    frequently abused as part of virus, spam or phishing campaigns and in
    some cases security breaches can compromise the entire operating system.

    Some advice:<pre>
       * Switch PageKite off when not using it.
       * Use the built-in access controls and SSL encryption.
       * Leave the firewall enabled unless you have good reason not to.
       * Make sure you use good passwords everywhere.
       * Static content is very hard to hack!
       * Always, always make frequent backups of any important work.</pre>

    Note that as of version 0.5, <b>pagekite.py</b> includes a very basic
    request firewall, which attempts to prevent access to phpMyAdmin and
    other sensitive systems.  If it gets in your way, the <b>+insecure</b>
    flag or <b>--insecure</b> option can be used to turn it off.

    For more, please visit: <https://pagekite.net/support/security/>
""")
MAN_TUNNEL_AUTH = ("""\
    When running <b>pagekite.py</b> as a front-end relay, you can enable
    dynamic authentication of incoming tunnel requests in two ways.

    One uses a DNS-based protocol for delegating authentication to a remote
    server. The nice thing about this, is relays can be deployed without
    any direct access to your user account databases - in particular, a
    zero-knowlege challenge/response protocol is used which means the relay
    never sees the shared secret used to authenticate the kite.

    The second method delegates authentication to an external app; this
    external app can be written in any language you like, as long as it
    implements the following command-line arguments:
    <pre>
      --capabilities     Print a list of capabilities to STDOUT and exit
      --server           Run as a "server", reading queries on STDIN and
                         sending one-line replies to STDOUT.
      --auth <domain>    Return JSON formatted auth and quota details
      --zk-auth <query>  Implement the DNS-based zero-knowlege protocol
    </pre>
    The recognized capabilities are SERVER, ZK-AUTH and AUTH. One of AUTH
    or ZK-AUTH is required.

    The JSON `--auth` responses should be dictionaries which have at least
    one element, `secret` or `error`. The secret is the shared secret to
    be used to authenticate the tunnel. The dictionary may also contain
    advisory quota values (`quota_kb`, `quota_days` and `quota_conns`), and
    IP rate limiting parameters (`ips_per_sec-ips` and `ips_per_sec-secs`).

    The source distribution of <b>pagekite.py</b> includes a script named
    `demo_auth_app.py` which implements this protocol.
""")
MAN_LICENSE = ("""\
    Copyright 2010-2017, the Beanstalks Project ehf. and Bjarni R. Einarsson.

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
""")
MAN_BUGS = ("""\
    Using <b>pagekite.py</b> as a front-end relay with the native Python SSL
    module may result in poor performance.  Please use the pyOpenSSL wrappers
    instead.
""")
MAN_SEE_ALSO = ("""\
    lapcat(1), <http://pagekite.org/>, <https://pagekite.net/>
""")
MAN_CREDITS = ("""\
    <pre>- Bjarni R. Einarsson <http://bre.klaki.net/>
    - The Beanstalks Project ehf. <https://pagekite.net/company/>
    - The Rannis Technology Development Fund <http://www.rannis.is/>
    - Joar Wandborg <http://wandborg.se/></pre>
    - Luc-Pierre Terral
""")

MANUAL_TOC = (
  ('SH', 'Name', MAN_NAME),
  ('SH', 'Synopsis', MAN_SYNOPSIS),
  ('SH', 'Description', MAN_DESCRIPTION),
  ('SH', 'Basic usage', MAN_EXAMPLES),
  ('SH', 'Services and kites', MAN_KITES),
  ('SH', 'Kite configuration', MAN_KITE_EXAMPLES),
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
  ('SH', 'Security', MAN_SECURITY),
  ('SH', 'Tunnel Request Authentication', MAN_TUNNEL_AUTH),
  ('SH', 'Bugs', MAN_BUGS),
  ('SH', 'See Also', MAN_SEE_ALSO),
  ('SH', 'Credits', MAN_CREDITS),
  ('SH', 'Copyright and license', MAN_LICENSE),
)

HELP_SHELL = ("""\
    Press ENTER to fly your kites, CTRL+C to quit or give some arguments to
    accomplish a more specific task.
""")
HELP_KITES = ("""\
""")
HELP_TOC = (
  ('about',    'About PageKite',                        MAN_DESCRIPTION),
  ('basics',   'Basic usage examples',                  MAN_EXAMPLES),
  ('kites',    'Services and kites',                    MAN_KITES),
  ('config',   'Adding, disabling or removing kites',   MAN_KITE_EXAMPLES),
  ('flags',    'Service flags',              '\n'.join([MAN_FLAGS,
                                                        MAN_FLAGS_COMMON,
                                                        MAN_FLAGS_HTTP,
                                                        MAN_FLAGS_BUILTIN])),
  ('files',    'Where are the config files?',           MAN_CONFIG_FILES),
  ('security', 'A few words about security.',           MAN_SECURITY),
  ('credits',  'License and credits',        '\n'.join([MAN_LICENSE,
                                                        'CREDITS:',
                                                        MAN_CREDITS])),
  ('manual', 'The complete manual.  See also: http://pagekite.net/man/', None)
)


def HELP(args):
  name = title = text = ''
  if args:
    what = args[0].strip().lower()
    for name, title, text in HELP_TOC:
      if name == what:
        break
  if name == 'manual':
    text = DOC()
  elif not text:
    text = ''.join([
      'Type `help TOPIC` to to read about one of these topics:\n\n',
      ''.join(['  %-10.10s %s\n' % (n, t) for (n, t, x) in HELP_TOC]),
      '\n',
      HELP_SHELL
    ])
  return unindent(clean_text(text))


def clean_text(text):
  return re.sub('</?(tt|i)>', '`',
                re.sub('</?(a|b|pre)>', '', text.replace(' __', '   ')))

def unindent(text):
  return re.sub('(?m)^    ', '', text)


def MINIDOC():
  return ("""\
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
  for h, section, text in MANUAL_TOC:
    doc += '%s\n\n%s\n' % (h == 'SH' and section.upper() or '  '+section,
                           clean_text(text))
  return doc


def MAN(pname=None):
  lastchange = float(os.environ.get('SOURCE_DATE_EPOCH',
                                    os.path.getmtime(sys.argv[0])))
  man = ("""\
.\\" This man page is autogenerated from the pagekite.py built-in manual.
.TH PAGEKITE "1" "%s" "https://pagekite.net/" "Awesome Commands"
.nh
.ad l
""") % ts_to_iso(lastchange).split('T')[0]
  for h, section, text in MANUAL_TOC:
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
                   .replace('<tt>', '\\fI').replace('</tt>', '\\fR')
                   .replace('\\fR\\fR\n', '\\fR'))
  if pname:
    man = man.replace('pagekite.py', pname)
  return man


def MARKDOWN(pname=None):
  mkd = ''
  for h, section, text in MANUAL_TOC:
     if h == 'SH':
       h = '##'
     else:
       h = '###'
     mkd += ('%s %s %s\n%s\n\n'
            ) % (h, section, h,
                 re.sub('(</[aib]>|`)</b>', '\\1',
                  re.sub(' +<br />([A-Z0-9])', '</b>  \n     \\1',
                   re.sub('\n        ', '\n     ',
                    re.sub('\n    ', '\n', '\n'+text.strip()))
                     .replace(' __', ' <br />')
                     .replace('\n--', '\n   * <b>--')
                     .replace('\n+', '\n   * <b>+')
                     .replace('<a>', '`').replace('</a>', '`')
                     .replace('<tt>', '`').replace('</tt>', '`'))))
  if pname:
    mkd = mkd.replace('pagekite.py', pname)
  return mkd


if __name__ == '__main__':
  import sys
  if '--nopy' in sys.argv:
    pname = 'pagekite'
  else:
    pname = None

  if '--man' in sys.argv:
    print MAN(pname)
  elif '--markdown' in sys.argv:
    print MARKDOWN(pname)
  elif '--minidoc' in sys.argv:
    print MINIDOC()
  else:
    print DOC()
