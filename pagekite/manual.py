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
from common import *

MAN_SYNOPSIS = ("""\
""")
MAN_EXAMPLES = ("""\
    Basic usage, gives http://localhost:80/ a public name:
    $ pagekite.py NAME.pagekite.me

    To expose specific folders, files or use alternate local ports:
    $ pagekite.py +indexes /a/path/ NAME.pagekite.me   # built-in HTTPD
    $ pagekite.py *.html            NAME.pagekite.me   # built-in HTTPD
    $ pagekite.py 3000              NAME.pagekite.me   # http://localhost:3000/

    To expose multiple local servers (SSH and HTTP):
    $ pagekite.py ssh://NAME.pagekite.me AND 3000 http://NAME.pagekite.me
""")
MANUAL = (
  ('NAME', 'pagekite - Make localhost servers publicly visible.'),
  ('SYNOPSIS',    """\
"""),
  ('DESCRIPTION', """\
"""),
  ('EXAMPLES', MAN_EXAMPLES),
  ('FLAGS', """\
"""),
  ('COMMON OPTIONS', """\
"""),
  ('BACK-END OPTIONS', """\
"""),
  ('FRONT-END OPTIONS', """\
"""),
  ('SEE ALSO', """\
"""),
  ('AUTHOR', 'Bjarni Runar Einarsson <http://bre.klaki.net/>'),
  ('COPYRIGHT AND LICENSE', LICENSE),
)
MINIDOC = ("""\
>>> Welcome to pagekite.py v%s!

%s
    To sign up with PageKite.net or get advanced instructions:
    $ pagekite.py --signup
    $ pagekite.py --help

    If you request a kite which does not exist in your configuration file,
    the program will offer to help you sign up with http://pagekite.net/ and
    create it. Pick a name, any name!""") % (APPVER, MAN_EXAMPLES)
DOC = ("""\
pagekite.py is Copyright 2010-2012, the Beanstalks Project ehf.
     v%s                               https://pagekite.net/

This the reference implementation of the PageKite tunneling protocol,
both the front- and back-end. This following protocols are supported:

  HTTP   - HTTP 1.1 only, requires a valid HTTP Host: header
  HTTPS  - Recent versions of TLS only, requires the SNI extension.

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
 --optdir=X     -O X    Read settings from *.rc in directory X.
 --savefile=X   -S X    Saved settings will be written to file X.
 --save                 Save this configuration to the savefile.
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
 --ports=A,B,C  -p A,B  Listen on ports A, B, C, ... use numbers, or the
                        string '%s' for arbitrary HTTP CONNECT ports.
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

 --local=ports          Configure for local serving only (no remote front-end)
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
 --new          -N      Don't attempt to connect to any kites' old front-ends.
 --noprobes             Reject all probes for back-end liveness.
 --fingerpath=P         Path recipe for the httpfinger back-end proxy.
 --proxy=T:S:P          Connect using a chain of proxies (requires socks.py)
 --socksify=S:P         Connect via SOCKS server S, port P (requires socks.py)
 --torify=S:P           Same as socksify, but more paranoid.
 --watch=N              Display proxied data (higher N = more verbosity)

 --list                 List all configured kites
 --add                  Add (or enable) the following kites, save config.
 --remove               Remove the following kites, save config.
 --disable              Disable the following kites, save config.
 --only                 Disable all but the following kites, save config.


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

    The options --list, --add, --disable and --remove can be combined with
    shortcuts to manipulate the kites in you configuration file.

Shortcut examples:

"""+MAN_EXAMPLES) % (APPVER, VIRTUAL_PN)


if __name__ == '__main__':
  print DOC
