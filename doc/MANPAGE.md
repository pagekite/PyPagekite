## Name ##

pagekite - Make localhost servers publicly visible

## Synopsis ##

<b>pagekite</b> [`--options`] [`service`] `kite-name` [`+flags`]

## Description ##

PageKite is a system for exposing `localhost` servers to the
public Internet.  It is most commonly used to make local web servers or
SSH servers publicly visible, although almost any TCP-based protocol can
work if the client knows how to use an HTTP proxy.

PageKite uses a combination of tunnels and reverse proxies to compensate
for the fact that `localhost` usually does not have a public IP
address and is often subject to adverse network conditions, including
aggressive firewalls and multiple layers of NAT.

This program implements both ends of the tunnel: the local "back-end"
and the remote "front-end" reverse-proxy relay.  For convenience,
<b>pagekite</b> also includes a basic HTTP server for quickly exposing
files and directories to the World Wide Web for casual sharing and
collaboration.

## Basic usage ##

<pre>Basic usage, gives `http://localhost:80/` a public name:
$ pagekite NAME.pagekite.me

To expose specific folders, files or use alternate local ports:
$ pagekite /a/path/ NAME.pagekite.me +indexes  # built-in HTTPD
$ pagekite *.html   NAME.pagekite.me           # built-in HTTPD
$ pagekite 3000     NAME.pagekite.me           # HTTPD on 3000

To expose multiple local servers (SSH and HTTP):
$ pagekite ssh://NAME.pagekite.me AND 3000 NAME.pagekite.me</pre>

## Services and kites ##

The most comman usage of <b>pagekite</b> is as a back-end, where it
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

## Kite configuration ##

The options <b>--list</b>, <b>--add</b>, <b>--disable</b> and <b>--remove</b> can be used to
manipulate the kites and service definitions in your configuration file,
if you prefer not to edit it by hand.  Examples:

<pre>Adding new kites
$ pagekite --add /a/path/ NAME.pagekite.me +indexes
$ pagekite --add 80 OTHER-NAME.pagekite.me

To display the current configuration
$ pagekite --list

Disable or delete kites (--add re-enables)
$ pagekite --disable OTHER-NAME.pagekite.me
$ pagekite --remove NAME.pagekite.me</pre>

## Flags ##

Flags are used to tune the behavior of a particular kite, for example
by enabling access controls or specific features of the built-in HTTP
server.

### Common flags ###

   * <b>+ip</b>/`1.2.3.4`  
     Enable connections only from this IP address.
   * <b>+ip</b>/`1.2.3`  
     Enable connections only from this /24 netblock.

### HTTP protocol flags ###

   * <b>+password</b>/`name`=`pass`
     Require a username and password (HTTP Basic Authentication)

   * <b>+rewritehost</b>  
     Rewrite the incoming Host: header.
   * <b>+rewritehost</b>=`N`  
     Replace Host: header value with N.
   * <b>+rawheaders</b>  
     Do not rewrite (or add) any HTTP headers at all.
   * <b>+proxyproto</b>  
     Use HAProxy's PROXY Protocol (v1) to relay IPs etc.
   * <b>+insecure</b>  
     Allow access to phpMyAdmin, /admin, etc. (per kite).

### Built-in HTTPD flags ###

   * <b>+indexes</b>  
     Enable directory indexes.
   * <b>+indexes</b>=`all`  
     Enable directory indexes including hidden (dot-) files.
   * <b>+hide</b>  
     Obfuscate URLs of shared files.
   * <b>+uploads</b>  
     Accept file uploads.
   * <b>+uploads</b>=`RE`  
     Accept uploads to paths matching regexp RE.
   * <b>+ul_filenames</b>=`P`  
     Upload naming policy. P = overwrite, keep or rename

   * <b>+cgi</b>=`list`
     A list of extensions, for which files should be treated as
     CGI scripts (example: `+cgi=cgi,pl,sh`).

   * <b>+photobackup</b>=`password`
     Enable built-in PhotoBackup server with the given password.
     See https://photobackup.github.io/ for details.

## Options ##

The full power of <b>pagekite</b> lies in the numerous options which
can be specified on the command line or in a configuration file (see below).

Note that many options, especially the service and domain definitions,
are additive and if given multiple options the program will attempt to
obey them all.  Options are processed in order and if they are not
additive then the last option will override all preceding ones.

Although <b>pagekite</b> accepts a great many options, most of the
time the program defaults will Just Work.

### Common options ###

   * <b>--clean</b>  
     Skip loading the default configuration file.
   * <b>--signup</b>  
     Interactively sign up for pagekite.net service.
   * <b>--defaults</b>  
     Set defaults for use with pagekite.net service.
   * <b>--whitelabel=D</b>  
     Set defaults for pagekite.net white-labels.
   * <b>--whitelabels=D</b>  
     Set defaults for pagekite.net white-labels (with TLS).
   * <b>--nocrashreport</b>  
     Don't send anonymous crash reports to pagekite.net.

### Back-end options ###

   * <b>--shell</b>  
     Run PageKite in an interactive shell.
   * <b>--nullui</b>  
     Silent UI for scripting. Assumes Yes on all questions.

   * <b>--list</b>  
     List all configured kites.
   * <b>--add</b>  
     Add (or enable) the following kites, save config.
   * <b>--remove</b>  
     Remove the following kites, save config.
   * <b>--disable</b>  
     Disable the following kites, save config.
   * <b>--only</b>  
     Disable all but the following kites, save config.

   * <b>--insecure</b>  
     Allow access to phpMyAdmin, /admin, etc. (global).

   * <b>--local</b>=`ports`  
     Configure for local serving only (no remote front-end).
   * <b>--watch</b>=`N`  
     Display proxied data (higher N = more verbosity).

   * <b>--noproxy</b>  
     Ignore system (or config file) proxy settings.

   * <b>--proxy</b>=`type`:`server`:`port`, <b>--socksify</b>=`server`:`port`, <b>--torify</b>=`server`:`port` <br />
     Connect to the front-ends using SSL, an HTTP proxy, a SOCKS proxy,
     or the Tor anonymity network.  The type can be any of 'ssl', 'http'
     or 'socks5'.  The server name can either be a plain hostname,
     user@hostname or user:password@hostname.  For SSL connections the
     user part may be a path to a client cert PEM file.  If multiple
     proxies are defined, they will be chained one after another.

   * <b>--service_on</b>=`proto`:`kitename`:`host`:`port`:`secret` <br />
     Explicit configuration for a service kite.  Generally kites are
     created on the command-line using the service short-hand
     described above, but this syntax is used in the config file.
     The kitename `unknown`, if allowed by the front-end, represents
     a backend of last resort for requests with no other match.

   * <b>--authdomain</b>=`DNS-suffix`, <b>--authdomain</b>=`/path/to/app`, <b>--authdomain</b>=`kite-domain`:`DNS-suffix`, <b>--authdomain</b>=`kite-domain`:`/path/to/app` <br />
     Use `DNS-suffix` for remote DNS-based authentication of
     incoming tunnel requests, or invoke an external application
     for this purpose.  If no <i>kite-domain</i> is given, use
     this as the default authentication method.  See the section
     below on tunnel authentication for further details.  In order
     for the app path to be recognized as such, it must contain at
     least one / character.

   * <b>--auththreads</b>=`N` <br />
     Start N threads to process auth requests. Default is 1.

   * <b>--authfail_closed</b> <br />
     If authentication fails, reject tunnel requests. The default is
     to fail open and allow tunnels if the auth checks are broken.


   * <b>--service_off</b>=`proto`:`kitename`:`host`:`port`:`secret` <br />
     Same as --service_on, except disabled by default.

   * <b>--service_cfg</b>=`...`, <b>--webpath</b>=`...` <br />
     These options are used in the configuration file to store service
     and flag settings (see above). These are both likely to change in
     the near future, so please just pretend you didn't notice them.

   * <b>--frontend</b>=`host`:`port` <br />
     Connect to the named front-end server. If this option is repeated,
     multiple connections will be made.

   * <b>--frontends</b>=`num`:`dns-name`:`port` <br />
     Choose `num` front-ends from the A records of a DNS domain
     name, using the given port number. Default behavior is to probe
     all addresses and use the fastest one.

   * <b>--frontends</b>=`num`:`@/path/to/file`:`port` <br />
     Same as above, except the IP address list will be loaded from
     a file (and reloaded periodically), instead of using DNS.

   * <b>--nofrontend</b>=`ip`:`port` <br />
     Never connect to the named front-end server. This can be used to
     exclude some front-ends from auto-configuration.

   * <b>--fe_certname</b>=`domain` <br />
     Connect using SSL, accepting valid certs for this domain. If
     this option is repeated, any of the named certificates will be
     accepted, but the first will be preferred.

   * <b>--fe_nocertcheck</b> <br />
     Connect using SSL/TLS, but do not verify the remote certificate.
     This is largely insecure but still thwarts passive attacks and
     prevents routers and firewalls from corrupting the PageKite tunnel.

   * <b>--ca_certs</b>=`/path/to/file` <br />
     Path to your trusted root SSL certificates file.

   * <b>--dyndns</b>=`X` <br />
     Register changes with DynDNS provider X.  X can either be simply
     the name of one of the 'built-in' providers, or a URL format
     string for ad-hoc updating.

   * <b>--keepalive</b>=`N` <br />
     Force traffic over idle tunnels every N seconds, to cope with
     firewalls that kill idle TCP connections. Backend only: if set
     to "auto" (the default), the interval will be adjusted
     automatically in response to disconnects.

   * <b>--all</b>  
     Terminate early if any tunnels fail to register.
   * <b>--new</b>  
     Don't attempt to connect to any kites' old front-ends.
   * <b>--noprobes</b>  
     Reject all probes for service state.

### Front-end options ###

   * <b>--isfrontend</b>  
     Enable front-end operation.

   * <b>--domain</b>=`proto,proto2,pN`:`domain`:`secret` <br />
     Accept tunneling requests for the named protocols and specified
     domain, using the given secret.  A * may be used as a wildcard
     for subdomains or protocols. This is for static configurations,
     for dynamic access controls use the `--authdomain` mechanism.
     The domain `unknown`, if configured, represents a backend of
     last resort for incoming requests with no other match.

   * <b>--authdomain</b>=`DNS-suffix`, <b>--authdomain</b>=`/path/to/app`, <b>--authdomain</b>=`kite-domain`:`DNS-suffix`, <b>--authdomain</b>=`kite-domain`:`/path/to/app` <br />
     Use `DNS-suffix` for remote DNS-based authentication of
     incoming tunnel requests, or invoke an external application
     for this purpose.  If no <i>kite-domain</i> is given, use
     this as the default authentication method.  See the section
     below on tunnel authentication for further details.  In order
     for the app path to be recognized as such, it must contain at
     least one / character.

   * <b>--auththreads</b>=`N` <br />
     Start N threads to process auth requests. Default is 1.

   * <b>--authfail_closed</b> <br />
     If authentication fails, reject tunnel requests. The default is
     to fail open and allow tunnels if the auth checks are broken.

   * <b>--motd</b>=`/path/to/motd` <br />
     Send the contents of this file to new back-ends as a
     "message of the day".

   * <b>--host</b>=`hostname`  
     Listen on the given hostname only.
   * <b>--ports</b>=`list`  
     Listen on a comma-separated list of ports.
   * <b>--portalias</b>=`A:B`  
     Report port A as port B to backends (because firewalls).
   * <b>--protos</b>=`list`  
     Accept the listed protocols for tunneling.

   * <b>--rawports</b>=`list` <br />
     Listen for raw connections these ports. The string '%s'
     allows arbitrary ports in HTTP CONNECT.

   * <b>--overload</b>=`baseline`, <b>--overload_cpu</b>=`fraction, 0-1`, <b>--overload_mem</b>=`fraction, 0-1` <br />
     Enable "overload" calculations, which cause the front-end to
     recommend back-ends go elsewhere if possible, once connection
     counts go above a certain number. The baseline is the initial
     overload level, but it will be adjusted dynamically based on
     load average (CPU use) and memory usage. This will really only
     work well on Linux and if PageKite is the only thing happening
     on the machine. Setting both fractions to 0 disables dynamic
     scaling.

   * <b>--overload_file</b>=`/path/to/baseline/file` <br />
     Path to a file, the contents of which overrides all overload
     calculations. This can be used to manage load calculations
     using an external process (or by hand, e.g. to prepare for
     maintenance). Note that <i>overload</i> must specify a non-zero
     baseline, otherwise this setting is ignored.

   * <b>--ratelimit_ips</b>=`IPs/seconds`, <b>--ratelimit_ips</b>=`kitename`:`IPs/seconds` <br />
     Limit how many different clients (IPs) can request data from
     a tunnel within a given window of time, e.g. 5/3600. This is
     useful as either a crude form of DDoS mitigation, or as a
     mechanism to make public kite services unusable for phishing.
     Note that limits are enforced per-tunnel (not per kite), and
     tunnels serving multiple kites will use the settings of the
     strictest kite. Limits apply to subdomains as well. A single
     IP may be counted more than once if request headers (such as
     User-Agent) differ.

   * <b>--accept_acl_file</b>=`/path/to/file` <br />
     Consult an external access control file before accepting an
     incoming connection. Quick'n'dirty for mitigating abuse. The
     format is one rule per line: `rule policy comment` where a
     rule is an IP or regexp and policy is 'allow' or 'deny'.

   * <b>--client_acl</b>=`policy`:`regexp`, <b>--tunnel_acl</b>=`policy`:`regexp` <br />
     Add a client connection or tunnel access control rule.
     Policies should be 'allow' or 'deny', the regular expression
     should be written to match IPv4 or IPv6 addresses.  If defined,
     access rules are checkd in order and if none matches, incoming
     connections will be rejected.

   * <b>--tls_default</b>=`name` <br />
     Default name to use for SSL, if SNI (Server Name Indication)
     is missing from incoming HTTPS connections.

   * <b>--tls_endpoint</b>=`name`:`/path/to/file` <br />
     Terminate SSL/TLS for a name using key/cert from a file.

   * <b>--dns_hints</b>=`domain`,`domain`,... <br />
     Advertise DNS information for listed domains in the fast ping
     response, to help upagekite connectors discover relays.

### System options ###

   * <b>--optfile</b>=`/path/to/file` <br />
     Read settings from file X. Default is `~/.pagekite.rc`.

   * <b>--optdir</b>=`/path/to/directory` <br />
     Read settings from `/path/to/directory/*.rc`, in
     lexicographical order.

   * <b>--savefile</b>=`/path/to/file` <br />
     Saved settings will be written to this file.

   * <b>--save</b>  
     Save the current configuration to the savefile.

   * <b>--settings</b> <br />
     Dump the current settings to STDOUT, formatted as a configuration
     file would be.

   * <b>--nopyopenssl</b>  
     Avoid use of the pyOpenSSL library (not in config file)
   * <b>--nossl</b>  
     Avoid use SSL entirely (not allowed in config file)

   * <b>--nozchunks</b>  
     Disable zlib tunnel compression.
   * <b>--sslzlib</b>  
     Enable zlib compression in OpenSSL.
   * <b>--buffers</b>=`N`  
     Buffer at most N kB of data before blocking.
   * <b>--logfile</b>=`F`  
     Log to file F, `stdio` means standard output.
   * <b>--daemonize</b>  
     Run as a daemon.
   * <b>--runas</b>=`U`:`G`  
     Set UID:GID after opening our listening sockets.
   * <b>--pidfile</b>=`P`  
     Write PID to the named file.
   * <b>--errorurl</b>=`U`  
     URL to redirect to when back-ends are not found.
   * <b>--errorurl</b>=`D:U`  
     Custom error URL for domain D.

   * <b>--selfsign</b> <br />
     Configure the built-in HTTP daemon for HTTPS, first generating a
     new self-signed certificate using <b>openssl</b> if necessary.

   * <b>--httpd</b>=`X`:`P`, <b>--httppass</b>=`X`, <b>--pemfile</b>=`X` <br />
     Configure the built-in HTTP daemon.  These options are likely to
     change in the near future, please pretend you didn't see them.

## Configuration files ##

If you are using <b>pagekite</b> as a command-line utility, it will
load its configuration from a file in your home directory.  The file is
named `.pagekite.rc` on Unix systems (including Mac OS X), or
`pagekite.cfg` on Windows.

If you are using <b>pagekite</b> as a system-daemon which starts up
when your computer boots, it is generally configured to load settings
from `/etc/pagekite.d/*.rc` (in lexicographical order).

In both cases, the configuration files contain one or more of the same
options as are used on the command line, with the difference that at most
one option may be present on each line, and the parser is more tolerant of
white-space.  The leading '--' may also be omitted for readability and
blank lines and lines beginning with '#' are treated as comments.

<b>NOTE:</b> When using <b>-o</b>, <b>--optfile</b> or <b>--optdir</b> on the command line,
it is advisable to use <b>--clean</b> to suppress the default configuration.

## Security ##

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

Note that as of version 0.5, <b>pagekite</b> includes a very basic
request firewall, which attempts to prevent access to phpMyAdmin and
other sensitive systems.  If it gets in your way, the <b>+insecure</b>
flag or <b>--insecure</b> option can be used to turn it off.

For more, please visit: <https://pagekite.net/support/security/>

## Tunnel Request Authentication ##

When running <b>pagekite</b> as a front-end relay, you can enable
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

The source distribution of <b>pagekite</b> includes a script named
`demo_auth_app.py` which implements this protocol.

## Bugs ##

Using <b>pagekite</b> as a front-end relay with the native Python SSL
module may result in poor performance.  Please use the pyOpenSSL wrappers
instead.

## See Also ##

lapcat(1), <http://pagekite.org/>, <https://pagekite.net/>

## Credits ##

<pre>- Bjarni R. Einarsson <http://bre.klaki.net/>
- The Beanstalks Project ehf. <https://pagekite.net/company/>
- The Rannis Technology Development Fund <http://www.rannis.is/>
- Joar Wandborg <http://wandborg.se/>
- Luc-Pierre Terral</pre>

## Copyright and license ##

Copyright 2010-2020, the Beanstalks Project ehf. and Bjarni R. Einarsson.

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


