## pagekite.py ##

This is the Python implementation of the *pageKite* remote web front-end
protocol.  It implements a tunneled reverse proxy, allowing you to run
an HTTP or HTTPS server on a machine without direct connectivity to the
Internet.

Try ./pagekite.py --help for instructions (or read the source).

Front-end service is available at <http://pagekite.net/>, or you can run
your own.  For a more general discussion of what *pageKite* is and how it
works, check out <http://pagekite.net/docs/>.


<a                                                              name=toc></a>
### 1. Table of contents ###

   1.  [Table of contents                               ](#toc)
   2.  [Requirements                                    ](#req)
   3.  [Running the back-end, using the service         ](#bes)
   4.  [Running the back-end, using a custom front-end  ](#bec)
   5.  [Running your own front-end                      ](#fe)
   6.  [The HTTP console                                ](#stp)
   7.  [Coexisting front-ends and other HTTP servers    ](#co)
   8.  [Configuring DNS                                 ](#dns)
   9.  [Connecting over Socks or Tor                    ](#tor)
   10. [Time/IP-based raw ports (SSH-after-HTTP)        ](#ipr)
   11. [Unix/Linux systems integration                  ](#unx)
   12. [Saving your configuration                       ](#cfg)
   13. [A word about security and logs                  ](#sec)
   14. [Limitations and caveats                         ](#lim)
   15. [Credits and licence                             ](#lic)


<a                                                              name=req></a>
### 2. Requirements ###

Pagekite.py requires Python 2.x, version 2.2 or later.

Pagekite.py does not at the moment include a useful web server, so in
order to do anything interesting with it, you you will need an HTTP
and/or HTTPS server as well. Which web-server you prefer is up to you
and depends on your goals, but any server should work.

If you need to use Socks or Tor to connect to the Internet, you will also
need a copy of SocksiPy: <http://code.google.com/p/socksipy-branch/>.

You can download pagekite.py from <http://pagekite.net/downloads/>.

[ [up](#toc) ]


<a                                                              name=bes></a>
### 3. Running the back-end, using the service ###

The most common use of pagekite.py, is to make a web server visible to
the outside world.  Assuming you are using the pageKite.net service and
your web server runs on port 80, a command like this should get you up
and running:

    backend$ pagekite.py \
      --defaults \
      --backend=http:YOURNAME:localhost:80:SECRET

Replace YOURNAME with your *pageKite* domain name (for example
*something.pagekite.me*) and SECRET with the shared secret displayed on
your account page.

You can add multiple backend specifications, one for each name and protocol
you wish to expose.  Here is an example running two websites, one of which
is available using three protocols: HTTP, HTTPS and WebSocket.

    backend$ pagekite.py \
      --defaults \
      --backend=http:YOURNAME:localhost:80:SECRET \
      --backend=https:YOURNAME:localhost:443:SECRET \
      --backend=websocket:YOURNAME:localhost:8080:SECRET \
      --backend=http:OTHERNAME:localhost:8080:SECRET

Alternately, if you want to run different HTTP back-ends on different ports
for the same domain name, you can include port numbers in your backend specs:

    backend$ pagekite.py \
      --defaults \
      --backend=http/80:YOURNAME:localhost:80:SECRET \
      --backend=http/8080:YOURNAME:localhost:8080:SECRET

Note that this really only works for HTTP.  Also, which ports are actually
available depends on the front-end, and the protocol must still be one
supported by *pageKite* (HTTP, HTTPS or WebSocket).

[ [up](#toc) ]


<a                                                              name=bec></a>
### 4. Running the back-end, using a custom front-end ###

If you prefer to run your own front-ends, you will need to follow the
instructions in this section on your back-ends, and the instructions in
the next section on your front-end.

When running your own front-end, you need to tell pagekite.py where it
is, using the --frontend argument:

    backend$ pagekite.py \
      --frontend=HOST:PORT \
      --backend=http:YOURNAME:localhost:80:YOURSECRET

Replace HOST with the DNS name or IP address of your front-end, and PORT
with one of the ports it listens for connections on.

[ [up](#toc) ]


<a                                                               name=fe></a>
### 5. Running your own front-end ###

To configure pagekite.py as a front-end server, you will need to have a
server with a publicly visible IP address, and you will need to configure
DNS correctly, [as discussed below](#dns).

Assuming you are not already running a web server on that machine, the
optimal configuration is to run pagekite.py so it listens on a few ports
(80 and 443 at least), like so:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --ports=80,443 --protos=http,https,websocket \
      --domain=http,https:YOURNAME:YOURSECRET

In this case, YOURNAME must be a DNS name which points to the IP of the
front-end server (either an A or CNAME record), and YOURSECRET is a
shared secret of your choosing - it has to match on the back-end, or the
connection will be rejected.

Perceptive readers will have noticed a few problems with this though.
One, is that you are running pagekite.py as root, which is generally
frowned upon by those concerned with security.  Another, is you have only
enabled a single back-end, which is a bit limited.

The second problem is easily addressed, as the --domain parameter will
accept wild-cards, and of course you can have as many --domain parameters
as you like. So something like this might make sense:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --ports=80,443,8080 --protos=http,https,websocket \
      --domain=http,https,websocket:*.YOURDOMAIN.COM:YOURSECRET \
      --domain=http,https,websocket:*.YOUROTHERDOMAIN.NET:YOUROTHERSECRET

Unfortunately, root permissions are required in order to bind ports 80
and 443, but it is possible to instruct pagekite.py to drop all privileges
as soon as possible, like so:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --runas=nobody:nogroup \
      --ports=80,443,8080 --protos=http,https,websocket \
      --domain=http,https,websocket:YOURNAME:YOURSECRET

This assumes the *nobody* user and *nogroup* group exist on your system.
Replace with other values as necessary.  See the section on [Unix/Linux
systems integration](#unx) for more useful flags for running a production
pagekite.py.

[ [up](#toc) ]


<a                                                              name=stp></a>
### 6. The HTTP console ###

Scanning the log output from pagekite.py is not exactly a user-friendly
experience.  A nicer way to see what the program is up to, is to enable
the HTTP console, using the --httpd=HOST:PORT argument.

This will make pagekite.py run a web server of it's own on the named
address and port (we recommend 127.0.0.1:2223), which you can visit with
any web browser to see which tunnels are active, browse and filter the logs
and other nice things like that. If you want to expose a back-end's console
to the wider Internet, that is possible too (just add a --backend line for
it), but in that case it is probably a good idea to use --httppass to set
a password.

An example:

    backend$ pagekite.py \
      --defaults \
      --httpd=127.0.0.1:2223 \
      --httppass=YOURPASSWORD \
      --backend=http:CONSOLENAME:localhost:2223:SECRET \
      --backend=http:YOURNAME:localhost:80:SECRET

This should make the console visible both on http://localhost:2223/ and
http://CONSOLENAME/.  When it prompts for a username and password, type in
whatever username you like, and the password given on the command-line.


#### Enabling SSL on the HTTP console ####

If you have the Python OpenSSL module installed, you can increase the
security of your HTTP console even further by creating a self-signed
SSL certificate and enabling it using the --pemfile option:

    backend$ pagekite.py \
      --defaults \
      --httpd=127.0.0.1:2223 \
      --httppass=YOURPASSWORD \
      --pemfile=cert.pem \
      ...

To generate a self-signed certificate:

    openssl req -new -x509 \
      -keyout cert.pem -out cert.pem \
      -days 365 -nodes

Note that your browser will complain when you first visit the console
and you will have to add a security exception in order to access the page.

[ [up](#toc) ]


<a                                                               name=co></a>
### 7. Coexisting front-ends and other HTTP servers ###

What to do if you already have a web server running on the machine you want
to use as a *pageKite* front-end?  Generally only one process can run on a
given IP:PORT pair, which is why this poses a problem.

The simplest solution, is to get another IP address for the machine, and
use one for pagekite.py, and the other for your web-server. In that case
you would add the --host=IP argument to your pagekite.py configuration.

If, however, you have to share a single IP, things get slightly more
complicated. Either the web-server will have to forward connections to
pagekite.py, or the other way around.

#### pagekite.py on port 80 (recommended) ####

As of pagekite.py 0.3.6, it is possible for front-ends to have direct local
back-ends, so just letting pagekite.py have port 80 (and 443) is the simplest
way to get the two to coexist:

   1. Move your old web-server to another port (such as 8080)
   2. Configure pagekite.py [as a front-end](#fe) on port 80
   3. Add --backend specifications for your old web-server.

For example:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --runas=nobody:nogroup \
      --ports=80,443 --protos=http,https,websocket \
      --domain=http,https,websocket:YOURNAME:YOURSECRET \
      --backend=http,websocket:OLDNAME:localhost:8080: \
      --backend=https:OLDNAME:localhost:8443: 

Note that no password is required for configuring local back-ends.


#### Another HTTP server on port 80 ####

The other option, assuming your web-server supports proxying, is to configure
it to proxy requests for your *pageKite* domains to pagekite.py, and run
pagekite.py on an alternate port.  How this is done depends on your HTTP
server software, but Apache and lighttpd at least are both capable of
forwarding requests to alternate ports.

This is likely to work in many cases for standard HTTP traffic, but very
unlikely to work for HTTPS.

**Warning:** If you have more than one domain behind *pageKite*, it is
of critical importance that the HTTP server *not* re-use the same proxy
connection for multiple requests.  For performance and compatibility
reasons, pagekite.py does not currently continue parsing the HTTP/1.1
request stream once it has chosen a back-end: it blindly forwards packets
back and forth. This means that if the web server proxy code sends a request
for *a.foo.com* first, and then requests *b.foo.com* over the same
connection, the second request will be routed to the wrong back-end.

Unfortunately, this means putting pagekite.py behind a high-performance
load-balancer may cause unpredictable (and quite undesirable) results:
Varnish at least is known to cause problems in this configuration.

Please send reports of success (or failure) configuring pagekite.py behind
another HTTP server, proxy or load-balancer to our Google Group:
<http://groups.google.com/group/pagekite-discuss>.

[ [up](#toc) ]


<a                                                              name=dns></a>
### 8. Configuring DNS ###

In order for your *pageKite* websites to be visible to the wider Internet,
you will have to make sure DNS records for them are properly configured.

If you are using the service, this is handled automatically by the
pageKite.net dynamic DNS service, but if you are running your own front-end,
then you may need to take some additional steps.


#### Static DNS configuration ####

Generally if you have a single fixed front-end, you can simply use a static
DNS entry, either an A record or a CNAME, linking your site's domain name
to the IP address of **the machine running the front-end**.

So, if the front-end's name is *foo.com* with the IP address *1.2.3.4*, and
your website is *blah.foo.com*, then you would need to configure the DNS
record for *blah.foo.com* as a CNAME to *foo.com* or an A record to *1.2.3.4*.

This is the same kind of configuration as if your front-end were a normal
web host.

Alternately, it might be useful to set up a wildcard DNS record for the
domain *foo.com*, directing all unspecified names to your front-end. That,
combined with the wildcard --domain argument described [above](#fe), will
give you the flexibility to trivially create as many *pageKite* websites
as you like, just by changing arguments to the [back-end](#bec).


#### Dynamic DNS configuration ####

This all gets a bit more complicated if you are running multiple front-ends,
and letting the back-end choose between them based on ping times (this is
the --default behavior does when using the *pageKite* service).

First of all, the back-end will need a way to receive the list of available
front-ends. Secondly, the back-end will need to be able to dynamically update
the DNS records for the sites it is connecting.

The list of front-ends should be provided to pagekite.py as a DNS name
with multiple A records.  As an example, the default for the *pageKite*
service, is the name **frontends.b5p.us**:

    $ host frontends.b5p.us
    frontends.b5p.us has address 69.164.211.158
    frontends.b5p.us has address 93.95.226.149
    frontends.b5p.us has address 178.79.140.143
    ...

When started up with a --frontends argument (note the trailing s),
pagekite.py will measure the distance of each of these IP addresses and
pick the one closest. (It will also perform DNS lookups on its own name
and connect to any old back-ends as well, to guarantee reachability while
the old DNS records expire.)

Pagekite.py has built-in support for most of the common dynamic DNS
providers, which can be accessed via. the --dyndns flag.  Assuming you were
using dyndns.org, running the back-end like this might work in that case:

    backend$ pagekite.py \
      --frontends=1:YOUR.FRONTENDS.COM:443 \
      --dyndns=USER:PASS@dyndns.org \
      --backend=http:YOURNAME.dyndns.org:localhost:80:YOURSECRET

**Note:** the dynamic DNS support for third parties (non-*pageKite*) is
currently not very well tested - if it does not work for you, please
[get in touch](http://pagekite.net/support/) and let us know.

[ [up](#toc) ]


<a                                                              name=tor></a>
### 9. Connecting over Socks or Tor ###

If you want to run pagekite.py from behind a restrictive firewall which
does not even allow outgoing connections, you might be able to work around
the problem by using a Socks proxy.

Alternately, if you are concerned about anonymity and want to hide your
IP even from the person running the front-end, you might want to connect
using the [Tor](https://www.torproject.org/) network.

For these situations, you can use the --torify or --socksify arguments,
like so:

    backend$ pagekite.py \
      --defaults \
      --socksify=SOCKSHOST:PORT \
      --backend=http:YOURNAME:localhost:80:YOURSECRET

In the case of Tor, replace --socksify with --torify and (probably) 
connect to localhost, on port 9050.

With --torify, some behavior is modified slightly in order to avoid leaking
information about which domains you are hosting through DNS side channels.

**Note:** This requires SocksiPy: <http://code.google.com/p/socksipy-branch/>

[ [up](#toc) ]


<a                                                              name=ipr></a>
### 10. Time/IP-based raw ports (SSH-after-HTTP) ###

Pagekite.py version 0.3.7 adds the "raw" protocol, which allows you to bind
a back-end to a raw port.  This may be useful for all sorts of things,
but was primarily designed as a "good enough" hack for tunneling SSH
connections.

As the pagekite.py front-end, and all the ports it listens on, are assumed to
be shared by multiple back-ends, raw ports do not work like normal ports:
they become temporarily available depending on which non-raw back-end the
client last connected to.

So assuming the host *some.pagekite.me* registers both HTTP and RAW/22
back-ends, it should be possible to connect via. SSH to *some.pagekite.me* -
but **only** if you visit *http://some.pagekite.me/* first.  The pagekite.py
back-end command for this use-case would look like this:

    backend$ pagekite.py \
      --defaults \
      --backend=raw/22:YOURNAME:localhost:22:SECRET \
      --backend=http:YOURNAME:localhost:80:SECRET

Note that doing things the other way around (SSH first, HTTP second) will
generally **not** work. Also note that which ports are actually available
depends on the configuration of the front-end.

WARNING: If the client IP address is shared or you are simply accessing many
different resources behind the same pagekite.py front-end, results may be
unpredictable - raw ports are *only* available for the domain most recently
visited by your IP.

Within the context of SSH, this implies a few guidelines:

   1. The directive "CheckHostIP no" should be added to your .ssh/config file
      for the hosts behind *pageKite*.
   2. Password-based auth should be avoided, as you may end up connecting
      to *the wrong site* now and then ("PasswordAuthentication no").
   3. If ssh complains about a man-in-the-middle attack: DO NOT CONTINUE!
   4. Make sure your user accounts have strong enough passwords for your
      host to withstand incoming SSH brute force attacks!

Note that this is all a bit of a hack: a more reliable way to tunnel SSH
would be to use the ProxyCommand directive and embed SSH in an SSL tunnel
(see ssh_config(5)).

For tunneling other things over raw ports, generally you will want to be
sure there is some sort of handshake built into the protocol, so it will not
go undetected when pagekite.py guesses wrong and routes the connection to
the wrong back-end.  If that kind of routing mistake sounds scary to you, 
then you probably do not want to use raw ports at all...


[ [up](#toc) ]


<a                                                              name=unx></a>
### 11. Unix/Linux systems integration ###

When deploying pagekite.py as a system component on Unix, there are quite
a few specialized arguments which can come in handy.

In addtion to --runas and --host (discussed above), pagekite.py understands
these: --pidfile, --logfile and --daemonize, each of which does more or
less what you would expect.  A special case worth noting is
--logfile=syslog, which instead of writing to a file, logs to the system
log service.

Putting these all together, a real production invocation of pagekite.py at
the front-end might look something like this:

    frontend$ sudo pagekite.py \
      --runas=nobody:nogroup \
      --pidfile=/var/run/pagekite.pid \
      --logfile=syslog \
      --daemonize \
      --isfrontend \
      --host=1.2.3.4 \
      --ports=80,443 \
      --protos=http,https,websocket \
      --domain=http,https,websocket:*.YOURDOMAIN.COM:YOURSECRET \
      --domain=http,https,websocket:*.YOUROTHERDOMAIN.NET:YOUROTHERSECRET

That is quite a lot of arguments!  So please read on, and learn how to
generate a configuration file...

[ [up](#toc) ]


<a                                                              name=cfg></a>
### 12. Saving your configuration ###
 
Once you have everything up and running properly, you may find it more
convenient to save the settings to a configuration file.  Pagekite.py can
generate the configuration file for you: just add --settings to **the very
end** of the command line and save the output to a file. On Linux or OS X,
that might look something like this:

    $ pagekite.py \
      --defaults \
      --backend=http:YOURNAME:localhost:80:SECRET \
      --settings \
    | tee ~/.pagekite.rc

The default configuration file on Linux and Mac OS X is ~/.pagekite.rc, on
Windows it is usually either C:\\Users\\USERNAME\\pagekite.cfg or
C:\\Documents and Settings\\USERNAME\\pagekite.cfg.

If you save your settings to this location, they will be loaded by default
whenever you run pagekite.py - which may not always be what you want if you
are experimenting. To *skip* the configuration file, you can use the 
--clean argument, and to load an alternate configuration, you can use 
--optfile. Combining both, you might end up with something like this:

    $ pagekite.py --clean --optfile=/etc/pagekite.cfg

The --optfile option can be used within configuration files as well, if
you want to "include" a one configuration into another for some reason.

[ [up](#toc) ]


<a                                                              name=sec></a>
### 13. A word about security and logs ###

When exposing services to the wider Internet, as pagekite.py is designed to
do, it is always important to keep some basic security principles in mind.

Pagekite.py itself should be quite secure - it never invokes any external
processes and the only modifications it makes to the file-system are the
log-files it writes.

The main security concern is your HTTP server, which you are exposing to
the wider Internet. Covering general web server security is out of scope for
this brief manual, but there is one important difference between running a
web server on a public host and running one through *pageKite*:

Just like most other reverse proxies, *pageKite* will make your logs "look
funny" and may break certain forms of naive access control.  This is because
from the point of view of your web server, all connections that travel over
*pageKite* will appear to originate from **localhost**, with the IP address
127.0.0.1. **This will break any access controls based on IP addresses.**

For logging purposes, the HTTP and WebSocket protocols, the "standard"
X-Forwarded-For header is added to initial requests (if HTTP 1.1 persistent
connections are used, subsequent requests may be lacking the header), in all
cases pagekite.py will report the actual remote IP in its own log.

[ [up](#toc) ]


<a                                                              name=lim></a>
### 14. Limitations and caveats ###

There are certain limitations to what can be accomplished using Pagekite, due
to the nature of the underlying protocls. Here is a brief discussion of the
most important ones.


#### HTTPS routing and Windows XP ###

Windows XP (and older) ships with an implementation of the HTTPS (TLS)
protocol which does not support the SNI extension.  As a result, pagekite.py
can not reliably detect which back-end should serve an incoming request.

Pagekite attempts to work around this by tracking which IP addresses have
recently visited which domains (using the HTTP or other unencrypted 
protocols), and *guessing* that the unidentifiable HTTPS connection was
destined for the same site.

This means the common pattern of a clear-text HTTP website "upgrading" to
HTTPS on certain pages is likely to work even for older browsers. But it is
*not* guaranteed.

A more reliable work-around is to upgrade your Windows XP browser to a recent
version of Chrome, which includes proper SNI support.


#### Raw ports ###

Raw ports are unreliable, as discussed in [the raw port section](#ipr).


[ [up](#toc) ]


<a                                                              name=lic></a>
### 15. Credits and licence ###

Pagekite.py is (C) Copyright 2010, Bjarni Rúnar Einarsson and The
Beanstalks Project ehf.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

[ [up](#toc) ]
