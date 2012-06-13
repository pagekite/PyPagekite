# pagekite.py #

PageKite implements a tunneled reverse proxy which makes it easy to make a
service (such as an HTTP or HTTPS server) on localhost visible to the wider
Internet.  It also supports other protocols (including SSH), by behaving
as a specialized HTTP proxy.

Try `./pagekite.py --help` for instructions (or read the source).

Managed front-end relay service is available at <https://pagekite.net/>, or
you can run your own using pagekite.py.


<a                                                              name=toc></a>
## 0. Table of contents ##

   1. [The basics                                          ](#basics)
      1.  [Requirements                                    ](#req)
      2.  [Getting started                                 ](#qs)
      3.  [Configuring from the command line               ](#cli)
      4.  [Terminology, how PageKite works                 ](#how)

   2. [Advanced usage                                      ](#advanced)
      1.  [Running the back-end, using pagekite.net        ](#bes)
      2.  [Running the back-end, using a custom front-end  ](#bec)
      3.  [Running your own front-end relay                ](#fe)
      4.  [The built-in HTTP server                        ](#stp)
      5.  [Coexisting front-ends and other HTTP servers    ](#co)
      6.  [Configuring DNS                                 ](#dns)
      7.  [Connecting over Socks or Tor                    ](#tor)
      8.  [Raw backends (HTTP CONNECT)                     ](#ipr)
      9.  [SSL/TLS back-ends, endpoints and SNI            ](#tls)
      10. [Unix/Linux systems integration                  ](#unx)
      11. [Saving your configuration                       ](#cfg)
      12. [A word about security and logs                  ](#sec)

   3. [Limitations, caveats and known bugs                 ](#lim)

   4. [Credits and licence                                 ](#lic)


<a                                                           name=basics></a>
## 1. The basics ##

<a                                                              name=req></a>
### 1.1. Requirements ###

`Pagekite.py` requires Python 2.x, version 2.2 or later.

`Pagekite.py` includes a basic web server for serving static content, but is
more commonly used to expose other HTTP servers running on localhost (such
as Apache or a Django development server) to the wider Internet.

In order for pagekite.py to terminate SSL connections or encrypt the built
in HTTPserver, you will need openssl and either python 2.6+ or the pyOpenSSL
module. These are not required if you just want to route HTTPS requests.

You can download pagekite.py from <http://pagekite.net/downloads/>.

**Note:** pagekite.py uses a customized version of SocksiPy (named
SocksipyChain) to handle SSL compatibility and connecting over Tor or
other proxy servers.  If you are downloading the "all-in-one" .py file
from <http://pagekite.net/downloads/>, this library is included and built
in. However, you are working with the source code, you will need to
download SocksipyChain.  For further details, please see
<https://pagekite.net/wiki/Floss/PySocksipyChain/>.

[ [up](#toc) ]


<a                                                              name=qs></a>
### 1.2. Getting started ###

The quickest way to get started with pagekite.py, is to download a
prebuilt package (combined .py file, .deb or .rpm) from
<http://pagekite.net/downloads/>.

Next, interactively sign up for service with <http://pagekite.net>:

    pagekite.py --signup

This will ask you for your e-mail address, ask you to choose your initial
kite name (*SOMETHING.pagekite.me*), and then make whatever server you
have running on <http://localhost:80/> visible to the outside world as
<http://SOMETHING.pagekite.me/>.

Here are a few useful examples:

    # Expose a local HTTP server, but password protect it.
    pagekite.py 80 http://FOO.pagekite.me/ +password/guest=foo

    # Expose a directory to the web, enabling indexes.
    pagekite.py /var/www http://FOO.pagekite.me:8080/ +indexes

    # Expose an SSH server to the world.
    pagekite.py localhost:22 ssh://FOO.pagekite.me/

The above examples could all be combined into a single command, and the
configuration saved as your default, like so:

    pagekite.py --add \
      80 http://FOO.pagekite.me +password/guest=foo AND \
      /var/www http://BAR.pagekite.me:8080/ +indexes AND \
      localhost:22 ssh://FOO.pagekite.me

After running that (admittedly longish) command, you can simply type
`pagekite.py` at any time to make all three services visible to the
Internet. If you have configured multiple services, but only want to
expose one of them, you can use the following short-hand:

    pagekite.py FOO.pagekite.me

Please consult the pagekite.net quick-start and wiki for more examples:

   * <https://pagekite.net/support/quickstart/>
   * <https://pagekite.net/wiki/>

**Note:** If using the .deb or .rpm packages, the command is simply
`pagekite`, not pagekite.py.

[ [up](#toc) ]


<a                                                              name=cli></a>
### 1.3. Configuring from the command line ###

PageKite knows how to both read and write its own configuration file, which
is usually named `.pagekite.rc` on Linux and the Mac, or `pagekite.cfg` on
Windows.

It is possible to add and remove service definitions from the configuration
file, by using commands like the following:

    # Add a service
    pagekite.py --add 8000 django-FOO.pagekite.me

    # Temporarily disable it
    pagekite.py --disable django-FOO.pagekite.me

    # List all configured services
    pagekite.py --list

    # Permanently remove one
    pagekite.py --remove django-FOO.pagekite.me

You can also use `--add` to update the configuration of a particular service,
for example to add a `+indexes` flag or access controls.

[ [up](#toc) ]


<a                                                              name=how></a>
### 1.4. Terminology, how PageKite works ###

PageKite works more or less like this:

   1. Your **services**, typically one or more HTTP servers, run on localhost.

   2. You run pagekite.py as a **back-end connector**, on the same machine.

   3. Another instance of pagekite.py runs as a **front-end relay** on a
      machine with a public IP address, in "the cloud".

   4. The **back-end** pagekite.py connects to the **front-end**, and
      creates a tunnel for the configured **services**.

   5. Clients, typically web browsers, connect to the **front-end** and
      request **service**.  The **front-end** relays the request over the
      appropriate tunnel, where the **back-end** forwards it to the actual
      server.  Responses travel back the same way.

In practice, the back-end is often configured to use multiple front-ends, and
will choose between them based on network latency or other factors.  In those
cases it will also update dynamic DNS servers to direct your services' DNS
names to the IP address of the front-end server.

If the connection to the front-end is lost, the back-end will attempt to
re-establish a connection, either with the same server or another one.


#### Terminology ####

The following terms are use throughout the rest of this document:

   * A **service** is a local server, for example a website or SSH server.

   * A **front-end** is an instance of pagekite.py which is configured to act
     as a public, client-facing visible relay server.

   * A **back-end** is an instance of pagekite.py which is configured to
     establish and maintain the tunnels and DNS records required to make a local
     **service** visible to the wider Internet.  The **back-end** must be able
     to make direct connections to local servers.

   * A **service** which is exposed to the wider Internet using PageKite is
     sometimes called **a kite**.

To avoid confusion, we prefer not to use the terms "client" and "server" to
describe the different roles of pagekite.py.

[ [up](#toc) ]


<a                                                           name=basics></a>
## 2. Advanced usage ##

In this chapter, the more esoteric features of PageKite will be explored.
Note that many of these topics are only relevant to people who are running
their own PageKite front-end relay servers.

In all examples below, the long-form `--argument=foo` syntax is used, for
precision and for compatibility with the PageKite configuration file.

Note that in release 0.4.7, the `--backend` argument was renamed to
`--service_on`.  This document uses the new name, although the old one is
still recognized by the program and will be for the forseeable future.


<a                                                              name=bes></a>
### 2.1. Running the back-end, using pagekite.net ###

The most common use of pagekite.py, is to make a web server visible to
the outside world.  Assuming you are using the pagekite.net service and
your web server runs on port 80, a command like this should get you up
and running:

    backend$ pagekite.py \
      --defaults \
      --service_on=http:YOURNAME:localhost:80:SECRET

Replace YOURNAME with your PageKite domain name (for example
*something.pagekite.me*) and SECRET with the shared secret displayed on
your account page.

You can add multiple backend specifications, one for each name and protocol
you wish to expose.  Here is an example running two websites, one of which
is available using three protocols: HTTP, HTTPS and WebSocket.

    backend$ pagekite.py \
      --defaults \
      --service_on=http:YOURNAME:localhost:80:SECRET \
      --service_on=https:YOURNAME:localhost:443:SECRET \
      --service_on=http:OTHERNAME:localhost:8080:SECRET

Alternately, if you want to run different HTTP back-ends on different ports
for the same domain name, you can include port numbers in your backend specs:

    backend$ pagekite.py \
      --defaults \
      --service_on=http/80:YOURNAME:localhost:80:SECRET \
      --service_on=http/8080:YOURNAME:localhost:8080:SECRET

Note that this really only works for HTTP.  Also, which ports are actually
available depends on the front-end, and the protocol must still be one
supported by PageKite (HTTP, HTTPS or WebSocket).

[ [up](#toc) ]


<a                                                              name=bec></a>
### 2.2. Running the back-end, using a custom front-end ###

If you prefer to run your own front-ends, you will need to follow the
instructions in this section on your back-ends, and the instructions in
the next section on your front-end.

When running your own front-end, you need to tell pagekite.py where it
is, using the `--frontend` argument:

    backend$ pagekite.py \
      --frontend=HOST:PORT \
      --service_on=http:YOURNAME:localhost:80:YOURSECRET

Replace HOST with the DNS name or IP address of your front-end, and PORT
with one of the ports it listens for connections on.  If your front-end
supports TLS-encrypted tunnels, add the --fe_certname=HOST argument as well.

[ [up](#toc) ]


<a                                                               name=fe></a>
### 2.3. Running your own front-end relay ###

To configure pagekite.py as a front-end relay, you will need to have a
host with a publicly visible IP address, and you will need to configure
DNS correctly, [as discussed below](#dns).

Assuming you are not already running a web server on that machine, the
optimal configuration is to run pagekite.py so it listens on a few ports
(80 and 443 at least), like so:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --ports=80,443 --protos=http,https \
      --domain=http,https:YOURNAME:YOURSECRET

In this case, YOURNAME must be a DNS name which points to the IP of the
front-end relay (either an A or CNAME record), and YOURSECRET is a
shared secret of your choosing - it has to match on the back-end, or the
connection will be rejected.

Perceptive readers will have noticed a few problems with this though.
One, is that you are running pagekite.py as root, which is generally
frowned upon by those concerned with security.  Another, is you have only
enabled a single back-end, which is a bit limited.

The second problem is easily addressed, as the `--domain` parameter will
accept wild-cards, and of course you can have as many `--domain` parameters
as you like. So something like this might make sense:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --ports=80,443,8080 --protos=http,https \
      --domain=http,https:*.YOURDOMAIN.COM:YOURSECRET \
      --domain=http,https:*.YOUROTHERDOMAIN.NET:YOUROTHERSECRET

Unfortunately, root permissions are required in order to bind ports 80
and 443, but it is possible to instruct pagekite.py to drop all privileges
as soon as possible, like so:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --runas=nobody:nogroup \
      --ports=80,443,8080 --protos=http,https \
      --domain=http,https:YOURNAME:YOURSECRET

This assumes the *nobody* user and *nogroup* group exist on your system.
Replace with other values as necessary.  See the section on [Unix/Linux
systems integration](#unx) for more useful flags for running a production
pagekite.py.

[ [up](#toc) ]


<a                                                              name=stp></a>
### 2.4. The built-in HTTP server ###

*FIXME: Write this.*

#### Enabling SSL in the built-in HTTP server ####

If you have the OpenSSL (pyOpenSSL or python 2.6+), you can increase the
security of your HTTP console even further by creating a self-signed
SSL certificate and enabling it using the `--pemfile` option:

    backend$ pagekite.py \
      --defaults \
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
### 2.5. Coexisting front-ends and other HTTP servers ###

What to do if you already have a web server running on the machine you want
to use as a PageKite front-end?  Generally only one process can run on a
given IP:PORT pair, which is why this poses a problem.

The simplest solution, is to get another IP address for the machine, and
use one for pagekite.py, and the other for your web-server. In that case
you would add the `--host=IP` argument to your pagekite.py configuration.

If, however, you have to share a single IP, things get slightly more
complicated. Either the web-server will have to forward connections to
pagekite.py, or the other way around.

#### pagekite.py on port 80 (recommended) ####

As of pagekite.py 0.3.6, it is possible for front-ends to have direct local
back-ends, so just letting pagekite.py have port 80 (and 443) is the simplest
way to get the two to coexist:

   1. Move your old web-server to another port (such as 8080)
   2. Configure pagekite.py [as a front-end](#fe) on port 80
   3. Add `--backend` specifications for your old web-server.

As of 0.3.14, you can make pagekite.py use a local back-end as a catch-all
for any unrecongized domains, by using the special hostname "unknown" in
the `--backend` line (remember to specify a protocol).

For example:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --runas=nobody:nogroup \
      --ports=80,443 --protos=http,https \
      --domain=http,https:YOURNAME:YOURSECRET \
      --service_on=http:OLDNAME:localhost:8080: \
      --service_on=https:OLDNAME:localhost:8443: \
      --service_on=https:unknown:localhost:8090:

Note that no password is required for configuring local back-ends.


#### Another HTTP server on port 80 ####

The other option, assuming your web-server supports proxying, is to configure
it to proxy requests for your PageKite domains to pagekite.py, and run
pagekite.py on an alternate port.  How this is done depends on your HTTP
server software, but Apache and lighttpd at least are both capable of
forwarding requests to alternate ports.

This is likely to work in many cases for standard HTTP traffic, but very
unlikely to work for HTTPS.

**Warning:** If you have more than one domain behind PageKite, it is
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
### 2.6. Configuring DNS ###

In order for your PageKite websites to be visible to the wider Internet,
you will have to make sure DNS records for them are properly configured.

If you are using the pagekite.net service, this is handled automatically
by a dynamic DNS server, but if you are running your own front-end, then
you may need to take some additional steps.


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
combined with the wildcard `--domain` argument described [above](#fe), will
give you the flexibility to trivially create as many PageKite websites
as you like, just by changing arguments to the [back-end](#bec).


#### Dynamic DNS configuration ####

This all gets a bit more complicated if you are running multiple front-ends,
and letting the back-end choose between them based on ping times (this is
the `--default` behavior does when using the PageKite service).

First of all, the back-end will need a way to receive the list of available
front-ends. Secondly, the back-end will need to be able to dynamically update
the DNS records for the sites it is connecting.

The list of front-ends should be provided to pagekite.py as a DNS name
with multiple A records.  As an example, the default for the PageKite
service, is the name **frontends.b5p.us**:

    $ host frontends.b5p.us
    frontends.b5p.us has address 69.164.211.158
    frontends.b5p.us has address 93.95.226.149
    frontends.b5p.us has address 178.79.140.143
    ...

When started up with a `--frontends` argument (note the trailing s),
pagekite.py will measure the distance of each of these IP addresses and
pick the one closest. (It will also perform DNS lookups on its own name
and connect to any old back-ends as well, to guarantee reachability while
the old DNS records expire.)

Pagekite.py has built-in support for most of the common dynamic DNS
providers, which can be accessed via. the `--dyndns` flag.  Assuming you were
using `dyndns.org`, running the back-end like this might work in that case:

    backend$ pagekite.py \
      --frontends=1:YOUR.FRONTENDS.COM:443 \
      --dyndns=USER:PASS@dyndns.org \
      --service_on=http:YOURNAME.dyndns.org:localhost:80:YOURSECRET

Instead of dyndns.org above, pagekite.py also has built-in support for
no-ip.com and of course pagekite.net. Other providers can be used by
providing a full HTTP or HTTPS URL, with the following python formatting
tokens in the appropriate places:

    %(ip)s - will be replaced by your new front-end IP address
    %(domain)s - will be replaced by your domain name

This example argument manually implements no-ip.com support (split between
lines for readability):

    --dyndns='https://USER:PASS@dynupdate.no-ip.com/nic/update?
    hostname=%(domain)s&myip=%(ip)s'


[ [up](#toc) ]


<a                                                              name=tor></a>
### 2.7. Connecting over Socks or Tor ###

If you want to run pagekite.py from behind a restrictive firewall which
does not even allow outgoing connections, you might be able to work around
the problem by using a Socks proxy.

Alternately, if you are concerned about anonymity and want to hide your
IP even from the person running the front-end, you might want to connect
using the [Tor](https://www.torproject.org/) network.

For these situations, you can use the `--torify` or `--socksify` arguments,
like so:

    backend$ pagekite.py \
      --defaults \
      --socksify=SOCKSHOST:PORT \
      --service_on=http:YOURNAME:localhost:80:YOURSECRET

In the case of Tor, replace `--socksify` with `--torify` and (probably)
connect to localhost, on port 9050.

With `--torify`, some behavior is modified slightly in order to avoid leaking
information about which domains you are hosting through DNS side channels.

[ [up](#toc) ]


<a                                                              name=ipr></a>
### 2.8. Raw backends (HTTP CONNECT) ###

Pagekite.py version 0.3.7 added the "raw" protocol, which allows you to
bind a back-end to a raw port.  This may be useful for all sorts of things,
but was primarily designed as a "good enough" hack for tunneling SSH
connections.

As the pagekite.py front-end, and all the ports it listens on, are assumed
to be shared by multiple back-ends, raw ports do not work like normal ports,
they must be accessed using an HTTP Proxy CONNECT request.

To expose a raw service, use a command like so:

    backend$ pagekite.py \
      --defaults \
      --service_on=raw/22:YOURNAME:localhost:22:SECRET \
      ...

This means you can place more or less any server behind PageKite, as long as
the client can be configured to use an HTTP Proxy to connect: simply configure
the client to use the PageKite front-end (and a normal port, not a raw port)
as an HTTP Proxy.

As an example, the following lines in **.ssh/config** provide reliable direct
access to an SSH server exposed via. pagekite.py and the pagekite.net service:

    Host HOME.pagekite.me
    CheckHostIP no
    ProxyCommand /bin/nc -X connect -x HOME.pagekite.me:443 %h %p


**Note:** The old 'RAW-after-HTTP' method is deprecated and no longer
supported.  It has therefore been removed from this manual.


[ [up](#toc) ]


<a                                                              name=tls></a>
### 2.9. SSL/TLS back-ends, endpoints and SNI ###

Pagekite.py includes powerful support for name-based virtual hosting of
multiple encrypted (HTTPS) web-sites behind a single IP address, something
which until recently was practically largely impossible.

This is done based on the new TLS/SNI extension, along with some work-arounds
for older clients (see Limitations below).


#### Encrypted back-ends (end-to-end) ####

The most secure use of TLS involves encrypted back-ends, registered with a
`--service_on=https:NAME:...` argument.

These back-ends themselves take care of the encryption and decryption, so
all pagekite.py sees is an incomprehensible stream of binary - this is as
secure as it gets!

How to obtain certificates and configure your back-ends is outside the
scope of this document.


#### Encrypted tunnels ####

As of pagekite.py version 0.3.8, it is possible to connect to the front-end
using a TLS-encrypted tunnel.

This is much more secure and is highly recommended: not only does this
prevent people from sniffing the traffic between your web server and the
front-end, it also protects you against any man-in-the-middle attacks where
someone impersonates your front-end of choice.

This requires additional configuration both on the front-end and on the back.

On the front-end, you need to define a TLS endpoint (and certificate) for
the domain of the SSL certificate (it does not actually have to match the
domain name of the front-end, but the front- and back-ends have to agree
what the certificate name is).

    frontend$ sudo pagekite.py \
      ...
      --tls_endpoint=frontend.domain.com:/path/to/key-and-cert-chain.pem \
      ...

On the back-end, you need to tell pagekite.py which certificate to
accept, and possibly give it the path to [a list of certificate authority
certificates](http://curl.haxx.se/ca/cacert.pem) (the default works on Linux).

    backend$ pagekite.py \
      --frontend=frontend.domain.com:443 \
      --fe_certname=frontend.domain.com \
      --ca_certs=/path/to/ca-certificates.pem \
      ...


#### Creating your own key and certificate (for tunnels) ####

Note that if you are running your own front-end, you do not need to purchase
a commecial certificate for this to work - you can generate your own
self-signed certificate and use that on both ends (this will actually be
*more* secure than using a 3rd party certificate). To generate a certificate
and a key, run this:

    openssl req -new -x509 \
      -keyout site-key.pem -out site-cert.pem \
      -days 365 -nodes

OpenSSL will ask a few questions - you can answer them in any way you like,
it does not really matter.  For use on the server, the key and certificate
must be combined into a single file, like so:

    cat site-key.pem site-cert.pem > frontend.pem

This frontend.pem file you would then configure as a TLS endpoint on the
front-end, and a copy of site-cert.pem would be distributed to all the
back-ends and used with the `--ca_certs` parameter.


#### Encrypting unencrypted back-ends ####

If you want to enable encryption for back-ends which do not themselves
support HTTPS, you can use the `--tls_endpoint` flag to ask pagekite.py
itself to handle TLS for a given domain.

In this configuration, clients will communicate securely with the
pagekite.py front-end, which will in turn forward decrypted requests to its
backends, encrypting any replies as they are sent to the client.

As the tunnel between pagekite front- and back-ends itself is generally
encapsulated in a secure TLS connection, this provides almost the same level
of security as end-to-end encryption above, with the exception that the
pagekite.py front-end has access to unencrypted data. So back-ends have to
trust the person running their front-end!

Although not perfect, for those concerned with casual snooping on shared
public WiFi, school or corporate networks, this is a significant security
benefit.

The expected use-case for this feature, is to deploy a wild-card certificate
at the front-end, allowing multiple back-ends to encrypt their communication
without the administrative overhead of generating, distributing and
maintaining keys and certificates on every single one.  An example:

    frontend$ sudo pagekite.py \
      --isfrontend \
      --ports=80,443 --protos=http,https \
      --tls_endpoint=frontend.domain.com:/tunnel/key-and-cert-chain.pem \
      --tls_endpoint=*.domain.com:/path/to/key-and-cert-chain.pem \
      --domain=http:*.domain.com:SECRET

    backend$ sudo pagekite.py \
      --frontend=frontend.domain.com:443 \
      --fe_certname=frontend.domain.com \
      --service_on=http:foo.domain.com:localhost:80:SECRET

This would enable both https://foo.domain.com/ and http://foo.domain.com/,
without an explicit https back-end being defined or configured - but the
tunnel between the back- and front-ends will be encrypted using TLS and
the *frontend.domain.com* certificate.

**Note:** Currently SSL endpoints are only available at the front-end, but
will be available on the back-end as well in a future release.

**Note:** This requires either pyOpenSSL or python 2.6+ and openssl support
at the OS level.


#### Limitations ####

Windows XP (and older) ships with an implementation of the HTTPS (TLS)
protocol which does not support the SNI extension.  The same is true for
certain older browsers under Linux (such as lynx), Android 1.6, and
generally any old or poorly maintained HTTPS clients.

Without SNI, pagekite.py can not reliably detect which domain is being
requested.  In its absence, pagekite.py employs the following fall-back
strategies to facilitate access:

   1. Obey the TLS/SNI extension, if present.
   2. Check if any known back-end was recently visited by the client IP,
      if one is found, try to use that for the domain.
   3. Fall back to a default domain specified by the `--tls_default` flag.

This means the common pattern of a clear-text HTTP website "upgrading" to
HTTPS on certain pages is quite likely to work even for older browsers. But
it is *not* guaranteed if the guest IP address is shared by multiple users,
or if the browser is idle for too long (so the SSL connection times out and
the IP expires from the tracking map maintained by pagekite.py).

When the above measures all fail and the wrong domain is chosen for routing
the TLS request, browsers should detect a certificate mismatch and abort the
request. So although inconvenient and not very user-friendly, this failure
mode should not pose a significant security risk.

The best solution is of course to upgrade all browsers accessing your site to
a recent version of Chrome, which includes proper SNI support.

As this may not be realistic, it might be wise want to provide an unencrypted
(HTTP) version of your website for older clients, upgrading to HTTPS only when
it has been verified to work; this can be done by fetching a javascript
upgrade script from the HTTPS version of your site.

[ [up](#toc) ]


<a                                                              name=unx></a>
### 2.10. Unix/Linux systems integration ###

When deploying pagekite.py as a system component on Unix, there are quite
a few specialized arguments which can come in handy.

In addtion to `--runas` and `--host` (discussed above), pagekite.py
understands these: `--pidfile`, `--logfile` and `--daemonize`, each of
which does more or less what you would expect.  Special cases worth noting
are `--logfile=syslog`, which instead of writing to a file, logs to the system
log service and `--logfile=stdio` which logs to standard output.

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
      --protos=http,https \
      --domain=http,https:*.YOURDOMAIN.COM:YOURSECRET \
      --domain=http,https:*.YOUROTHERDOMAIN.NET:YOUROTHERSECRET

That is quite a lot of arguments!  So please read on, and learn how to
generate a configuration file...

[ [up](#toc) ]


<a                                                              name=cfg></a>
### 2.11. Saving your configuration ###

Once you have everything up and running properly, you may find it more
convenient to save the settings to a configuration file.  Pagekite.py can
generate the configuration file for you: just add `--settings` to **the very
end** of the command line and save the output to a file. On Linux or OS X,
that might look something like this:

    $ pagekite.py \
      --defaults \
      --service_on=http:YOURNAME:localhost:80:SECRET \
      --settings \
    | tee ~/.pagekite.rc

The default configuration file on Linux and Mac OS X is `~/.pagekite.rc`, on
Windows it is usually either `C:\\Users\\USERNAME\\pagekite.cfg` or
`C:\\Documents and Settings\\USERNAME\\pagekite.cfg`.

If you save your settings to this location, they will be loaded by default
whenever you run pagekite.py - which may not always be what you want if you
are experimenting. To *skip* the configuration file, you can use the
`--clean` argument, and to load an alternate configuration, you can use
`--optfile`. Combining both, you might end up with something like this:

    $ pagekite.py --clean --optfile=/etc/pagekite.cfg

The `--optfile` option can be used within configuration files as well, if
you want to "include" a one configuration into another for some reason.

[ [up](#toc) ]


<a                                                              name=sec></a>
### 2.12. A word about security and logs ###

When exposing services to the wider Internet, as pagekite.py is designed to
do, it is always important to keep some basic security principles in mind.

Pagekite.py itself should be quite secure - it never invokes any external
processes and the only modifications it makes to the file-system are the
log-files it writes.

The main security concern is your HTTP server, which you are exposing to
the wider Internet. Covering general web server security is out of scope for
this brief manual, but there is one important difference between running a
web server on a public host and running one through PageKite:

Just like most other reverse proxies, PageKite will make your logs "look
funny" and may break certain forms of naive access control.  This is because
from the point of view of your web server, all connections that travel over
PageKite will appear to originate from **localhost**, with the IP address
127.0.0.1. **This will break any access controls based on IP addresses.**

For logging purposes, the HTTP and WebSocket protocols, the "standard"
X-Forwarded-For header is added to initial requests (if HTTP 1.1 persistent
connections are used, subsequent requests may be lacking the header), in all
cases pagekite.py will report the actual remote IP in its own log.

[ [up](#toc) ]


<a                                                              name=lim></a>
## 3. Limitations, caveats and known bugs ##

There are certain limitations to what can be accomplished using Pagekite, due
to the nature of the underlying protocls. Here is a brief discussion of the
most important ones.


#### HTTPS routing and Windows XP ###

HTTPS support depends on recent additions to the TLS protocol, which are
unsupported by older browsers and operating systems - most importantly
including the still common Windows XP.

The mechanisms employed by pagekite.py to work around these problems are
discussed in [the TLS/SSL section](#tls).


#### Raw ports ###

Raw ports are unreliable for clients sharing IP addresses with others or
accessing multiple resources behind the same front-end at the same time.

See the discussed in [the raw port section](#ipr) for details and instructions
on how to reliably configure clients to use the HTTP CONNECT method to work
around this limitation.


[ [up](#toc) ]


<a                                                              name=lic></a>
## 4. Credits and licence ##

Please see individual files for details on their licensing; as a rule
Python source code falls under the same license as pagekite.py,
documentation (including this document) under the Creative Commons
Attribution-ShareAlike (CC-BY-SA) 3.0, and sample configuration files are
placed in the Public Domain.

If these licensing terms to not suit you for some reason, please contact
the authors as it may be possible to negotiate alternate terms.


#### This document ####

This document is (C) Copyright 2010-2012, Bjarni Rúnar Einarsson and The
Beanstalks Project ehf.

This work is licensed under the Creative Commons Attribution-ShareAlike
3.0 Unported License. To view a copy of this license, visit
<http://creativecommons.org/licenses/by-sa/3.0/> or send a letter to
Creative Commons, 171 Second Street, Suite 300, San Francisco,
California, 94105, USA.


#### pagekite.py ####

Pagekite.py is (C) Copyright 2010-2012, Bjarni Rúnar Einarsson and The
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
