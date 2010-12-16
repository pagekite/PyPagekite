## pagekite.py ##

This is the Python implementation of the pageKite remote web front-end
protocol.  It implements a tunneled reverse proxy, allowing you to run
an HTTP or HTTPS server on a machine without direct connectivity to the
Internet.

Try ./pagekite.py --help for instructions (or read the source).

Front-end service is available at <http://pagekite.net/>, or you can run
your own.


<a                                                              name=toc></a>
### 1. Table of contents ###

   1. [Table of contents                               ](#toc)
   2. [Requirements                                    ](#req)
   3. [Running the back-end, using the service         ](#bes)
   4. [Running the back-end, using a custom front-end  ](#bec)
   5. [Running your own front-end                      ](#fe)
   6. [Coexisting front-ends and other HTTP servers    ](#co)
   7. [Configuring DNS                                 ](#dns)
   8. [Saving your configuration                       ](#cfg)
   9. [Credits and licence                             ](#lic)


<a                                                              name=req></a>
### 2. Requirements ###

Pagekite.py requires Python 2.2 or later.

Pagekite.py does not at the moment include a useful web server, so in
order to do anything interesting with it, you you will need an HTTP
and/or HTTPS server as well. Which web-server you prefer is up to you
and depends on your goals, but any server should work.

If you need to use Socks or Tor to connect to the Internet, you will also
need a copy of SocksiPy: <http://code.google.com/p/socksipy-branch/>.

You can download pagekite.py from <http://pagekite.net/downloads/>.


<a                                                              name=bes></a>
### 3. Running the back-end, using the service ###

The most common use of Pagekite.py, is to make a web server visible to
the outside world.  Assuming you are using the PageKite.net service and
your web server runs on port 80, a command like this should get you up
and running:

    pagekite.py --defaults \
      --backend=http:YOURNAME:localhost:80:SECRET

Replace YOURNAME with your Pagekite domain name (for example
*something.pagekite.me*) and SECRET with the shared secret displayed on
your account page.

You can add multiple backend specifications, one for each name and protocol
you wish to expose.  Here is an example running two websites, one of which
is available both as HTTP and HTTPS:

    pagekite.py --defaults \
      --backend=http:YOURNAME:localhost:80:SECRET \
      --backend=https:YOURNAME:localhost:443:SECRET \
      --backend=http:OTHERNAME:localhost:8080:SECRET


<a                                                              name=bec></a>
### 4. Running the back-end, using a custom front-end ###

If you prefer to run your own front-ends, you will need to follow the
instructions in this section on your back-ends, and the instructions in
the next section on your front-end.

When running your own front-end, you need to tell pagekite.py where it
is, using the --frontend argument:

    pagekite.py --defaults \
      --frontend=HOST:PORT \
      --backend=http:YOURNAME:localhost:80:YOURSECRET

Replace HOST with the DNS name or IP address of your front-end, and PORT
with one of the ports it listens for connections on.


<a                                                               name=fe></a>
### 5. Running your own front-end ###

To configure pagekite.py as a front-end server, you will need to have a
server with a publicly visible IP address.  Assuming you are not already
running a web server on that machine, the optimal configuration is to
run pagekite.py so it listens on both ports 80 and 443, like so:

    sudo pagekite.py --isfrontend \
      --ports=80,443 --protos=http,https \
      --domain=http,https:YOURNAME:YOURSECRET

In this case, YOURNAME must be a DNS name which points to the IP of the
front-end server (either an A or CNAME record), and YOURSECRET is a
shared secret of your choosing - it has to match on the back-end, or the
connection will be rejected.

Perceptive readers will have noticed a few problems with this though.
One, is that you are running Pagekite.py as root, which is generally
frowned upon by those concerned with security.  Another, is you've only
enabled a single back-end, which is a bit limited.

The second problem is easily addressed, as the --domain parameter will
accept wild-cards, and of course you can have as many --domain parameters
as you like. So something like this might make sense:

    sudo pagekite.py --isfrontend \
      --ports=80,443 --protos=http,https \
      --domain=http,https:*.YOURDOMAIN.COM:YOURSECRET \
      --domain=http,https:*.YOUROTHERDOMAIN.NET:YOUROTHERSECRET

Unfortunately, root permissions are required in order to bind ports 80
and 443, but it is possible to instruct pagekite.py to drop all privileges
as soon as possible, like so:

    sudo pagekite.py --isfrontend \
      --runas=nobody:nogroup \
      --ports=80,443 --protos=http,https \
      --domain=http,https:YOURNAME:YOURSECRET

This assumes the *nobody* user and *nogroup* group exist on your system.
Replace with other values as necessary.  Other useful flags for proper
system integration are --pidfile, --logfile and --daemonize, each of which
does more or less what you would expect, although --logfile=syslog is
special - instead of logging to a file, it logs to the system log service.

Putting it all together, a real production invocation of pagekite.py at
the front-end might look something like this:

    sudo pagekite.py \
      --runas=nobody:nogroup \
      --pidfile=/var/run/pagekite.pid \
      --logfile=syslog \
      --daemonize \
      --isfrontend \
      --ports=80,443 \
      --protos=http,https \
      --domain=http,https:*.YOURDOMAIN.COM:YOURSECRET \
      --domain=http,https:*.YOUROTHERDOMAIN.NET:YOUROTHERSECRET

That's quite a lot of arguments, so at this point you might want to skip 
to the end of this manual and learn how to generate a configuration
file...


<a                                                               name=co></a>
### 6. Coexisting front-ends and other HTTP servers ###

(to be written)


<a                                                              name=dns></a>
### 7. Configuring DNS ###

(to be written)


<a                                                              name=cfg></a>
### 8. Saving your configuration ###
 
Once you have everything up and running properly, you may find it more
convenient to save the settings to a configuration file.  Pagekite.py can
generate the configuration file for you: just add --settings to **the very
end** of the command line and save the output to a file. On Linux or OS X,
that might look something like this:

    pagekite.py --defaults \
      --backend=http:YOURNAME:localhost:80:SECRET \
      --settings \
    | tee ~/.pagekite.rc

The default configuration file on Linux and Mac OS X is ~/.pagekite.rc, on
Windows it is C:\\Users and Settings\\USERNAME\\pagekite.cfg.

If you save your settings to this location, they will be loaded by default
whenever you run pagekite.py - which may not always be what you want if you
are experimenting. To *skip* the configuration file, you can use the 
--clean argument, and to load an alternate configuration, you can use 
--optfile. Combining both, you might end up with something like this:

    pagekite.py --clean --optfile=/etc/pagekite.cfg

The --optfile option can be used within configuration files as well, if
you want to "include" a one configuration into another for some reason.


<a                                                              name=lic></a>
### 9. Credits and licence ###

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

