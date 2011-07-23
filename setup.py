#!/usr/bin/python
from distutils.core import setup
from pagekite import APPVER

setup(
    name="pagekite",
    version=APPVER,
    license="AGPLv3+",
    author="Bjarni R. Einarsson",
    author_email="bre@pagekite.net",
    url="http://pagekite.org/",
    description="""PageKite makes localhost servers visible to the world.""",
    long_description="""\
PageKite is a system for running publicly visible servers (generally web-
servers) on machines without a direct connection to the Internet, such as
mobile devices or computers behind restrictive firewalls. PageKite works
around NAT, firewalls and IP-address limitations by using a combination of 
tunnels and reverse proxies.

Natively supported protocols: HTTP, HTTPS
Partially supported protocols: IRC, Finger

Any other TCP-based service, including SSH and VNC, may be exposed as well
as well to clients supporting HTTP Proxies.
""",
   packages=['pagekite'],
)
