#!/usr/bin/python
import time
from datetime import date
from setuptools import setup
from pagekite.common import APPVER
import os

try:
  # This borks sdist.
  os.remove('.SELF')
except:
  pass

setup(
    name="pagekite",
    version=APPVER.replace('github', 'dev%d' % (120*int(time.time()/120))),
    license="AGPLv3+",
    author="Bjarni R. Einarsson",
    author_email="bre@pagekite.net",
    url="http://pagekite.org/",
    description="""PageKite makes localhost servers visible to the world.""",
    long_description="""\
PageKite is a system for running publicly visible servers (generally
web servers) on machines without a direct connection to the Internet,
such as mobile devices or computers behind restrictive firewalls.
PageKite works around NAT, firewalls and IP-address limitations by
using a combination of  tunnels and reverse proxies.

Natively supported protocols: HTTP, HTTPS
Partially supported protocols: IRC, Finger

Any other TCP-based service, including SSH and VNC, may be exposed
as well to clients supporting HTTP Proxies.
""",
   packages=['pagekite', 'pagekite.ui', 'pagekite.proto'],
   scripts=['scripts/pagekite', 'scripts/lapcat'],
   install_requires=['SocksipyChain >= 2.0.9']
)
