#!/usr/bin/python2 -u

from __future__ import absolute_import

#
# This is a trivial demo auth server, which just approves any requests
# it sees, while printing debug information to STDERR.
#
# This code is in the public domain, feel free to adapt to your needs.
#
import getopt
import json
import os
import sys


# By default we advertise only the AUTH method; ZK-AUTH is not listed.
# Roughly 50% of the time we'll offer SERVER mode as well.
CAPABILITIES = (('SERVER ' if (os.getpid() % 2 == 0) else '')
                + 'AUTH')


def Auth(domain):
    # This method simply returns a dictionary of quota values, along with
    # the shared secret in the clear. Pagekite.py takes care of challenging
    # and authenticating the user.
    #
    # Note that the quota values are mostly advisory; it is assumed that
    # accounting happens elsewhere and Pagekite.py is mostly just relaying
    # values back to the user as information.
    #
    # Exception #1: a quota_kb value of zero means the user exists but no
    # longer has access to the service (ran out of quota). Negative or
    # missing quota_kb values mean "no bandwidth quota, just grant access."
    #
    # Exception #2: The IPs-per-second rate limits are enforced by
    # pagekite.py, using the semantics of the --ratelimit_ips option.
    #
    # Valid rejection reasons that will be understood by the connector
    # include: "unauthorized", "quota", "nodays", "noquota", "noconns"
    #
    # Note that rejection reasons are ignored unless quota_kb is 0.
    #
    return {
        'secret': 'testing',  # Important! This is used for authentication.

        'quota_kb': 10240,    # If set, 0 means "out of quota"; else advisory
        'quota_days': 24,     # Advisory
        'quota_conns': 5,     # Advisory
        'reason': 'reason',   # If set, explains why user is "out of quota"

        'ips_per_sec-ips': 1,    # Inform PageKite what IP rate limits apply
        'ips_per_sec-secs': 900} # ... to this tunnel's incoming traffic.



def ZkAuth(domain):
    # This usually does nothing, adjust CAPABILITIES above if you want to
    # take this code path.
    #
    # In reality this method would both decode the incoming "auth domain"
    # string and verify the signed challenge against a shared secret, and
    # then reformat the returned quota values as a dynamic DNS response...
    #
    return {'hostname': domain, 'alias': '', 'ips': ['0.0.255.255']}


def P(string):
    # Delete the sys.stderr line if you're not debugging.
    sys.stderr.write('>> ' + string + '\n')
    print(string)


def ProcessArgs(args, server=False):
    o, a = getopt.getopt(args, 'a:z:',
        ([] if server else ['capabilities', 'server']) +
        ['auth=', 'zk-auth='])

    for opt, arg in o:
        sys.stderr.write('<< %s=%s\n' % (opt, arg))

        if opt == '--capabilities':
            P(CAPABILITIES)
            return

        if opt == '--server':
            ServerLoop()
            return

        if opt in ('-z', '--zk-auth'):
            P(json.dumps(ZkAuth(arg), indent=None))
            return

        if opt in ('-a', '--auth'):
            P(json.dumps(Auth(arg), indent=None))
            return


def ServerLoop():
    while True:
        line = sys.stdin.readline()
        if not line:
            return

        args = line.strip().split()
        if args and not args[0][:2] == '--':
            args[0] = '--' + args[0]
        ProcessArgs(args, server=True)


if __name__ == '__main__':
    ProcessArgs(sys.argv[1:])
