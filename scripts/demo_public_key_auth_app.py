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
import sys
import subprocess


CAPABILITIES = ('ZK-AUTH')


def ZkAuth(domain):

    parts = domain.split('.')
    sys.stderr.write(str(parts) + '\n')

    jws = ".".join(parts[2:5])

    tunnel_domain = '.'.join(parts[6:-4])

    sys.stderr.write(jws + '\n' + tunnel_domain + '\n')

    jws_check_process = subprocess.Popen(['jose-util', 'verify', '--key=./scripts/jwk-sig-example.com-pub.json'],stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           stdin=subprocess.PIPE)
    jws_payload, _ = jws_check_process.communicate(input=jws)

    if jws_check_process.returncode != 0:
        return {'hostname': domain, 'alias': '', 'ips': ['0.0.0.0']}

    sys.stderr.write(jws_payload + '\n')

    payload_dict = json.loads(jws_payload)

    if tunnel_domain != payload_dict.get('domain'):
        sys.stderr.write('Domain mismatch!\n%s != %s' % (tunnel_domain, payload_dict.get('domain')))
        return {'hostname': domain, 'alias': '', 'ips': ['0.0.0.0']}

    return {'hostname': domain, 'alias': '', 'ips': ['255.255.255.0']}


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
