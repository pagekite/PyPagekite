"""
This is what is left of the original monolithic pagekite.py.
This is slowly being refactored into smaller sub-modules.
"""
##############################################################################
LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2017, the Beanstalks Project ehf. and Bjarni Runar Einarsson

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
import base64
import cgi
from cgi import escape as escape_html
import errno
import getopt
import httplib
import os
import random
import re
import select
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib
import xmlrpclib
import zlib

import SocketServer
from CGIHTTPServer import CGIHTTPRequestHandler
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import Cookie

from compat import *
from common import *
import compat
import common
import logging

# This allows us to run, degraded, on Python < 2.6.
try:
    import subprocess
    import json
except ImportError:
    subprocess = json = None


OPT_FLAGS = 'o:O:S:H:P:X:L:ZI:fA:R:h:p:aD:U:NE:'
OPT_ARGS = ['noloop', 'clean', 'nopyopenssl', 'nossl', 'nocrashreport',
            'nullui', 'remoteui', 'uiport=', 'help', 'settings',
            'optfile=', 'optdir=', 'savefile=',
            'friendly', 'shell',
            'signup', 'list', 'add', 'only', 'disable', 'remove', 'save',
            'service_xmlrpc=', 'controlpanel', 'controlpass',
            'httpd=', 'pemfile=', 'httppass=', 'errorurl=', 'webpath=',
            'logfile=', 'daemonize', 'nodaemonize', 'runas=', 'pidfile=',
            'isfrontend', 'noisfrontend', 'settings',
            'defaults', 'whitelabel=', 'whitelabels=', 'local=', 'domain=',
            'auththreads=', 'authdomain=', 'motd=', 'register=', 'host=',
            'noupgradeinfo', 'upgradeinfo=',
            'ports=', 'protos=', 'portalias=', 'rawports=',
            'tls_legacy', 'tls_default=', 'tls_endpoint=', 'selfsign',
            'fe_certname=', 'fe_nocertcheck', 'ca_certs=',
            'kitename=', 'kitesecret=', 'fingerpath=',
            'backend=', 'define_backend=', 'be_config=',
            'insecure', 'ratelimit_ips=',
            'service_on=', 'service_off=', 'service_cfg=',
            'tunnel_acl=', 'client_acl=', 'accept_acl_file=',
            'frontend=', 'nofrontend=', 'frontends=', 'keepalive=',
            'torify=', 'socksify=', 'proxy=', 'noproxy',
            'new', 'all', 'noall', 'dyndns=', 'nozchunks', 'sslzlib',
            'buffers=', 'noprobes', 'debugio', 'watch=', 'overload=',
            # DEPRECATED:
            'reloadfile=', 'autosave', 'noautosave', 'webroot=',
            'webaccess=', 'webindexes=', 'delete_backend=']


# Enable system proxies
# This will all fail if we don't have PySocksipyChain available.
# FIXME: Move this code somewhere else?
socks.usesystemdefaults()
socks.wrapmodule(sys.modules[__name__])

if socks.HAVE_SSL:
  # Secure otherwise cleartext connections to pagekite.net in SSL tunnels.
  def_hop = socks.parseproxy('default')
  for dest in ('pagekite.net', 'up.pagekite.net', 'up.b5p.us'):
    https_hop = socks.parseproxy(
      'httpcs!%s!443' % ','.join([dest]+SERVICE_CERTS))
    socks.setproxy(dest, *def_hop)
    socks.addproxy(dest, *https_hop)
else:
  # FIXME: Should scream and shout about lack of security.
  pass


##[ PageKite.py code starts here! ]############################################

from proto.proto import *
from proto.parsers import *
from proto.selectables import *
from proto.filters import *
from proto.conns import *
from ui.nullui import NullUi


class AuthApp(object):
  def __init__(self, app_path):
    assert(subprocess is not None)
    self.app_path = app_path
    self.capabilities = [cap.upper() for cap in
      subprocess.check_output([app_path, '--capabilities']).split() if cap]
    if 'SERVER' in self.capabilities:
      self.lock = threading.Lock()
      self.server = subprocess.Popen([app_path, '--server'],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE)
    else:
      self.server = None
      self.lock = None

  def _q(self, args):
    if self.server is not None:
      try:
        self.lock.acquire()
        self.server.stdin.write(' '.join(args) + '\n')
        self.server.stdin.flush()
        return self.server.stdout.readline().strip()
      finally:
        self.lock.release()
    else:
      return subprocess.check_output([self.app_path] + args).strip()

  def auth(self, domain):
    return json.loads(self._q(['--auth', domain]))

  def zk_auth(self, query):
    r = json.loads(self._q(['--zk-auth', query]))
    return (r['hostname'], r.get('alias', ''), r.get('ips', ['']))

  def supports_zk_auth(self):
    return ('ZK-AUTH' in self.capabilities)

  def supports_auth(self):
    return ('AUTH' in self.capabilities)


class AuthThread(threading.Thread):
  """Handle authentication work in a separate thread."""

  #daemon = True

  def __init__(self, conns):
    threading.Thread.__init__(self)
    self.qc = threading.Condition()
    self.jobs = []
    self.conns = conns

  def check(self, requests, conn, callback):
    self.qc.acquire()
    self.jobs.append((requests, conn, callback))
    self.qc.notify()
    self.qc.release()

  def quit(self):
    self.qc.acquire()
    self.keep_running = False
    self.qc.notify()
    self.qc.release()
    try:
      self.join()
    except RuntimeError:
      pass

  def run(self):
    self.keep_running = True
    while self.keep_running:
      try:
        self._run()
      except Exception, e:
        logging.LogError('AuthThread died: %s' % e)
        time.sleep(5)
    logging.LogDebug('AuthThread: done')

  def _run(self):
    self.qc.acquire()
    while self.keep_running:
      now = int(time.time())
      if not self.jobs:
        (requests, conn, callback) = None, None, None
        self.qc.wait()
      else:
        (requests, conn, callback) = self.jobs.pop(0)
        if logging.DEBUG_IO: print '=== AUTH REQUESTS\n%s\n===' % requests
        self.qc.release()

        quotas = []
        q_conns = []
        q_days = []
        ip_limits = []
        results = []
        log_info = []
        session = '%x:%s:' % (now, globalSecret())
        for request in requests:
          try:
            proto, domain, srand, token, sign, prefix = request
          except:
            logging.LogError('Invalid request: %s' % (request, ))
            continue

          what = '%s:%s:%s' % (proto, domain, srand)
          session += what
          if not token or not sign:
            # Send a challenge. Our challenges are time-stamped, so we can
            # put stict bounds on possible replay attacks (20 minutes atm).
            results.append(('%s-SignThis' % prefix,
                            '%s:%s' % (what, signToken(payload=what,
                                                       timestamp=now))))
          else:
            # This is a bit lame, but we only check the token if the quota
            # for this connection has never been verified.
            (quota, days, conns, ipc, ips, reason) = (
              self.conns.config.GetDomainQuota(
                proto, domain, srand, token, sign,
                check_token=(conn.quota is None)))
            duplicates = self.conns.Tunnel(proto, domain)
            if not quota:
              if not reason: reason = 'quota'
              results.append(('%s-Invalid' % prefix, what))
              results.append(('%s-Invalid-Why' % prefix,
                              '%s;%s' % (what, reason)))
              log_info.extend([('rejected', domain),
                               ('quota', quota),
                               ('reason', reason)])
            elif duplicates:
              # Duplicates... is the old one dead?  Trigger a ping.
              for conn in duplicates:
                conn.TriggerPing()
              results.append(('%s-Duplicate' % prefix, what))
              log_info.extend([('rejected', domain),
                               ('duplicate', 'yes')])
            else:
              results.append(('%s-OK' % prefix, what))
              quotas.append((quota, request))
              if conns: q_conns.append(conns)
              if days: q_days.append(days)
              if ipc: ip_limits.append((float(ipc)/ips, ipc, ips))
              if (proto.startswith('http') and
                  self.conns.config.GetTlsEndpointCtx(domain)):
                results.append(('%s-SSL-OK' % prefix, what))

        results.append(('%s-SessionID' % prefix,
                        '%x:%s' % (now, sha1hex(session))))
        results.append(('%s-Misc' % prefix, urllib.urlencode({
                          'motd': (self.conns.config.motd_message or ''),
                        })))
        for upgrade in self.conns.config.upgrade_info:
          results.append(('%s-Upgrade' % prefix, ';'.join(upgrade)))

        if quotas:
          min_qconns = min(q_conns or [0])
          if q_conns and min_qconns:
            results.append(('%s-QConns' % prefix, min_qconns))

          min_qdays = min(q_days or [0])
          if q_days and min_qdays:
            results.append(('%s-QDays' % prefix, min_qdays))

          min_ip_limits = min(ip_limits or [(0, None, None)])[1:]
          if ip_limits and min_ip_limits[0]:
            results.append(('%s-IPsPerSec' % prefix, '%s/%s' % min_ip_limits))

          nz_quotas = [qp for qp in quotas if qp[0] and qp[0] > 0]
          if nz_quotas:
            quota = min(nz_quotas)[0]
            conn.quota = [quota, [qp[1] for qp in nz_quotas], time.time()]
            results.append(('%s-Quota' % prefix, quota))
          elif requests:
            if not conn.quota:
              conn.quota = [None, requests, time.time()]
            else:
              conn.quota[2] = time.time()

        if logging.DEBUG_IO: print '=== AUTH RESULTS\n%s\n===' % results
        callback(results, log_info)
        self.qc.acquire()

    self.buffering = 0
    self.qc.release()


##[ Selectables ]##############################################################

class Connections(object):
  """A container for connections (Selectables), config and tunnel info."""

  def __init__(self, config):
    self.config = config
    self.ip_tracker = {}
    self.idle = []
    self.conns = []
    self.conns_by_id = {}
    self.tunnels = {}
    self.auth_pool = []

  def start(self, auth_threads=None, auth_thread_count=1):
    self.auth_pool = auth_threads or []
    while len(self.auth_pool) < auth_thread_count:
      self.auth_pool.append(AuthThread(self))
    for th in self.auth_pool:
      th.start()

  def Add(self, conn):
    self.conns.append(conn)

  def auth(self):
    return self.auth_pool[random.randint(0, len(self.auth_pool)-1)]

  def SetAltId(self, conn, new_id):
    if conn.alt_id and conn.alt_id in self.conns_by_id:
      del self.conns_by_id[conn.alt_id]
    if new_id:
      self.conns_by_id[new_id] = conn
    conn.alt_id = new_id

  def SetIdle(self, conn, seconds):
    self.idle.append((time.time() + seconds, conn.last_activity, conn))

  def TrackIP(self, ip, domain):
    tick = '%d' % (time.time()/12)
    if tick not in self.ip_tracker:
      deadline = int(tick)-10
      for ot in self.ip_tracker.keys():
        if int(ot) < deadline:
          del self.ip_tracker[ot]
      self.ip_tracker[tick] = {}

    if ip not in self.ip_tracker[tick]:
      self.ip_tracker[tick][ip] = [1, domain]
    else:
      self.ip_tracker[tick][ip][0] += 1
      self.ip_tracker[tick][ip][1] = domain

  def LastIpDomain(self, ip):
    domain = None
    for tick in sorted(self.ip_tracker.keys()):
      if ip in self.ip_tracker[tick]:
        domain = self.ip_tracker[tick][ip][1]
    return domain

  def Remove(self, conn, retry=True):
    try:
      if conn.alt_id and conn.alt_id in self.conns_by_id:
        del self.conns_by_id[conn.alt_id]
      if conn in self.conns:
        self.conns.remove(conn)
      rmp = []
      for elc in self.idle:
        if elc[-1] == conn:
          rmp.append(elc)
      for elc in rmp:
        self.idle.remove(elc)
      for tid, tunnels in self.tunnels.items():
        if conn in tunnels:
          tunnels.remove(conn)
          if not tunnels:
            del self.tunnels[tid]
    except (ValueError, KeyError):
      # Let's not asplode if another thread races us for this.
      logging.LogError('Failed to remove %s: %s' % (conn, format_exc()))
      if retry:
        return self.Remove(conn, retry=False)

  def IdleConns(self):
    return [p[-1] for p in self.idle]

  def Sockets(self):
    return [s.fd for s in self.conns]

  def Readable(self):
    # FIXME: This is O(n)
    now = time.time()
    return [s.fd for s in self.conns if s.IsReadable(now)]

  def Blocked(self):
    # FIXME: This is O(n)
    # Magic side-effect: update buffered byte counter
    blocked = [s for s in self.conns if s.IsBlocked()]
    common.buffered_bytes[0] = sum([len(s.write_blocked) for s in blocked])
    return [s.fd for s in blocked]

  def DeadConns(self):
    return [s for s in self.conns if s.IsDead()]

  def CleanFds(self):
    evil = []
    for s in self.conns:
      try:
        i, o, e = select.select([s.fd], [s.fd], [s.fd], 0)
      except:
        evil.append(s)
    for s in evil:
      logging.LogDebug('Removing broken Selectable: %s' % s)
      s.Cleanup()
      self.Remove(s)

  def Connection(self, fd):
    for conn in self.conns:
      if conn.fd == fd:
        return conn
    return None

  def TunnelServers(self):
    servers = {}
    for tid in self.tunnels:
      for tunnel in self.tunnels[tid]:
        server = tunnel.server_info[tunnel.S_NAME]
        if server is not None:
          servers[server] = 1
    return servers.keys()

  def CloseTunnel(self, proto, domain, conn):
    tid = '%s:%s' % (proto, domain)
    if tid in self.tunnels:
      if conn in self.tunnels[tid]:
        self.tunnels[tid].remove(conn)
      if not self.tunnels[tid]:
        del self.tunnels[tid]

  def CheckIdleConns(self, now):
    active = []
    for elc in self.idle:
      expire, last_activity, conn = elc
      if conn.last_activity > last_activity:
        active.append(elc)
      elif expire < now:
        logging.LogDebug('Killing idle connection: %s' % conn)
        conn.Die(discard_buffer=True)
      elif conn.created < now - 1:
        conn.SayHello()
    for pair in active:
      self.idle.remove(pair)

  def Tunnel(self, proto, domain, conn=None):
    tid = '%s:%s' % (proto, domain)
    if conn is not None:
      if tid not in self.tunnels:
        self.tunnels[tid] = []
      self.tunnels[tid].append(conn)

    if tid in self.tunnels:
      return self.tunnels[tid]
    else:
      try:
        dparts = domain.split('.')[1:]
        while len(dparts) > 1:
          wild_tid = '%s:*.%s' % (proto, '.'.join(dparts))
          if wild_tid in self.tunnels:
            return self.tunnels[wild_tid]
          dparts = dparts[1:]
      except:
        pass

      return []


class HttpUiThread(threading.Thread):
  """Handle HTTP UI in a separate thread."""

  daemon = True

  def __init__(self, pkite, conns,
               server=None, handler=None, ssl_pem_filename=None):
    threading.Thread.__init__(self)
    if not (server and handler):
      self.serve = False
      self.httpd = None
      return

    self.ui_sspec = pkite.ui_sspec
    self.httpd = server(self.ui_sspec, pkite, conns,
                        handler=handler,
                        ssl_pem_filename=ssl_pem_filename)
    self.httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.ui_sspec = pkite.ui_sspec = (self.ui_sspec[0],
                                      self.httpd.socket.getsockname()[1])
    self.serve = True

  def quit(self):
    self.serve = False
    try:
      knock = rawsocket(socket.AF_INET, socket.SOCK_STREAM)
      knock.connect(self.ui_sspec)
      knock.close()
    except IOError:
      pass
    try:
      self.join()
    except RuntimeError:
      try:
        if self.httpd and self.httpd.socket:
          self.httpd.socket.close()
      except IOError:
        pass

  def run(self):
    while self.serve:
      try:
        self.httpd.handle_request()
      except KeyboardInterrupt:
        self.serve = False
      except Exception, e:
        logging.LogInfo('HTTP UI caught exception: %s' % e)
    if self.httpd: self.httpd.socket.close()
    logging.LogDebug('HttpUiThread: done')


class UiCommunicator(threading.Thread):
  """Listen for interactive commands."""

  def __init__(self, config, conns):
    threading.Thread.__init__(self)
    self.looping = False
    self.config = config
    self.conns = conns
    logging.LogDebug('UiComm: Created')

  def run(self):
    self.looping = True
    while self.looping:
      if not self.config or not self.config.ui.ALLOWS_INPUT:
        time.sleep(1)
        continue

      line = ''
      try:
        i, o, e = select.select([self.config.ui.rfile], [], [], 1)
        if not i: continue
      except:
        pass

      if self.config:
        line = self.config.ui.rfile.readline().strip()
        if line:
          self.Parse(line)

    logging.LogDebug('UiCommunicator: done')

  def Reconnect(self):
    if self.config.tunnel_manager:
      self.config.ui.Status('reconfig')
      self.config.tunnel_manager.CloseTunnels()
      self.config.tunnel_manager.HurryUp()

  def Parse(self, line):
    try:
      command, args = line.split(': ', 1)
      logging.LogDebug('UiComm: %s(%s)' % (command, args))

      if args.lower() == 'none': args = None
      elif args.lower() == 'true': args = True
      elif args.lower() == 'false': args = False

      if command == 'exit':
        self.config.keep_looping = False
        self.config.main_loop = False
      elif command == 'restart':
        self.config.keep_looping = False
        self.config.main_loop = True
      elif command == 'config':
        command = 'change settings'
        self.config.Configure(['--%s' % args])
      elif command == 'enablekite':
        command = 'enable kite'
        if args and args in self.config.backends:
          self.config.backends[args][BE_STATUS] = BE_STATUS_UNKNOWN
          self.Reconnect()
        else:
          raise Exception('No such kite: %s' % args)
      elif command == 'disablekite':
        command = 'disable kite'
        if args and args in self.config.backends:
          self.config.backends[args][BE_STATUS] = BE_STATUS_DISABLED
          self.Reconnect()
        else:
          raise Exception('No such kite: %s' % args)
      elif command == 'delkite':
        command = 'remove kite'
        if args and args in self.config.backends:
          del self.config.backends[args]
          self.Reconnect()
        else:
          raise Exception('No such kite: %s' % args)
      elif command == 'addkite':
        command = 'create new kite'
        args = (args or '').strip().split() or ['']
        if self.config.RegisterNewKite(kitename=args[0],
                                       autoconfigure=True, ask_be=True):
          self.Reconnect()
      elif command == 'save':
        command = 'save configuration'
        self.config.SaveUserConfig(quiet=(args == 'quietly'))

    except ValueError:
      logging.LogDebug('UiComm: bogus: %s' % line)
    except SystemExit:
      self.config.keep_looping = False
      self.config.main_loop = False
    except:
      logging.LogDebug('UiComm: failed %s' % (sys.exc_info(), ))
      self.config.ui.Tell(['Oops!', '', 'Failed to %s, details:' % command,
                           '', '%s' % (sys.exc_info(), )], error=True)

  def quit(self):
    self.looping = False
    self.conns = None
    try:
      self.join()
    except RuntimeError:
      pass


class TunnelManager(threading.Thread):
  """Create new tunnels as necessary or kill idle ones."""

  daemon = True

  def __init__(self, pkite, conns):
    threading.Thread.__init__(self)
    self.pkite = pkite
    self.conns = conns

  def CheckTunnelQuotas(self, now):
    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        tunnel.RecheckQuota(self.conns, when=now)

  def PingTunnels(self, now):
    dead = {}

    # If we keep getting disconnected, maybe we have a nasty firewall
    # and should ping more frequently. Disabled at the frontend!
    while (common.DISCONNECT_COUNT >= 2 and
           not self.pkite.isfrontend and
           not self.pkite.keepalive):
      common.DISCONNECT_COUNT -= 2
      common.PING_INTERVAL = max(common.PING_INTERVAL_MIN,
                                 0.5 * common.PING_INTERVAL)
      logging.LogDebug('TunnelManager: adjusted ping interval, PI=%s'
                       % common.PING_INTERVAL)

    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        pings = int(self.pkite.keepalive or common.PING_INTERVAL)
        if tunnel.server_info[tunnel.S_IS_MOBILE]:
          pings = common.PING_INTERVAL_MOBILE
        grace = max(PING_GRACE_DEFAULT,
                    len(tunnel.write_blocked)/(tunnel.write_speed or 0.001))
        if tunnel.last_activity == 0:
          pass
        elif tunnel.last_ping < now - PING_GRACE_MIN:
          if tunnel.last_activity < tunnel.last_ping-(PING_GRACE_MIN+grace):
            dead['%s' % tunnel] = tunnel
          elif tunnel.last_activity < now-pings:
            tunnel.SendPing()
          elif random.randint(0, 10*pings) == 0:
            tunnel.SendPing()

    for tunnel in dead.values():
      logging.Log([('dead', tunnel.server_info[tunnel.S_NAME])])
      tunnel.Die(discard_buffer=True)

  def CloseTunnels(self):
    close = []
    for tid in self.conns.tunnels:
      for tunnel in self.conns.tunnels[tid]:
        close.append(tunnel)
    for tunnel in close:
      logging.Log([('closing', tunnel.server_info[tunnel.S_NAME])])
      tunnel.Die(discard_buffer=True)

  def quit(self):
    self.keep_running = False
    try:
      self.join()
    except RuntimeError:
      pass

  def run(self):
    self.keep_running = True
    self.explained = False
    while self.keep_running:
      try:
        self._run()
      except Exception, e:
        logging.LogError('TunnelManager died: %s' % e)
        if logging.DEBUG_IO:
          traceback.print_exc(file=sys.stderr)
        time.sleep(5)
    logging.LogDebug('TunnelManager: done')

  def DoFrontendWork(self):
    self.CheckTunnelQuotas(time.time())
    self.pkite.LoadMOTD()

    # FIXME: Front-ends should close dead back-end tunnels.
    for tid in self.conns.tunnels:
      proto, domain = tid.split(':')
      if '-' in proto:
        proto, port = proto.split('-')
      else:
        port = ''
      self.pkite.ui.NotifyFlyingFE(proto, port, domain)

  def ListBackEnds(self):
    self.pkite.ui.StartListingBackEnds()

    for bid in self.pkite.backends:
      be = self.pkite.backends[bid]
      # Do we have auto-SSL at the front-end?
      protoport, domain = bid.split(':', 1)
      tunnels = self.conns.Tunnel(protoport, domain)
      if be[BE_PROTO] in ('http', 'http2', 'http3') and tunnels:
        has_ssl = True
        for t in tunnels:
          if (protoport, domain) not in t.remote_ssl:
            has_ssl = False
      else:
        has_ssl = False

      # Get list of webpaths...
      domainp = '%s/%s' % (domain, be[BE_PORT] or '80')
      if (self.pkite.ui_sspec and
          be[BE_BHOST] == self.pkite.ui_sspec[0] and
          be[BE_BPORT] == self.pkite.ui_sspec[1]):
        builtin = True
        dpaths = self.pkite.ui_paths.get(domainp, {})
      else:
        builtin = False
        dpaths = {}

      self.pkite.ui.NotifyBE(bid, be, has_ssl, dpaths,
                             is_builtin=builtin,
                         fingerprint=(builtin and self.pkite.ui_pemfingerprint))

    self.pkite.ui.EndListingBackEnds()

  def UpdateUiStatus(self, problem, connecting):
    tunnel_count = len(self.pkite.conns and
                       self.pkite.conns.TunnelServers() or [])
    tunnel_total = len(self.pkite.servers)
    if tunnel_count == 0:
      if self.pkite.isfrontend:
        self.pkite.ui.Status('idle', message='Waiting for back-ends.')

      elif tunnel_total == 0:
        self.pkite.ui.Status('down', color=self.pkite.ui.GREY,
                             message='No kites ready to fly.  Waiting...')
        self.pkite.ui.Notify('It looks like your Internet connection might '
                             'be down! Will retry soon.',
                             color=self.pkite.ui.YELLOW)
        self.pkite.ui.Notify(
          ' - Check whether you can ping pagekite.net or google.com')
        if self.pkite.servers_auto:
          hostname = self.pkite.servers_auto[1]
          self.pkite.ui.Notify(
            ' - Check whether `%s` can be looked up in DNS' % hostname)
        for hostport in self.pkite.servers_manual:
          hostname = hostport.split(':')[0]
          self.pkite.ui.Notify(
            ' - Check whether `%s` can be looked up in DNS' % hostname)

      elif connecting == 0:
        self.pkite.ui.Status('down', color=self.pkite.ui.RED,
                       message='Not connected to any front-end relays, will retry...')
    elif tunnel_count < tunnel_total:
      self.pkite.ui.Status('flying', color=self.pkite.ui.YELLOW,
                    message=('Only connected to %d/%d front-end relays, will retry...'
                             ) % (tunnel_count, tunnel_total))
    elif problem:
      self.pkite.ui.Status('flying', color=self.pkite.ui.YELLOW,
                     message='DynDNS updates may be incomplete, will retry...')
    else:
      self.pkite.ui.Status('flying', color=self.pkite.ui.GREEN,
                                   message='Kites are flying and all is well.')

  def _run(self):
    self.check_interval = 5
    loop_count = 0
    last_log = 0
    while self.keep_running:
      loop_count += 1
      now = time.time()
      if (now - last_log) >= (60 * 15):
        # Report liveness/state roughly once every 15 minutes
        logging.LogDebug('TunnelManager: loop #%d, interval=%s'
                         % (loop_count, self.check_interval))
        last_log = now

      # Reconnect if necessary, randomized exponential fallback.
      problem, connecting = self.pkite.CreateTunnels(self.conns)
      if problem or connecting:
        logging.LogDebug(
          'TunnelManager: problem=%s, connecting=%s, DC=%s, PI=%d'
          % (problem, connecting,
             common.DISCONNECT_COUNT,
             (self.pkite.keepalive or common.PING_INTERVAL)))
        incr = int(1+random.random()*self.check_interval)
        self.check_interval = min(60, self.check_interval + incr)
        time.sleep(1)
      else:
        self.check_interval = 5

      # Make sure tunnels are really alive.
      if self.pkite.isfrontend:
        self.DoFrontendWork()
      self.PingTunnels(time.time())

      # FIXME: This is constant noise, instead there should be a
      #        command which requests this stuff.
      self.ListBackEnds()
      self.UpdateUiStatus(problem, connecting)

      for i in xrange(0, self.check_interval):
        if self.keep_running:
          time.sleep(1)
          if i > self.check_interval:
            break
          if self.pkite.isfrontend:
            self.conns.CheckIdleConns(time.time())

  def HurryUp(self):
    self.check_interval = 0


def SecureCreate(path):
  fd = open(path, 'w')
  try:
    os.chmod(path, 0600)
  except OSError:
    pass
  return fd

def CreateSelfSignedCert(pem_path, ui):
  ui.Notify('Creating a 2048-bit self-signed TLS certificate ...',
            prefix='-', color=ui.YELLOW)

  workdir = tempfile.mkdtemp()
  def w(fn):
    return os.path.join(workdir, fn)

  os.system(('openssl genrsa -out %s 2048') % w('key'))
  os.system(('openssl req -batch -new -key %s -out %s'
                        ' -subj "/CN=PageKite/O=Self-Hosted/OU=Website"'
             ) % (w('key'), w('csr')))
  os.system(('openssl x509 -req -days 3650 -in %s -signkey %s -out %s'
             ) % (w('csr'), w('key'), w('crt')))

  pem = SecureCreate(pem_path)
  pem.write(open(w('key')).read())
  pem.write('\n')
  pem.write(open(w('crt')).read())
  pem.close()

  for fn in ['key', 'csr', 'crt']:
    os.remove(w(fn))
  os.rmdir(workdir)

  ui.Notify('Saved certificate to: %s' % pem_path,
            prefix='-', color=ui.YELLOW)


class PageKite(object):
  """Configuration and master select loop."""

  def __init__(self, ui=None, http_handler=None, http_server=None):
    self.progname = ((sys.argv[0] or 'pagekite.py').split('/')[-1]
                                                   .split('\\')[-1])
    self.pyfile = os.path.abspath(sys.argv[0])
    self.ui = ui or NullUi()
    self.ui_request_handler = http_handler
    self.ui_http_server = http_server
    self.ResetConfiguration()

  def ResetConfiguration(self):
    self.isfrontend = False
    self.upgrade_info = []
    self.auth_threads = 1
    self.auth_domain = None
    self.auth_domains = {}
    self.auth_apps = {}
    self.motd = None
    self.motd_message = None
    self.server_host = ''
    self.server_ports = [80]
    self.server_raw_ports = []
    self.server_portalias = {}
    self.server_aliasport = {}
    self.server_protos = ['http', 'http2', 'http3', 'https', 'websocket',
                          'irc', 'finger', 'httpfinger', 'raw', 'minecraft']

    self.accept_acl_file = None
    self.tunnel_acls = []
    self.client_acls = []

    self.tls_legacy = False
    self.tls_default = None
    self.tls_endpoints = {}
    self.fe_certname = []
    self.fe_nocertcheck = False

    self.service_provider = SERVICE_PROVIDER
    self.service_xmlrpc = SERVICE_XMLRPC

    self.daemonize = False
    self.pidfile = None
    self.logfile = None
    self.setuid = None
    self.setgid = None
    self.ui_httpd = None
    self.ui_sspec_cfg = None
    self.ui_sspec = None
    self.ui_socket = None
    self.ui_password = None
    self.ui_pemfile = None
    self.ui_pemfingerprint = None
    self.ui_magic_file = '.pagekite.magic'
    self.ui_paths = {}
    self.insecure = False
    self.ratelimit_ips = {}
    self.be_config = {}
    self.disable_zchunks = False
    self.enable_sslzlib = False
    self.buffer_max = DEFAULT_BUFFER_MAX
    self.error_url = None
    self.error_urls = {}
    self.finger_path = '/~%s/.finger'

    self.tunnel_manager = None
    self.client_mode = 0

    self.proxy_servers = []
    self.no_proxy = False
    self.require_all = False
    self.no_probes = False
    self.servers = []
    self.servers_manual = []
    self.servers_never = []
    self.servers_auto = None
    self.servers_new_only = False
    self.servers_no_ping = False
    self.servers_preferred = []
    self.servers_sessionids = {}
    self.keepalive = None
    self.dns_cache = {}
    self.ping_cache = {}
    self.last_frontend_choice = 0

    self.kitename = ''
    self.kitesecret = ''
    self.dyndns = None
    self.last_updates = []
    self.postpone_ddns_updates = [0, 0]
    self.backends = {}  # These are the backends we want tunnels for.
    self.conns = None
    self.last_loop = 0
    self.keep_looping = True
    self.main_loop = True
    self.watch_level = [None]
    self.overload = None

    self.crash_report_url = '%scgi-bin/crashes.pl' % WWWHOME
    self.rcfile_recursion = 0
    self.rcfiles_loaded = []
    self.savefile = None
    self.added_kites = False
    self.ui_wfile = sys.stderr
    self.ui_rfile = sys.stdin
    self.ui_port = None
    self.ui_conn = None
    self.ui_comm = None

    self.save = 0
    self.shell = False
    self.kite_add = False
    self.kite_only = False
    self.kite_disable = False
    self.kite_remove = False

    # Searching for our configuration file!  We prefer the documented
    # 'standard' locations, but if nothing is found there and something local
    # exists, use that instead.
    try:
      if sys.platform[:3] in ('win', 'os2'):
        self.rcfile = os.path.join(os.path.expanduser('~'), 'pagekite.cfg')
        self.devnull = 'nul'
      else:
        # Everything else
        self.rcfile = os.path.join(os.path.expanduser('~'), '.pagekite.rc')
        self.devnull = '/dev/null'

    except Exception, e:
      # The above stuff may fail in some cases, e.g. on Android in SL4A.
      self.rcfile = 'pagekite.cfg'
      self.devnull = '/dev/null'

    self.ca_certs_default = self.ca_certs = None
    self.SetDefaultCACerts()

  def SetDefaultCACerts(self, **kwargs):
    # Look for CA Certificates. If we don't find them in the host OS,
    # we assume there might be something good in the program itself.
    if self.ca_certs_default != self.pyfile:
      self.ca_certs_default = self.FindCACerts(**kwargs)
    self.ca_certs = self.ca_certs_default

  def FindCACerts(self, use_curl_bundle=False):
    # Search a bunch of paths, preferring the biggest/newest bundle found
    biggest, newest, found = 0, 0, None
    own_pemfile = "%s.pem" % '.'.join(self.rcfile.split('.')[:-1])

    for path in list(OS_CA_CERTS) + [own_pemfile]:
      if os.path.exists(path):
        # We consider all bundles over 200k to be the same size...
        size = min(200000, os.stat(path).st_size)
        mtime = os.stat(path).st_mtime
        if size > biggest:
          # Choose the biggest bundle!
          found, biggest, newest = path, size, mtime
        elif size == biggest and mtime > newest:
          # Choose the freshest bundle!
          found, newest = path, mtime

    if use_curl_bundle and ((not found) or
        ((found == own_pemfile) and (newest < time.time() - 365*24*3600))):
      # No bundle found or bundle old, download a new one from the cURL site.
      try:
        urllib.URLopener().retrieve(CURL_CA_CERTS, filename=own_pemfile)
        return self.FindCACerts(use_curl_bundle=False)
      except:
        pass

    if found:
      return found

    return sys.argv[0]  # Fall back to distributed CA certs

  ACL_SHORTHAND = {
    'localhost': '((::ffff:)?127\..*|::1)',
    'any': '.*'
  }
  def CheckAcls(self, acls, address, which, conn=None):
    if not acls:
      return True
    for policy, pattern in acls:
      if re.match(self.ACL_SHORTHAND.get(pattern, pattern)+'$', address[0]):
        if (policy.lower() == 'allow'):
          return True
        else:
          if conn:
            conn.LogError(('%s rejected by %s ACL: %s:%s'
                           ) % (address[0], which, policy, pattern))
          return False
    if conn:
      conn.LogError('%s rejected by default %s ACL' % (address[0], which))
    return False

  def CheckClientAcls(self, address, conn=None):
    return self.CheckAcls(self.client_acls, address, 'client', conn)

  def CheckTunnelAcls(self, address, conn=None):
    return self.CheckAcls(self.tunnel_acls, address, 'tunnel', conn)

  def SetLocalSettings(self, ports):
    self.isfrontend = True
    self.servers_auto = None
    self.servers_manual = []
    self.servers_never = []
    self.server_ports = ports
    self.backends = self.ArgToBackendSpecs('http:localhost:localhost:builtin:-')

  def APPVER_DNS(self, tld):
    appver_without_patchlevel = '.'.join(APPVER.split('.')[:3])
    return ('fe4_%s.' + tld) % re.sub(r'[^\d]', '', appver_without_patchlevel)

  def SetServiceDefaults(self, clobber=True, check=False):
    def_dyndns    = (DYNDNS['pagekite.net'], {'user': '', 'pass': ''})
    def_frontends = (1, self.APPVER_DNS('b5p.us'), 443)
    def_fe_certs  = ['b5p.us'] + [c for c in SERVICE_CERTS if c != 'b5p.us']
    def_ca_certs  = self.pyfile
    def_error_url = 'https://pagekite.net/offline/?'
    if check:
      return (self.dyndns == def_dyndns and
              self.servers_auto == def_frontends and
              self.error_url == def_error_url and
              self.ca_certs == def_ca_certs and
              (sorted(self.fe_certname) == sorted(def_fe_certs) or
               not socks.HAVE_SSL))
    else:
      self.dyndns = (not clobber and self.dyndns) or def_dyndns
      self.servers_auto = (not clobber and self.servers_auto) or def_frontends
      self.error_url = (not clobber and self.error_url) or def_error_url
      if socks.HAVE_SSL:
        self.ca_certs_default = (not clobber and self.ca_certs_default) or def_ca_certs
        self.ca_certs = (not clobber and self.ca_certs) or def_ca_certs
        for cert in def_fe_certs:
          if cert not in self.fe_certname:
            self.fe_certname.append(cert)
      return True

  def SetWhitelabelDefaults(self, wld, secure=False, clobber=True, check=False):
    def_dyndns = (DYNDNS[secure and 'whitelabels' or 'whitelabel'] % wld,
                  {'user': '', 'pass': ''})
    def_frontends = (1, self.APPVER_DNS(wld), 443)
    def_fe_certs = ['fe.%s' % wld, wld] + [c for c in SERVICE_CERTS if c != wld]
    def_ca_certs  = self.pyfile
    def_error_url = 'http%s://www.%s/offline/?' % (secure and 's' or '', wld)
    if check:
      return (self.dyndns == def_dyndns and
              self.servers_auto == def_frontends and
              self.error_url == def_error_url and
              self.ca_certs == def_ca_certs and
              (sorted(self.fe_certname) == sorted(def_fe_certs) or
               not socks.HAVE_SSL))
    else:
      self.dyndns = (not clobber and self.dyndns) or def_dyndns
      self.servers_auto = (not clobber and self.servers_auto) or def_frontends
      self.error_url = (not clobber and self.error_url) or def_error_url
      if socks.HAVE_SSL:
        self.ca_certs_default = (not clobber and self.ca_certs_default) or def_ca_certs
        self.ca_certs = (not clobber and self.ca_certs) or def_ca_certs
        for cert in def_fe_certs:
          if cert not in self.fe_certname:
            self.fe_certname.append(cert)
      return True

  def GenerateConfig(self, safe=False):
    config = [
      '###[ Current settings for pagekite.py v%s. ]#########' % APPVER,
      '#',
      '## NOTE: This file may be rewritten/reordered by pagekite.py.',
      '#',
      '',
    ]

    if not self.kitename:
      for be in self.backends.values():
        if not self.kitename or len(self.kitename) < len(be[BE_DOMAIN]):
          self.kitename = be[BE_DOMAIN]
          self.kitesecret = be[BE_SECRET]

    new = not (self.kitename or self.kitesecret or self.backends)
    def p(vfmt, value, dval):
      return '%s%s' % (value and value != dval
                             and ('', vfmt % value) or ('# ', vfmt % dval))

    if self.kitename or self.kitesecret or new:
      config.extend([
        '##[ Default kite and account details ]##',
        p('kitename   = %s', self.kitename, 'NAME'),
        p('kitesecret = %s', self.kitesecret, 'SECRET'),
        ''
      ])

    kite_tld = None
    if self.kitename:
      kite_tld = '.'.join(self.kitename.split('.')[-2:])

    def addManualFrontends():
      if self.servers_manual or self.servers_never:
        config.append('')
        config.append('##[ Manual front-ends ]##')
        for server in sorted(self.servers_manual):
          config.append('frontend=%s' % server)
        for server in sorted(self.servers_never):
          config.append('nofrontend=%s' % server)

    if self.SetServiceDefaults(check=True):
      config.extend([
        '##[ Front-end settings: use pagekite.net defaults ]##',
        'defaults',
      ])
      addManualFrontends()
    elif (kite_tld and
          self.SetWhitelabelDefaults(kite_tld, secure=False, check=True)):
      config.extend([
        '##[ Front-end settings: use %s defaults ]##' % kite_tld,
        'whitelabel = %s' % kite_tld,
        ''
      ])
      addManualFrontends()
    elif (kite_tld and
          self.SetWhitelabelDefaults(kite_tld, secure=True, check=True)):
      config.extend([
        '##[ Front-end settings: use %s defaults ]##' % kite_tld,
        'whitelabels = %s' % kite_tld,
        ''
      ])
      addManualFrontends()
    else:
      if not self.servers_auto and not self.servers_manual:
        new = True
        config.extend([
          '##[ Use this to just use pagekite.net defaults ]##',
          '# defaults',
          ''
        ])
      config.append('##[ Custom front-end and dynamic DNS settings ]##')
      if self.servers_auto:
        config.append('frontends = %d:%s:%d' % self.servers_auto)
      if self.servers_manual:
        for server in sorted(self.servers_manual):
          config.append('frontend = %s' % server)
      if self.servers_never:
        for server in sorted(self.servers_never):
          config.append('nofrontend = %s' % server)
      if not self.servers_auto and not self.servers_manual:
        new = True
        config.append('# frontends = N:hostname:port')
        config.append('# frontend = hostname:port')
        config.append('# nofrontend = hostname:port  # never connect')

      for server in self.fe_certname:
        config.append('fe_certname = %s' % server)
      if self.fe_nocertcheck:
        config.append('fe_nocertcheck')

      if self.dyndns:
        provider, args = self.dyndns
        for prov in sorted(DYNDNS.keys()):
          if DYNDNS[prov] == provider and prov != 'beanstalks.net':
            args['prov'] = prov
        if 'prov' not in args:
          args['prov'] = provider
        if args['pass']:
          config.append('dyndns = %(user)s:%(pass)s@%(prov)s' % args)
        elif args['user']:
          config.append('dyndns = %(user)s@%(prov)s' % args)
        else:
          config.append('dyndns = %(prov)s' % args)
      else:
        new = True
        config.extend([
          '# dyndns = pagekite.net OR',
          '# dyndns = user:pass@dyndns.org OR',
          '# dyndns = user:pass@no-ip.com' ,
          '#',
          p('errorurl = %s', self.error_url, 'http://host/page/'),
          p('fingerpath = %s', self.finger_path, '/~%s/.finger'),
          '',
        ])
    if self.ca_certs != self.ca_certs_default:
      config.append('ca_certs = %s' % self.ca_certs)
    if self.keepalive != None:
      config.append('keepalive = %d' % self.keepalive)
    for dom in sorted(self.error_urls.keys()):
      config.append('errorurl = %s:%s' % (dom, self.error_urls[dom]))
    config.append('')

    if self.ui_sspec or self.ui_password or self.ui_pemfile:
      config.extend([
        '##[ Built-in HTTPD settings ]##',
        p('httpd = %s:%s', self.ui_sspec_cfg, ('host', 'port'))
      ])
      if self.ui_password: config.append('httppass=%s' % self.ui_password)
      if self.ui_pemfile: config.append('pemfile=%s' % self.ui_pemfile)
      for http_host in sorted(self.ui_paths.keys()):
        for path in sorted(self.ui_paths[http_host].keys()):
          up = self.ui_paths[http_host][path]
          config.append('webpath = %s:%s:%s:%s' % (http_host, path, up[0], up[1]))
      config.append('')

    config.append('##[ Back-ends and local services ]##')
    bprinted = 0
    for bid in sorted(self.backends.keys()):
      be = self.backends[bid]
      proto, domain = bid.split(':')
      if be[BE_BHOST]:
        be_spec = (be[BE_BHOST], be[BE_BPORT])
        be_spec = ((be_spec == self.ui_sspec) and 'localhost:builtin'
                                               or ('%s:%s' % be_spec))
        fe_spec = ('%s:%s' % (proto, (domain == self.kitename) and '@kitename'
                                                               or domain))
        secret = ((be[BE_SECRET] == self.kitesecret) and '@kitesecret'
                                                      or be[BE_SECRET])
        config.append(('%s = %-33s: %-18s: %s'
                       ) % ((be[BE_STATUS] == BE_STATUS_DISABLED
                             ) and 'service_off' or 'service_on ',
                            fe_spec, be_spec, secret))
        bprinted += 1
    if bprinted == 0:
      config.append('# No back-ends!  How boring!')
    config.append('')
    for http_host in sorted(self.be_config.keys()):
      for key in sorted(self.be_config[http_host].keys()):
        config.append(('service_cfg = %-30s: %-15s: %s'
                       ) % (http_host, key, self.be_config[http_host][key]))
    config.append('')

    if bprinted == 0:
      new = True
      config.extend([
        '##[ Back-end service examples ... ]##',
        '#',
        '# service_on = http:YOU.pagekite.me:localhost:80:SECRET',
        '# service_on = ssh:YOU.pagekite.me:localhost:22:SECRET',
        '# service_on = http/8080:YOU.pagekite.me:localhost:8080:SECRET',
        '# service_on = https:YOU.pagekite.me:localhost:443:SECRET',
        '# service_on = websocket:YOU.pagekite.me:localhost:8080:SECRET',
        '# service_on = minecraft:YOU.pagekite.me:localhost:8080:SECRET',
        '#',
        '# service_off = http:YOU.pagekite.me:localhost:4545:SECRET',
        ''
      ])

    config.extend([
      '##[ Allow risky known-to-be-risky incoming HTTP requests? ]##',
      (self.insecure) and 'insecure' or '# insecure',
      ''
    ])

    if self.isfrontend or new:
      config.extend([
        '##[ Front-end Options ]##',
        (self.isfrontend and 'isfrontend' or '# isfrontend')
      ])
      comment = ((not self.isfrontend) and '# ' or '')
      config.extend([
        p('host = %s', self.isfrontend and self.server_host, 'machine.domain.com'),
        '%sports = %s' % (comment, ','.join(['%s' % x for x in sorted(self.server_ports)] or [])),
        '%sprotos = %s' % (comment, ','.join(['%s' % x for x in sorted(self.server_protos)] or []))
      ])
      for pa in self.server_portalias:
        config.append('portalias = %s:%s' % (int(pa), int(self.server_portalias[pa])))
      config.extend([
        '%srawports = %s' % (comment or (not self.server_raw_ports) and '# ' or '',
                           ','.join(['%s' % x for x in sorted(self.server_raw_ports)] or [VIRTUAL_PN])),
        p('auththreads = %s', self.isfrontend and self.auth_threads, 1),
        p('authdomain = %s', self.isfrontend and self.auth_domain, 'foo.com'),
        p('motd = %s', self.isfrontend and self.motd, '/path/to/motd.txt')
      ])
      for d in sorted(self.auth_domains.keys()):
        config.append('authdomain=%s:%s' % (d, self.auth_domains[d]))
      dprinted = 0
      for bid in sorted(self.backends.keys()):
        be = self.backends[bid]
        if not be[BE_BHOST]:
          config.append('domain = %s:%s' % (bid, be[BE_SECRET]))
          dprinted += 1
      if not dprinted:
        new = True
        config.extend([
          '# domain = http:*.pagekite.me:SECRET1',
          '# domain = http,https,websocket:THEM.pagekite.me:SECRET2',
        ])

      eprinted = 0
      config.extend([
        '',
        '##[ Domains we terminate SSL/TLS for natively, with key/cert-files ]##'
      ])
      for ep in sorted(self.tls_endpoints.keys()):
        config.append('tls_endpoint = %s:%s' % (ep, self.tls_endpoints[ep][0]))
        eprinted += 1
      if eprinted == 0:
        new = True
        config.append('# tls_endpoint = DOMAIN:PEM_FILE')
      config.extend([
        p('tls_default = %s', self.tls_default, 'DOMAIN'),
        p('tls_legacy = %s', self.tls_legacy, False),
        '',
      ])

    config.extend([
      '##[ Proxy-chain settings ]##',
      (self.no_proxy and 'noproxy' or '# noproxy'),
    ])
    for proxy in self.proxy_servers:
      config.append('proxy = %s' % proxy)
    if not self.proxy_servers:
      config.extend([
        '# socksify = host:port',
        '# torify   = host:port',
        '# proxy    = ssl:/path/to/client-cert.pem@host,CommonName:port',
        '# proxy    = http://user:password@host:port/',
        '# proxy    = socks://user:password@host:port/'
      ])

    config.extend([
      '',
      '##[ Front-end access controls (default=deny, if configured) ]##',
      p('accept_acl_file = %s', self.accept_acl_file, '/path/to/file'),
    ])
    for d in sorted(self.ratelimit_ips.keys()):
      if d == '*':
        config.append('ratelimit_ips = %s' % self.ratelimit_ips[d])
      else:
        config.append('ratelimit_ips = %s:%s' % (d, self.ratelimit_ips[d]))
    for policy, pattern in self.client_acls:
      config.append('client_acl = %s:%s' % (policy, pattern))
    if not self.client_acls:
      config.append('# client_acl = [allow|deny]:IP-regexp')
    for policy, pattern in self.tunnel_acls:
      config.append('tunnel_acl = %s:%s' % (policy, pattern))
    if not self.tunnel_acls:
      config.append('# tunnel_acl = [allow|deny]:IP-regexp')
    config.extend([
      '',
      '',
      '###[ Anything below this line can usually be ignored. ]#########',
      '',
      '##[ Miscellaneous settings ]##',
      p('logfile = %s', self.logfile, '/path/to/file'),
      p('buffers = %s', self.buffer_max, DEFAULT_BUFFER_MAX),
      (self.servers_new_only is True) and 'new' or '# new',
      (self.require_all and 'all' or '# all'),
      (self.no_probes and 'noprobes' or '# noprobes'),
      (self.crash_report_url and '# nocrashreport' or 'nocrashreport'),
      p('savefile = %s', safe and self.savefile, '/path/to/savefile'),
      '',
    ])

    if self.daemonize or self.setuid or self.setgid or self.pidfile or new:
      config.extend([
        '##[ Systems administration settings ]##',
        (self.daemonize and 'daemonize' or '# daemonize')
      ])
      if self.setuid and self.setgid:
        config.append('runas = %s:%s' % (self.setuid, self.setgid))
      elif self.setuid:
        config.append('runas = %s' % self.setuid)
      else:
        new = True
        config.append('# runas = uid:gid')
      config.append(p('pidfile = %s', self.pidfile, '/path/to/file'))

    config.extend([
      '',
      '###[ End of pagekite.py configuration ]#########',
      'END',
      ''
    ])
    if not new:
      config = [l for l in config if not l.startswith('# ')]
      clean_config = []
      for i in range(0, len(config)-1):
        if i > 0 and (config[i].startswith('#') or config[i] == ''):
          if config[i+1] != '' or clean_config[-1].startswith('#'):
            clean_config.append(config[i])
        else:
          clean_config.append(config[i])
      clean_config.append(config[-1])
      return clean_config
    else:
      return config

  def ConfigSecret(self, new=False):
    # This method returns a stable secret for the lifetime of this process.
    #
    # The secret depends on the active configuration as, reported by
    # GenerateConfig().  This lets external processes generate the same
    # secret and use the remote-control APIs as long as they can read the
    # *entire* config (which contains all the sensitive bits anyway).
    #
    if self.ui_httpd and self.ui_httpd.httpd and not new:
      return self.ui_httpd.httpd.secret
    else:
      return sha1hex('\n'.join(self.GenerateConfig()))

  def LoginPath(self, goto):
    return '/_pagekite/login/%s/%s' % (self.ConfigSecret(), goto)

  def LoginUrl(self, goto=''):
    return 'http%s://%s%s' % (self.ui_pemfile and 's' or '',
                              '%s:%s' % self.ui_sspec,
                              self.LoginPath(goto))

  def ListKites(self):
    self.ui.welcome = '>>> ' + self.ui.WHITE + 'Your kites:' + self.ui.NORM
    message = []
    for bid in sorted(self.backends.keys()):
      be = self.backends[bid]
      be_be = (be[BE_BHOST], be[BE_BPORT])
      backend = (be_be == self.ui_sspec) and 'builtin' or '%s:%s' % be_be
      fe_port = be[BE_PORT] or ''
      frontend = '%s://%s%s%s' % (be[BE_PROTO], be[BE_DOMAIN],
                                  fe_port and ':' or '', fe_port)

      if be[BE_STATUS] == BE_STATUS_DISABLED:
        color = self.ui.GREY
        status = '(disabled)'
      else:
        color = self.ui.NORM
        status = (be[BE_PROTO] == 'raw') and '(HTTP proxied)' or ''
      message.append(''.join([color, backend, ' ' * (19-len(backend)),
                              frontend, ' ' * (42-len(frontend)), status]))
    message.append(self.ui.NORM)
    self.ui.Tell(message)

  def PrintSettings(self, safe=False):
    print '\n'.join(self.GenerateConfig(safe=safe))

  def SaveUserConfig(self, quiet=False):
    self.savefile = self.savefile or self.rcfile
    try:
      fd = SecureCreate(self.savefile)
      fd.write('\n'.join(self.GenerateConfig(safe=True)))
      fd.close()
      if not quiet:
        self.ui.Tell(['Settings saved to: %s' % self.savefile])
        self.ui.Spacer()
      logging.Log([('saved', 'Settings saved to: %s' % self.savefile)])
    except Exception, e:
      if logging.DEBUG_IO: traceback.print_exc(file=sys.stderr)
      self.ui.Tell(['Could not save to %s: %s' % (self.savefile, e)],
                   error=True)
      self.ui.Spacer()

  def FallDown(self, message, help=True, longhelp=False, noexit=False):
    if self.conns and self.conns.auth_pool:
      for th in self.conns.auth_pool:
        th.quit()
    if self.ui_httpd:
      self.ui_httpd.quit()
    if self.ui_comm:
      self.ui_comm.quit()
    if self.tunnel_manager:
      self.tunnel_manager.quit()
    self.keep_looping = False

    for fd in (self.conns and self.conns.Sockets() or []):
      try:
        fd.close()
      except (IOError, OSError, TypeError, AttributeError):
        pass
    self.conns = self.ui_httpd = self.ui_comm = self.tunnel_manager = None

    try:
      os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    except:
      pass
    print
    if help or longhelp:
      import manual
      print longhelp and manual.DOC() or manual.MINIDOC()
      print '***'
    elif not noexit:
      self.ui.Status('exiting', message=(message or 'Good-bye!'))
    if message:
      print 'Error: %s' % message

    if logging.DEBUG_IO:
      traceback.print_exc(file=sys.stderr)
    if not noexit:
      self.main_loop = False
      sys.exit(1)

  def GetTlsEndpointCtx(self, domain):
    if domain in self.tls_endpoints:
      return self.tls_endpoints[domain][1]
    parts = domain.split('.')
    # Check for wildcards ...
    if len(parts) > 2:
      parts[0] = '*'
      domain = '.'.join(parts)
      if domain in self.tls_endpoints:
        return self.tls_endpoints[domain][1]
    return None

  def SetBackendStatus(self, domain, proto='', add=None, sub=None):
    match = '%s:%s' % (proto, domain)
    for bid in self.backends:
      if bid == match or (proto == '' and bid.endswith(match)):
        status = self.backends[bid][BE_STATUS]
        if add: self.backends[bid][BE_STATUS] |= add
        if sub and (status & sub): self.backends[bid][BE_STATUS] -= sub
        logging.Log([('bid', bid),
             ('status', '0x%x' % self.backends[bid][BE_STATUS])])

  def GetBackendData(self, proto, domain, recurse=True):
    backend = '%s:%s' % (proto.lower(), domain.lower())
    if backend in self.backends:
      if self.backends[backend][BE_STATUS] not in BE_INACTIVE:
        return self.backends[backend]

    if recurse:
      dparts = domain.split('.')
      while len(dparts) > 1:
        dparts = dparts[1:]
        data = self.GetBackendData(proto, '.'.join(['*'] + dparts), recurse=False)
        if data: return data

    return None

  def GetBackendServer(self, proto, domain, recurse=True):
    backend = self.GetBackendData(proto, domain) or BE_NONE
    bhost, bport = (backend[BE_BHOST], backend[BE_BPORT])
    if bhost == '-' or not bhost: return None, None
    return (bhost, bport), backend

  def IsSignatureValid(self, sign, secret, proto, domain, srand, token):
    return checkSignature(sign=sign, secret=secret,
                          payload='%s:%s:%s:%s' % (proto, domain, srand, token))

  def GetAuthApp(self, command):
    auth_app = self.auth_apps.get(command)
    if auth_app is None:
      self.auth_apps[command] = AuthApp(command)
    return self.auth_apps[command]

  def LookupDomainQuota(self, srand, token, sign, protoport, domain, adom):
    if '/' in adom:
      auth_app = self.GetAuthApp(adom)
      if not auth_app.supports_zk_auth():
        auth = auth_app.auth(domain)
        secret = auth.get('secret')
        if not secret:
          # We cannot validate: the auth app was unavailable or broken.
          raise ValueError('Auth app provided no secret for: %s' % domain)
        elif self.IsSignatureValid(sign, secret, protoport, domain,
                                   srand, token):
          return (auth.get('quota_kb', -2),  # None or Zero would deny access
                  auth.get('quota_days'),
                  auth.get('quota_conns'),
                  auth.get('ips_per_sec-ips'),
                  auth.get('ips_per_sec-secs'),
                  auth.get('reason', auth.get('error')))
        else:
          logging.LogError('Invalid signature for: %s (%s)'
                           % (domain, protoport))
          return (None, None, None, None, None, 'signature')
    else:
      auth_app = None

    lookup = '.'.join([srand, token, sign, protoport, domain, adom])
    if not lookup.endswith('.'): lookup += '.'
    if logging.DEBUG_IO: print '=== AUTH LOOKUP\n%s\n===' % lookup

    if auth_app:
      (hn, al, iplist) = auth_app.zk_auth(lookup)
    else:
      (hn, al, iplist) = socket.gethostbyname_ex(lookup)

    if logging.DEBUG_IO: print 'hn=%s\nal=%s\niplist=%s\n' % (hn, al, iplist)

    # Extract auth error and extended quota info from CNAME replies
    if al:
      error, hg, hd, hc, junk = hn.split('.', 4)
      q_days = int(hd, 16)
      if '-' in hc:
        hc, ipc, ips = hc.split('-')
        hc = int(hc, 16)
        ipc = int(hc, 16)
        ips = int(hc, 16)
      else:
        q_conns = int(hc, 16)
        ipc = ips = None
    else:
      error = q_days = q_conns = ipc = ips = None

    # If not an authentication error, quota should be encoded as an IP.
    ip = iplist[0]
    if ip.startswith(AUTH_ERRORS):
      if not error and (ip.endswith(AUTH_ERR_USER_UNKNOWN) or
                        ip.endswith(AUTH_ERR_INVALID)):
        error = 'unauthorized'
    else:
      o = [int(x) for x in ip.split('.')]
      return ((((o[0]*256 + o[1])*256 + o[2])*256 + o[3]),
              q_days, q_conns, ipc, ips, None)

    # Errors on real errors are final.
    if not ip.endswith(AUTH_ERR_USER_UNKNOWN):
      return (None, q_days, q_conns, ipc, ips, error)

    # User unknown, fall through to local test.
    return (-1, q_days, q_conns, ipc, ips, error)

  def GetDomainQuota(self, protoport, domain, srand, token, sign,
                     recurse=True, check_token=True):
    if '-' in protoport:
      try:
        proto, port = protoport.split('-', 1)
        if proto == 'raw':
          port_list = self.server_raw_ports
        else:
          port_list = self.server_ports

        porti = int(port)
        if porti in self.server_aliasport: porti = self.server_aliasport[porti]
        if porti not in port_list and VIRTUAL_PN not in port_list:
          logging.LogInfo('Unsupported port request: %s (%s:%s)'
                          % (porti, protoport, domain))
          return (None, None, None, None, None, 'port')

      except ValueError:
        logging.LogError('Invalid port request: %s:%s' % (protoport, domain))
        return (None, None, None, None, None, 'port')
    else:
      proto, port = protoport, None

    if proto not in self.server_protos:
      logging.LogInfo('Invalid proto request: %s:%s' % (protoport, domain))
      return (None, None, None, None, None, 'proto')

    data = '%s:%s:%s' % (protoport, domain, srand)
    auth_error_type = None
    if ((not token) or
        (not check_token) or
        checkSignature(sign=token, payload=data)):

      secret = (self.GetBackendData(protoport, domain) or BE_NONE)[BE_SECRET]
      if not secret:
        secret = (self.GetBackendData(proto, domain) or BE_NONE)[BE_SECRET]

      if secret:
        if self.IsSignatureValid(sign, secret, protoport, domain, srand, token):
          return (-1, None, None, None, None, None)
        elif not (self.auth_domain or self.auth_domains):
          logging.LogError('Invalid signature for: %s (%s)' % (domain, protoport))
          return (None, None, None, None, None, auth_error_type or 'signature')

      if self.auth_domain or self.auth_domains:
        adom = ''
        adom_keys = self.auth_domains.keys()
        adom_keys.sort(key=lambda k: (len(k), k))  # Longest match will win
        for dom in adom_keys:
          if domain.endswith('.' + dom):
            adom = self.auth_domains[dom]
        if not adom:
          adom = self.auth_domain
        if adom:
          try:
            return self.LookupDomainQuota(srand, token, sign, protoport,
                                          domain.replace('*', '_any_'), adom)
          except Exception, e:
            # Lookup failed, fail open.
            if logging.DEBUG_IO: traceback.print_exc(file=sys.stderr)
            logging.LogError('Quota lookup failed: %s' % e)
            return (-2, None, None, None, None, None)

    logging.LogInfo('No authentication found for: %s (%s)'
                    % (domain, protoport))
    return (None, None, None, None, None, auth_error_type or 'unauthorized')

  def Overloaded(self):
    if not self.overload or not self.conns:
      return False
    return (len(self.conns.conns) > self.overload)

  def ConfigureFromFile(self, filename=None, data=None):
    if not filename: filename = self.rcfile

    if self.rcfile_recursion > 25:
      raise ConfigError('Nested too deep: %s' % filename)

    self.rcfiles_loaded.append(filename)
    optfile = data or open(filename)
    args = []
    for line in optfile:
      line = line.strip()
      if line and not line.startswith('#'):
        if line.startswith('END'): break
        if not line.startswith('-'): line = '--%s' % line
        args.append(re.sub(r'\s*:\s*', ':', re.sub(r'\s*=\s*', '=', line)))

    self.rcfile_recursion += 1
    self.Configure(args)
    self.rcfile_recursion -= 1
    return self

  def ConfigureFromDirectory(self, dirname):
    for fn in sorted(os.listdir(dirname)):
      if not fn.startswith('.') and fn.endswith('.rc'):
        self.ConfigureFromFile(os.path.join(dirname, fn))

  def HelpAndExit(self, longhelp=False):
    import manual
    print longhelp and manual.DOC() or manual.MINIDOC()
    sys.exit(0)

  def AddNewKite(self, kitespec, status=BE_STATUS_UNKNOWN, secret=None):
    new_specs = self.ArgToBackendSpecs(kitespec, status, secret)
    self.backends.update(new_specs)
    req = {}
    for server in self.conns.TunnelServers():
      req[server] = '\r\n'.join(PageKiteRequestHeaders(server, new_specs, {}))
    for tid, tunnels in self.conns.tunnels.iteritems():
      for tunnel in tunnels:
        server_name = tunnel.server_info[tunnel.S_NAME]
        if server_name in req:
          tunnel.SendChunked('NOOP: 1\r\n%s\r\n\r\n!' % req[server_name],
                             compress=False)
          del req[server_name]

  def ArgToBackendSpecs(self, arg, status=BE_STATUS_UNKNOWN, secret=None):
    protos, fe_domain, be_host, be_port = '', '', '', ''

    # Interpret the argument into a specification of what we want.
    parts = arg.split(':')
    if len(parts) == 5:
      protos, fe_domain, be_host, be_port, secret = parts
    elif len(parts) == 4:
      protos, fe_domain, be_host, be_port = parts
    elif len(parts) == 3:
      protos, fe_domain, be_port = parts
    elif len(parts) == 2:
      if (parts[1] == 'builtin') or ('.' in parts[0] and
                                            os.path.exists(parts[1])):
        fe_domain, be_port = parts[0], parts[1]
        protos = 'http'
      else:
        try:
          fe_domain, be_port = parts[0], '%s' % int(parts[1])
          protos = 'http'
        except:
          be_port = ''
          protos, fe_domain = parts
    elif len(parts) == 1:
      fe_domain = parts[0]
    else:
      return {}

    # Allow http:// as a common typo instead of http:
    fe_domain = fe_domain.replace('/', '').lower()

    # Allow easy referencing of built-in HTTPD
    if be_port == 'builtin':
      self.BindUiSspec()
      be_host, be_port = self.ui_sspec

    # Specs define what we are searching for...
    specs = []
    if protos:
      for proto in protos.replace('/', '-').lower().split(','):
        if proto == 'ssh':
          specs.append(['raw', '22', fe_domain, be_host, be_port or '22', secret])
        else:
          if '-' in proto:
            proto, port = proto.split('-')
          else:
            if len(parts) == 1:
              port = '*'
            else:
              port = ''
          specs.append([proto, port, fe_domain, be_host, be_port, secret])
    else:
      specs = [[None, '', fe_domain, be_host, be_port, secret]]

    backends = {}
    # For each spec, search through the existing backends and copy matches
    # or just shared secrets for partial matches.
    for proto, port, fdom, bhost, bport, sec in specs:
      matches = 0
      for bid in self.backends:
        be = self.backends[bid]
        if fdom and fdom != be[BE_DOMAIN]: continue
        if not sec and be[BE_SECRET]: sec = be[BE_SECRET]
        if proto and (proto != be[BE_PROTO]): continue
        if bhost and (bhost.lower() != be[BE_BHOST]): continue
        if bport and (int(bport) != be[BE_BHOST]): continue
        if port and (port != '*') and (int(port) != be[BE_PORT]): continue
        backends[bid] = be[:]
        backends[bid][BE_STATUS] = status
        matches += 1

      if matches == 0:
        proto = (proto or 'http')
        bhost = (bhost or 'localhost')
        bport = (bport or (proto in ('http', 'httpfinger', 'websocket') and 80)
                       or (proto == 'irc' and 6667)
                       or (proto == 'https' and 443)
                       or (proto == 'minecraft' and 25565)
                       or (proto == 'finger' and 79))
        if port:
          bid = '%s-%d:%s' % (proto, int(port), fdom)
        else:
          bid = '%s:%s' % (proto, fdom)

        backends[bid] = BE_NONE[:]
        backends[bid][BE_PROTO] = proto
        backends[bid][BE_PORT] = port and int(port) or ''
        backends[bid][BE_DOMAIN] = fdom
        backends[bid][BE_BHOST] = bhost.lower()
        backends[bid][BE_BPORT] = int(bport)
        backends[bid][BE_SECRET] = sec
        backends[bid][BE_STATUS] = status

    return backends

  def BindUiSspec(self, force=False):
    # Create the UI thread
    if self.ui_httpd and self.ui_httpd.httpd:
      if not force: return self.ui_sspec
      self.ui_httpd.httpd.socket.close()

    self.ui_sspec = self.ui_sspec or ('localhost', 0)
    self.ui_httpd = HttpUiThread(self, self.conns,
                                 handler=self.ui_request_handler,
                                 server=self.ui_http_server,
                                 ssl_pem_filename = self.ui_pemfile)
    return self.ui_sspec

  def LoadMOTD(self):
    if self.motd:
      try:
        f = open(self.motd, 'r')
        self.motd_message = ''.join(f.readlines()).strip()[:8192]
        f.close()
      except (OSError, IOError):
        pass

  def SetPem(self, filename):
    self.ui_pemfile = filename
    try:
      p = os.popen('openssl x509 -noout -fingerprint -in %s' % filename, 'r')
      data = p.read().strip()
      p.close()
      self.ui_pemfingerprint = data.split('=')[1]
    except (OSError, ValueError):
      pass

  def GetDefaultIPsPerSecond(self, dom=None, limit=None):
    ips, secs = (limit or self.ratelimit_ips.get(dom or '*', '')).split('/')
    return int(ips), int(secs)

  def Configure(self, argv):
    self.conns = self.conns or Connections(self)
    opts, args = getopt.getopt(argv, OPT_FLAGS, OPT_ARGS)

    for opt, arg in opts:
      if opt in ('-o', '--optfile'):
        self.ConfigureFromFile(arg)
      elif opt in ('-O', '--optdir'):
        self.ConfigureFromDirectory(arg)
      elif opt in ('-S', '--savefile'):
        if self.savefile: raise ConfigError('Multiple save-files!')
        self.savefile = arg
      elif opt == '--shell':
        self.shell = True
      elif opt == '--save':
        self.save = True
      elif opt == '--only':
        self.save = self.kite_only = True
        if self.kite_remove or self.kite_add or self.kite_disable:
          raise ConfigError('One change at a time please!')
      elif opt == '--add':
        self.save = self.kite_add = True
        if self.kite_remove or self.kite_only or self.kite_disable:
          raise ConfigError('One change at a time please!')
      elif opt == '--remove':
        self.save = self.kite_remove = True
        if self.kite_add or self.kite_only or self.kite_disable:
          raise ConfigError('One change at a time please!')
      elif opt == '--disable':
        self.save = self.kite_disable = True
        if self.kite_add or self.kite_only or self.kite_remove:
          raise ConfigError('One change at a time please!')
      elif opt == '--list': pass

      elif opt in ('-I', '--pidfile'): self.pidfile = arg
      elif opt in ('-L', '--logfile'): self.logfile = arg
      elif opt in ('-Z', '--daemonize'):
        self.daemonize = True
        if not self.ui.DAEMON_FRIENDLY: self.ui = NullUi()
      elif opt in ('-U', '--runas'):
        import pwd
        import grp
        parts = arg.split(':')
        if len(parts) > 1:
          self.setuid, self.setgid = (pwd.getpwnam(parts[0])[2],
                                      grp.getgrnam(parts[1])[2])
        else:
          self.setuid = pwd.getpwnam(parts[0])[2]
        self.main_loop = False

      elif opt in ('-X', '--httppass'): self.ui_password = arg
      elif opt in ('-P', '--pemfile'): self.SetPem(arg)
      elif opt in ('--selfsign', ):
        pf = self.rcfile.replace('.rc', '.pem').replace('.cfg', '.pem')
        if not os.path.exists(pf):
          CreateSelfSignedCert(pf, self.ui)
        self.SetPem(pf)
      elif opt in ('-H', '--httpd'):
        parts = arg.split(':')
        host = parts[0] or 'localhost'
        if len(parts) > 1:
          self.ui_sspec = self.ui_sspec_cfg = (host, int(parts[1]))
        else:
          self.ui_sspec = self.ui_sspec_cfg = (host, 0)

      elif opt == '--nowebpath':
        host, path = arg.split(':', 1)
        if host in self.ui_paths and path in self.ui_paths[host]:
          del self.ui_paths[host][path]
      elif opt == '--webpath':
        host, path, policy, fpath = arg.split(':', 3)

        # Defaults...
        path = path or os.path.normpath(fpath)
        host = host or '*'
        policy = policy or WEB_POLICY_DEFAULT

        if policy not in WEB_POLICIES:
          raise ConfigError('Policy must be one of: %s' % WEB_POLICIES)
        elif os.path.isdir(fpath):
          if not path.endswith('/'): path += '/'

        hosti = self.ui_paths.get(host, {})
        hosti[path] = (policy or 'public', os.path.abspath(fpath))
        self.ui_paths[host] = hosti

      elif opt == '--tls_default': self.tls_default = arg
      elif opt == '--tls_legacy': self.tls_legacy = True
      elif opt == '--tls_endpoint':
        name, pemfile = arg.split(':', 1)
        ctx = socks.MakeBestEffortSSLContext(legacy=self.tls_legacy)
        ctx.use_privatekey_file(pemfile)
        ctx.use_certificate_chain_file(pemfile)
        self.tls_endpoints[name] = (pemfile, ctx)

      elif opt in ('-D', '--dyndns'):
        if arg.startswith('http'):
          self.dyndns = (arg, {'user': '', 'pass': ''})
        elif '@' in arg:
          splits = arg.split('@')
          provider = splits.pop()
          usrpwd = '@'.join(splits)
          if provider in DYNDNS: provider = DYNDNS[provider]
          if ':' in usrpwd:
            usr, pwd = usrpwd.split(':', 1)
            self.dyndns = (provider, {'user': usr, 'pass': pwd})
          else:
            self.dyndns = (provider, {'user': usrpwd, 'pass': ''})
        elif arg:
          if arg in DYNDNS: arg = DYNDNS[arg]
          self.dyndns = (arg, {'user': '', 'pass': ''})
        else:
          self.dyndns = None

      elif opt in ('-p', '--ports'):
        self.server_ports = [int(x) for x in arg.split(',')]
      elif opt == '--portalias':
        port, alias = arg.split(':')
        self.server_portalias[int(port)] = int(alias)
        self.server_aliasport[int(alias)] = int(port)
      elif opt == '--protos': self.server_protos = [x.lower() for x in arg.split(',')]
      elif opt == '--rawports':
        self.server_raw_ports = [(x == VIRTUAL_PN and x or int(x)) for x in arg.split(',')]
      elif opt in ('-h', '--host'): self.server_host = arg
      elif opt == '--auththreads':
        self.auth_threads = int(arg)
      elif opt in ('-A', '--authdomain'):
        if ':' in arg:
          d, a = arg.split(':')
          self.auth_domains[d.lower()] = a
        else:
          self.auth_domains = {}
          self.auth_domain = arg
      elif opt == '--motd':
        self.motd = arg
        self.LoadMOTD()
      elif opt == '--noupgradeinfo': self.upgrade_info = []
      elif opt == '--upgradeinfo':
        version, tag, md5, human_url, file_url = arg.split(';')
        self.upgrade_info.append((version, tag, md5, human_url, file_url))
      elif opt == '--keepalive':
        if arg == 'auto':
          self.keepalive = None
        else:
          self.keepalive = max(PING_INTERVAL_MIN, int(arg))
      elif opt in ('-f', '--isfrontend'):
        self.isfrontend = True
        logging.LOG_THRESHOLD *= 4

      elif opt in ('-a', '--all'): self.require_all = True
      elif opt in ('-N', '--new'): self.servers_new_only = True
      elif opt == '--ratelimit_ips':
        if ':' in arg:
          which, limit = arg.split(':')
        else:
          which, limit = '*', arg
        self.GetDefaultIPsPerSecond(None, limit.strip())  # ValueErrors if bad
        self.ratelimit_ips[which.strip()] = limit.strip()
      elif opt == '--accept_acl_file':
        self.accept_acl_file = arg
      elif opt == '--client_acl':
        policy, pattern = arg.split(':', 1)
        self.client_acls.append((policy, pattern))
      elif opt == '--tunnel_acl':
        policy, pattern = arg.split(':', 1)
        self.tunnel_acls.append((policy, pattern))
      elif opt in ('--noproxy', ):
        self.no_proxy = True
        self.proxy_servers = []
        socks.setdefaultproxy()
      elif opt in ('--proxy', '--socksify', '--torify'):
        if opt == '--proxy':
          socks.adddefaultproxy(*socks.parseproxy(arg))
        else:
          (host, port) = arg.rsplit(':', 1)
          socks.adddefaultproxy(socks.PROXY_TYPE_SOCKS5, host, int(port))

        if not self.proxy_servers:
          # Make DynDNS updates go via the proxy.
          socks.wrapmodule(urllib)
          self.proxy_servers = [arg]
        else:
          self.proxy_servers.append(arg)

        if opt == '--torify':
          self.servers_new_only = True  # Disable initial DNS lookups (leaks)
          self.servers_no_ping = True   # Disable front-end pings
          self.crash_report_url = None  # Disable crash reports

          # This increases the odds of unrelated requests getting lumped
          # together in the tunnel, which makes traffic analysis harder.
          compat.SEND_ALWAYS_BUFFERS = True

      elif opt == '--ca_certs':
        if arg == 'auto':
          self.SetDefaultCACerts(use_curl_bundle=True)
        else:
          self.ca_certs = arg
      elif opt == '--fe_certname':
        if arg == '':
          self.fe_certname = []
        else:
          cert = arg.lower()
          if cert not in self.fe_certname: self.fe_certname.append(cert)
      elif opt == '--fe_nocertcheck':
        self.fe_nocertcheck = True
      elif opt == '--service_xmlrpc': self.service_xmlrpc = arg
      elif opt == '--frontend': self.servers_manual.append(arg)
      elif opt == '--nofrontend': self.servers_never.append(arg)
      elif opt == '--frontends':
        count, domain, port = arg.split(':')
        self.servers_auto = (int(count), domain, int(port))

      elif opt in ('--errorurl', '-E'):
        if ':http' in arg:
          dom, url = arg.split(':', 1)
          self.error_urls[dom] = url
        else:
          self.error_url = arg
      elif opt == '--fingerpath': self.finger_path = arg
      elif opt == '--kitename': self.kitename = arg
      elif opt == '--kitesecret': self.kitesecret = arg

      elif opt in ('--service_on', '--service_off',
                   '--backend', '--define_backend'):
        if opt in ('--backend', '--service_on'):
          status = BE_STATUS_UNKNOWN
        else:
          status = BE_STATUS_DISABLED
        bes = self.ArgToBackendSpecs(arg.replace('@kitesecret', self.kitesecret)
                                        .replace('@kitename', self.kitename),
                                     status=status)
        for bid in bes:
          if bid in self.backends:
            raise ConfigError("Same service/domain defined twice: %s" % bid)
          if not self.kitename:
            self.kitename = bes[bid][BE_DOMAIN]
            self.kitesecret = bes[bid][BE_SECRET]
        self.backends.update(bes)
      elif opt in ('--be_config', '--service_cfg'):
        host, key, val = arg.split(':', 2)
        if key.startswith('user/'): key = key.replace('user/', 'password/')
        hostc = self.be_config.get(host, {})
        hostc[key] = {'True': True, 'False': False, 'None': None}.get(val, val)
        self.be_config[host] = hostc

      elif opt == '--domain':
        protos, domain, secret = arg.split(':')
        if protos in ('*', ''): protos = ','.join(self.server_protos)
        for proto in protos.split(','):
          bid = '%s:%s' % (proto, domain)
          if bid in self.backends:
            raise ConfigError("Same service/domain defined twice: %s" % bid)
          self.backends[bid] = BE_NONE[:]
          self.backends[bid][BE_PROTO] = proto
          self.backends[bid][BE_DOMAIN] = domain
          self.backends[bid][BE_SECRET] = secret
          self.backends[bid][BE_STATUS] = BE_STATUS_UNKNOWN

      elif opt == '--insecure': self.insecure = True
      elif opt == '--noprobes': self.no_probes = True
      elif opt == '--nofrontend': self.isfrontend = False
      elif opt == '--nodaemonize': self.daemonize = False
      elif opt == '--noall': self.require_all = False
      elif opt == '--nozchunks': self.disable_zchunks = True
      elif opt == '--nullui': self.ui = NullUi()
      elif opt == '--remoteui':
        import pagekite.ui.remote
        self.ui = pagekite.ui.remote.RemoteUi()
      elif opt == '--uiport': self.ui_port = int(arg)
      elif opt == '--sslzlib': self.enable_sslzlib = True
      elif opt == '--watch':
        self.watch_level[0] = int(arg)
      elif opt == '--overload':
        self.overload = int(arg)
      elif opt == '--debugio':
        logging.DEBUG_IO = True
      elif opt == '--buffers': self.buffer_max = int(arg)
      elif opt == '--nocrashreport': self.crash_report_url = None
      elif opt == '--noloop': self.main_loop = False
      elif opt == '--local':
        self.SetLocalSettings([int(p) for p in arg.split(',')])
        if not 'localhost' in args: args.append('localhost')
      elif opt == '--defaults': self.SetServiceDefaults()
      elif opt == '--whitelabel': self.SetWhitelabelDefaults(arg, secure=False)
      elif opt == '--whitelabels': self.SetWhitelabelDefaults(arg, secure=True)
      elif opt in ('--clean', '--nopyopenssl', '--nossl', '--settings',
                   '--signup', '--friendly'):
        # These are handled outside the main loop, we just ignore them.
        pass
      elif opt in ('--webroot', '--webaccess', '--webindexes',
                   '--noautosave', '--autosave', '--reloadfile',
                   '--delete_backend'):
        # FIXME: These are deprecated, we should probably warn the user.
        pass
      elif opt == '--help':
        self.HelpAndExit(longhelp=True)

      elif opt == '--controlpanel':
        import webbrowser
        webbrowser.open(self.LoginUrl())
        sys.exit(0)

      elif opt == '--controlpass':
        print self.ConfigSecret()
        sys.exit(0)

      else:
        self.HelpAndExit()

    # Make sure these are configured before we try and do XML-RPC stuff.
    socks.DEBUG = (logging.DEBUG_IO or socks.DEBUG) and logging.LogDebug
    if self.ca_certs:
      socks.setdefaultcertfile(self.ca_certs)

    # Handle the user-friendly argument stuff and simple registration.
    return self.ParseFriendlyBackendSpecs(args)

  def ParseFriendlyBackendSpecs(self, args):
    just_these_backends = {}
    just_these_webpaths = {}
    just_these_be_configs = {}
    argsets = []
    while 'AND' in args:
      argsets.append(args[0:args.index('AND')])
      args[0:args.index('AND')+1] = []
    if args:
      argsets.append(args)

    for args in argsets:
      # Extract the config options first...
      be_config = [p for p in args if p.startswith('+')]
      args = [p for p in args if not p.startswith('+')]

      fe_spec = (args.pop().replace('@kitesecret', self.kitesecret)
                           .replace('@kitename', self.kitename))
      if os.path.exists(fe_spec):
        raise ConfigError('Is a local file: %s' % fe_spec)

      be_paths = []
      be_path_prefix = ''
      if len(args) == 0:
        be_spec = ''
      elif len(args) == 1:
        if '*' in args[0] or '?' in args[0]:
          if sys.platform[:3] in ('win', 'os2'):
            be_paths = [args[0]]
            be_spec = 'builtin'
        elif os.path.exists(args[0]):
          be_paths = [args[0]]
          be_spec = 'builtin'
        else:
          be_spec = args[0]
      else:
        be_spec = 'builtin'
        be_paths = args[:]

      be_proto = 'http' # A sane default...
      if be_spec == '':
        be = None
      else:
        be = be_spec.replace('/', '').split(':')
        if be[0].lower() in ('http', 'http2', 'http3', 'https',
                             'httpfinger', 'finger', 'ssh', 'irc'):
          be_proto = be.pop(0)
          if len(be) < 2:
            be.append({'http': '80', 'http2': '80', 'http3': '80',
                       'https': '443', 'irc': '6667',
                       'httpfinger': '80', 'finger': '79',
                       'ssh': '22'}[be_proto])
        if len(be) > 2:
          raise ConfigError('Bad back-end definition: %s' % be_spec)
        if len(be) < 2:
          try:
            if be[0] != 'builtin':
              int(be[0])
            be = ['localhost', be[0]]
          except ValueError:
            raise ConfigError('`%s` should be a file, directory, port or '
                              'protocol' % be_spec)

      # Extract the path prefix from the fe_spec
      fe_urlp = fe_spec.split('/', 3)
      if len(fe_urlp) == 4:
        fe_spec = '/'.join(fe_urlp[:3])
        be_path_prefix = '/' + fe_urlp[3]

      fe = fe_spec.replace('/', '').split(':')
      if len(fe) == 3:
        fe = ['%s-%s' % (fe[0], fe[2]), fe[1]]
      elif len(fe) == 2:
        try:
          fe = ['%s-%s' % (be_proto, int(fe[1])), fe[0]]
        except ValueError:
          pass
      elif len(fe) == 1 and be:
        fe = [be_proto, fe[0]]

      # Do our own globbing on Windows
      if sys.platform[:3] in ('win', 'os2'):
        import glob
        new_paths = []
        for p in be_paths:
          new_paths.extend(glob.glob(p))
        be_paths = new_paths

      for f in be_paths:
        if not os.path.exists(f):
          raise ConfigError('File or directory not found: %s' % f)

      spec = ':'.join(fe)
      if be: spec += ':' + ':'.join(be)
      specs = self.ArgToBackendSpecs(spec)
      just_these_backends.update(specs)

      spec = specs[specs.keys()[0]]
      http_host = '%s/%s' % (spec[BE_DOMAIN], spec[BE_PORT] or '80')
      if be_config:
        # Map the +foo=bar values to per-site config settings.
        host_config = just_these_be_configs.get(http_host, {})
        for cfg in be_config:
          if '=' in cfg:
            key, val = cfg[1:].split('=', 1)
          elif cfg.startswith('+no'):
            key, val = cfg[3:], False
          else:
            key, val = cfg[1:], True
          if ':' in key:
            raise ConfigError('Please do not use : in web config keys.')
          if key.startswith('user/'): key = key.replace('user/', 'password/')
          host_config[key] = val
        just_these_be_configs[http_host] = host_config

      if be_paths:
        host_paths = just_these_webpaths.get(http_host, {})
        host_config = just_these_be_configs.get(http_host, {})
        rand_seed = '%s:%x' % (specs[specs.keys()[0]][BE_SECRET],
                               time.time()/3600)

        first = (len(host_paths.keys()) == 0) or be_path_prefix
        paranoid = host_config.get('hide', False)
        set_root = host_config.get('root', True)
        if len(be_paths) == 1:
          skip = len(os.path.dirname(be_paths[0]))
        else:
          skip = len(os.path.dirname(os.path.commonprefix(be_paths)+'X'))

        for path in be_paths:
          phead, ptail = os.path.split(path)
          if paranoid:
            if path.endswith('/'): path = path[0:-1]
            webpath = '%s/%s' % (sha1hex(rand_seed+os.path.dirname(path))[0:9],
                                  os.path.basename(path))
          elif (first and set_root and os.path.isdir(path)):
            webpath = ''
          elif (os.path.isdir(path) and
                not path.startswith('.') and
                not os.path.isabs(path)):
            webpath = path[skip:] + '/'
          elif path == '.':
            webpath = ''
          else:
            webpath = path[skip:]
          while webpath.endswith('/.'):
            webpath = webpath[:-2]
          host_paths[(be_path_prefix + '/' + webpath).replace('///', '/'
                                                    ).replace('//', '/')
                     ] = (WEB_POLICY_DEFAULT, os.path.abspath(path))
          first = False
        just_these_webpaths[http_host] = host_paths

    need_registration = {}
    for be in just_these_backends.values():
      if not be[BE_SECRET]:
        if self.kitesecret and be[BE_DOMAIN] == self.kitename:
          be[BE_SECRET] = self.kitesecret
        elif not self.kite_remove and not self.kite_disable:
          need_registration[be[BE_DOMAIN]] = True

    for domain in need_registration:
      if '.' not in domain:
        raise ConfigError('Not valid domain: %s' % domain)

    for domain in need_registration:
      result = self.RegisterNewKite(kitename=domain)
      if not result:
        raise ConfigError("Not sure what to do with %s, giving up." % domain)

      # Update the secrets...
      rdom, rsecret = result
      for be in just_these_backends.values():
        if be[BE_DOMAIN] == domain: be[BE_SECRET] = rsecret

      # Update the kite names themselves, if they changed.
      if rdom != domain:
        for bid in just_these_backends.keys():
          nbid = bid.replace(':'+domain, ':'+rdom)
          if nbid != bid:
            just_these_backends[nbid] = just_these_backends[bid]
            just_these_backends[nbid][BE_DOMAIN] = rdom
            del just_these_backends[bid]

    if just_these_backends.keys():
      if self.kite_add:
        self.backends.update(just_these_backends)
      elif self.kite_remove:
        try:
          for bid in just_these_backends:
            be = self.backends[bid]
            if be[BE_PROTO] in ('http', 'http2', 'http3'):
              http_host = '%s/%s' % (be[BE_DOMAIN], be[BE_PORT] or '80')
              if http_host in self.ui_paths: del self.ui_paths[http_host]
              if http_host in self.be_config: del self.be_config[http_host]
            del self.backends[bid]
        except KeyError:
          raise ConfigError('No such kite: %s' % bid)
      elif self.kite_disable:
        try:
          for bid in just_these_backends:
            self.backends[bid][BE_STATUS] = BE_STATUS_DISABLED
        except KeyError:
          raise ConfigError('No such kite: %s' % bid)
      elif self.kite_only:
        for be in self.backends.values(): be[BE_STATUS] = BE_STATUS_DISABLED
        self.backends.update(just_these_backends)
      else:
        # Nothing explictly requested: 'only' behavior with a twist;
        # If kites are new, don't make disables persist on save.
        for be in self.backends.values():
          be[BE_STATUS] = (need_registration and BE_STATUS_DISABLE_ONCE
                                              or BE_STATUS_DISABLED)
        self.backends.update(just_these_backends)

      self.ui_paths.update(just_these_webpaths)
      self.be_config.update(just_these_be_configs)

    return self

  def GetServiceXmlRpc(self):
    service = self.service_xmlrpc
    return xmlrpclib.ServerProxy(self.service_xmlrpc, None, None, False)

  def _KiteInfo(self, kitename):
    is_service_domain = kitename and SERVICE_DOMAIN_RE.search(kitename)
    is_subdomain_of = is_cname_for = is_cname_ready = False
    secret = None

    for be in self.backends.values():
      if be[BE_SECRET] and (be[BE_DOMAIN] == kitename):
        secret = be[BE_SECRET]

    if is_service_domain:
      parts = kitename.split('.')
      if '-' in parts[0]:
        parts[0] = '-'.join(parts[0].split('-')[1:])
        is_subdomain_of = '.'.join(parts)
      elif len(parts) > 3:
        is_subdomain_of = '.'.join(parts[1:])

    elif kitename:
      try:
        (hn, al, ips) = socket.gethostbyname_ex(kitename)
        if hn != kitename and SERVICE_DOMAIN_RE.search(hn):
          is_cname_for = hn
      except:
        pass

    return (secret, is_subdomain_of, is_service_domain,
            is_cname_for, is_cname_ready)

  def RegisterNewKite(self, kitename=None, first=False,
                            ask_be=False, autoconfigure=False):
    registered = False
    if kitename:
      (secret, is_subdomain_of, is_service_domain,
       is_cname_for, is_cname_ready) = self._KiteInfo(kitename)
      if secret:
        self.ui.StartWizard('Updating kite: %s' % kitename)
        registered = True
      else:
        self.ui.StartWizard('Creating kite: %s' % kitename)
    else:
      if first:
        self.ui.StartWizard('Create your first kite')
      else:
        self.ui.StartWizard('Creating a new kite')
      is_subdomain_of = is_service_domain = False
      is_cname_for = is_cname_ready = False

    # This is the default...
    be_specs = ['http:%s:localhost:80']

    if self.ca_certs == self.ca_certs_default:
      # We're using the defaults, but the defaults might be lame so we
      # reset them here, allowing for downloading the cURL bundle.
      self.SetDefaultCACerts(use_curl_bundle=True)

    service = self.GetServiceXmlRpc()
    service_accounts = {}
    if self.kitename and self.kitesecret:
      service_accounts[self.kitename] = self.kitesecret

    for be in self.backends.values():
      if SERVICE_DOMAIN_RE.search(be[BE_DOMAIN]):
        if be[BE_DOMAIN] == is_cname_for:
          is_cname_ready = True
        if be[BE_SECRET] not in service_accounts.values():
          service_accounts[be[BE_DOMAIN]] = be[BE_SECRET]
    service_account_list = service_accounts.keys()

    if registered:
      state = ['choose_backends']
    if service_account_list:
      state = ['choose_kite_account']
    else:
      state = ['use_service_question']
    history = []

    def Goto(goto, back_skips_current=False):
      if not back_skips_current: history.append(state[0])
      state[0] = goto
    def Back():
      if history:
        state[0] = history.pop(-1)
      else:
        Goto('abort')

    register = is_cname_for or kitename
    account = email = None
    while 'end' not in state:
      try:
        if 'use_service_question' in state:
          ch = self.ui.AskYesNo('Use the PageKite.net service?',
                                pre=['<b>Welcome to PageKite!</b>',
                                     '',
                                     'Please answer a few quick questions to',
                                     'create your first kite.',
                                     '',
                                     'By continuing, you agree to play nice',
                                     'and abide by the Terms of Service at:',
                                     '- <a href="%s">%s</a>' % (SERVICE_TOS_URL, SERVICE_TOS_URL)],
                                default=True, back=-1, no='Abort')
          if ch is True:
            self.SetServiceDefaults(clobber=True)
            socks.setdefaultcertfile(self.ca_certs)
            if not kitename:
              Goto('service_signup_email')
            elif is_cname_for and is_cname_ready:
              register = kitename
              Goto('service_signup_email')
            elif is_service_domain:
              register = is_cname_for or kitename
              if is_subdomain_of:
                # FIXME: Shut up if parent is already in local config!
                Goto('service_signup_is_subdomain')
              else:
                Goto('service_signup_email')
            else:
              Goto('service_signup_bad_domain')
          else:
            Goto('manual_abort')

        elif 'service_login_email' in state:
          p = None
          while not email or not p:
            (email, p) = self.ui.AskLogin('Please log on ...', pre=[
                                            'By logging on to %s,' % self.service_provider,
                                            'you will be able to use this kite',
                                            'with your pre-existing account.'
                                          ], email=email, back=(email, False))
            if email and p:
              try:
                self.ui.Working('Logging on to your account')
                service_accounts[email] = service.getSharedSecret(email, p)
                # FIXME: Should get the list of preconfigured kites via. RPC
                #        so we don't try to create something that already
                #        exists?  Or should the RPC not just not complain?
                account = email
                Goto('create_kite')
              except:
                email = p = None
                self.ui.Tell(['Login failed! Try again?'], error=True)
            if p is False:
              Back()
              break

        elif ('service_signup_is_subdomain' in state):
          ch = self.ui.AskYesNo('Use this name?',
                                pre=['%s is a sub-domain.' % kitename, '',
                                     '<b>NOTE:</b> This process will fail if you',
                                     'have not already registered the parent',
                                     'domain, %s.' % is_subdomain_of],
                                default=True, back=-1)
          if ch is True:
            if account:
              Goto('create_kite')
            elif email:
              Goto('service_signup')
            else:
              Goto('service_signup_email')
          elif ch is False:
            Goto('service_signup_kitename')
          else:
            Back()

        elif ('service_signup_bad_domain' in state or
              'service_login_bad_domain' in state):
          if is_cname_for:
            alternate = is_cname_for
            ch = self.ui.AskYesNo('Create both?',
                                  pre=['%s is a CNAME for %s.' % (kitename, is_cname_for)],
                                  default=True, back=-1)
          else:
            alternate = kitename.split('.')[-2]+'.'+SERVICE_DOMAINS[0]
            ch = self.ui.AskYesNo('Try to create %s instead?' % alternate,
                                  pre=['Sorry, %s is not a valid service domain.' % kitename],
                                  default=True, back=-1)
          if ch is True:
            register = alternate
            Goto(state[0].replace('bad_domain', 'email'))
          elif ch is False:
            register = alternate = kitename = False
            Goto('service_signup_kitename', back_skips_current=True)
          else:
            Back()

        elif 'service_signup_email' in state:
          email = self.ui.AskEmail('<b>What is your e-mail address?</b>',
                                   pre=['We need to be able to contact you',
                                        'now and then with news about the',
                                        'service and your account.',
                                        '',
                                        'Your details will be kept private.'],
                                   back=False)
          if email and register:
            Goto('service_signup')
          elif email:
            Goto('service_signup_kitename')
          else:
            Back()

        elif ('service_signup_kitename' in state or
              'service_ask_kitename' in state):
          try:
            self.ui.Working('Fetching list of available domains')
            domains = service.getAvailableDomains('', '')
          except:
            domains = ['.%s' % x for x in SERVICE_DOMAINS_SIGNUP]

          ch = self.ui.AskKiteName(domains, 'Name this kite:',
                                 pre=['Your kite name becomes the public name',
                                      'of your personal server or web-site.',
                                      '',
                                      'Names are provided on a first-come,',
                                      'first-serve basis. You can create more',
                                      'kites with different names later on.'],
                                 back=False)
          if ch:
            kitename = register = ch
            (secret, is_subdomain_of, is_service_domain,
             is_cname_for, is_cname_ready) = self._KiteInfo(ch)
            if secret:
              self.ui.StartWizard('Updating kite: %s' % kitename)
              registered = True
            else:
              self.ui.StartWizard('Creating kite: %s' % kitename)
            Goto('choose_backends')
          else:
            Back()

        elif 'choose_backends' in state:
          if ask_be and autoconfigure:
            skip = False
            ch = self.ui.AskBackends(kitename, ['http'], ['80'], [],
                                     'Enable which service?', back=False, pre=[
                                  'You control which of your files or servers',
                                  'PageKite exposes to the Internet. ',
                                     ], default=','.join(be_specs))
            if ch:
              be_specs = ch.split(',')
          else:
            skip = ch = True

          if ch:
            if registered:
              Goto('create_kite', back_skips_current=skip)
            elif is_subdomain_of:
              Goto('service_signup_is_subdomain', back_skips_current=skip)
            elif account:
              Goto('create_kite', back_skips_current=skip)
            elif email:
              Goto('service_signup', back_skips_current=skip)
            else:
              Goto('service_signup_email', back_skips_current=skip)
          else:
            Back()

        elif 'service_signup' in state:
          try:
            self.ui.Working('Signing up')
            details = service.signUp(email, register)
            if details.get('secret', False):
              service_accounts[email] = details['secret']
              self.ui.AskYesNo('Continue?', pre=[
                '<b>Your kite is ready to fly!</b>',
                '',
                '<b>Note:</b> To complete the signup process,',
                'check your e-mail (and spam folders) for',
                'activation instructions. You can give',
                'PageKite a try first, but un-activated',
                'accounts are disabled after %d minutes.' % details['timeout'],
              ], yes='Finish', no=False, default=True)
              self.ui.EndWizard()
              if autoconfigure:
                for be_spec in be_specs:
                  self.backends.update(self.ArgToBackendSpecs(
                                                    be_spec % register,
                                                    secret=details['secret']))
              self.added_kites = True
              return (register, details['secret'])
            else:
              error = details.get('error', 'unknown')
          except IOError:
            error = 'network'
          except:
            error = '%s' % (sys.exc_info(), )

          if error == 'pleaselogin':
            self.ui.ExplainError(error, 'Signup failed!',
                                 subject=email)
            Goto('service_login_email', back_skips_current=True)
          elif error == 'email':
            self.ui.ExplainError(error, 'Signup failed!',
                                 subject=register)
            Goto('service_login_email', back_skips_current=True)
          elif error in ('domain', 'domaintaken', 'subdomain'):
            self.ui.ExplainError(error, 'Invalid domain!',
                                 subject=register)
            register, kitename = None, None
            Goto('service_signup_kitename', back_skips_current=True)
          elif error == 'network':
            self.ui.ExplainError(error, 'Network error!',
                                 subject=self.service_provider)
            Goto('service_signup', back_skips_current=True)
          else:
            self.ui.ExplainError(error, 'Unknown problem!')
            print 'FIXME!  Error is %s' % error
            Goto('abort')

        elif 'choose_kite_account' in state:
          choices = service_account_list[:]
          choices.append('Use another service provider')
          justdoit = (len(service_account_list) == 1)
          if justdoit:
            ch = 1
          else:
            ch = self.ui.AskMultipleChoice(choices, 'Register with',
                                       pre=['Choose an account for this kite:'],
                                           default=1)
          account = choices[ch-1]
          if ch == len(choices):
            Goto('manual_abort')
          elif kitename:
            Goto('choose_backends', back_skips_current=justdoit)
          else:
            Goto('service_ask_kitename', back_skips_current=justdoit)

        elif 'create_kite' in state:
          secret = service_accounts[account]
          subject = None
          cfgs = {}
          result = {}
          error = None
          try:
            if registered and kitename and secret:
              pass
            elif is_cname_for and is_cname_ready:
              self.ui.Working('Creating your kite')
              subject = kitename
              result = service.addCnameKite(account, secret, kitename)
              time.sleep(2) # Give the service side a moment to replicate...
            else:
              self.ui.Working('Creating your kite')
              subject = register
              result = service.addKite(account, secret, register)
              time.sleep(2) # Give the service side a moment to replicate...
              for be_spec in be_specs:
                cfgs.update(self.ArgToBackendSpecs(be_spec % register,
                                                   secret=secret))
              if is_cname_for == register and 'error' not in result:
                subject = kitename
                result.update(service.addCnameKite(account, secret, kitename))

            error = result.get('error', None)
            if not error:
              for be_spec in be_specs:
                cfgs.update(self.ArgToBackendSpecs(be_spec % kitename,
                                                   secret=secret))
          except Exception, e:
            error = '%s' % e

          if error:
            self.ui.ExplainError(error, 'Kite creation failed!',
                                 subject=subject)
            Goto('abort')
          else:
            self.ui.Tell(['Success!'])
            self.ui.EndWizard()
            if autoconfigure: self.backends.update(cfgs)
            self.added_kites = True
            return (register or kitename, secret)

        elif 'manual_abort' in state:
          if self.ui.Tell(['Aborted!', '',
            'Please manually add information about your',
            'kites and front-ends to the configuration file:',
            '', ' %s' % self.rcfile],
                          error=True, back=False) is False:
            Back()
          else:
            self.ui.EndWizard()
            if self.ui.ALLOWS_INPUT: return None
            sys.exit(0)

        elif 'abort' in state:
          self.ui.EndWizard()
          if self.ui.ALLOWS_INPUT: return None
          sys.exit(0)

        else:
          raise ConfigError('Unknown state: %s' % state)

      except KeyboardInterrupt:
        sys.stderr.write('\n')
        if history:
          Back()
        else:
          raise KeyboardInterrupt()

    self.ui.EndWizard()
    return None

  def CheckConfig(self):
    if self.ui_sspec: self.BindUiSspec()
    if (not self.servers_manual and
        not self.servers_auto and
        not self.isfrontend):
      if not self.servers and not self.ui.ALLOWS_INPUT:
        raise ConfigError('Nothing to do!  List some servers, or run me as one.')
    return self

  def CheckAllTunnels(self, conns):
    missing = []
    for backend in self.backends:
      proto, domain = backend.split(':')
      if not conns.Tunnel(proto, domain):
        missing.append(domain)
    if missing:
      self.FallDown('No tunnel for %s' % missing, help=False)

  TMP_UUID_MAP = {
    '2400:8900::f03c:91ff:feae:ea35:443': '106.187.99.46:443',
    '2a01:7e00::f03c:91ff:fe96:234:443': '178.79.140.143:443',
    '2600:3c03::f03c:91ff:fe96:2bf:443': '50.116.52.206:443',
    '2600:3c01::f03c:91ff:fe96:257:443': '173.230.155.164:443',
    '69.164.211.158:443': '50.116.52.206:443',
  }
  def Ping(self, host, port):
    cid = uuid = '%s:%s' % (host, port)

    if cid in self.servers_never:
      return (9999, uuid)
    if self.servers_no_ping:
      return (0, uuid)

    while ((cid not in self.ping_cache) or
           (len(self.ping_cache[cid]) < 2) or
           (time.time()-self.ping_cache[cid][0][0] > 60)):

      start = time.time()
      try:
        try:
          if ':' in host:
            fd = socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM)
          else:
            fd = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        except:
          fd = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)

        try:
          fd.settimeout(3.0) # Missing in Python 2.2
        except:
          fd.setblocking(1)

        fd.connect((host, port))
        fd.send('HEAD /ping HTTP/1.1\r\nHost: ping.pagekite\r\n\r\n')
        data = fd.recv(1024)
        fd.close()
        if not data.startswith('HTTP/1.1 503 Unavailable'):
          raise Exception()

      except Exception, e:
        logging.LogDebug('Ping %s:%s failed: %s' % (host, port, e))
        return (100000, uuid)

      elapsed = (time.time() - start)
      try:
        uuid = data.split('X-PageKite-UUID: ')[1].split()[0]
      except:
        uuid = self.TMP_UUID_MAP.get(uuid, uuid)

      try:
        if data.index('X-PageKite-Overloaded:') >= 0:
          elapsed += 1  # Simulate slowness: add full second to ping time
      except ValueError:
        pass

      if cid not in self.ping_cache:
        self.ping_cache[cid] = []
      elif len(self.ping_cache[cid]) > 10:
        self.ping_cache[cid][8:] = []

      self.ping_cache[cid][0:0] = [(time.time(), (elapsed, uuid))]

    window = min(3, len(self.ping_cache[cid]))
    pingval = sum([e[1][0] for e in self.ping_cache[cid][:window]])/window
    uuid = self.ping_cache[cid][0][1][1]

    logging.LogDebug(('Pinged %s:%s: %f [win=%s, uuid=%s]'
                      ) % (host, port, pingval, window, uuid))
    return (pingval, uuid)

  def GetHostIpAddrs(self, host):
    rv = []
    try:
      info = socket.getaddrinfo(host, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
      rv = [i[4][0] for i in info]
    except AttributeError:
      rv = socket.gethostbyname_ex(host)[2]
    return rv

  def CachedGetHostIpAddrs(self, host):
    now = int(time.time())

    if host in self.dns_cache:
      # FIXME: This number (900) is 3x the pagekite.net service DNS TTL, which
      # should be about right.  BUG: nothing keeps those two numbers in sync!
      # This number must be larger, or we prematurely disconnect frontends.
      for exp in [t for t in self.dns_cache[host] if t < now-900]:
        del self.dns_cache[host][exp]
    else:
      self.dns_cache[host] = {}

    try:
      self.dns_cache[host][now] = self.GetHostIpAddrs(host)
    except:
      logging.LogDebug('DNS lookup failed for %s' % host)

    ips = {}
    for ipaddrs in self.dns_cache[host].values():
      for ip in ipaddrs:
        ips[ip] = 1
    return ips.keys()

  def GetActiveBackends(self, include_loopback=False):
    active = []
    for bid in self.backends:
      (proto, bdom) = bid.split(':')
      if (self.backends[bid][BE_STATUS] not in BE_INACTIVE and
          (include_loopback or self.backends[bid][BE_SECRET]) and
          not bdom.startswith('*')):
        active.append(bid)
    return active

  def ChooseFrontEnds(self, periodic=False):
    self.servers = []
    self.servers_preferred = []
    self.last_frontend_choice = time.time()

    servers_all = {}
    servers_pref = {}

    # Increase our ping interval slightly unless it has been reduced
    # to the minimum: that means our connection is crap and we should
    # just leave it be.
    if (periodic
        and not self.keepalive
        and not self.isfrontend
        and common.PING_INTERVAL > common.PING_INTERVAL_MIN):
      common.DISCONNECT_COUNT = 0
      common.PING_INTERVAL = min(common.PING_INTERVAL * 1.3,
                                 common.PING_INTERVAL_MAX)
      logging.LogDebug('TunnelManager: adjusted ping interval, PI=%s'
                       % common.PING_INTERVAL)

    # Enable internal loopback
    if self.isfrontend:
      need_loopback = False
      for be in self.backends.values():
        if be[BE_BHOST]:
          need_loopback = True
      if need_loopback:
        # Note: Add to servers_pref to keep from getting disconnected
        servers_all['loopback'] = servers_pref['loopback'] = LOOPBACK_FE

    # Process the manually requested servers first (--frontend= lines); these
    # are always added (and preferred, so in DNS) no matter what.
    def sping(server):
      (host, port) = server.split(':')
      ipaddrs = self.CachedGetHostIpAddrs(host)
      if ipaddrs:
        ptime, uuid = self.Ping(ipaddrs[0], int(port))
        server = '%s:%s' % (ipaddrs[0], port)
        servers_all[uuid] = servers_pref[uuid] = server
    threads, deadline = [], time.time() + 5
    for server in self.servers_manual:
      threads.append(threading.Thread(target=sping, args=(server,)))
      threads[-1].daemon = True
      threads[-1].start()
    for t in threads:
      t.join(max(0.1, deadline - time.time()))

    # Lookup and choose from the auto-list (and our old domain).
    if self.servers_auto:
      (count, domain, port) = self.servers_auto
      pinged = {}

      try:
        # First, check for old addresses and always connect to those.
        selected = {}
        if not self.servers_new_only:
          def bping(bid):
            (proto, bdom) = bid.split(':')
            for ip in self.CachedGetHostIpAddrs(bdom):
              # FIXME: What about IPv6 localhost?
              if not ip.startswith('127.') and ip not in pinged:
                server = '%s:%s' % (ip, port)
                pingtime, uuid = pinged[ip] = self.Ping(ip, int(port))
                servers_all[uuid] = server
          threads, deadline = [], time.time() + 5
          for bid in self.GetActiveBackends():
            threads.append(threading.Thread(target=bping, args=(bid,)))
            threads[-1].daemon = True
            threads[-1].start()
          for t in threads:
            t.join(max(0.1, deadline - time.time()))

        ips = [i for i in self.CachedGetHostIpAddrs(domain) if i not in pinged]
        def iping(ip):
          pinged[ip] = self.Ping(ip, int(port))
        threads, deadline = [], time.time() + 5
        for ip in ips:
          threads.append(threading.Thread(target=iping, args=(ip,)))
          threads[-1].daemon = True
          threads[-1].start()
        for t in threads:
          t.join(max(0.1, deadline - time.time()))
      except Exception, e:
        logging.LogDebug('Unreachable: %s, %s' % (domain, e))

      # Evaluate ping results, mark fastest N servers as preferred
      pings = [list(ping) + [ip] for ip, ping in pinged.iteritems()]
      while count > 0 and pings:
        mIdx = pings.index(min(pings))
        if pings[mIdx][0] > 60:
          # This is worthless data, abort.
          break
        else:
          count -= 1
          ptime, uuid, ip = pings[mIdx]
          server = '%s:%s' % (ip, port)
          if uuid not in servers_all:
            servers_all[uuid] = server
          if uuid not in servers_pref:
            servers_pref[uuid] = server
          del pings[mIdx]

    nvr = self.servers_never
    self.servers = [v for v in servers_all.values() if v not in nvr]
    self.servers_preferred = [v for v in servers_pref.values() if v not in nvr]
    logging.LogDebug('Preferred: %s' % ', '.join(self.servers_preferred))

  def ConnectFrontend(self, conns, server):
    self.ui.Status('connect', color=self.ui.YELLOW,
                   message='Front-end connect: %s' % server)
    tun = Tunnel.BackEnd(server, self.backends, self.require_all, conns)
    if tun:
      tun.filters.append(HttpHeaderFilter(self.ui))
      if not self.insecure:
        tun.filters.append(HttpSecurityFilter(self.ui))
        if self.watch_level[0] is not None:
          tun.filters.append(TunnelWatcher(self.ui, self.watch_level))
      logging.Log([('connect', server)])
      return True
    else:
      logging.LogInfo('Failed to connect', [('FE', server)])
      self.ui.Notify('Failed to connect to %s' % server,
                     prefix='!', color=self.ui.YELLOW)

      for line in logging.LOG[-5:]:
        if 'err' in line and 'ssl' in line['err'].lower():
          self.ui.Notify('Unable to verify SSL certificates!')
          self.ui.Notify(socks.HAVE_PYOPENSSL and
            ' - Using pyOpenSSL wrapper, good.'  or
            ' - Using standard Python ssl: try installing pyOpenSSL?')
          self.ui.Notify(' - CA certificates loaded: %s' % self.ca_certs)
          for dom in self.fe_certname:
            self.ui.Notify(' - Would accept a certificate for: %s' % dom)
          self.ui.Notify(' - Check your system clock (dates matter)')
          self.ui.Notify(
            ' - Beware firewalls that intercept outgoing SSL/TLS connections!')
          self.ui.Notify(
            ' - Danger Zone: use --fe_nocertcheck to connect insecurely.')

          # Dammit, if we know what the problem is, just fix it.
          if (self.ca_certs != self.pyfile
                  and 'b5p.us' in (self.servers_auto or ['', ''])[1]):
              logging.LogInfo('Reconfiguring', [('ca_certs', self.pyfile)])
              self.ui.Notify('Reconfiguring to use internal CA certificates',
                             prefix="!", color=self.ui.RED)
              self.ca_certs = self.pyfile
              socks.setdefaultcertfile(self.ca_certs)

      return False

  def DisconnectFrontend(self, conns, server):
    logging.Log([('disconnect', server)])
    kill = []
    for bid in conns.tunnels:
      for tunnel in conns.tunnels[bid]:
        if (server == tunnel.server_info[tunnel.S_NAME] and
            tunnel.countas.startswith('frontend')):
          kill.append(tunnel)
    for tunnel in kill:
      if len(tunnel.users.keys()) < 1:
        tunnel.Die()
    return kill and True or False

  def CreateTunnels(self, conns):
    live_servers = conns.TunnelServers()
    failures = 0
    connections = 0

    if len(self.GetActiveBackends(include_loopback=True)) > 0:
      if (not self.servers) or len(self.servers) > len(live_servers):
        self.ChooseFrontEnds()
      elif self.last_frontend_choice < time.time()-FE_PING_INTERVAL:
        self.servers = []
        self.ChooseFrontEnds(periodic=True)
    else:
      self.servers_preferred = []
      self.servers = []

    if not self.servers:
      logging.LogDebug('Not sure which servers to contact, making no changes.')
      return 0, 0

    threads, deadline = [], time.time() + 120
    def connect_in_thread(conns, server, state):
      try:
        state[1] = self.ConnectFrontend(conns, server)
      except (IOError, OSError):
        state[1] = False
    for server in self.servers:
      if server not in live_servers:
        if server == LOOPBACK_FE:
          loop = LoopbackTunnel.Loop(conns, self.backends)
          loop.filters.append(HttpHeaderFilter(self.ui))
          if not self.insecure:
            loop.filters.append(HttpSecurityFilter(self.ui))
        elif server not in self.servers_never:
          state = [None, None]
          state[0] = threading.Thread(target=connect_in_thread,
                                      args=(conns, server, state))
          state[0].daemon = True
          state[0].start()
          threads.append(state)

    for thread, result in threads:
      thread.join(max(0.1, deadline - time.time()))

    for thread, result in threads:
      # This will treat timeouts both as connections AND failures
      if result is not False:
        connections += 1
      if result is not True:
        failures += 1

    for server in live_servers:
      if (server not in self.servers and
          server not in self.servers_preferred):
        if self.DisconnectFrontend(conns, server):
          connections += 1

    if self.dyndns and ([time.time(), 0] > self.postpone_ddns_updates):
      ddns_fmt, ddns_args = self.dyndns

      domains = {}
      for bid in self.backends.keys():
        proto, domain = bid.split(':')
        if domain not in domains:
          domains[domain] = (self.backends[bid][BE_SECRET], [])

        if bid in conns.tunnels:
          ips, bips = [], []
          for tunnel in conns.tunnels[bid]:
            srv = tunnel.server_info[tunnel.S_NAME]
            ip = rsplit(':', srv)[0]
            if not ip == LOOPBACK_HN and not tunnel.read_eof:
              if (not self.servers_preferred) or srv in self.servers_preferred:
                ips.append(ip)
              else:
                bips.append(ip)

          for ip in (ips or bips):
            if ip not in domains[domain]:
              domains[domain][1].append(ip)

      updates = {}
      for domain, (secret, ips) in domains.iteritems():
        if ips:
          # NOTE: Here it would be tempting to skip updates if we already
          #       see correct results in DNS. We avoid this temptation,
          #       because always updating DNS will resolve and mitigate
          #       harms caused by stale DNS caches. The DDNS service just
          #       has to deal with the load.
          iplist = ','.join(ips)
          payload = '%s:%s' % (domain, iplist)
          args = {}
          args.update(ddns_args)
          args.update({
            'domain': domain,
            'ip': ips[0],
            'ips': iplist,
            'sign': signToken(secret=secret, payload=payload, length=100)
          })
          # Note: This may be wrong if different front-ends support different
          #       protocols. Unfortunately, that isn't easily solvable.
          updates[payload] = ddns_fmt % args

      failed_updates = []
      planned_updates = sorted(updates.values())
      last_updates = sorted(self.last_updates)
      if last_updates != planned_updates:

        self.last_updates = []
        for update in updates:
          if update in last_updates:
            self.last_updates.append(update)

        for update in updates:
          if update in last_updates:
            continue
          domain, ips = update.split(':', 1)
          try:
            self.ui.Status('dyndns', color=self.ui.YELLOW,
                                     message='Updating DNS for %s...' % domain)
            # FIXME: If the network misbehaves, can this stall forever?
            result = ''.join(urllib.urlopen(updates[update]).readlines())
            if result.startswith('good') or result.startswith('nochg'):
              logging.Log([('dyndns', result), ('data', update)])
              self.SetBackendStatus(domain, sub=BE_STATUS_ERR_DNS)
              self.last_updates.append(update)
              # Success!  Make sure we remember these IP were live.
              if domain not in self.dns_cache:
                self.dns_cache[domain] = {}
              self.dns_cache[domain][int(time.time())] = ips.split(',')
            else:
              failed_updates.append(domain)
              logging.LogInfo('DynDNS update failed: %s' % result,
                              [('data', update)])
          except Exception, e:
            failed_updates.append(update.split(':')[0])
            logging.LogInfo('DynDNS update failed: %s' % e, [('data', update)])
            if logging.DEBUG_IO:
              traceback.print_exc(file=sys.stderr)

            # Hmm, the update may have succeeded - assume the "worst".
            if domain not in self.dns_cache:
              self.dns_cache[domain] = {}
            self.dns_cache[domain][int(time.time())] = ips.split(',')

            # Avoid hammering broken services.
            break

      if failed_updates:
        for domain in failed_updates:
          self.SetBackendStatus(domain, add=BE_STATUS_ERR_DNS)
          failures += 1

        # Exponential fallback for DDNS updates, up to at most half an hour.
        self.postpone_ddns_updates[1] += 1
        self.postpone_ddns_updates[0] = int(
          time.time() + (56 * (2 ** min(5, self.postpone_ddns_updates[1]))))
        logging.LogInfo('DynDNS updates postponed until ts>%x (errors=%d)'
                        % tuple(self.postpone_ddns_updates))
      else:
        self.postpone_ddns_updates = [0, 0]

    # DDNS updates being postponed counts as at least one failure.
    if self.dyndns and self.postpone_ddns_updates[1]:
      failures = min(1, failures)

    return failures, connections

  def LogTo(self, filename, close_all=True, dont_close=[]):
    if filename == 'memory':
      logging.Log = logging.LogToMemory
      filename = self.devnull

    elif filename == 'syslog':
      logging.Log = logging.LogSyslog
      filename = self.devnull
      compat.syslog.openlog(self.progname, syslog.LOG_PID, syslog.LOG_DAEMON)

    else:
      logging.Log = logging.LogToFile

    if filename in ('stdio', 'stdout'):
      try:
        logging.LogFile = os.fdopen(sys.stdout.fileno(), 'w', 0)
      except:
        logging.LogFile = sys.stdout
    else:
      try:
        logging.LogFile = fd = open(filename, "a", 0)
        os.dup2(fd.fileno(), sys.stdout.fileno())
        if not self.ui.WANTS_STDERR:
          os.dup2(fd.fileno(), sys.stdin.fileno())
          os.dup2(fd.fileno(), sys.stderr.fileno())
      except Exception, e:
        raise ConfigError('%s' % e)

  def Daemonize(self):
    # Fork once...
    if os.fork() != 0: os._exit(0)

    # Fork twice...
    os.setsid()
    if os.fork() != 0: os._exit(0)

  def ProcessWritable(self, oready):
    if logging.DEBUG_IO:
      print '\n=== Ready for Write: %s' % [o and o.fileno() or ''
                                           for o in oready]
    for osock in oready:
      if osock:
        conn = self.conns.Connection(osock)
        if conn and not conn.Send([], try_flush=True):
          conn.Die(discard_buffer=True)

  def ProcessReadable(self, iready, throttle):
    if logging.DEBUG_IO:
      print '\n=== Ready for Read: %s' % [i and i.fileno() or None
                                          for i in iready]
    for isock in iready:
      if isock is not None:
        conn = self.conns.Connection(isock)
        if conn and not (conn.fd and conn.ReadData(maxread=throttle)):
          conn.Die(discard_buffer=True)

  def ProcessDead(self, epoll=None):
    for conn in self.conns.DeadConns():
      if epoll and conn.fd:
        try:
          epoll.unregister(conn.fd)
        except (IOError, TypeError):
          pass
      conn.Cleanup()
      self.conns.Remove(conn)

  def Select(self, epoll, waittime):
    iready = oready = eready = None
    isocks, osocks = self.conns.Readable(), self.conns.Blocked()
    try:
      if isocks or osocks:
        iready, oready, eready = select.select(isocks, osocks, [], waittime)
      else:
        # Windoes does not seem to like empty selects, so we do this instead.
        time.sleep(waittime/2)
    except KeyboardInterrupt:
      raise
    except:
      logging.LogError('Error in select(%s/%s): %s' % (isocks, osocks,
                                                       format_exc()))
      self.conns.CleanFds()
      self.last_loop -= 1

    now = time.time()
    if not iready and not oready:
      if (isocks or osocks) and (now < self.last_loop + 1):
        logging.LogError('Spinning, pausing ...')
        time.sleep(0.1)

    return None, iready, oready, eready

  def Epoll(self, epoll, waittime):
    fdc = {}
    now = time.time()
    evs = []
    broken = False
    try:
      bbc = 0
      for c in self.conns.conns:
        fd, mask = c.fd, 0
        if not c.IsDead():
          if c.IsBlocked():
            bbc += len(c.write_blocked)
            mask |= select.EPOLLOUT
          if c.IsReadable(now):
            mask |= select.EPOLLIN

        if mask:
          try:
            fdc[fd.fileno()] = fd
          except socket.error:
            # If this fails, then the socket has HUPed, however we need to
            # bypass epoll to make sure that's reflected in iready below.
            bid = 'dead-%d' % len(evs)
            fdc[bid] = fd
            evs.append((bid, select.EPOLLHUP))
            # Trigger removal of c.fd, if it was still in the epoll.
            fd, mask = None, 0

        if mask:
          try:
            epoll.modify(fd, mask)
          except IOError:
            try:
              epoll.register(fd, mask)
            except (IOError, TypeError):
              evs.append((fd, select.EPOLLHUP))  # Error == HUP
        else:
          try:
            epoll.unregister(c.fd)  # Important: Use c.fd, not fd!
          except (IOError, TypeError):
            # Failing to unregister is OK, ignore
            pass

      common.buffered_bytes[0] = bbc
      evs.extend(epoll.poll(waittime))
    except (IOError, OSError):
      broken = 'in poll'
    except KeyboardInterrupt:
      epoll.close()
      raise

    rmask = select.EPOLLIN | select.EPOLLHUP
    iready = [fdc.get(e[0]) for e in evs if e[1] & rmask]
    oready = [fdc.get(e[0]) for e in evs if e[1] & select.EPOLLOUT]

    if not broken and ((None in iready) or (None in oready)):
      broken = 'unknown FDs'
    if broken:
      logging.LogError('Epoll appears to be broken (%s), recreating' % broken)
      try:
        epoll.close()
      except (IOError, OSError, TypeError, AttributeError):
        pass
      epoll = select.epoll()

    return epoll, iready, oready, []

  def CreatePollObject(self):
    try:
      epoll = select.epoll()
      mypoll = self.Epoll
    except:
      epoll = None
      mypoll = self.Select
    return epoll, mypoll

  def Loop(self):
    self.conns.start(auth_thread_count=self.auth_threads)
    if self.ui_httpd: self.ui_httpd.start()
    if self.tunnel_manager: self.tunnel_manager.start()
    if self.ui_comm: self.ui_comm.start()

    epoll, mypoll = self.CreatePollObject()
    self.last_barf = self.last_loop = time.time()

    logging.LogDebug('Entering main %s loop' % (epoll and 'epoll' or 'select'))
    loop_count = 0
    while self.keep_looping:
      epoll, iready, oready, eready = mypoll(epoll, 1.1)
      now = time.time()

      if oready:
        self.ProcessWritable(oready)

      if common.buffered_bytes[0] < 1024 * self.buffer_max:
        throttle = None
      else:
        logging.LogDebug("FIXME: Nasty pause to let buffers clear!")
        time.sleep(0.1)
        throttle = 1024

      if iready:
        self.ProcessReadable(iready, throttle)

      self.ProcessDead(epoll)
      self.last_loop = now
      loop_count += 1

      if now - self.last_barf > (logging.DEBUG_IO and 15 or 600):
        self.last_barf = now
        if epoll:
          epoll.close()
        epoll, mypoll = self.CreatePollObject()
        logging.LogDebug('Loop #%d, selectable map: %s' % (loop_count, SELECTABLES))

    if epoll:
      epoll.close()

  def Start(self, howtoquit='CTRL+C = Stop'):
    conns = self.conns = self.conns or Connections(self)

    # If we are going to spam stdout with ugly crap, then there is no point
    # attempting the fancy stuff. This also makes us backwards compatible
    # for the most part.
    if self.logfile == 'stdio':
      if not self.ui.DAEMON_FRIENDLY: self.ui = NullUi()

    # Announce that we've started up!
    self.ui.Status('startup', message='Starting up...')
    self.ui.Notify(('Hello! This is %s v%s.'
                    ) % (self.progname, APPVER),
                    prefix='>', color=self.ui.GREEN,
                    alignright='[%s]' % howtoquit)
    config_report = [('started', self.pyfile), ('version', APPVER),
                     ('platform', sys.platform),
                     ('argv', ' '.join(sys.argv[1:])),
                     ('ca_certs', self.ca_certs)]
    for optf in self.rcfiles_loaded:
      config_report.append(('optfile_%s' % optf, 'ok'))
    logging.Log(config_report)

    if not socks.HAVE_SSL:
      self.ui.Notify('SECURITY WARNING: No SSL support was found, tunnels are insecure!',
                     prefix='!', color=self.ui.WHITE)
      self.ui.Notify('Please install either pyOpenSSL or python-ssl.',
                     prefix='!', color=self.ui.WHITE)

    # Create global secret
    self.ui.Status('startup', message='Collecting entropy for a secure secret...')
    logging.LogInfo('Collecting entropy for a secure secret.')
    globalSecret()
    self.ui.Status('startup', message='Starting up...')

    # Create the UI Communicator
    self.ui_comm = UiCommunicator(self, conns)

    try:

      # Set up our listeners if we are a server.
      if self.isfrontend:
        self.ui.Notify('This is a PageKite front-end server.')
        for port in self.server_ports:
          Listener(self.server_host, port, conns, acl=self.accept_acl_file)
        for port in self.server_raw_ports:
          if port != VIRTUAL_PN and port > 0:
            Listener(self.server_host, port, conns,
                     connclass=RawConn, acl=self.accept_acl_file)

      if self.ui_port:
        Listener('127.0.0.1', self.ui_port, conns,
                 connclass=UiConn, acl=self.accept_acl_file)

      # Create the Tunnel Manager
      self.tunnel_manager = TunnelManager(self, conns)

    except Exception, e:
      self.LogTo('stdio')
      logging.FlushLogMemory()
      if logging.DEBUG_IO:
        traceback.print_exc(file=sys.stderr)
      raise ConfigError('Configuring listeners: %s ' % e)

    # Configure logging
    if self.logfile:
      keep_open = [s.fd.fileno() for s in conns.conns]
      if self.ui_httpd: keep_open.append(self.ui_httpd.httpd.socket.fileno())
      self.LogTo(self.logfile, dont_close=keep_open)

    elif not (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()):
      # Preserve sane behavior when not run at the console.
      self.LogTo('stdio')

    # Flush in-memory log, if necessary
    logging.FlushLogMemory()

    # Set up SIGHUP handler.
    if self.logfile:
      try:
        import signal
        def reopen(x,y):
          if self.logfile:
            self.LogTo(self.logfile, close_all=False)
            logging.LogDebug('SIGHUP received, reopening: %s' % self.logfile)
        signal.signal(signal.SIGHUP, reopen)
      except Exception:
        logging.LogError('Warning: signal handler unavailable, logrotate will not work.')

    # Disable compression in OpenSSL
    if socks.HAVE_SSL and not self.enable_sslzlib:
      socks.DisableSSLCompression()

    # Daemonize!
    if self.daemonize:
      self.Daemonize()

    # Create PID file
    if self.pidfile:
      pf = open(self.pidfile, 'w')
      pf.write('%s\n' % os.getpid())
      pf.close()

    # Do this after creating the PID and log-files.
    if self.daemonize:
      os.chdir('/')

    # Drop privileges, if we have any.
    if self.setgid:
      os.setgid(self.setgid)
    if self.setuid:
      os.setuid(self.setuid)
    if self.setuid or self.setgid:
      logging.Log([('uid', os.getuid()), ('gid', os.getgid())])

    # Make sure we have what we need
    if self.require_all:
      self.CreateTunnels(conns)
      self.CheckAllTunnels(conns)

    # Finally, run our select loop.
    self.Loop()

    self.ui.Status('exiting', message='Stopping...')
    logging.Log([('stopping', 'pagekite.py')])
    if self.ui_httpd:
      self.ui_httpd.quit()
    if self.ui_comm:
      self.ui_comm.quit()
    if self.tunnel_manager:
      self.tunnel_manager.quit()
    if self.conns:
      if self.conns.auth_pool:
        for th in self.conns.auth_pool:
          th.quit()
      for conn in self.conns.conns:
        conn.Cleanup()


##[ Main ]#####################################################################

def Main(pagekite, configure, uiclass=NullUi,
                              progname=None, appver=APPVER,
                              http_handler=None, http_server=None):
  crashes = 0
  shell_mode = None
  while True:
    ui = uiclass()
    logging.ResetLog()
    pk = pagekite(ui=ui, http_handler=http_handler, http_server=http_server)
    try:
      try:
        try:
          configure(pk)
        except SystemExit, status:
          sys.exit(status)
        except Exception, e:
          if logging.DEBUG_IO:
              raise
          raise ConfigError(e)

        shell_mode = shell_mode or pk.shell
        if shell_mode is not True:
          pk.Start()

      except (ConfigError, getopt.GetoptError), msg:
        pk.FallDown(msg, help=(not shell_mode), noexit=shell_mode)
        if shell_mode:
          shell_mode = 'more'

      except KeyboardInterrupt, msg:
        pk.FallDown(None, help=False, noexit=True)
        if shell_mode:
          shell_mode = 'auto'
        else:
          return

    except SystemExit, status:
      if shell_mode:
        shell_mode = 'more'
      else:
        sys.exit(status)

    except Exception, msg:
      traceback.print_exc(file=sys.stderr)
      if pk.crash_report_url:
        try:
          print 'Submitting crash report to %s' % pk.crash_report_url
          logging.LogDebug(''.join(urllib.urlopen(pk.crash_report_url,
                                          urllib.urlencode({
                                            'platform': sys.platform,
                                            'appver': APPVER,
                                            'crash': format_exc()
                                          })).readlines()))
        except Exception, e:
          print 'FAILED: %s' % e

      pk.FallDown(msg, help=False, noexit=pk.main_loop)
      crashes = min(9, crashes+1)

    if shell_mode:
      crashes = 0
      try:
        sys.argv[1:] = Shell(pk, ui, shell_mode)
        shell_mode = 'more'
      except (KeyboardInterrupt, IOError, OSError):
        ui.Status('quitting')
        print
        return
    elif not pk.main_loop:
      return

    # Exponential fall-back.
    logging.LogDebug('Restarting in %d seconds...' % (2 ** crashes))
    time.sleep(2 ** crashes)


def Shell(pk, ui, shell_mode):
  import manual
  try:
    ui.Reset()
    if shell_mode != 'more':
      ui.StartWizard('The PageKite Shell')
      pre = [
        'Press ENTER to fly your kites or CTRL+C to quit.  Or, type some',
        'arguments to and try other things.  Type `help` for help.'
      ]
    else:
      pre = ''

    prompt = os.path.basename(sys.argv[0])
    while True:
      rv = ui.AskQuestion(prompt, prompt='  $', back=False, pre=pre
                          ).strip().split()
      ui.EndWizard(quietly=True)
      while rv and rv[0] in ('pagekite.py', prompt):
        rv.pop(0)
      if rv and rv[0] == 'help':
        ui.welcome = '>>> ' + ui.WHITE + ' '.join(rv) + ui.NORM
        ui.Tell(manual.HELP(rv[1:]).splitlines())
        pre = []
      elif rv and rv[0] == 'quit':
        raise KeyboardInterrupt()
      else:
        if rv and rv[0] in OPT_ARGS:
          rv[0] = '--'+rv[0]
        return rv
  finally:
    ui.EndWizard(quietly=True)
    print


def Configure(pk):
  if '--appver' in sys.argv:
    print '%s' % APPVER
    sys.exit(0)

  if '--clean' not in sys.argv and '--help' not in sys.argv:
    if os.path.exists(pk.rcfile):
      pk.ConfigureFromFile()

  friendly_mode = (('--friendly' in sys.argv) or
                   (sys.platform[:3] in ('win', 'os2', 'dar')))
  if friendly_mode and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
    pk.shell = (len(sys.argv) < 2) and 'auto'

  pk.Configure(sys.argv[1:])

  if '--settings' in sys.argv:
    pk.PrintSettings(safe=True)
    sys.exit(0)

  if not pk.backends.keys() and (not pk.kitesecret or not pk.kitename):
    if '--signup' in sys.argv or friendly_mode:
      pk.RegisterNewKite(autoconfigure=True, first=True)
    if friendly_mode:
      pk.save = True

  pk.CheckConfig()

  if pk.added_kites:
    if (pk.save or
        pk.ui.AskYesNo('Save settings to %s?' % pk.rcfile,
                       default=(len(pk.backends.keys()) > 0))):
      pk.SaveUserConfig()
    pk.servers_new_only = 'Once'
  elif pk.save:
    pk.SaveUserConfig(quiet=True)

  if ('--list' in sys.argv or
      pk.kite_add or pk.kite_remove or pk.kite_only or pk.kite_disable):
    pk.ListKites()
    sys.exit(0)
