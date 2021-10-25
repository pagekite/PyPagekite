"""
These are the Connection classes, relatively high level classes that handle
incoming or outgoing network connections.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

##############################################################################
LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2020, the Beanstalks Project ehf. and Bjarni Runar Einarsson

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

import six

import socket
import sys
import threading
import time

from pagekite.compat import *
from pagekite.common import *
import pagekite.common as common
import pagekite.logging as logging

from .filters import HttpSecurityFilter
from .selectables import *
from .parsers import *
from .proto import *

SMTP_PORTS = (25, 465, 587, 2525)


class Tunnel(ChunkParser):
  """A Selectable representing a PageKite tunnel."""

  S_NAME = 0
  S_PORTS = 1
  S_RAW_PORTS = 2
  S_PROTOS = 3
  S_ADD_KITES = 4
  S_IS_MOBILE = 5
  S_VERSION = 6
  S_WEBSOCKET = 7

  def __init__(self, conns):
    ChunkParser.__init__(self, ui=conns.config.ui)
    if conns.config.websocket_chunks:
      self.PrepareWebsockets()

    self.server_info = ['x.x.x.x:x', [], [], [], False, False, None, False]
    self.Init(conns)

  def Init(self, conns):
    self.conns = conns
    self.users = {}
    self.remote_ssl = {}
    self.zhistory = {}
    self.backends = {}
    self.last_ping = 0
    self.weighted_rtt = -1
    self.using_tls = False
    self.filters = []
    self.ip_limits = None
    self.maxread = int(common.MAX_READ_BYTES * common.MAX_READ_TUNNEL_X)

  def Cleanup(self, close=True):
    if self.users:
      for sid in list(six.iterkeys(self.users)):
        self.CloseStream(sid)
    ChunkParser.Cleanup(self, close=close)
    self.Init(None)

  def __html__(self):
    return ('<b>Server name</b>: %s<br>'
            '%s') % (self.server_info[self.S_NAME], ChunkParser.__html__(self))

  def LogTrafficStatus(self, final=False):
    if self.ui:
      if final:
        message = 'Disconnected from: %s' % self.server_info[self.S_NAME]
        self.ui.Status('down', color=self.ui.GREY, message=message)
      else:
        self.ui.Status('traffic')

  def GetKiteRequests(self, parse):
    requests = []
    for prefix in ('X-Beanstalk', 'X-PageKite'):
      for bs in parse.Header(prefix):
        # X-PageKite: proto:my.domain.com:token:signature
        proto, domain, srand, token, sign = bs.split(':')
        requests.append((proto.lower(), domain.lower(),
                         srand, token, sign, prefix))
    return requests

  def RejectTraffic(self, client_conn, address, host):
    # This function allows the tunnel to reject an incoming connection
    # based on the remote address and the requested host. For now we
    # only know how to discriminate by remote IP.
    return self.RejectRemoteIP(client_conn, str(address[0]), host) or False

  def RejectRemoteIP(self, client_conn, ip, host):
    if not self.ip_limits:
      return False

    if len(self.ip_limits) == 1:
      whitelist = self.ip_limits[0]
      delta = maxips = seen = None
    else:
      whitelist = None
      delta, maxips, seen = self.ip_limits

    # Do we have a whitelist-only policy for this tunnel?
    if whitelist:
      for prefix in whitelist:
        if ip.startswith(prefix):
          return False
      self.LogError('Rejecting connection from unrecognized IP')
      return 'not_whitelisted'

    # Do we have a delta/maxips policy?
    if delta and maxips:

      # Since IP addresses are often shared, we try to differentiate browsers
      # based on few of the request headers as well. We don't track cookies
      # since they're mutated by the site itself, which would lead to false
      # positives here.
      client = ip
      log_info = []
      if hasattr(client_conn, 'parser'):
        if hasattr(client_conn.parser, 'Header'):
          client = sha1hex('/'.join([ip] +
            (client_conn.parser.Header('User-Agent') or []) +
            (client_conn.parser.Header('Accept-Language') or [])))
        if hasattr(client_conn.parser, 'method'):
          log_info.append(
            (str(client_conn.parser.method), str(client_conn.parser.path)))

      now = time.time()
      if client in seen:
        seen[client] = now
        return False

      for seen_ip in list(six.iterkeys(seen)):
        if seen[seen_ip] < now - delta:
          del seen[seen_ip]

      if len(seen) >= maxips:
        self.LogError('Rejecting connection from new client',
                      [('client', client[:12]),
                       ('ips_per_sec', '%d/%ds' % (maxips, delta)),
                       ('domain', host)] + log_info)
        return 'ips_per_sec'
      else:
        seen[client] = now
        return False

    # All else is allowed
    return False

  def ProcessPageKiteHeaders(self, parser):
    for prefix in ('X-Beanstalk', 'X-PageKite'):
      for feature in parser.Header(prefix+'-Features'):
        if feature == 'ZChunks':
          if not self.conns.config.disable_zchunks:
            self.EnableZChunks(level=1)
        elif feature == 'AddKites':
          self.server_info[self.S_ADD_KITES] = True
        elif feature == 'Mobile':
          self.server_info[self.S_IS_MOBILE] = True

      # Track which versions we see in the wild.
      version = 'old'
      for v in parser.Header(prefix+'-Version'):
        version = v
      if common.gYamon:
        common.gYamon.vadd('version-%s' % version, 1, wrap=10000000)
      self.server_info[self.S_VERSION] = version

      for replace in parser.Header(prefix+'-Replace'):
        if replace in self.conns.conns_by_id:
          repl = self.conns.conns_by_id[replace]
          self.LogInfo('Disconnecting old tunnel: %s' % repl)
          repl.Die(discard_buffer=True)

  def _FrontEnd(conn, body, conns):
    """This is what the front-end does when a back-end requests a new tunnel."""
    self = Tunnel(conns)
    try:
      if 'websocket' in conn.parser.Header('Upgrade'):
        self.server_info[self.S_ADD_KITES] = True
        self.server_info[self.S_WEBSOCKET] = (
          ''.join(conn.parser.Header('Sec-WebSocket-Key')) or True)

      self.ProcessPageKiteHeaders(conn.parser)
      requests = self.GetKiteRequests(conn.parser)

    except Exception as err:
      self.LogError('Discarding connection: %s' % err)
      self.Cleanup()
      return None

    except socket.error as err:
      self.LogInfo('Discarding connection: %s' % err)
      self.Cleanup()
      return None

    try:
      ips, seconds = conns.config.GetDefaultIPsPerSecond()
      self.UpdateIP_Limits(ips, seconds)
    except ValueError:
      pass

    self.last_activity = time.time()
    self.CountAs('backends_live')
    self.SetConn(conn)
    if requests:
      conns.auth().check(requests[:], conn,
                         lambda r, l: self.AuthCallback(conn, r, l))
    elif self.server_info[self.S_WEBSOCKET]:
      self.AuthCallback(conn, [], [])

    return self

  def RecheckQuota(self, conns, when=None):
    if when is None: when = time.time()
    if (self.quota and
        self.quota[0] is not None and
        self.quota[1] and
        (self.quota[2] < when-900)):
      self.quota[2] = when
      self.LogDebug('Rechecking: %s' % (self.quota, ))
      conns.auth().check(self.quota[1], self,
                         lambda r, l: self.QuotaCallback(conns, r, l))

  def ProcessAuthResults(self, results, duplicates_ok=False, add_tunnels=True):
    ok = []
    bad = []

    if not self.conns:
      # This can be delayed until the connecting client gives up, which
      # means we may have already called Die().  In that case, just abort.
      return True

    ok_results = ['X-PageKite-OK']
    bad_results = ['X-PageKite-Invalid']
    if duplicates_ok is True:
      ok_results.extend(['X-PageKite-Duplicate'])
    elif duplicates_ok is False:
      bad_results.extend(['X-PageKite-Duplicate'])

    for r in results:
      if r[0] in ok_results:
        ok.append(r[1])
      elif r[0] in bad_results:
        bad.append(r[1])
      elif r[0] == 'X-PageKite-SessionID':
        self.conns.SetAltId(self, r[1])

    logi = []
    if self.server_info[self.S_IS_MOBILE]:
      logi.append(('mobile', 'True'))
    if self.server_info[self.S_ADD_KITES]:
      logi.append(('add_kites', 'True'))
    if self.server_info[self.S_WEBSOCKET]:
      logi.append(('websocket', 'True'))
    if self.server_info[self.S_VERSION]:
      logi.append(('version', self.server_info[self.S_VERSION]))

    if bad:
      for backend in bad:
        if backend in self.backends:
          del self.backends[backend]
      proto, domain, srand = backend.split(':')
      self.Log([('BE', 'Dead'), ('proto', proto), ('domain', domain)] + logi,
               level=logging.LOG_LEVEL_MACH)
      self.conns.CloseTunnel(proto, domain, self)

    # Update IP rate limits, if necessary
    first = True
    for r in results:
      if r[0] in ('X-PageKite-IPsPerSec',):
        ips, seconds = [int(x) for x in r[1].split('/')]
        self.UpdateIP_Limits(ips, seconds, force=first)
        first = False
    if first:
      for backend in ok:
        try:
          proto, domain, srand = backend.split(':')
          ips, seconds = self.conns.config.GetDefaultIPsPerSecond(domain)
          self.UpdateIP_Limits(ips, seconds)
        except ValueError:
          pass

    if add_tunnels:
      if self.ip_limits and len(self.ip_limits) > 2:
        logi.append(('ips_per_sec',
                     '%d/%ds' % (self.ip_limits[1], self.ip_limits[0])))

      for backend in ok:
        if backend not in self.backends:
          self.backends[backend] = 1
        proto, domain, srand = backend.split(':')
        self.Log([('BE', 'Live'),
                  ('proto', proto),
                  ('domain', domain)] + logi,
                 level=logging.LOG_LEVEL_MACH)
        self.conns.Tunnel(proto, domain, self)
      if not ok:
        if self.server_info[self.S_ADD_KITES] and not bad:
          self.LogDebug('No tunnels configured, idling...')
          self.conns.SetIdle(self, 60)
        else:
          self.LogWarning('No tunnels configured, closing connection.')
          self.Die()

    return True

  def QuotaCallback(self, conns, results, log_info):
    # Report new values to the back-end... unless they are mobile.
    if self.quota and (self.quota[0] >= 0):
      if not self.server_info[self.S_IS_MOBILE]:
        self.SendQuota()

    self.ProcessAuthResults(results, duplicates_ok=True, add_tunnels=False)
    for r in results:
      if r[0] in ('X-PageKite-OK', 'X-PageKite-Duplicate'):
        return self

    # Nothing is OK anymore, give up and shut down the tunnel.
    self.Log(log_info)
    self.LogWarning('Ran out of quota or account deleted, closing tunnel.')
    self.Die()
    return self

  def AuthCallback(self, conn, results, log_info):
    if log_info:
      logging.Log(log_info)

    if self.server_info[self.S_WEBSOCKET]:
      output = [HTTP_WebsocketResponse(self.server_info[self.S_WEBSOCKET])]
      extras = []
    else:
      output = [HTTP_ResponseHeader(200, 'OK'),
                HTTP_Header('Transfer-Encoding', 'chunked')]
      extras = output
      if not self.conns.config.disable_zchunks:
        output.append(HTTP_Header('X-PageKite-Features', 'ZChunks'))

    extras.extend([
              HTTP_Header('X-PageKite-Features', 'WebSockets'),
              HTTP_Header('X-PageKite-Features', 'AddKites'),
              HTTP_Header('X-PageKite-Protos', ', '.join(['%s' % p
                            for p in self.conns.config.server_protos])),
              HTTP_Header('X-PageKite-Ports', ', '.join(
                            ['%s' % self.conns.config.server_portalias.get(p, p)
                             for p in self.conns.config.server_ports]))])

    if self.conns.config.server_raw_ports:
      extras.append(
        HTTP_Header('X-PageKite-Raw-Ports',
                    ', '.join(['%s' % p for p
                               in self.conns.config.server_raw_ports])))

    for r in results:
      extras.append('%s: %s\r\n' % r)

    output.append(HTTP_StartBody())
    if not self.Send(output, activity=False):
      conn.LogDebug('No tunnels configured, closing connection (send failed).')
      self.Die(discard_buffer=True)
      return self

    if conn.quota and conn.quota[0]:
      self.quota = conn.quota
      self.Log([('BE-Quota', self.quota[0])])

    if self.server_info[self.S_WEBSOCKET]:
      self.EnableWebsockets()
      self.SendChunked('NOOP: 1\r\n%s\r\n!' % ''.join(extras))
      self.conns.Add(self)
    elif self.ProcessAuthResults(results):
      self.conns.Add(self)
    else:
      self.Die()

    return self

  def ChunkAuthCallback(self, results, log_info):
    if log_info:
      logging.Log(log_info, level=logging.LOG_LEVEL_MACH)

    if self.ProcessAuthResults(results):
      output = ['NOOP: 1\r\n']
      for r in results:
        output.append('%s: %s\r\n' % r)
      output.append('\r\n!')
      self.SendChunked(''.join(output), compress=False, just_buffer=True)

  def _RecvHttpHeaders(self, fd=None):
    data = ''
    fd = fd or self.fd
    while not data.endswith('\r\n\r\n') and not data.endswith('\n\n'):
      try:
        buf = s(fd.recv(1))
      except:
        # This is sloppy, but the back-end will just connect somewhere else
        # instead, so laziness here should be fine.
        buf = None
      if buf is None or buf == '':
        self.LogDebug('Remote end closed connection.')
        return None
      data += buf
      self.read_bytes += len(buf)
    if logging.DEBUG_IO:
      print('<== IN (headers) =[%s]==(\n%s)==' % (self, data))
    return data

  def _Connect(self, server, conns, tokens=None):
    if self.fd:
      self.fd.close()

    sspec = server.rsplit(':', 1)
    if len(sspec) < 2:
      sspec = (sspec[0], 443)

    # Use chained SocksiPy to secure our communication.
    socks.DEBUG = (logging.DEBUG_IO or socks.DEBUG) and logging.LogDebug
    sock = socks.socksocket()
    if socks.HAVE_SSL:
      pp = socks.parseproxy
      chain = [pp('default')]
      if self.conns.config.fe_nocertcheck:
        chain.append([socks.PROXY_TYPE_SSL_WEAK, sspec[0], int(sspec[1])])
      elif self.conns.config.fe_certname:
        chain.append(pp('http!%s!%s' % (sspec[0], sspec[1])))
        chain.append(pp('ssl!%s!443' % ','.join(self.conns.config.fe_certname)))
      for hop in chain:
        sock.addproxy(*hop)
    self.SetFD(sock)

    try:
      # Note: This value is a magic number which should correlate with
      #       bounds on auth thread queue length, set in AuthThread._run().
      self.fd.settimeout(30.0)  # Missing in Python 2.2
    except:
      self.fd.setblocking(1)

    self.LogDebug('Connecting to %s:%s' % (sspec[0], sspec[1]))
    self.fd.connect((sspec[0], int(sspec[1])))
    replace_sessionid = self.conns.config.servers_sessionids.get(server, None)
    if (not self.Send(HTTP_PageKiteRequest(server,
                                         conns.config.backends,
                                       tokens,
                                     nozchunks=conns.config.disable_zchunks,
                                    replace=replace_sessionid,
                                   websocket_key=self.websocket_key),
                      activity=False, try_flush=True, allow_blocking=False)
        or not self.Flush(wait=True, allow_blocking=False)):
      self.LogError('Failed to send kite request, closing.')
      raise IOError('Failed to send kite request, closing.')

    data = self._RecvHttpHeaders()
    if not data:
      self.LogError('Failed to parse kite response, closing.')
      raise IOError('Failed to parse kite response, closing.')

    self.fd.setblocking(0)
    parse = HttpLineParser(lines=data.splitlines(),
                           state=HttpLineParser.IN_RESPONSE)

    return data, parse

  def CheckForTokens(self, parse):
    tcount = 0
    tokens = {}
    if parse:
      for request in parse.Header('X-PageKite-SignThis'):
        proto, domain, srand, token = request.split(':')
        tokens['%s:%s' % (proto, domain)] = token
        tcount += 1
    return tcount, tokens

  def ParsePageKiteCapabilities(self, parse):
    for portlist in parse.Header('X-PageKite-Ports'):
      self.server_info[self.S_PORTS].extend(portlist.split(', '))
    for portlist in parse.Header('X-PageKite-Raw-Ports'):
      self.server_info[self.S_RAW_PORTS].extend(portlist.split(', '))
    for protolist in parse.Header('X-PageKite-Protos'):
      self.server_info[self.S_PROTOS].extend(protolist.split(', '))
    if not self.conns.config.disable_zchunks:
      for feature in parse.Header('X-PageKite-Features'):
        if feature == 'ZChunks':
          self.EnableZChunks(level=9)
        elif feature == 'AddKites':
          self.server_info[self.S_ADD_KITES] = True
        elif feature == 'Mobile':
          self.server_info[self.S_IS_MOBILE] = True

  def UpdateIP_Limits(self, ips, seconds, force=False):
    if self.ip_limits and len(self.ip_limits) > 2 and not force:
      new_rate = float(ips)/(seconds or 1)  # Float division
      old_rate = float(self.ip_limits[1] or 9999)/(self.ip_limits[0] or 1)  # Float division
      if new_rate < old_rate:
        self.ip_limits[0] = seconds
        self.ip_limits[1] = ips
    else:
      self.ip_limits = [(seconds or 1), ips, {}]

  def HandlePageKiteResponse(self, parse):
    config = self.conns.config
    have_kites = 0
    have_kite_info = None

    sname = self.server_info[self.S_NAME]
    config.ui.NotifyServer(self, self.server_info)
    logged = 0

    for misc in parse.Header('X-PageKite-Misc'):
      args = parse_qs(misc)
      logdata = [('FE', sname)]
      for arg in args:
        logdata.append((arg, args[arg][0]))
      logging.Log(logdata, level=logging.LOG_LEVEL_MACH)
      if 'motd' in args and args['motd'][0]:
        config.ui.NotifyMOTD(sname, args['motd'][0])
      logged += 1

    # FIXME: Really, we should keep track of quota dimensions for
    #        each kite.  At the moment that isn't even reported...
    quota_log = []
    for quota in parse.Header('X-PageKite-Quota'):
      self.quota = [float(quota), None, None]
      quota_log.append(('quota_bw', quota))
    for quota in parse.Header('X-PageKite-QConns'):
      self.q_conns = float(quota)
      quota_log.append(('quota_conns', quota))
    for quota in parse.Header('X-PageKite-QDays'):
      self.q_days = float(quota)
      quota_log.append(('quota_days', quota))
    for quota in parse.Header('X-PageKite-IPsPerSec'):
      quota_log.append(('ips_per_sec', quota))
      try:
        config.ui.NotifyIPsPerSec(*[int(i) for i in quota.split('/')])
      except ValueError:
        pass
    if quota_log:
      self.Log([('FE', sname)] + quota_log)
      logged += 1

    invalid_reasons = {}
    for request in parse.Header('X-PageKite-Invalid-Why'):
      # This is future-compatible, in that we can add more fields later.
      details = request.split(';')
      invalid_reasons[details[0]] = details[1]
      logged += 1

    for request in parse.Header('X-PageKite-Invalid'):
      have_kite_info = True
      proto, domain, srand = request.split(':')
      reason = invalid_reasons.get(request, 'unknown')
      self.Log([('FE', sname),
                ('err', 'Rejected'),
                ('proto', proto),
                ('reason', reason),
                ('domain', domain)],
               level=logging.LOG_LEVEL_WARN)
      config.ui.NotifyKiteRejected(proto, domain, reason, crit=True)
      config.SetBackendStatus(domain, proto, add=BE_STATUS_ERR_TUNNEL)
      logged += 1

    for request in parse.Header('X-PageKite-Duplicate'):
      have_kite_info = True
      proto, domain, srand = request.split(':')
      self.Log([('FE', self.server_info[self.S_NAME]),
                ('err', 'Duplicate'),
                ('proto', proto),
                ('domain', domain)],
               level=logging.LOG_LEVEL_WARN)
      config.ui.NotifyKiteRejected(proto, domain, 'duplicate')
      config.SetBackendStatus(domain, proto, add=BE_STATUS_ERR_TUNNEL)
      logged += 1

    ssl_available = {}
    for request in parse.Header('X-PageKite-SSL-OK'):
      ssl_available[request] = True
      logged += 1

    for request in parse.Header('X-PageKite-OK'):
      have_kite_info = True
      have_kites += 1
      proto, domain, srand = request.split(':')
      self.conns.Tunnel(proto, domain, self)
      status = BE_STATUS_OK
      if request in ssl_available:
        status |= BE_STATUS_REMOTE_SSL
        self.remote_ssl[(proto, domain)] = True
      self.Log([('FE', sname),
                ('proto', proto),
                ('domain', domain),
                ('ssl', (request in ssl_available))],
               level=logging.LOG_LEVEL_INFO)
      config.SetBackendStatus(domain, proto, add=status)
      logged += 1

    if logged:
      if self.quota and self.quota[0] is not None:
        config.ui.NotifyQuota(self.quota[0], self.q_days, self.q_conns)

      # Also log the server capabilities
      logging.Log([
        ('FE', sname),
        ('ports', ','.join(self.server_info[self.S_PORTS])),
        ('protocols', ','.join(self.server_info[self.S_PROTOS])),
        ('raw_ports', ','.join(self.server_info[self.S_RAW_PORTS] or []))])

    return have_kite_info and have_kites

  def _BackEnd(server, backends, require_all, conns):
    """This is the back-end end of a tunnel."""
    self = Tunnel(conns)
    if conns and not conns.config.isfrontend:
        self.ExtendSSLRetryDelays()

    self.backends = backends
    self.require_all = require_all
    self.server_info[self.S_NAME] = server
    abort = True
    try:
      try:
        data, parse = self._Connect(server, conns)
      except:
        logging.LogError('Error in connect: %s' % format_exc())
        raise

      if data and parse:
        # Collect info about front-end capabilities, for interactive config
        self.ParsePageKiteCapabilities(parse)

        for sessionid in parse.Header('X-PageKite-SessionID'):
          conns.SetAltId(self, sessionid)
          conns.config.servers_sessionids[server] = sessionid

        for upgrade in parse.Header('Upgrade'):
          if upgrade.lower() == 'websocket':
            self.EnableWebsockets()
            abort = data = parse = False

        tryagain, tokens = self.CheckForTokens(parse)
        if tryagain:
          if self.server_info[self.S_ADD_KITES]:
            request = PageKiteRequestHeaders(server, conns.config.backends,
                                             tokens)
            abort = not self.SendChunked(('NOOP: 1\r\n%s\r\n\r\n!'
                                          ) % ''.join(request),
                                         compress=False, just_buffer=True)
            data = parse = None
          else:
            try:
              data, parse = self._Connect(server, conns, tokens)
            except:
              logging.LogError('Error in connect: %s' % format_exc())
              raise

        if data and parse:
          kites = self.HandlePageKiteResponse(parse)
          abort = (kites is None) or (kites < 1)

    except socket.error:
      self.Cleanup()
      return None

    except Exception as e:
      self.LogError('Connect failed: %s' % e)
      self.Cleanup()
      return None

    if abort:
      return False

    conns.Add(self)
    self.CountAs('frontends_live')
    self.last_activity = time.time()

    return self

  FrontEnd = staticmethod(_FrontEnd)
  BackEnd = staticmethod(_BackEnd)

  def Send(self, data, try_flush=False, activity=False, just_buffer=False,
                       allow_blocking=True):
    try:
      if TUNNEL_SOCKET_BLOCKS and allow_blocking and not just_buffer:
        if self.fd is not None:
          self.fd.setblocking(1)
      return ChunkParser.Send(self, data, try_flush=try_flush,
                                          activity=activity,
                                          just_buffer=just_buffer,
                                          allow_blocking=allow_blocking)
    finally:
      if TUNNEL_SOCKET_BLOCKS and allow_blocking and not just_buffer:
        if self.fd is not None:
          self.fd.setblocking(0)

  def SendData(self, conn, data, sid=None, host=None, proto=None, port=None,
                                 chunk_headers=None):
    sid = int(sid or conn.sid)
    if conn: self.users[sid] = conn
    if not sid in self.zhistory: self.zhistory[sid] = [0, 0]

    # Pass outgoing data through any defined filters
    for f in self.filters:
      if 'data_out' in f.FILTERS:
        try:
          data = f.filter_data_out(self, sid, data)
        except:
          logging.LogWarning(('Ignoring error in filter_out %s: %s'
                              ) % (f, format_exc()))

    sending = ['SID: %s\r\n' % sid]
    if proto: sending.append('Proto: %s\r\n' % proto)
    if host: sending.append('Host: %s\r\n' % host)
    if port:
      porti = int(port)
      if self.conns and (porti in self.conns.config.server_portalias):
        sending.append('Port: %s\r\n' % self.conns.config.server_portalias[porti])
      else:
        sending.append('Port: %s\r\n' % port)
    if chunk_headers:
      for ch in chunk_headers: sending.append('%s: %s\r\n' % ch)
    sending.append('\r\n')

    # Small amounts of data we just send...
    if len(data) <= 1024:
      sending.append(data)
      return self.SendChunked(sending, zhistory=self.zhistory.get(sid))

    # Larger amounts we break into fragments at the FE, to work around bugs
    # in some of our small-buffered embedded clients. We aim for roughly
    # one fragment per packet, assuming an MTU of 1500 bytes. We use
    # much larger fragments at the back-end, relays can be assumed to
    # be up-to-date and larger chunks saves CPU and improves throughput.
    frag_size = self.conns.config.isfrontend and 1024 or (self.maxread+1024)
    sending.append('')
    frag_size = max(frag_size, 1400-len(''.join(sending)))
    first = True
    while data or first:
      sending[-1] = data[:frag_size]
      if not self.SendChunked(sending, zhistory=self.zhistory.get(sid)):
        return False
      data = data[frag_size:]
      if first:
        sending = ['SID: %s\r\n' % sid, '\r\n', '']
        frag_size = max(frag_size, 1400-len(''.join(sending)))
        first = False

    return True

  def SendStreamEof(self, sid, write_eof=False, read_eof=False):
    return self.SendChunked('SID: %s\r\nEOF: 1%s%s\r\n\r\nBye!' % (sid,
                            (write_eof or not read_eof) and 'W' or '',
                            (read_eof or not write_eof) and 'R' or ''),
                            compress=False)

  def EofStream(self, sid, eof_type='WR'):
    if sid in self.users and self.users[sid] is not None:
      write_eof = (-1 != eof_type.find('W'))
      read_eof = (-1 != eof_type.find('R'))
      self.users[sid].ProcessTunnelEof(read_eof=(read_eof or not write_eof),
                                       write_eof=(write_eof or not read_eof))

  def CloseStream(self, sid, stream_closed=False):
    if sid in self.users:
      stream = self.users[sid]
      del self.users[sid]

      if not stream_closed and stream is not None:
        stream.CloseTunnel(tunnel_closed=True)

    if sid in self.zhistory:
      del self.zhistory[sid]

  def ResetRemoteZChunks(self):
    return self.SendChunked('NOOP: 1\r\nZRST: 1\r\n\r\n!',
                            compress=False, just_buffer=True)

  def TriggerPing(self):
    when = time.time() - PING_GRACE_MIN - PING_INTERVAL_MAX
    self.last_ping = self.last_activity = when

  def SendPing(self):
    now = time.time()
    self.last_ping = int(now)
    self.Log([
      ('FE', self.server_info[self.S_NAME]),
      ('pinged_tunnel', '@%.4f' % now)],
      level=logging.LOG_LEVEL_DEBUG)
    return self.SendChunked('NOOP: 1\r\nPING: %.4f\r\n\r\n!' % now,
                            compress=False, just_buffer=True)

  def ProcessPong(self, pong):
    try:
      rtt = int(1000*(time.time()-float(pong)))
      if self.weighted_rtt < 0:
        self.weighted_rtt = rtt
      else:
        self.weighted_rtt = int(0.9 * self.weighted_rtt + 0.1 * rtt)

      sname = self.server_info[self.S_NAME]
      log_info = [('FE', sname),
                  ('tunnel_ping_ms', '%d' % rtt),
                  ('tunnel_ping_wrtt', '%d' % self.weighted_rtt)]

      if self.weighted_rtt > 2500:  # Magic number: 2.5 seconds is a long time!
        if not self.conns.config.isfrontend:
          # If the weighted RTT is this high, then we've had poor connectivity
          # for quite some time. Set things in motion to try another relay.
          self.conns.config.servers_errored[sname] = time.time()
          self.conns.config.last_frontend_choice = 0
          # Avoid re-triggering again right away
          self.weighted_rtt = 0
          log_info.append(('flagged', 'Flagged relay as broken'))

      self.Log(log_info, level=(
        logging.LOG_LEVEL_WARN if ('flagged' in log_info) else
        logging.LOG_LEVEL_INFO))
      if common.gYamon:
        common.gYamon.ladd('tunnel_rtt', rtt)
        common.gYamon.ladd('tunnel_wrtt', self.weighted_rtt)

    except ValueError:
      pass

  def SendPong(self, data):
    if (self.conns.config.isfrontend and
        self.quota and (self.quota[0] >= 0)):
      # May as well make ourselves useful!
      return self.SendQuota(pong=data[:64])
    else:
      return self.SendChunked('NOOP: 1\r\nPONG: %s\r\n\r\n!' % data[:64],
                              compress=False, just_buffer=True)

  def SendQuota(self, pong=''):
    if pong:
      pong = 'PONG: %s\r\n' % pong
    if self.q_days is not None:
      return self.SendChunked(('NOOP: 1\r\n%sQuota: %s\r\nQDays: %s\r\nQConns: %s\r\n\r\n!'
                               ) % (pong, self.quota[0], self.q_days, self.q_conns),
                              compress=False, just_buffer=True)
    else:
      return self.SendChunked(('NOOP: 1\r\n%sQuota: %s\r\n\r\n!'
                               ) % (pong, self.quota[0]),
                              compress=False, just_buffer=True)

  def SendProgress(self, sid, conn):
    msg = ('NOOP: 1\r\n'
           'SID: %s\r\n'
           'SKB: %d\r\n\r\n') % (sid, (conn.all_out + conn.wrote_bytes)/1024)
    return self.SendChunked(msg, compress=False, just_buffer=True)

  def ProcessCorruptChunk(self, data):
    self.ResetRemoteZChunks()
    return True

  def Probe(self, host):
    for bid in self.conns.config.backends:
      be = self.conns.config.backends[bid]
      if be[BE_DOMAIN] == host:
        bhost, bport = (be[BE_BHOST], be[BE_BPORT])
        # FIXME: Should vary probe by backend type
        if self.conns.config.Ping(bhost, int(bport)) > 2:
          return False
    return True

  def ProgressTo(self, parse):
    try:
      sid = int(parse.Header('SID')[0])
      skb = int((parse.Header('SKB') or [-1])[0])
      if sid in self.users:
        self.users[sid].RecordProgress(skb)
    except:
      logging.LogError(('Tunnel::ProgressTo: That made no sense! %s'
                        ) % format_exc())
    return True

  # If a tunnel goes down, we just go down hard and kill all our connections.
  def ProcessEofRead(self):
    self.Die()
    return False

  def ProcessEofWrite(self):
    return self.ProcessEofRead()

  def ProcessChunkQuotaInfo(self, parse):
    new_quota = 0
    if parse.Header('QDays'):
      self.q_days = new_quota = int(parse.Header('QDays'))
    if parse.Header('QConns'):
      self.q_conns = new_quota = int(parse.Header('QConns'))
    if parse.Header('Quota'):
      new_quota = 1
      if self.quota:
        self.quota[0] = int(parse.Header('Quota')[0])
      else:
        self.quota = [int(parse.Header('Quota')[0]), None, None]
    if new_quota:
      self.conns.config.ui.NotifyQuota(self.quota[0],
                                       self.q_days, self.q_conns)

  def ProcessChunkDirectives(self, parse):
    if parse.Header('PONG'):
      self.ProcessPong(parse.Header('PONG')[0])
    if parse.Header('PING'):
      return self.SendPong(parse.Header('PING')[0])
    if parse.Header('ZRST') and not self.ResetZChunks():
      return False
    if parse.Header('SPD') or parse.Header('SKB'):
      if not self.ProgressTo(parse):
        return False
    if parse.Header('NOOP'):
      return True

    return None

  def FilterIncoming(self, sid, data=None, info=None, connecting=False):
    """Pass incoming data through filters, if we have any."""
    for f in self.filters:
      if 'data_in' in f.FILTERS or (connecting and 'connected' in f.FILTERS):
        try:
          if sid and info:
            f.filter_set_sid(sid, info)
          if connecting and 'connected' in f.FILTERS:
            data = f.filter_connected(self, sid, data)
          if data is not None:
            data = f.filter_data_in(self, sid, data)
        except:
          logging.LogWarning(('Ignoring error in filter_in %s: %s'
                              ) % (f, format_exc()))
    return data

  def GetChunkDestination(self, parse):
    return ((parse.Header('Proto') or [''])[0].lower(),
            (parse.Header('Port')  or [''])[0].lower(),
            (parse.Header('Host')  or [''])[0].lower(),
            (parse.Header('RIP')   or [''])[0].lower(),
            (parse.Header('RPort') or [''])[0].lower(),
            (parse.Header('RTLS')  or [''])[0].lower())

  def ReplyToProbe(self, proto, sid, host):
    if self.conns.config.no_probes:
      what, reply = 'rejected', HTTP_NoFeConnection(proto)
    elif self.Probe(host):
      what, reply = 'good', HTTP_GoodBeConnection(proto)
    else:
      what, reply = 'back-end down', HTTP_NoBeConnection(proto)
    self.LogDebug('Responding to probe for %s: %s' % (host, what))
    return self.SendChunked('SID: %s\r\n\r\n%s' % (sid, reply))

  def ConnectBE(self, sid, proto, port, host, rIp, rPort, rTLS, data):
    conn = UserConn.BackEnd(proto, host, sid, self, port,
                            remote_ip=rIp, remote_port=rPort, data=data)

    if self.filters:
      if conn:
        rewritehost = conn.config.get('rewritehost')
        if rewritehost is True:
          rewritehost = conn.backend[BE_BHOST]
      else:
        rewritehost = False

      data = self.FilterIncoming(sid, data, info={
        'proto': proto,
        'port': port,
        'host': host,
        'remote_ip': rIp,
        'remote_port': rPort,
        'using_tls': rTLS,
        'be_host': conn and conn.backend[BE_BHOST],
        'be_port': conn and conn.backend[BE_BPORT],
        'trusted': conn and (conn.security or
                             conn.config.get('insecure', False)),
        'rawheaders': conn and conn.config.get('rawheaders', False),
        'proxyproto': conn and conn.config.get('proxyproto', False),
        'rewritehost': rewritehost
      }, connecting=True)

    if proto in ('http', 'http2', 'http3', 'websocket'):
      if conn and data.startswith(HttpSecurityFilter.REJECT):
        # Pretend we need authentication for dangerous URLs
        conn.Die()
        conn, data, code = False, '', 500
      else:
        code = (conn is None) and 503 or 401
      if not conn:
        # conn is None means we have no back-end.
        # conn is False means authentication is required.
        if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                                self.HTTP_Unavail(
                                  self.conns.config, 'be', proto, host,
                                  code=code
                                )), just_buffer=True):
          return False, False
        else:
          conn = None

    elif not conn and proto == 'https':
      if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                              TLS_Unavailable(unavailable=True)),
                              just_buffer=True):
        return False, False

    if conn:
      self.users[sid] = conn

    return conn, data

  def ProcessKiteUpdates(self, parse):
    # Look for requests for new tunnels
    if self.conns.config.isfrontend:
      self.ProcessPageKiteHeaders(parse)
      requests = self.GetKiteRequests(parse)
      if requests:
        self.conns.auth().check(requests[:], self,
                                lambda r, l: self.ChunkAuthCallback(r, l))
    else:
      self.ParsePageKiteCapabilities(parse)

      # Look for responses to requests for new tunnels
      tryagain, tokens = self.CheckForTokens(parse)
      if tryagain:
        server = self.server_info[self.S_NAME]
        backends = { }
        for bid in tokens:
          backends[bid] = self.conns.config.backends[bid]
        request = ''.join(PageKiteRequestHeaders(server, backends, tokens))
        self.SendChunked('NOOP: 1\r\n%s\r\n\r\n!' % request,
                         compress=False, just_buffer=True)

      kites = self.HandlePageKiteResponse(parse)
      if (kites is not None) and (kites < 1):
        self.Die()

  def ProcessChunk(self, data):
    # First, we process the chunk headers.
    try:
      headers, data = data.split('\r\n\r\n', 1)
      parse = HttpLineParser(lines=headers.splitlines(),
                             state=HttpLineParser.IN_HEADERS)

      # Process PING/NOOP/etc: may result in a short-circuit.
      rv = self.ProcessChunkDirectives(parse)
      if rv is not None:
        # Update quota and kite information if necessary: this data is
        # always sent along with a NOOP, so checking for it here is safe.
        self.ProcessChunkQuotaInfo(parse)
        self.ProcessKiteUpdates(parse)
        return rv

      sid = int(parse.Header('SID')[0])
      eof = parse.Header('EOF')
    except:
      logging.LogError(('Tunnel::ProcessChunk: Corrupt chunk: %s'
                        ) % format_exc())
      return False

    # EOF stream?
    if eof:
      self.EofStream(sid, eof[0])
      return True

    # Headers done, not EOF: let's get the other end of this connection.
    if sid in self.users:
      # Either from pre-existing connections...
      conn = self.users[sid]
      if self.filters:
        data = self.FilterIncoming(sid, data)
    else:
      # ... or we connect to a back-end.
      proto, port, host, rIp, rPort, rTLS = self.GetChunkDestination(parse)
      if proto and host:

        # Probe requests are handled differently (short circuit)
        if proto.startswith('probe'):
          return self.ReplyToProbe(proto, sid, host)

        conn, data = self.ConnectBE(sid, proto, port, host,
                                         rIp, rPort, rTLS, data)
        if conn is False:
          return False
      else:
        conn = None

    # Send the data or shut down.
    if conn:
      if data and not conn.Send(data, try_flush=True):
        # If that failed something is wrong, but we'll let the outer
        # select/epoll loop catch and handle it.
        pass

    else:
      # No connection?  Close this stream.
      self.CloseStream(sid)
      return self.SendStreamEof(sid) and self.Flush()

    return True


class LoopbackTunnel(Tunnel):
  """A Tunnel which just loops back to this process."""

  def __init__(self, conns, which, backends):
    Tunnel.__init__(self, conns)

    if self.fd:
      self.fd = None
    self.weighted_rtt = -1000
    self.backends = backends
    self.require_all = True
    self.server_info[self.S_NAME] = LOOPBACK[which]
    self.other_end = None
    self.which = which
    self.buffer_count = 0
    self.CountAs('loopbacks_live')
    if which == 'FE':
      for d in list(six.iterkeys(backends)):
        if backends[d][BE_BHOST]:
          proto, domain = d.split(':')
          self.conns.Tunnel(proto, domain, self)
          self.Log([('FE', self.server_info[self.S_NAME]),
                    ('proto', proto),
                    ('domain', domain)])

  def __str__(self):
    return '%s %s' % (Tunnel.__str__(self), self.which)

  def Cleanup(self, close=True):
    Tunnel.Cleanup(self, close=close)
    other = self.other_end
    self.other_end = None
    if other and other.other_end:
      other.Cleanup(close=close)

  def Linkup(self, other):
    """Links two LoopbackTunnels together."""
    self.other_end = other
    other.other_end = self
    return other

  def _Loop(conns, backends):
    """Creates a loop, returning the back-end tunnel object."""
    return LoopbackTunnel(conns, 'FE', backends
                          ).Linkup(LoopbackTunnel(conns, 'BE', backends))

  Loop = staticmethod(_Loop)

  # FIXME: This is a zero-length tunnel, but the code relies in some places
  #        on the tunnel having a length.  We really need a pipe here, or
  # things will go horribly wrong now and then.  For now we hack this by
  # separating Write and Flush and looping back only on Flush.

  def Send(self, data, try_flush=False, activity=False, just_buffer=True,
                       allow_blocking=True):
    if self.write_blocked:
      data = [self.write_blocked] + data
      self.write_blocked = ''
    joined_data = ''.join(data)
    if try_flush or (len(joined_data) > 10240) or (self.buffer_count >= 100):
      if logging.DEBUG_IO:
        print('|%s| %s \n|%s| %s' % (self.which, self, self.which, data))
      self.buffer_count = 0
      return self.other_end.ProcessData(joined_data)
    else:
      self.buffer_count += 1
      self.write_blocked = joined_data
      return True


class UserConn(Selectable):
  """A Selectable representing a user's connection."""

  def __init__(self, address, ui=None):
    Selectable.__init__(self, address=address, ui=ui)
    self.Reset()

  def Reset(self):
    self.tunnel = None
    self.conns = None
    self.backend = BE_NONE[:]
    self.config = {}
    self.security = None

  def Cleanup(self, close=True):
    if close:
      self.CloseTunnel()
    Selectable.Cleanup(self, close=close)
    self.Reset()

  def ConnType(self):
    if self.backend[BE_BHOST]:
      return 'BE=%s:%s' % (self.backend[BE_BHOST], self.backend[BE_BPORT])
    else:
      return 'FE'

  def __str__(self):
    return '%s %s' % (Selectable.__str__(self), self.ConnType())

  def __html__(self):
    return ('<b>Tunnel</b>: <a href="/conn/%s">%s</a><br>'
            '%s') % (self.tunnel and self.tunnel.sid or '',
                     escape_html('%s' % (self.tunnel or ''), quote=False) if PY3 else escape_html('%s' % (self.tunnel or '')),
                     Selectable.__html__(self))

  def IsReadable(self, now):
    if self.tunnel and self.tunnel.IsBlocked():
      return False
    return Selectable.IsReadable(self, now)

  def CloseTunnel(self, tunnel_closed=False):
    tunnel, self.tunnel = self.tunnel, None
    if tunnel and not tunnel_closed:
      tunnel.SendStreamEof(self.sid, write_eof=True, read_eof=True)
      tunnel.CloseStream(self.sid, stream_closed=True)
    self.ProcessTunnelEof(read_eof=True, write_eof=True)

  def _FrontEnd(conn, address, proto, host, on_port, body, conns):
    # This is when an external user connects to a server and requests a
    # web-page.  We have to give it to them!
    try:
      self = UserConn(address, ui=conns.config.ui)
    except (ValueError, IOError, OSError):
      conn.LogError('Unable to create new connection object!')
      return None
    self.conns = conns
    self.SetConn(conn)

    if ':' in host: host, port = host.split(':', 1)
    self.proto = oproto = proto
    self.host = StripEncodedIP(host)

    # If the listening port is an alias for another...
    if int(on_port) in conns.config.server_portalias:
      on_port = conns.config.server_portalias[int(on_port)]

    # Try and find the right tunnel. We prefer proto/port specifications first,
    # then the just the proto. If the protocol is WebSocket and no tunnel is
    # found, look for a plain HTTP tunnel.
    if proto.startswith('probe'):
      protos = ['http', 'https', 'websocket', 'raw', 'irc', 'xmpp']
      ports = conns.config.server_ports[:]
      ports.extend(conns.config.server_aliasport.keys())
      ports.extend([x for x in conns.config.server_raw_ports if x != VIRTUAL_PN])
    else:
      protos = [proto]
      ports = [on_port]
      if proto == 'websocket': protos.extend(['http', 'http2', 'http3'])
      elif proto == 'http': protos.extend(['http2', 'http3'])

    tunnels = []
    for p in protos:
      for prt in ports:
        if not tunnels:
          tunnels = conns.Tunnel('%s-%s' % (p, prt), host)
          if tunnels: self.proto = proto = p
      if not tunnels:
        tunnels = conns.Tunnel(p, host)
        if tunnels: self.proto = proto = p
    if not tunnels:
      tunnels = conns.Tunnel(protos[0], CATCHALL_HN)
      if tunnels: self.proto = proto = protos[0]

    if self.address:
      chunk_headers = [('RIP', self.address[0]), ('RPort', self.address[1])]
      if conn.my_tls: chunk_headers.append(('RTLS', 1))

    if len(tunnels) > 1:
      tunnels.sort(key=lambda t: t.weighted_rtt)

    for tun in tunnels:
      rejection = tun.RejectTraffic(conn, address, host)
      if rejection and hasattr(conn, 'error_details'):
        conn.error_details['rejected'] = rejection
      else:
        self.tunnel = tun
        break

    if (self.tunnel and self.tunnel.SendData(self, ''.join(body), host=host,
                                             proto=proto, port=on_port,
                                             chunk_headers=chunk_headers)
                    and self.conns):
      log_info = [('domain', self.host), ('on_port', on_port),
                  ('proto', self.proto), ('is', 'FE')]
      if oproto != proto:
        log_info.append(('sniffed_proto', proto))
      self.Log(log_info)
      self.conns.Add(self)
      if proto in ('http', 'http2', 'http3', 'websocket'):
        self.conns.TrackIP(address[0], host)
        # FIXME: Use the tracked data to detect & mitigate abuse?
      return self

    self.LogDebug('No back-end', [('on_port', on_port), ('proto', self.proto),
                                  ('domain', self.host), ('is', 'FE')])
    self.Cleanup(close=False)
    return None

  def _BackEnd(proto, host, sid, tunnel, on_port,
               remote_ip=None, remote_port=None, data=None):
    # This is when we open a backend connection, because a user asked for it.
    try:
      self = UserConn(None, ui=tunnel.conns.config.ui)
    except (ValueError, IOError, OSError):
      tunnel.LogDebug('Unable to create new connection object!')
      return None

    self.sid = sid
    self.proto = proto
    self.host = host
    self.conns = tunnel.conns
    self.tunnel = tunnel
    failure = None

    # Try and find the right back-end. We prefer proto/port specifications
    # first, then the just the proto. If the protocol is WebSocket and no
    # tunnel is found, look for a plain HTTP tunnel.  Fallback hosts can
    # be registered using the http2/3/4 protocols.
    backend = None

    if proto == 'http':
      protos = [proto, 'http2', 'http3']
    elif proto.startswith('probe'):
      protos = ['http', 'http2', 'http3']
    elif proto == 'websocket':
      protos = [proto, 'http', 'http2', 'http3']
    else:
      protos = [proto]

    for p in protos:
      if not backend:
        p_p = '%s-%s' % (p, on_port)
        backend, be = self.conns.config.GetBackendServer(p_p, host)
      if not backend:
        backend, be = self.conns.config.GetBackendServer(p, host)
      if not backend:
        backend, be = self.conns.config.GetBackendServer(p, CATCHALL_HN)
      if backend:
        break

    logInfo = [
      ('on_port', on_port),
      ('proto', proto),
      ('domain', host),
      ('is', 'BE')]

    # Strip off useless IPv6 prefix, if this is an IPv4 address.
    if remote_ip.startswith('::ffff:') and ':' not in remote_ip[7:]:
      remote_ip = remote_ip[7:]
    if remote_ip:
      logInfo.append(('remote_ip', remote_ip))

    if not backend or not backend[0]:
      self.ui.Notify(('%s - %s://%s:%s (FAIL: no server)'
                      ) % (remote_ip or 'unknown', proto, host, on_port),
                     prefix='?', color=self.ui.YELLOW)
    else:
      http_host = '%s/%s' % (be[BE_DOMAIN], be[BE_PORT] or '80')
      self.backend = be
      self.config = host_config = self.conns.config.be_config.get(http_host, {})

      # Access control interception: check remote IP addresses first.
      ip_keys = [k for k in host_config if k.startswith('ip/')]
      if ip_keys:
        k1 = 'ip/%s' % remote_ip
        k2 = '.'.join(k1.split('.')[:-1])
        if not (k1 in host_config or k2 in host_config):
          self.ui.Notify(('%s - %s://%s:%s (IP ACCESS DENIED)'
                          ) % (remote_ip or 'unknown', proto, host, on_port),
                         prefix='!', color=self.ui.YELLOW)
          logInfo.append(('forbidden-ip', '%s' % remote_ip))
          backend = None
        else:
          self.security = 'ip'

      # Parse things!
      if proto in ('websocket', 'http', 'http2', 'http3'):
        http_parse = HttpLineParser(lines=data.splitlines())
        logInfo[0:0] = [(http_parse.method, http_parse.path)]
      else:
        http_parse = None

      # Access control interception: check for HTTP Basic authentication.
      user_keys = [k for k in host_config if k.startswith('password/')]
      if user_keys:
        user, pwd, fail = None, None, True
        if http_parse:
          auth = http_parse.Header('Authorization')
          try:
            (how, ab64) = auth[0].strip().split()
            if how.lower() == 'basic':
              user, pwd = base64.decodestring(ab64).split(':')
          except:
            user = auth

          user_key = 'password/%s' % user
          if user and user_key in host_config:
            if host_config[user_key] == pwd:
              fail = False

        if fail:
          if logging.DEBUG_IO:
            print('=== REQUEST\n%s\n===' % data)
          self.ui.Notify(('%s - %s://%s:%s (USER ACCESS DENIED)'
                          ) % (remote_ip or 'unknown', proto, host, on_port),
                         prefix='!', color=self.ui.YELLOW)
          logInfo.append(('forbidden-user', '%s' % user))
          backend = None
          failure = ''
        else:
          self.security = 'password'

    if not backend:
      logInfo.append(('err', 'No back-end'))
      self.Log(logInfo, level=logging.LOG_LEVEL_ERR)
      self.Cleanup(close=False)
      return failure

    try:
      self.SetFD(rawsocket(socket.AF_INET, socket.SOCK_STREAM))
      try:
        self.fd.settimeout(2.0) # Missing in Python 2.2
      except:
        self.fd.setblocking(1)

      sspec = list(backend)
      if len(sspec) == 1: sspec.append(80)
      self.fd.connect(tuple(sspec))

      self.fd.setblocking(0)

    except socket.error as err:
      logInfo.append(('socket_error', '%s' % err))
      self.ui.Notify(('%s - %s://%s:%s (FAIL: %s:%s is down)'
                      ) % (remote_ip or 'unknown', proto, host, on_port,
                           sspec[0], sspec[1]),
                     prefix='!', color=self.ui.YELLOW)
      self.Log(logInfo, level=logging.LOG_LEVEL_ERR)
      self.Cleanup(close=False)
      return None

    sspec = (sspec[0], sspec[1])
    be_name = (sspec == self.conns.config.ui_sspec) and 'builtin' or ('%s:%s' % sspec)
    self.ui.Status('serving')
    self.ui.Notify(('%s < %s://%s:%s (%s)'
                    ) % (remote_ip or 'unknown', proto, host, on_port, be_name))
    self.Log(logInfo)
    self.conns.Add(self)
    return self

  FrontEnd = staticmethod(_FrontEnd)
  BackEnd = staticmethod(_BackEnd)

  def Shutdown(self, direction):
    try:
      if self.fd:
        if 'sock_shutdown' in dir(self.fd):
          # This is a pyOpenSSL socket, which has incompatible shutdown.
          if direction == socket.SHUT_RD:
            self.fd.shutdown()
          else:
            self.fd.sock_shutdown(direction)
        else:
          self.fd.shutdown(direction)
    except Exception as e:
      pass

  def ProcessTunnelEof(self, read_eof=False, write_eof=False):
    rv = True
    if write_eof and not self.read_eof:
      rv = self.ProcessEofRead(tell_tunnel=False) and rv
    if read_eof and not self.write_eof:
      rv = self.ProcessEofWrite(tell_tunnel=False) and rv
    return rv

  def ProcessEofRead(self, tell_tunnel=True):
    self.read_eof = True
    self.Shutdown(socket.SHUT_RD)

    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, read_eof=True)

    return self.ProcessEof()

  def ProcessEofWrite(self, tell_tunnel=True):
    self.write_eof = True
    if not self.write_blocked:
      self.Shutdown(socket.SHUT_WR)

    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, write_eof=True)

    if (self.conns and
        self.ConnType() == 'FE' and
        (not self.read_eof)):
      self.conns.SetIdle(self, 120)

    return self.ProcessEof()

  def Send(self, data, try_flush=False, activity=True, just_buffer=False,
                       allow_blocking=True):
    rv = Selectable.Send(self, data, try_flush=try_flush, activity=activity,
                                     just_buffer=just_buffer,
                                     allow_blocking=allow_blocking)
    if self.write_eof and not self.write_blocked:
      self.Shutdown(socket.SHUT_WR)
    elif try_flush or not self.write_blocked:
      if self.tunnel:
        self.tunnel.SendProgress(self.sid, self)
    return rv

  def ProcessData(self, data):
    if not self.tunnel:
      self.LogError('No tunnel! %s' % self)
      return False

    if not self.tunnel.SendData(self, data):
      self.LogDebug('Send to tunnel failed')
      return False

    if self.read_eof:
      return self.ProcessEofRead()
    return True


class UnknownConn(MagicProtocolParser):
  """This class is a connection which we're not sure what is yet."""

  def __init__(self, fd, address, on_port, conns):
    MagicProtocolParser.__init__(self, fd, address, on_port, ui=conns.config.ui)
    self.peeking = True
    self.sid = -1
    self.host = None
    self.proto = None
    self.said_hello = False
    self.bad_loops = 0
    self.error_details = {}

    # Set up our parser chain.
    self.parsers = [HttpLineParser]
    if IrcLineParser.PROTO in conns.config.server_protos:
      self.parsers.append(IrcLineParser)
    self.parser = MagicLineParser(parsers=self.parsers)

    self.conns = conns
    self.conns.Add(self)
    self.conns.SetIdle(self, 10)

  def Cleanup(self, close=True):
    MagicProtocolParser.Cleanup(self, close=close)
    self.conns = self.parser = None

  def SayHello(self):
    if self.said_hello:
      return False
    else:
      self.said_hello = True
    if self.on_port in SMTP_PORTS:
      self.Send(['220 ready ESMTP PageKite Magic Proxy\n'], try_flush=True)
    return True

  def __str__(self):
    return '%s (%s/%s:%s)' % (MagicProtocolParser.__str__(self),
                              (self.proto or '?'),
                              (self.on_port or '?'),
                              (self.host or '?'))

  # Any sort of EOF just means give up: if we haven't figured out what
  # kind of connnection this is yet, we won't without more data.
  def ProcessEofRead(self):
    self.Die(discard_buffer=True)
    return self.ProcessEof()
  def ProcessEofWrite(self):
    self.Die(discard_buffer=True)
    return self.ProcessEof()

  def ProcessLine(self, line, lines):
    if not self.parser: return True
    if self.parser.Parse(line) is False: return False
    if not self.parser.ParsedOK(): return True

    self.parser = self.parser.last_parser
    if self.parser.protocol == HttpLineParser.PROTO:
      # HTTP has special cases, including CONNECT etc.
      return self.ProcessParsedHttp(line, lines)
    else:
      return self.ProcessParsedMagic(self.parser.PROTOS, line, lines)

  def ProcessParsedMagic(self, protos, line, lines):
    if (self.conns and
        self.conns.config.CheckTunnelAcls(self.address, conn=self)):
      for proto in protos:
        if UserConn.FrontEnd(self, self.address,
                             proto, self.parser.domain, self.on_port,
                             self.parser.lines + lines, self.conns) is not None:
          self.Cleanup(close=False)
          return True

    self.Send([self.parser.ErrorReply(port=self.on_port)], try_flush=True)
    self.Cleanup()
    return False

  def ProcessParsedHttp(self, line, lines):
    done = False
    if self.parser.method == 'PING':
      self.Send('PONG %s\r\n\r\n' % self.parser.path)
      self.read_eof = self.write_eof = done = True
      self.fd.close()

    elif self.parser.method == 'CONNECT':
      if self.parser.path.lower().startswith('pagekite:'):
        if not self.conns.config.CheckTunnelAcls(self.address, conn=self):
          self.Send(HTTP_ConnectBad(code=403, status='Forbidden'),
                    try_flush=True)
          return False
        if Tunnel.FrontEnd(self, lines, self.conns) is None:
          self.Send(HTTP_ConnectBad(), try_flush=True)
          return False
        done = True

      else:
        try:
          connect_parser = self.parser
          chost, cport = connect_parser.path.split(':', 1)

          cport = int(cport)
          chost = StripEncodedIP(chost.lower())
          sid1 = ':%s' % chost
          sid2 = '-%s:%s' % (cport, chost)
          tunnels = self.conns.tunnels

          if not self.conns.config.CheckClientAcls(self.address, conn=self):
            self.Send(self.HTTP_Unavail(
                        self.conns.config, 'fe', 'raw', chost,
                        code=403, status='Forbidden',
                        other_details=self.error_details),
                      try_flush=True)
            return False

          # These allow explicit CONNECTs to direct http(s) or raw backends.
          # If no match is found, we throw an error.

          if cport in (80, 8080):
            if (('http'+sid1) in tunnels) or (
                ('http'+sid2) in tunnels) or (
                ('http2'+sid1) in tunnels) or (
                ('http2'+sid2) in tunnels) or (
                ('http3'+sid1) in tunnels) or (
                ('http3'+sid2) in tunnels):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpLineParser()
              self.Send(HTTP_ConnectOK(), try_flush=True)
              return True

          whost = chost
          if '.' in whost:
            whost = '*.' + '.'.join(whost.split('.')[1:])

          if cport == 443:
            if (('https'+sid1) in tunnels) or (
                ('https'+sid2) in tunnels) or (
                chost in self.conns.config.tls_endpoints) or (
                whost in self.conns.config.tls_endpoints):
              (self.on_port, self.host) = (cport, chost)
              self.parser = HttpLineParser()
              self.Send(HTTP_ConnectOK(), try_flush=True)
              return self.ProcessTls(''.join(lines), chost)

          if (cport in self.conns.config.server_raw_ports or
              VIRTUAL_PN in self.conns.config.server_raw_ports):
            for raw in ('raw',):
              if ((raw+sid1) in tunnels) or ((raw+sid2) in tunnels):
                (self.on_port, self.host) = (cport, chost)
                self.parser = HttpLineParser()
                self.Send(HTTP_ConnectOK(), try_flush=True)
                return self.ProcessProto(''.join(lines), raw, self.host)

          self.Send(HTTP_ConnectBad(), try_flush=True)
          return False

        except ValueError:
          pass

    if (not done and self.parser.method == 'GET'
                 and self.parser.path in MAGIC_PATHS
                 and 'v1.pagekite.org' in self.parser.Header('Sec-WebSocket-Protocol')
                 and 'websocket' in self.parser.Header('Upgrade')):
      if not self.conns.config.CheckTunnelAcls(self.address, conn=self):
        self.Send(HTTP_ConnectBad(code=403, status='Forbidden'),
                  try_flush=True)
        return False
      if Tunnel.FrontEnd(self, lines, self.conns) is None:
        self.Send(HTTP_ConnectBad(), try_flush=True)
        return False
      done = True

    if not done:
      if not self.host:
        hosts = self.parser.Header('Host')
        if hosts:
          self.host = StripEncodedIP(hosts[0].lower())
        else:
          self.Send(HTTP_Response(400, 'Bad request',
                    ['<html><body><h1>400 Bad request</h1>',
                     '<p>Invalid request, no Host: found.</p>',
                     '</body></html>\n'],
                    trackable=True,
                    overloaded=self.conns.config.Overloaded()))
          return False

      if self.parser.path.startswith(MAGIC_PREFIX):
        try:
          self.host = StripEncodedIP(self.parser.path.split('/')[2])
          if self.parser.path.endswith('.json'):
            self.proto = 'probe.json'
          else:
            self.proto = 'probe'
        except ValueError:
          pass

      if self.proto is None:
        self.proto = 'http'
        upgrade = self.parser.Header('Upgrade')
        if 'websocket' in self.conns.config.server_protos:
          if upgrade and upgrade[0].lower() == 'websocket':
            self.proto = 'websocket'

      if not self.conns.config.CheckClientAcls(self.address, conn=self):
        self.Send(self.HTTP_Unavail(
                    self.conns.config, 'fe', self.proto, self.host,
                    code=403, status='Forbidden',
                    other_details=self.error_details),
                  try_flush=True)
        self.Cleanup(close=True)
        return False

      address = self.address
      if int(self.on_port) in self.conns.config.server_portalias:
        xfwdf = self.parser.Header('X-Forwarded-For')
        if xfwdf and address[0] == '127.0.0.1':
          address = (xfwdf[0], address[1])

      done = True
      if UserConn.FrontEnd(self, address,
                           self.proto, self.host, self.on_port,
                           self.parser.lines + lines, self.conns) is None:
        if self.proto.startswith('probe'):
          self.Send(HTTP_NoFeConnection(self.proto),
                    try_flush=True)
        else:
          self.Send(self.HTTP_Unavail(
                        self.conns.config, 'fe', self.proto, self.host,
                        overloaded=self.conns.config.Overloaded(),
                        other_details=self.error_details
                    ), try_flush=True)
        self.Cleanup(close=True)
        return False

    # We are done!
    self.Cleanup(close=False)
    return True

  def ProcessTls(self, data, domain=None):
    if (not self.conns or
        not self.conns.config.CheckClientAcls(self.address, conn=self)):
      self.Send(TLS_Unavailable(forbidden=True), try_flush=True)
      return False

    if domain:
      domains = [domain]
    else:
      try:
        domains = self.GetSni(data)
        if not domains:
          domains = [self.conns.config.tls_default]
          if domains[0]:
            self.LogDebug('No SNI - trying: %s' % domains[0])
          else:
            domains = None
      except:
        # Probably insufficient data, just True and assume we'll have
        # better luck on the next round... but with a timeout.
        self.bad_loops += 1
        if self.bad_loops < 25:
          self.LogDebug('Error in ProcessTLS, will time out in 120 seconds.')
          self.conns.SetIdle(self, 120)
          return True
        else:
          self.LogDebug('Persistent error in ProcessTLS, aborting.')
          self.Send(TLS_Unavailable(unavailable=True), try_flush=True)
          return False

    if domains and domains[0] is not None:
      if UserConn.FrontEnd(self, self.address,
                           'https', domains[0], self.on_port,
                           [data], self.conns) is not None:
        # We are done!
        self.EatPeeked()
        self.Cleanup(close=False)
        return True
      else:
        # If we know how to terminate the TLS/SSL, do so!
        ctx = self.conns.config.GetTlsEndpointCtx(domains[0])
        if ctx:
          self.fd = socks.SSL_Connect(ctx, self.fd,
                                      accepted=True, server_side=True)
          self.peeking = False
          self.is_tls = False
          self.my_tls = True
          self.conns.SetIdle(self, 120)
          return True
        else:
          self.Send(TLS_Unavailable(unavailable=True), try_flush=True)
          return False

    self.Send(TLS_Unavailable(unavailable=True), try_flush=True)
    return False

  def ProcessProto(self, data, proto, domain):
    if (not self.conns or
        not self.conns.config.CheckClientAcls(self.address, conn=self)):
      return False

    if UserConn.FrontEnd(self, self.address,
                         proto, domain, self.on_port,
                         [data], self.conns) is None:
      return False

    # We are done!
    self.Cleanup(close=False)
    return True


class UiConn(LineParser):

  STATE_PASSWORD = 0
  STATE_LIVE     = 1

  def __init__(self, fd, address, on_port, conns):
    LineParser.__init__(self, fd=fd, address=address, on_port=on_port)
    self.state = self.STATE_PASSWORD

    self.conns = conns
    self.conns.Add(self)
    self.lines = []
    self.qc = threading.Condition()

    self.challenge = sha1hex('%s%8.8x' % (globalSecret(),
                                          random.randint(0, 0x7FFFFFFD)+1))
    self.expect = signToken(token=self.challenge,
                            secret=self.conns.config.ConfigSecret(),
                            payload=self.challenge,
                            length=1000)
    self.LogDebug('Expecting: %s' % self.expect)
    self.Send('PageKite? %s\r\n' % self.challenge)

  def readline(self):
    with self.qc:
      while not self.lines:
        self.qc.wait()
      line = self.lines.pop(0)
    return line

  def write(self, data):
    self.conns.config.ui_wfile.write(data)
    self.Send(data)

  def Cleanup(self):
    self.conns.config.ui.wfile = self.conns.config.ui_wfile
    self.conns.config.ui.rfile = self.conns.config.ui_rfile
    self.lines = self.conns.config.ui_conn = None
    self.conns = None
    LineParser.Cleanup(self)

  def Disconnect(self):
    self.Send('Goodbye')
    self.Cleanup()

  def ProcessLine(self, line, lines):
    if self.state == self.STATE_LIVE:
      with self.qc:
        self.lines.append(line)
        self.qc.notify()
      return True
    elif self.state == self.STATE_PASSWORD:
      if line.strip() == self.expect:
        if self.conns.config.ui_conn: self.conns.config.ui_conn.Disconnect()
        self.conns.config.ui_conn = self
        self.conns.config.ui.wfile = self
        self.conns.config.ui.rfile = self
        self.state = self.STATE_LIVE
        self.Send('OK!\r\n')
        return True
      else:
        self.Send('Sorry.\r\n')
        return False
    else:
      return False


class RawConn(Selectable):
  """This class is a raw/timed connection."""

  def __init__(self, fd, address, on_port, conns):
    Selectable.__init__(self, fd, address, on_port)
    self.my_tls = False
    self.is_tls = False

    domain = conns.LastIpDomain(address[0])
    if domain and UserConn.FrontEnd(self, address, 'raw', domain, on_port,
                                    [], conns):
      self.Cleanup(close=False)
    else:
      self.Cleanup()


class FastPingHelper(threading.Thread):
  def __init__(self, conns):
    threading.Thread.__init__(self)
    self.daemon = True
    self.lock = threading.Lock()
    self.conns = conns
    self.config = conns.config
    self.clients = []
    self.rejection = None
    self.overloaded = False
    self.waiting = True
    self.sleeptime = 0.03
    self.fast_pinged = []
    self.next_pinglog = time.time() + 1
    self.wq = Queue()
    self.up_rejection()

  def up_rejection(self):
    self.overloaded = self.config.Overloaded()
    self.rejection = HTTP_Unavailable('fe', 'http', 'ping.pagekite',
                                      overloaded=self.overloaded,
                                      advertise=False,
                                      dns_hints=self.config.DNS_Hints())

  def add_client(self, client, addr, handler):
    client.setblocking(0)
    with self.lock:
      self.clients.append((time.time(), client, addr, handler))
      if self.waiting:
        self.wq.put(1)

  def run_once(self):
    now = time.time()
    with self.lock:
      _clients, self.clients = self.clients, []
    for ts, client, addr, handler in _clients:
      try:
        data = s(client.recv(64, socket.MSG_PEEK))
      except:
        data = None
      try:
        if data:
          if '\nHost: ping.pagekite' in data:
            client.send(b(self.rejection))
            client.close()
            self.fast_pinged.append(obfuIp(addr[0]))
          else:
            handler(client, addr)
        elif ts > (now-5):
          with self.lock:
            self.clients.append((ts, client, addr, handler))
        else:
          logging.LogDebug('Timeout, dropping ' + obfuIp(addr[0]))
          client.close()
      except IOError:
        logging.LogDebug('IOError, dropping ' + obfuIp(addr[0]))
        # No action: just let the client get garbage collected
      except:
        logging.LogDebug('Error in FastPing: ' + format_exc())

    if now > self.next_pinglog:
      logging.LogDebug('Fast ping %s %d clients: %s' % (
        'discouraged' if self.overloaded else 'welcomed',
        len(self.fast_pinged),
        ', '.join(self.fast_pinged)))
      self.fast_pinged = []
      self.up_rejection()
      self.next_pinglog = now + 1

    self.sleeptime = max(0, (now + 0.015) - time.time())

  def run_until(self, deadline):
    try:
      while (time.time() + self.sleeptime) < deadline and self.clients:
        with self.lock:
          self.waiting = True
        while not self.wq.empty():
          self.wq.get()
        self.waiting = False
        time.sleep(self.sleeptime)
        self.run_once()
    except:
      logging.LogError('FastPingHelper crashed: ' + format_exc())

  def run(self):
    while True:
      try:
        while True:
          with self.lock:
            self.waiting = True
          while not self.clients or not self.wq.empty():
            self.wq.get()
          self.waiting = False
          time.sleep(self.sleeptime)
          self.run_once()
      except:
        logging.LogError('FastPingHelper crashed: ' + format_exc())
        time.sleep(1)


class Listener(Selectable):
  """This class listens for incoming connections and accepts them."""

  def __init__(self, host, port, conns, backlog=100,
                     connclass=UnknownConn, quiet=False, acl=None):
    Selectable.__init__(self, bind=(host, port), backlog=backlog)
    self.Log([('listen', '%s:%s' % (host, port))])
    if not quiet:
      conns.config.ui.Notify(' - Listening on %s:%s' % (host or '*', port))

    self.acl = acl
    self.acl_match = None

    self.connclass = connclass
    self.port = port
    self.conns = conns
    self.conns.Add(self)
    self.CountAs('listeners_live')

  def __str__(self):
    return '%s port=%s' % (Selectable.__str__(self), self.port)

  def __html__(self):
    return '<p>Listening on port %s for %s</p>' % (self.port, self.connclass)

  def check_acl(self, ipaddr, default=True):
    if self.acl and os.path.exists(self.acl):
      try:
        ipaddr = '%s' % ipaddr
        lc = 0
        with open(self.acl, 'r') as fd:
          for line in fd:
            line = line.lower().strip()
            lc += 1
            if line.startswith('#') or not line:
              continue
            try:
              words = line.split()
              pattern, rule = words[:2]
              reason = ' '.join(words[2:])
              if ipaddr == pattern:
                self.acl_match = (lc, pattern, rule, reason)
                return bool('allow' in rule)
              elif re.compile(pattern).match(ipaddr):
                self.acl_match = (lc, pattern, rule, reason)
                return bool('allow' in rule)
            except IndexError:
              self.LogDebug('Invalid line %d in ACL %s' % (lc, self.acl))
      except:
        self.LogDebug(
          'Failed to read/parse %s: %s' % (self.acl, format_exc()))
    self.acl_match = (0, '.*', default and 'allow' or 'reject', 'Default')
    return default

  def HandleClient(self, client, address):
    log_info = [('port', self.port)]
    if self.check_acl(address[0]):
      log_info += [('accept', '%s:%s' % (obfuIp(address[0]), address[1]))]
      uc = self.connclass(client, address, self.port, self.conns)
    else:
      log_info += [('reject', '%s:%s' % (obfuIp(address[0]), address[1]))]
      client.close()
    if self.acl:
      log_info += [('acl_line', '%s' % self.acl_match[0]),
                   ('reason', self.acl_match[3])]
    self.Log(log_info)
    return True

  def ReadData(self, maxread=None):
    try:
      self.sstate = 'accept'
      self.last_activity = time.time()
      client, address = self.fd.accept()
      if self.port not in SMTP_PORTS:
        while client:
          try:
            self.conns.ping_helper.add_client(client, address, self.HandleClient)
            client, address = self.fd.accept()
          except IOError:
            client = None
      elif client:
        self.sstate = 'client'
        self.HandleClient(client, address)
      self.sstate = (self.dead and 'dead' or 'idle')
      return True
    except IOError as err:
      self.sstate += '/ioerr=%s' % (err.errno,)
      self.LogDebug('Listener::ReadData: error: %s (%s)' % (err, err.errno))

    except socket.error as e:
      (errno, msg) = e
      self.sstate += '/sockerr=%s' % (errno,)
      self.LogInfo('Listener::ReadData: error: %s (errno=%s)' % (msg, errno))

    except Exception as e:
      self.sstate += '/exc'
      self.LogDebug('Listener::ReadData: %s' % e)

    return True
