#!/usr/bin/python -u
"""
These are the Connection classes, relatively high level classes that handle
incoming or outgoing network connections.
"""
##############################################################################
LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2012, the Beanstalks Project ehf. and Bjarni Runar Einarsson

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
import time
import traceback
import socket
import sys

from pagekite.compat import *
from pagekite.common import *
import pagekite.logging as logging

from selectables import *
from parsers import *
from proto import *


class Tunnel(ChunkParser):
  """A Selectable representing a PageKite tunnel."""

  S_NAME = 0
  S_PORTS = 1
  S_RAW_PORTS = 2
  S_PROTOS = 3

  def __init__(self, conns):
    ChunkParser.__init__(self, ui=conns.config.ui)

    # We want to be sure to read the entire chunk at once, including
    # headers to save cycles, so we double the size we're willing to
    # read here.
    self.maxread *= 2

    self.server_info = ['x.x.x.x:x', [], [], []]
    self.conns = conns
    self.users = {}
    self.remote_ssl = {}
    self.zhistory = {}
    self.backends = {}
    self.rtt = 100000
    self.last_ping = 0
    self.using_tls = False
    self.filters = []

  def __html__(self):
    return ('<b>Server name</b>: %s<br>'
            '%s') % (self.server_info[self.S_NAME], ChunkParser.__html__(self))

  def _FrontEnd(conn, body, conns):
    """This is what the front-end does when a back-end requests a new tunnel."""
    self = Tunnel(conns)
    requests = []
    try:
      for prefix in ('X-Beanstalk', 'X-PageKite'):
        for feature in conn.parser.Header(prefix+'-Features'):
          if not conns.config.disable_zchunks:
            if feature == 'ZChunks': self.EnableZChunks(level=1)

        # Track which versions we see in the wild.
        version = 'old'
        for v in conn.parser.Header(prefix+'-Version'): version = v
        global gYamon
        if gYamon: gYamon.vadd('version-%s' % version, 1, wrap=10000000)

        for replace in conn.parser.Header(prefix+'-Replace'):
          if replace in self.conns.conns_by_id:
            repl = self.conns.conns_by_id[replace]
            self.LogInfo('Disconnecting old tunnel: %s' % repl)
            self.conns.Remove(repl)
            repl.Cleanup()

        for bs in conn.parser.Header(prefix):
          # X-Beanstalk: proto:my.domain.com:token:signature
          proto, domain, srand, token, sign = bs.split(':')
          requests.append((proto.lower(), domain.lower(), srand, token, sign,
                           prefix))

    except Exception, err:
      self.LogError('Discarding connection: %s' % err)
      self.Cleanup()
      return None

    except socket.error, err:
      self.LogInfo('Discarding connection: %s' % err)
      self.Cleanup()
      return None

    self.last_activity = time.time()
    self.CountAs('backends_live')
    self.SetConn(conn)
    conns.auth.check(requests[:], conn,
                     lambda r, l: self.AuthCallback(conn, r, l))

    return self

  def RecheckQuota(self, conns, when=None):
    if when is None: when = time.time()
    if (self.quota and
        self.quota[0] is not None and
        self.quota[1] and
        (self.quota[2] < when-900)):
      self.quota[2] = when
      logging.LogDebug('Rechecking: %s' % (self.quota, ))
      conns.auth.check([self.quota[1]], self,
                       lambda r, l: self.QuotaCallback(conns, r, l))

  def QuotaCallback(self, conns, results, log_info):
    # Report new values to the back-end...
    if self.quota and (self.quota[0] >= 0): self.SendQuota()

    for r in results:
      if r[0] in ('X-PageKite-OK', 'X-PageKite-Duplicate'):
        return self

    self.Log(log_info)
    self.LogInfo('Ran out of quota or account deleted, closing tunnel.')
    conns.Remove(self)
    self.Cleanup()
    return None

  def AuthCallback(self, conn, results, log_info):

    if log_info: logging.Log(log_info)

    output = [HTTP_ResponseHeader(200, 'OK'),
              HTTP_Header('Transfer-Encoding', 'chunked'),
              HTTP_Header('X-PageKite-Protos', ', '.join(['%s' % p
                            for p in self.conns.config.server_protos])),
              HTTP_Header('X-PageKite-Ports', ', '.join(
                            ['%s' % self.conns.config.server_portalias.get(p, p)
                             for p in self.conns.config.server_ports]))]

    if not self.conns.config.disable_zchunks:
      output.append(HTTP_Header('X-PageKite-Features', 'ZChunks'))

    if self.conns.config.server_raw_ports:
      output.append(
        HTTP_Header('X-PageKite-Raw-Ports',
                    ', '.join(['%s' % p for p
                               in self.conns.config.server_raw_ports])))

    ok = {}
    for r in results:
      if r[0] in ('X-PageKite-OK', 'X-Beanstalk-OK'): ok[r[1]] = 1
      if r[0] == 'X-PageKite-SessionID': self.alt_id = r[1]
      output.append('%s: %s\r\n' % r)

    output.append(HTTP_StartBody())
    if not self.Send(output, try_flush=True, activity=False):
      conn.LogDebug('No tunnels configured, closing connection (send failed).')
      self.Cleanup()
      return None

    self.backends = ok.keys()
    if self.backends:
      for backend in self.backends:
        proto, domain, srand = backend.split(':')
        self.Log([('BE', 'Live'), ('proto', proto), ('domain', domain)])
        self.conns.Tunnel(proto, domain, self)
      if conn.quota:
        self.quota = conn.quota
        self.Log([('BE', 'Live'), ('quota', self.quota[0])])
      self.conns.Add(self, alt_id=self.alt_id)
      return self
    else:
      conn.LogDebug('No tunnels configured, closing connection.')
      self.Cleanup()
      return None

  def _RecvHttpHeaders(self, fd=None):
    data = ''
    fd = fd or self.fd
    while not data.endswith('\r\n\r\n') and not data.endswith('\n\n'):
      try:
        buf = fd.recv(1)
      except:
        # This is sloppy, but the back-end will just connect somewhere else
        # instead, so laziness here should be fine.
        buf = None
      if buf is None or buf == '':
        logging.LogDebug('Remote end closed connection.')
        return None
      data += buf
      self.read_bytes += len(buf)
    if logging.DEBUG_IO:
      print '<== IN (headers) =[%s]==(\n%s)==' % (self, data)
    return data

  def _Connect(self, server, conns, tokens=None):
    if self.fd: self.fd.close()

    sspec = server.split(':')
    if len(sspec) < 2: sspec = (sspec[0], 443)

    # Use chained SocksiPy to secure our communication.
    socks.DEBUG = (logging.DEBUG_IO or socks.DEBUG) and logging.LogDebug
    sock = socks.socksocket()
    if socks.HAVE_SSL:
      chain = ['default']
      if self.conns.config.fe_anon_tls_wrap:
        chain.append('ssl-anon:%s:%s' % (sspec[0], sspec[1]))
      if self.conns.config.fe_certname:
        chain.append('http:%s:%s' % (sspec[0], sspec[1]))
        chain.append('ssl:%s:443' % ','.join(self.conns.config.fe_certname))
      for hop in chain:
        sock.addproxy(*socks.parseproxy(hop))
    self.SetFD(sock)

    try:
      self.fd.settimeout(20.0) # Missing in Python 2.2
    except Exception:
      self.fd.setblocking(1)

    self.fd.connect((sspec[0], int(sspec[1])))
    replace_sessionid = self.conns.config.servers_sessionids.get(server, None)
    if (not self.Send(HTTP_PageKiteRequest(server,
                                         conns.config.backends,
                                       tokens,
                                     nozchunks=conns.config.disable_zchunks,
                                    replace=replace_sessionid),
                      activity=False, try_flush=True)
        or not self.Flush(wait=True)):
      return None, None

    data = self._RecvHttpHeaders()
    if not data: return None, None

    self.fd.setblocking(0)
    parse = HttpLineParser(lines=data.splitlines(),
                           state=HttpLineParser.IN_RESPONSE)

    return data, parse

  def _BackEnd(server, backends, require_all, conns):
    """This is the back-end end of a tunnel."""
    self = Tunnel(conns)
    self.backends = backends
    self.require_all = require_all
    self.server_info[self.S_NAME] = server
    abort = True
    try:
      begin = time.time()
      try:
        data, parse = self._Connect(server, conns)
      except:
        logging.LogError('Error in connect: %s' % traceback.format_exc())
        raise
      if data and parse:

        # Collect info about front-end capabilities, for interactive config
        for portlist in parse.Header('X-PageKite-Ports'):
          self.server_info[self.S_PORTS].extend(portlist.split(', '))
        for portlist in parse.Header('X-PageKite-Raw-Ports'):
          self.server_info[self.S_RAW_PORTS].extend(portlist.split(', '))
        for protolist in parse.Header('X-PageKite-Protos'):
          self.server_info[self.S_PROTOS].extend(protolist.split(', '))

        for sessionid in parse.Header('X-PageKite-SessionID'):
          self.alt_id = sessionid
          conns.config.servers_sessionids[server] = sessionid

        tryagain = False
        tokens = {}
        for request in parse.Header('X-PageKite-SignThis'):
          proto, domain, srand, token = request.split(':')
          tokens['%s:%s' % (proto, domain)] = token
          tryagain = True

        if tryagain:
          begin = time.time()
          data, parse = self._Connect(server, conns, tokens)

        if data and parse:
          sname = self.server_info[self.S_NAME]
          conns.config.ui.NotifyServer(self, self.server_info)

          for misc in parse.Header('X-PageKite-Misc'):
            args = parse_qs(misc)
            logdata = [('FE', sname)]
            for arg in args:
              logdata.append((arg, args[arg][0]))
            logging.Log(logdata)
            if 'motd' in args and args['motd'][0]:
              conns.config.ui.NotifyMOTD(sname, args['motd'][0])

          for quota in parse.Header('X-PageKite-Quota'):
            self.quota = [float(quota), None, None]
            self.Log([('FE', sname), ('quota', quota)])

          for quota in parse.Header('X-PageKite-QConns'):
            self.q_conns = float(quota)
            self.Log([('FE', sname), ('q_conns', quota)])

          for quota in parse.Header('X-PageKite-QDays'):
            self.q_days = float(quota)
            self.Log([('FE', sname), ('q_days', quota)])

          if self.quota:
            conns.config.ui.NotifyQuota(self.quota[0],
                                        self.q_days, self.q_conns)

          invalid_reasons = {}
          for request in parse.Header('X-PageKite-Invalid-Why'):
            # This is future-compatible, in that we can add more fields later.
            details = request.split(';')
            invalid_reasons[details[0]] = details[1]

          for request in parse.Header('X-PageKite-Invalid'):
            proto, domain, srand = request.split(':')
            reason = invalid_reasons.get(request, 'unknown')
            self.Log([('FE', sname),
                      ('err', 'Rejected'),
                      ('proto', proto),
                      ('reason', reason),
                      ('domain', domain)])
            conns.config.ui.NotifyKiteRejected(proto, domain, reason, crit=True)
            conns.config.SetBackendStatus(domain, proto,
                                          add=BE_STATUS_ERR_TUNNEL)

          for request in parse.Header('X-PageKite-Duplicate'):
            abort = True
            proto, domain, srand = request.split(':')
            self.Log([('FE', self.server_info[self.S_NAME]),
                      ('err', 'Duplicate'),
                      ('proto', proto),
                      ('domain', domain)])
            conns.config.ui.NotifyKiteRejected(proto, domain, 'duplicate')
            conns.config.SetBackendStatus(domain, proto,
                                          add=BE_STATUS_ERR_TUNNEL)

          if not conns.config.disable_zchunks:
            for feature in parse.Header('X-PageKite-Features'):
              if feature == 'ZChunks': self.EnableZChunks(level=9)

          ssl_available = {}
          for request in parse.Header('X-PageKite-SSL-OK'):
            ssl_available[request] = True

          for request in parse.Header('X-PageKite-OK'):
            abort = False
            proto, domain, srand = request.split(':')
            conns.Tunnel(proto, domain, self)
            status = BE_STATUS_OK
            if request in ssl_available:
              status |= BE_STATUS_REMOTE_SSL
              self.remote_ssl[(proto, domain)] = True
            self.Log([('FE', sname),
                      ('proto', proto),
                      ('domain', domain),
                      ('ssl', (request in ssl_available))])
            conns.config.SetBackendStatus(domain, proto, add=status)

        self.rtt = (time.time() - begin)


    except socket.error, e:
      self.Cleanup()
      return None

    except Exception, e:
      self.LogError('Server response parsing failed: %s' % e)
      self.Cleanup()
      return None

    if abort: return None

    conns.Add(self)
    self.CountAs('frontends_live')
    self.last_activity = time.time()

    return self

  FrontEnd = staticmethod(_FrontEnd)
  BackEnd = staticmethod(_BackEnd)

  def SendData(self, conn, data, sid=None, host=None, proto=None, port=None,
                                 chunk_headers=None):
    sid = int(sid or conn.sid)
    if conn: self.users[sid] = conn
    if not sid in self.zhistory: self.zhistory[sid] = [0, 0]

    # Pass outgoing data through any defined filters
    for f in self.filters:
      try:
        data = f.filter_data_out(self, sid, data)
      except:
        logging.LogError(('Ignoring error in filter_out %s: %s'
                          ) % (f, traceback.format_exc()))

    sending = ['SID: %s\r\n' % sid]
    if proto: sending.append('Proto: %s\r\n' % proto)
    if host: sending.append('Host: %s\r\n' % host)
    if port:
      porti = int(port)
      if porti in self.conns.config.server_portalias:
        sending.append('Port: %s\r\n' % self.conns.config.server_portalias[porti])
      else:
        sending.append('Port: %s\r\n' % port)
    if chunk_headers:
      for ch in chunk_headers: sending.append('%s: %s\r\n' % ch)
    sending.append('\r\n')
    sending.append(data)

    return self.SendChunked(sending, zhistory=self.zhistory[sid])

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

  def Cleanup(self, close=True):
    if self.users:
      for sid in self.users.keys(): self.CloseStream(sid)
    ChunkParser.Cleanup(self, close=close)
    self.conns = None
    self.users = self.zhistory = self.backends = {}

  def ResetRemoteZChunks(self):
    return self.SendChunked('NOOP: 1\r\nZRST: 1\r\n\r\n!', compress=False)

  def SendPing(self):
    self.last_ping = int(time.time())
    self.LogDebug("Ping", [('host', self.server_info[self.S_NAME])])
    return self.SendChunked('NOOP: 1\r\nPING: 1\r\n\r\n!', compress=False)

  def SendPong(self):
    return self.SendChunked('NOOP: 1\r\n\r\n!', compress=False)

  def SendQuota(self):
    if self.q_days is not None:
      return self.SendChunked(('NOOP: 1\r\nQuota: %s\r\nQDays: %s\r\nQConns: %s\r\n\r\n!'
                               ) % (self.quota[0], self.q_days, self.q_conns),
                              compress=False)
    else:
      return self.SendChunked('NOOP: 1\r\nQuota: %s\r\n\r\n!' % self.quota[0],
                              compress=False)

  def SendProgress(self, sid, conn, throttle=False):
    # FIXME: Optimize this away unless meaningful progress has been made?
    msg = ('NOOP: 1\r\n'
           'SID: %s\r\n'
           'SKB: %d\r\n') % (sid, (conn.all_out + conn.wrote_bytes)/1024)
    throttle = throttle and ('SPD: %d\r\n' % conn.write_speed) or ''
    return self.SendChunked('%s%s\r\n!' % (msg, throttle), compress=False)

  def ProcessCorruptChunk(self, data):
    self.ResetRemoteZChunks()
    return True

  def Probe(self, host):
    for bid in self.conns.config.backends:
      be = self.conns.config.backends[bid]
      if be[BE_DOMAIN] == host:
        bhost, bport = (be[BE_BHOST], be[BE_BPORT])
        # FIXME: Should vary probe by backend type
        if self.conns.config.Ping(bhost, int(bport)) > 2: return False
    return True

  def AutoThrottle(self, max_speed=None, remote=False, delay=0.2):
    # Never throttle tunnels.
    return True

  def ProgressTo(self, parse):
    try:
      sid = int(parse.Header('SID')[0])
      bps = int((parse.Header('SPD') or [-1])[0])
      skb = int((parse.Header('SKB') or [-1])[0])
      if sid in self.users:
        self.users[sid].RecordProgress(skb, bps)
    except:
      logging.LogError(('Tunnel::ProgressTo: That made no sense! %s'
                        ) % traceback.format_exc())
    return True

  # If a tunnel goes down, we just go down hard and kill all our connections.
  def ProcessEofRead(self):
    if self.conns: self.conns.Remove(self)
    self.Cleanup()
    return True

  def ProcessEofWrite(self):
    return self.ProcessEofRead()

  def ProcessChunk(self, data):
    try:
      headers, data = data.split('\r\n\r\n', 1)
      parse = HttpLineParser(lines=headers.splitlines(),
                             state=HttpLineParser.IN_HEADERS)
    except ValueError:
      logging.LogError('Tunnel::ProcessChunk: Corrupt packet!')
      return False

    try:
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
      if parse.Header('PING'): return self.SendPong()
      if parse.Header('ZRST') and not self.ResetZChunks(): return False
      if parse.Header('SPD') or parse.Header('SKB'):
        if not self.ProgressTo(parse): return False
      if parse.Header('NOOP'): return True
    except Exception, e:
      logging.LogError('Tunnel::ProcessChunk: Corrupt chunk: %s' % e)
      return False

    proto = conn = sid = None
    try:
      sid = int(parse.Header('SID')[0])
      eof = parse.Header('EOF')
    except IndexError:
      logging.LogError('Tunnel::ProcessChunk: Corrupt packet!')
      return False

    if eof:
      self.EofStream(sid, eof[0])
    else:
      if sid in self.users:
        conn = self.users[sid]
        # Pass incoming data through filters, if we have any.
        for f in self.filters:
          try:
            data = f.filter_data_in(self, sid, data)
          except:
            logging.LogError(('Ignoring error in filter_in %s: %s'
                              ) % (f, traceback.format_exc()))
      else:
        proto = (parse.Header('Proto') or [''])[0].lower()
        port = (parse.Header('Port') or [''])[0].lower()
        host = (parse.Header('Host') or [''])[0].lower()
        rIp = (parse.Header('RIP') or [''])[0].lower()
        rPort = (parse.Header('RPort') or [''])[0].lower()
        rTLS = (parse.Header('RTLS') or [''])[0].lower()
        if proto and host:
# FIXME:
#         if proto == 'https':
#           if host in self.conns.config.tls_endpoints:
#             print 'Should unwrap SSL from %s' % host

          if proto.startswith('probe'):
            if self.conns.config.no_probes:
              logging.LogDebug('Responding to probe for %s: rejected' % host)
              if not self.SendChunked('SID: %s\r\n\r\n%s' % (
                                      sid, HTTP_NoFeConnection(proto) )):
                return False
            elif self.Probe(host):
              logging.LogDebug('Responding to probe for %s: good' % host)
              if not self.SendChunked('SID: %s\r\n\r\n%s' % (
                                      sid, HTTP_GoodBeConnection(proto) )):
                return False
            else:
              logging.LogDebug('Responding to probe for %s: back-end down' % host)
              if not self.SendChunked('SID: %s\r\n\r\n%s' % (
                                      sid, HTTP_NoBeConnection(proto) )):
                return False
          else:
            # Pass incoming data through filters, if we have any.
            for f in self.filters:
              try:
                f.filter_set_sid(sid, {
                  'proto': proto,
                  'port': port,
                  'host': host,
                  'remote_ip': rIp,
                  'remote_port': rPort
                })
                data = f.filter_data_in(self, sid, data)
              except:
                logging.LogError(('Ignoring error in filter_new/in %s: %s'
                                  ) % (f, traceback.format_exc()))

            conn = UserConn.BackEnd(proto, host, sid, self, port,
                                    remote_ip=rIp, remote_port=rPort, data=data)
            if proto in ('http', 'http2', 'http3', 'websocket'):
              if conn is None:
                if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                                        HTTP_Unavailable('be', proto, host,
                                       frame_url=self.conns.config.error_url))):
                  return False
              elif not conn:
                if not self.SendChunked('SID: %s\r\n\r\n%s' % (sid,
                                        HTTP_Unavailable('be', proto, host,
                                       frame_url=self.conns.config.error_url,
                                      code=401))):
                  return False
              elif rIp:
                add_headers = ('\nX-Forwarded-For: %s\r\n'
                               'X-PageKite-Port: %s\r\n'
                               'X-PageKite-Proto: %s\r\n'
                               ) % (rIp, port,
                                    # FIXME: Checking for port == 443 is wrong!
                                    ((rTLS or (int(port) == 443)) and 'https'
                                                                   or 'http'))
                rewritehost = conn.config.get('rewritehost', False)
                if rewritehost:
                  if rewritehost is True:
                    rewritehost = conn.backend[BE_BHOST]
                  for hdr in ('host', 'connection', 'keep-alive'):
                    data = re.sub(r'(?mi)^'+hdr, 'X-Old-'+hdr, data)
                  add_headers += ('Connection: close\r\n'
                                  'Host: %s\r\n') % rewritehost
                req, rest = re.sub(r'(?mi)^x-forwarded-for',
                                   'X-Old-Forwarded-For', data).split('\n', 1)
                data = ''.join([req, add_headers, rest])

            elif proto == 'httpfinger':
              # Rewrite a finger request to HTTP.
              try:
                firstline, rest = data.split('\n', 1)
                if conn.config.get('rewritehost', False):
                  rewritehost = conn.backend[BE_BHOST]
                else:
                  rewritehost = host
                if '%s' in self.conns.config.finger_path:
                  args =  (firstline.strip(), rIp, rewritehost, rest)
                else:
                  args =  (rIp, rewritehost, rest)
                data = ('GET '+self.conns.config.finger_path+' HTTP/1.1\r\n'
                        'X-Forwarded-For: %s\r\n'
                        'Connection: close\r\n'
                        'Host: %s\r\n\r\n%s') % args
              except Exception, e:
                self.LogError('Error formatting HTTP-Finger: %s' % e)
                conn = None

          if conn:
            self.users[sid] = conn

            if proto == 'httpfinger':
              conn.fd.setblocking(1)
              conn.Send(data, try_flush=True) or conn.Flush(wait=True)
              self._RecvHttpHeaders(fd=conn.fd)
              conn.fd.setblocking(0)
              data = ''

      if not conn:
        self.CloseStream(sid)
        if not self.SendStreamEof(sid): return False
      else:
        if not conn.Send(data, try_flush=True):
          # FIXME
          pass

        if len(conn.write_blocked) > 0 and conn.created < time.time()-3:
          return self.SendProgress(sid, conn, throttle=True)

    return True


class LoopbackTunnel(Tunnel):
  """A Tunnel which just loops back to this process."""

  def __init__(self, conns, which, backends):
    Tunnel.__init__(self, conns)

    self.backends = backends
    self.require_all = True
    self.server_info[self.S_NAME] = LOOPBACK[which]
    self.other_end = None
    if which == 'FE':
      for d in backends.keys():
        if backends[d][BE_BHOST]:
          proto, domain = d.split(':')
          self.conns.Tunnel(proto, domain, self)
          self.Log([('FE', self.server_info[self.S_NAME]),
                    ('proto', proto),
                    ('domain', domain)])

  def Cleanup(self, close=True):
    Tunnel.Cleanup(self, close=close)
    other = self.other_end
    self.other_end = None
    if other and other.other_end: other.Cleanup()

  def Linkup(self, other):
    self.other_end = other
    other.other_end = self

  def _Loop(conns, backends):
    return LoopbackTunnel(conns, 'FE', backends
                          ).Linkup(LoopbackTunnel(conns, 'BE', backends))

  Loop = staticmethod(_Loop)

  def Send(self, data):
    return self.other_end.ProcessData(''.join(data))


class UserConn(Selectable):
  """A Selectable representing a user's connection."""

  def __init__(self, address, ui=None):
    Selectable.__init__(self, address=address, ui=ui)
    self.tunnel = None
    self.conns = None
    self.backend = BE_NONE[:]
    self.config = {}
    # UserConn objects are considered active immediately
    self.last_activity = time.time()

  def __html__(self):
    return ('<b>Tunnel</b>: <a href="/conn/%s">%s</a><br>'
            '%s') % (self.tunnel and self.tunnel.sid or '',
                     escape_html('%s' % (self.tunnel or '')),
                     Selectable.__html__(self))

  def IsReadable(self, now):
    if self.tunnel and self.tunnel.IsBlocked():
      return False
    return Selectable.IsReadable(self, now)

  def CloseTunnel(self, tunnel_closed=False):
    tunnel = self.tunnel
    self.tunnel = None
    if tunnel and not tunnel_closed:
      if not self.read_eof or not self.write_eof:
        tunnel.SendStreamEof(self.sid, write_eof=True, read_eof=True)
      tunnel.CloseStream(self.sid, stream_closed=True)
    self.ProcessTunnelEof(read_eof=True, write_eof=True)

  def Cleanup(self, close=True):
    if close:
      self.CloseTunnel()
    Selectable.Cleanup(self, close=close)
    if self.conns:
      self.conns.Remove(self)
      self.backend = self.config = self.conns = None

  def _FrontEnd(conn, address, proto, host, on_port, body, conns):
    # This is when an external user connects to a server and requests a
    # web-page.  We have to give it to them!
    self = UserConn(address, ui=conns.config.ui)
    self.conns = conns
    self.SetConn(conn)

    if ':' in host: host, port = host.split(':', 1)
    self.proto = proto
    self.host = host

    # If the listening port is an alias for another...
    if int(on_port) in conns.config.server_portalias:
      on_port = conns.config.server_portalias[int(on_port)]

    # Try and find the right tunnel. We prefer proto/port specifications first,
    # then the just the proto. If the protocol is WebSocket and no tunnel is
    # found, look for a plain HTTP tunnel.
    if proto.startswith('probe'):
      protos = ['http', 'https', 'websocket', 'raw', 'irc',
                'finger', 'httpfinger']
      ports = conns.config.server_ports[:]
      ports.extend(conns.config.server_aliasport.keys())
      ports.extend([x for x in conns.config.server_raw_ports if x != VIRTUAL_PN])
    else:
      protos = [proto]
      ports = [on_port]
      if proto == 'websocket': protos.append('http')
      elif proto == 'http': protos.extend(['http2', 'http3'])

    tunnels = None
    for p in protos:
      for prt in ports:
        if not tunnels: tunnels = conns.Tunnel('%s-%s' % (p, prt), host)
      if not tunnels: tunnels = conns.Tunnel(p, host)
    if not tunnels: tunnels = conns.Tunnel(protos[0], CATCHALL_HN)

    if self.address:
      chunk_headers = [('RIP', self.address[0]), ('RPort', self.address[1])]
      if conn.my_tls: chunk_headers.append(('RTLS', 1))

    if tunnels: self.tunnel = tunnels[0]
    if (self.tunnel and self.tunnel.SendData(self, ''.join(body), host=host,
                                             proto=proto, port=on_port,
                                             chunk_headers=chunk_headers)
                    and self.conns):
      self.Log([('domain', self.host), ('on_port', on_port), ('proto', self.proto), ('is', 'FE')])
      self.conns.Add(self)
      if proto.startswith('http'):
        self.conns.TrackIP(address[0], host)
        # FIXME: Use the tracked data to detect & mitigate abuse?
      return self
    else:
      self.LogDebug('No back-end', [('on_port', on_port), ('proto', self.proto),
                                    ('domain', self.host), ('is', 'FE')])
      self.Cleanup(close=False)
      return None

  def _BackEnd(proto, host, sid, tunnel, on_port,
               remote_ip=None, remote_port=None, data=None):
    # This is when we open a backend connection, because a user asked for it.
    self = UserConn(None, ui=tunnel.conns.config.ui)
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

    if proto == 'http': protos = [proto, 'http2', 'http3']
    elif proto.startswith('probe'): protos = ['http', 'http2', 'http3']
    elif proto == 'websocket': protos = [proto, 'http', 'http2', 'http3']
    else: protos = [proto]

    for p in protos:
      if not backend: backend, be = self.conns.config.GetBackendServer('%s-%s' % (p, on_port), host)
      if not backend: backend, be = self.conns.config.GetBackendServer(p, host)
      if not backend: backend, be = self.conns.config.GetBackendServer(p, CATCHALL_HN)

    logInfo = [
      ('on_port', on_port),
      ('proto', proto),
      ('domain', host),
      ('is', 'BE')
    ]
    if remote_ip: logInfo.append(('remote_ip', remote_ip))

    # Strip off useless IPv6 prefix, if this is an IPv4 address.
    if remote_ip.startswith('::ffff:') and ':' not in remote_ip[7:]:
      remote_ip = remote_ip[7:]

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

      # Access control interception: check for HTTP Basic authentication.
      user_keys = [k for k in host_config if k.startswith('password/')]
      if user_keys:
        user, pwd, fail = None, None, True
        if proto in ('websocket', 'http', 'http2', 'http3'):
          parse = HttpLineParser(lines=data.splitlines())
          auth = parse.Header('Authorization')
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
          if logging.DEBUG_IO: print '=== REQUEST\n%s\n===' % data
          self.ui.Notify(('%s - %s://%s:%s (USER ACCESS DENIED)'
                          ) % (remote_ip or 'unknown', proto, host, on_port),
                         prefix='!', color=self.ui.YELLOW)
          logInfo.append(('forbidden-user', '%s' % user))
          backend = None
          failure = ''

    if not backend:
      logInfo.append(('err', 'No back-end'))
      self.Log(logInfo)
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

    except socket.error, err:
      logInfo.append(('socket_error', '%s' % err))
      self.ui.Notify(('%s - %s://%s:%s (FAIL: %s:%s is down)'
                      ) % (remote_ip or 'unknown', proto, host, on_port,
                           sspec[0], sspec[1]),
                     prefix='!', color=self.ui.YELLOW)
      self.Log(logInfo)
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
    except Exception, e:
      pass

  def ProcessTunnelEof(self, read_eof=False, write_eof=False):
    if read_eof and not self.write_eof:
      self.ProcessEofWrite(tell_tunnel=False)
    if write_eof and not self.read_eof:
      self.ProcessEofRead(tell_tunnel=False)
    return True

  def ProcessEofRead(self, tell_tunnel=True):
    self.read_eof = True
    self.Shutdown(socket.SHUT_RD)

    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, read_eof=True)

    return self.ProcessEof()

  def ProcessEofWrite(self, tell_tunnel=True):
    self.write_eof = True
    if not self.write_blocked: self.Shutdown(socket.SHUT_WR)

    if tell_tunnel and self.tunnel:
      self.tunnel.SendStreamEof(self.sid, write_eof=True)

    return self.ProcessEof()

  def Send(self, data, try_flush=False):
    rv = Selectable.Send(self, data, try_flush=try_flush)
    if self.write_eof and not self.write_blocked:
      self.Shutdown(socket.SHUT_WR)
    elif try_flush or not self.write_blocked:
      self.tunnel.SendProgress(self.sid, self)
    return rv

  def ProcessData(self, data):
    if not self.tunnel:
      self.LogError('No tunnel! %s' % self)
      return False

    if not self.tunnel.SendData(self, data):
      self.LogDebug('Send to tunnel failed')
      return False

    # Back off if tunnel is stuffed.
    if self.tunnel and len(self.tunnel.write_blocked) > 1024000:
      # FIXME: think about this...
      self.Throttle(delay=(len(self.tunnel.write_blocked)-204800)/max(50000,
                    self.tunnel.write_speed))

    if self.read_eof: return self.ProcessEofRead()
    return True


class UnknownConn(MagicProtocolParser):
  """This class is a connection which we're not sure what is yet."""

  def __init__(self, fd, address, on_port, conns):
    MagicProtocolParser.__init__(self, fd, address, on_port, ui=conns.config.ui)
    self.peeking = True

    # Set up our parser chain.
    self.parsers = [HttpLineParser]
    if IrcLineParser.PROTO in conns.config.server_protos:
      self.parsers.append(IrcLineParser)
    if FingerLineParser.PROTO in conns.config.server_protos:
      self.parsers.append(FingerLineParser)
    self.parser = MagicLineParser(parsers=self.parsers)

    self.conns = conns
    self.conns.Add(self)
    self.sid = -1

    self.host = None
    self.proto = None
    self.said_hello = False

  def Cleanup(self, close=True):
    if self.conns: self.conns.Remove(self)
    MagicProtocolParser.Cleanup(self, close=close)
    self.conns = self.parser = None

  def SayHello(self):
    if self.said_hello:
      return
    else:
      self.said_hello = True

    if self.on_port in (25, 125, ):
      # FIXME: We don't actually support SMTP yet and 125 is bogus.
      self.Send(['220 ready ESMTP PageKite Magic Proxy\n'], try_flush=True)

  def __str__(self):
    return '%s (%s/%s:%s)' % (MagicProtocolParser.__str__(self),
                              (self.proto or '?'),
                              (self.on_port or '?'),
                              (self.host or '?'))

  def ProcessEofRead(self):
    self.read_eof = True
    return self.ProcessEof()

  def ProcessEofWrite(self):
    self.read_eof = True
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
        if Tunnel.FrontEnd(self, lines, self.conns) is None: return False
        done = True

      else:
        try:
          connect_parser = self.parser
          chost, cport = connect_parser.path.split(':', 1)

          cport = int(cport)
          chost = chost.lower()
          sid1 = ':%s' % chost
          sid2 = '-%s:%s' % (cport, chost)
          tunnels = self.conns.tunnels

          # These allow explicit CONNECTs to direct http(s) or raw backends.
          # If no match is found, we fall through to default HTTP processing.

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
            for raw in ('raw', 'finger'):
              if ((raw+sid1) in tunnels) or ((raw+sid2) in tunnels):
                (self.on_port, self.host) = (cport, chost)
                self.parser = HttpLineParser()
                self.Send(HTTP_ConnectOK(), try_flush=True)
                return self.ProcessRaw(''.join(lines), self.host)

        except ValueError:
          pass

    if (not done and self.parser.method == 'POST'
                 and self.parser.path in MAGIC_PATHS):
      # FIXME: DEPRECATE: Make this go away!
      if Tunnel.FrontEnd(self, lines, self.conns) is None: return False
      done = True

    if not done:
      if not self.host:
        hosts = self.parser.Header('Host')
        if hosts:
          self.host = hosts[0].lower()
        else:
          self.Send(HTTP_Response(400, 'Bad request',
                    ['<html><body><h1>400 Bad request</h1>',
                     '<p>Invalid request, no Host: found.</p>',
                     '</body></html>']))
          return False

      if self.parser.path.startswith(MAGIC_PREFIX):
        try:
          self.host = self.parser.path.split('/')[2]
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
          self.Send(HTTP_Unavailable('fe', self.proto, self.host,
                                     frame_url=self.conns.config.error_url),
                    try_flush=True)

        return False

    # We are done!
    self.Cleanup(close=False)
    return True

  def ProcessTls(self, data, domain=None):
    if domain:
      domains = [domain]
    else:
      try:
        domains = self.GetSni(data)
        if not domains:
          domains = [self.conns.LastIpDomain(self.address[0]) or self.conns.config.tls_default]
          logging.LogDebug('No SNI - trying: %s' % domains[0])
          if not domains[0]: domains = None
      except Exception:
        # Probably insufficient data, just return True and assume we'll have
        # better luck on the next round.
        return True

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
          return True
        else:
          return False

    return False

  def ProcessRaw(self, data, domain):
    if UserConn.FrontEnd(self, self.address,
                         'raw', domain, self.on_port,
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
    logging.LogDebug('Expecting: %s' % self.expect)
    self.Send('PageKite? %s\r\n' % self.challenge)


  def readline(self):
    self.qc.acquire()
    while not self.lines: self.qc.wait()
    line = self.lines.pop(0)
    self.qc.release()
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
      self.qc.acquire()
      self.lines.append(line)
      self.qc.notify()
      self.qc.release()
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


class Listener(Selectable):
  """This class listens for incoming connections and accepts them."""

  def __init__(self, host, port, conns, backlog=100,
                     connclass=UnknownConn, quiet=False):
    Selectable.__init__(self, bind=(host, port), backlog=backlog)
    self.Log([('listen', '%s:%s' % (host, port))])
    if not quiet:
      conns.config.ui.Notify(' - Listening on %s:%s' % (host or '*', port))

    self.connclass = connclass
    self.port = port
    self.last_activity = self.created + 1
    self.conns = conns
    self.conns.Add(self)

  def __str__(self):
    return '%s port=%s' % (Selectable.__str__(self), self.port)

  def __html__(self):
    return '<p>Listening on port %s for %s</p>' % (self.port, self.connclass)

  def ReadData(self, maxread=None):
    try:
      client, address = self.fd.accept()
      if client:
        self.Log([('accept', '%s:%s' % (obfuIp(address[0]), address[1]))])
        uc = self.connclass(client, address, self.port, self.conns)
        return True

    except IOError, err:
      if err.errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogDebug('Listener::ReadData: error: %s (%s)' % (err, err.errno))

    except socket.error, (errno, msg):
      if errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogInfo('Listener::ReadData: error: %s (errno=%s)' % (msg, errno))
        raise

    except Exception, e:
      logging.LogDebug('Listener::ReadData: %s' % e)
      raise

    return False
