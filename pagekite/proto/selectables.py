#!/usr/bin/python -u
"""
Selectables are low level base classes which cooperate with our select-loop.
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
import errno
import struct
import threading
import time
import zlib

from pagekite.compat import *
from pagekite.common import *
import pagekite.logging as logging
import pagekite.compat as compat
import pagekite.common as common


def obfuIp(ip):
  quads = ('%s' % ip).replace(':', '.').split('.')
  return '~%s' % '.'.join([q for q in quads[-2:]])


SELECTABLE_LOCK = threading.Lock()
SELECTABLE_ID = 0
SELECTABLES = {}
def getSelectableId(what):
  global SELECTABLES, SELECTABLE_ID, SELECTABLE_LOCK
  try:
    SELECTABLE_LOCK.acquire()
    count = 0
    while SELECTABLE_ID in SELECTABLES:
      SELECTABLE_ID += 1
      SELECTABLE_ID %= 0x10000
      if SELECTABLE_ID & 0x01000:
        logging.LogDebug('Selectable map: %s' % (SELECTABLES, ))
      count += 1
      if count > 0x10001:
        raise ValueError('Too many conns!')
    SELECTABLES[SELECTABLE_ID] = what
    return SELECTABLE_ID
  finally:
    SELECTABLE_LOCK.release()


class Selectable(object):
  """A wrapper around a socket, for use with select."""

  HARMLESS_ERRNOS = (errno.EINTR, errno.EAGAIN, errno.ENOMEM, errno.EBUSY,
                     errno.EDEADLK, errno.EWOULDBLOCK, errno.ENOBUFS,
                     errno.EALREADY)

  def __init__(self, fd=None, address=None, on_port=None, maxread=16*1024,
                     ui=None, tracked=True, bind=None, backlog=100):
    self.fd = None

    try:
      self.SetFD(fd or rawsocket(socket.AF_INET6, socket.SOCK_STREAM), six=True)
      if bind:
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.fd.bind(bind)
        self.fd.listen(backlog)
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except:
      self.SetFD(fd or rawsocket(socket.AF_INET, socket.SOCK_STREAM))
      if bind:
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.fd.bind(bind)
        self.fd.listen(backlog)
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    self.address = address
    self.on_port = on_port
    self.created = self.bytes_logged = time.time()
    self.last_activity = 0
    self.dead = False
    self.ui = ui

    # Quota-related stuff
    self.quota = None
    self.q_conns = None
    self.q_days = None

    # Read-related variables
    self.maxread = maxread
    self.read_bytes = self.all_in = 0
    self.read_eof = False
    self.peeking = False
    self.peeked = 0

    # Write-related variables
    self.wrote_bytes = self.all_out = 0
    self.write_blocked = ''
    self.write_speed = 102400
    self.write_eof = False
    self.write_retry = None

    # Flow control v1
    self.throttle_until = (time.time() - 1)
    self.max_read_speed = 96*1024
    # Flow control v2
    self.acked_kb_delta = 0

    # Compression stuff
    self.lock = threading.Lock()
    self.zw = None
    self.zlevel = 1
    self.zreset = False

    # logging.Logging
    self.logged = []
    self.alt_id = None
    self.countas = 'selectables_live'
    self.sid = getSelectableId(self.countas)

    if address:
      addr = address or ('x.x.x.x', 'x')
      self.log_id = 's%x/%s:%s' % (self.sid, obfuIp(addr[0]), addr[1])
    else:
      self.log_id = 's%x' % self.sid

    if common.gYamon:
      common.gYamon.vadd(self.countas, 1)
      common.gYamon.vadd('selectables', 1)

  def CountAs(self, what):
    global SELECTABLES
    SELECTABLES[self.sid] = what
    if common.gYamon:
      common.gYamon.vadd(self.countas, -1)
      common.gYamon.vadd(what, 1)
    self.countas = what

  def __del__(self):
    global SELECTABLES
    if self.sid in SELECTABLES:
      del SELECTABLES[self.sid]
    if common.gYamon:
      common.gYamon.vadd(self.countas, -1)
      common.gYamon.vadd('selectables', -1)

  def __str__(self):
    return '%s: %s' % (self.log_id, self.__class__)

  def __html__(self):
    try:
      peer = self.fd.getpeername()
      sock = self.fd.getsockname()
    except:
      peer = ('x.x.x.x', 'x')
      sock = ('x.x.x.x', 'x')

    return ('<b>Outgoing ZChunks</b>: %s<br>'
            '<b>Buffered bytes</b>: %s<br>'
            '<b>Remote address</b>: %s<br>'
            '<b>Local address</b>: %s<br>'
            '<b>Bytes in / out</b>: %s / %s<br>'
            '<b>Created</b>: %s<br>'
            '<b>Status</b>: %s<br>'
            '<br>'
            '<b>Logged</b>: <ul>%s</ul><br>'
            '\n') % (self.zw and ('level %d' % self.zlevel) or 'off',
                     len(self.write_blocked),
                     self.dead and '-' or (obfuIp(peer[0]), peer[1]),
                     self.dead and '-' or (obfuIp(sock[0]), sock[1]),
                     self.all_in + self.read_bytes,
                     self.all_out + self.wrote_bytes,
                     time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.localtime(self.created)),
                     self.dead and 'dead' or 'alive',
                     ''.join(['<li>%s' % (l, ) for l in self.logged]))

  def ResetZChunks(self):
    if self.zw:
      self.zreset = True
      self.zw = zlib.compressobj(self.zlevel)

  def EnableZChunks(self, level=1):
    self.zlevel = level
    self.zw = zlib.compressobj(level)

  def SetFD(self, fd, six=False):
    if self.fd:
      self.fd.close()
    self.fd = fd
    self.fd.setblocking(0)
    try:
      if six:
        self.fd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
      # This hurts mobile devices, let's try living without it
      #self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
      #self.fd.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)
      #self.fd.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 10)
      #self.fd.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 1)
    except:
      pass

  def SetConn(self, conn):
    self.SetFD(conn.fd)
    self.log_id = conn.log_id
    self.read_bytes = conn.read_bytes
    self.wrote_bytes = conn.wrote_bytes

  def Log(self, values):
    if self.log_id: values.append(('id', self.log_id))
    logging.Log(values)
    self.logged.append(('', values))

  def LogError(self, error, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    logging.LogError(error, values)
    self.logged.append((error, values))

  def LogDebug(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    logging.LogDebug(message, values)
    self.logged.append((message, values))

  def LogInfo(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    logging.LogInfo(message, values)
    self.logged.append((message, values))

  def LogTraffic(self, final=False):
    if self.wrote_bytes or self.read_bytes:
      now = time.time()
      self.all_out += self.wrote_bytes
      self.all_in += self.read_bytes

      if self.ui: self.ui.Status('traffic')

      if common.gYamon:
        common.gYamon.vadd("bytes_all", self.wrote_bytes
                                        + self.read_bytes, wrap=1000000000)

      if final:
        self.Log([('wrote', '%d' % self.wrote_bytes),
                  ('wbps', '%d' % self.write_speed),
                  ('read', '%d' % self.read_bytes),
                  ('eof', '1')])
      else:
        self.Log([('wrote', '%d' % self.wrote_bytes),
                  ('wbps', '%d' % self.write_speed),
                  ('read', '%d' % self.read_bytes)])

      self.bytes_logged = now
      self.wrote_bytes = self.read_bytes = 0
    elif final:
      self.Log([('eof', '1')])

  def Cleanup(self, close=True):
    common.buffered_bytes -= len(self.write_blocked)
    self.write_blocked = self.peeked = self.zw = ''

    if not self.dead:
      self.dead = True
      self.CountAs('selectables_dead')

    if close:
      if self.fd:
        self.fd.close()
      self.LogTraffic(final=True)
    self.fd = None

  def SayHello(self):
    pass

  def ProcessData(self, data):
    self.LogError('Selectable::ProcessData: Should be overridden!')
    return False

  def ProcessEof(self):
    if self.read_eof and self.write_eof and not self.write_blocked:
      self.Cleanup()
      return False
    return True

  def ProcessEofRead(self):
    self.read_eof = True
    self.LogError('Selectable::ProcessEofRead: Should be overridden!')
    return False

  def ProcessEofWrite(self):
    self.write_eof = True
    self.LogError('Selectable::ProcessEofWrite: Should be overridden!')
    return False

  def EatPeeked(self, eat_bytes=None, keep_peeking=False):
    if not self.peeking: return
    if eat_bytes is None: eat_bytes = self.peeked
    discard = ''
    while len(discard) < eat_bytes:
      try:
        discard += self.fd.recv(eat_bytes - len(discard))
      except socket.error, (errno, msg):
        self.LogInfo('Error reading (%d/%d) socket: %s (errno=%s)' % (
                       eat_bytes, self.peeked, msg, errno))
        time.sleep(0.1)

    self.peeked -= eat_bytes
    self.peeking = keep_peeking
    return

  def ReadData(self, maxread=None):
    if self.read_eof:
      return False

    now = time.time()
    maxread = maxread or self.maxread
    flooded = self.Flooded()
    if flooded > self.max_read_speed and not self.acked_kb_delta:
      # FIXME: This is v1 flow control, kill it when 0.4.7 is "everywhere"
      last = self.throttle_until
      # Disable local throttling for really slow connections; remote
      # throttles (trigged by blocked sockets) still work.
      if self.max_read_speed > 1024:
        self.AutoThrottle()
        maxread = 1024
      if now > last and self.all_in > 2*self.max_read_speed:
        self.max_read_speed *= 1.25
        self.max_read_speed += maxread

    try:
      if self.peeking:
        data = self.fd.recv(maxread, socket.MSG_PEEK)
        self.peeked = len(data)
        if logging.DEBUG_IO:
          print '<== PEEK =[%s]==(\n%s)==' % (self, data[:160])
      else:
        data = self.fd.recv(maxread)
        if logging.DEBUG_IO:
          print ('<== IN =[%s @ %dbps]==(\n%s)=='
                 ) % (self, self.max_read_speed, data[:160])
    except (SSL.WantReadError, SSL.WantWriteError), err:
      return True
    except IOError, err:
      if err.errno not in self.HARMLESS_ERRNOS:
        self.LogDebug('Error reading socket: %s (%s)' % (err, err.errno))
        return False
      else:
        return True
    except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError), err:
      self.LogDebug('Error reading socket (SSL): %s' % err)
      return False
    except socket.error, (errno, msg):
      if errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogInfo('Error reading socket: %s (errno=%s)' % (msg, errno))
        return False

    self.last_activity = now
    if data is None or data == '':
      self.read_eof = True
      if logging.DEBUG_IO:
        print '<== IN =[%s]==(EOF)==' % self
      return self.ProcessData('')
    else:
      if not self.peeking:
        self.read_bytes += len(data)
        if self.acked_kb_delta:
          self.acked_kb_delta += (len(data)/1024)
        if self.read_bytes > logging.LOG_THRESHOLD: self.LogTraffic()
      return self.ProcessData(data)

  def Flooded(self):
    flooded = self.read_bytes + self.all_in
    flooded -= self.max_read_speed * 0.95 * (time.time() - self.created)
    return flooded

  def RecordProgress(self, skb, bps):
    if skb >= 0:
      all_read = (self.all_in + self.read_bytes) / 1024
      if self.acked_kb_delta:
        self.acked_kb_delta = max(1, all_read - skb)
        self.LogDebug('Delta is: %d' % self.acked_kb_delta)
    elif bps >= 0:
      self.Throttle(max_speed=bps, remote=True)

  def Throttle(self, max_speed=None, remote=False, delay=0.2):
    if max_speed:
      self.max_read_speed = max_speed

    flooded = max(-1, self.Flooded())
    if self.max_read_speed:
      delay = min(10, max(0.1, flooded/self.max_read_speed))
      if flooded < 0: delay = 0

    if delay:
      ot = self.throttle_until
      self.throttle_until = time.time() + delay
      if ((self.throttle_until - ot) > 30 or
          (int(ot) != int(self.throttle_until) and delay > 8)):
        self.LogInfo('Throttled %.1fs until %x (flood=%d, bps=%s, %s)' % (
                     delay, self.throttle_until, flooded,
                     self.max_read_speed, remote and 'remote' or 'local'))

    return True

  def AutoThrottle(self, max_speed=None, remote=False, delay=0.2):
    return self.Throttle(max_speed, remote, delay)

  def Send(self, data, try_flush=False, activity=True):
    common.buffered_bytes -= len(self.write_blocked)
    self.write_speed = int((self.wrote_bytes + self.all_out)
                           / max(1, (time.time() - self.created)))

    # If we're already blocked, just buffer unless explicitly asked to flush.
    if (not try_flush) and (len(self.write_blocked) > 0 or compat.SEND_ALWAYS_BUFFERS):
      self.write_blocked += str(''.join(data))
      common.buffered_bytes += len(self.write_blocked)
      return True

    sending = ''.join([self.write_blocked, str(''.join(data))])
    self.write_blocked = ''
    sent_bytes = 0
    if sending:
      try:
        sent_bytes = self.fd.send(sending[:(self.write_retry or SEND_MAX_BYTES)])
        if logging.DEBUG_IO:
          print '==> OUT =[%s]==(\n%s)==' % (self, sending[:min(160, sent_bytes)])
        self.wrote_bytes += sent_bytes
        self.write_retry = None
      except IOError, err:
        if err.errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s' % err)
          self.ProcessEofWrite()
          return False
        else:
          self.write_retry = len(sending)
      except (SSL.WantWriteError, SSL.WantReadError), err:
        self.write_retry = len(sending)
      except socket.error, (errno, msg):
        if errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s (errno=%s)' % (msg, errno))
          self.ProcessEofWrite()
          return False
        else:
          self.write_retry = len(sending)
      except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError), err:
        self.LogInfo('Error sending (SSL): %s' % err)
        self.ProcessEofWrite()
        return False

    if activity:
      self.last_activity = time.time()

    self.write_blocked = sending[sent_bytes:]
    common.buffered_bytes += len(self.write_blocked)

    if self.wrote_bytes >= logging.LOG_THRESHOLD:
      self.LogTraffic()

    if self.write_eof and not self.write_blocked:
      self.ProcessEofWrite()
    return True

  def SendChunked(self, data, compress=True, zhistory=None):
    rst = ''
    if self.zreset:
      self.zreset = False
      rst = 'R'

    # Stop compressing streams that just get bigger.
    if zhistory and (zhistory[0] < zhistory[1]): compress = False
    try:
      self.lock.acquire()
      sdata = ''.join(data)
      if self.zw and compress:
        try:
          zdata = self.zw.compress(sdata) + self.zw.flush(zlib.Z_SYNC_FLUSH)
          if zhistory:
            zhistory[0] = len(sdata)
            zhistory[1] = len(zdata)
          return self.Send(['%xZ%x%s\r\n%s' % (len(sdata), len(zdata), rst, zdata)],
                           activity=False)
        except zlib.error:
          logging.LogError('Error compressing, resetting ZChunks.')
          self.ResetZChunks()

      return self.Send(['%x%s\r\n%s' % (len(sdata), rst, sdata)],
                       activity=False)
    finally:
      self.lock.release()

  def Flush(self, loops=50, wait=False):
    while loops != 0 and len(self.write_blocked) > 0 and self.Send([],
                                                                try_flush=True,
                                                                activity=False):
      if wait and len(self.write_blocked) > 0:
        time.sleep(0.1)
      logging.LogDebug('Flushing...')
      loops -= 1

    if self.write_blocked: return False
    return True

  def IsReadable(s, now):
    return (s.fd and (not s.read_eof)
                 and (s.acked_kb_delta < 64)  # FIXME
                 and (s.throttle_until <= now))

  def IsBlocked(s):
    return (s.fd and (len(s.write_blocked) > 0))

  def IsDead(s):
    return (s.read_eof and s.write_eof and not s.write_blocked)


class LineParser(Selectable):
  """A Selectable which parses the input as lines of text."""

  def __init__(self, fd=None, address=None, on_port=None,
                     ui=None, tracked=True):
    Selectable.__init__(self, fd, address, on_port, ui=ui, tracked=tracked)
    self.leftovers = ''

  def __html__(self):
    return Selectable.__html__(self)

  def Cleanup(self, close=True):
    Selectable.Cleanup(self, close=close)
    self.leftovers = ''

  def ProcessData(self, data):
    lines = (self.leftovers+data).splitlines(True)
    self.leftovers = ''

    while lines:
      line = lines.pop(0)
      if line.endswith('\n'):
        if self.ProcessLine(line, lines) is False:
          return False
      else:
        if not self.peeking: self.leftovers += line

    if self.read_eof: return self.ProcessEofRead()
    return True

  def ProcessLine(self, line, lines):
    self.LogError('LineParser::ProcessLine: Should be overridden!')
    return False


TLS_CLIENTHELLO = '%c' % 026
SSL_CLIENTHELLO = '\x80'
FLASH_POLICY_REQ = '<policy-file-request/>'

# FIXME: XMPP support
class MagicProtocolParser(LineParser):
  """A Selectable which recognizes HTTP, TLS or XMPP preambles."""

  def __init__(self, fd=None, address=None, on_port=None, ui=None):
    LineParser.__init__(self, fd, address, on_port, ui=ui, tracked=False)
    self.leftovers = ''
    self.might_be_tls = True
    self.is_tls = False
    self.my_tls = False

  def __html__(self):
    return ('<b>Detected TLS</b>: %s<br>'
            '%s') % (self.is_tls,
                     LineParser.__html__(self))

  # FIXME: DEPRECATE: Make this all go away, switch to CONNECT.
  def ProcessMagic(self, data):
    args = {}
    try:
      prefix, words, data = data.split('\r\n', 2)
      for arg in words.split('; '):
        key, val = arg.split('=', 1)
        args[key] = val

      self.EatPeeked(eat_bytes=len(prefix)+2+len(words)+2)
    except ValueError, e:
      return True

    try:
      port = 'port' in args and args['port'] or None
      if port: self.on_port = int(port)
    except ValueError, e:
      return False

    proto = 'proto' in args and args['proto'] or None
    if proto in ('http', 'http2', 'http3', 'websocket'):
      return LineParser.ProcessData(self, data)

    domain = 'domain' in args and args['domain'] or None
    if proto == 'https': return self.ProcessTls(data, domain)
    if proto == 'raw' and domain: return self.ProcessRaw(data, domain)
    return False

  def ProcessData(self, data):
    if data.startswith(MAGIC_PREFIX):
      return self.ProcessMagic(data)

    if self.might_be_tls:
      self.might_be_tls = False
      if not (data.startswith(TLS_CLIENTHELLO) or
              data.startswith(SSL_CLIENTHELLO)):
        self.EatPeeked()
        if data.startswith(FLASH_POLICY_REQ):
          return self.ProcessFlashPolicyRequest(data)
        else:
          return LineParser.ProcessData(self, data)
      self.is_tls = True

    if self.is_tls:
      return self.ProcessTls(data)
    else:
      self.EatPeeked()
      return LineParser.ProcessData(self, data)

  def GetMsg(self, data):
    mtype, ml24, mlen = struct.unpack('>BBH', data[0:4])
    mlen += ml24 * 0x10000
    return mtype, data[4:4+mlen], data[4+mlen:]

  def GetClientHelloExtensions(self, msg):
    # Ugh, so many magic numbers! These are accumulated sizes of
    # the different fields we are ignoring in the TLS headers.
    slen = struct.unpack('>B', msg[34])[0]
    cslen = struct.unpack('>H', msg[35+slen:37+slen])[0]
    cmlen = struct.unpack('>B', msg[37+slen+cslen])[0]
    extofs = 34+1+2+1+2+slen+cslen+cmlen
    if extofs < len(msg): return msg[extofs:]
    return None

  def GetSniNames(self, extensions):
    names = []
    while extensions:
      etype, elen = struct.unpack('>HH', extensions[0:4])
      if etype == 0:
        # OK, we found an SNI extension, get the list.
        namelist = extensions[6:4+elen]
        while namelist:
          ntype, nlen = struct.unpack('>BH', namelist[0:3])
          if ntype == 0: names.append(namelist[3:3+nlen].lower())
          namelist = namelist[3+nlen:]
      extensions = extensions[4+elen:]
    return names

  def GetSni(self, data):
    hello, vmajor, vminor, mlen = struct.unpack('>BBBH', data[0:5])
    data = data[5:]
    sni = []
    while data:
      mtype, msg, data = self.GetMsg(data)
      if mtype == 1:
        # ClientHello!
        sni.extend(self.GetSniNames(self.GetClientHelloExtensions(msg)))
    return sni

  def ProcessFlashPolicyRequest(self, data):
    self.LogError('MagicProtocolParser::ProcessFlashPolicyRequest: Should be overridden!')
    return False

  def ProcessTls(self, data, domain=None):
    self.LogError('MagicProtocolParser::ProcessTls: Should be overridden!')
    return False

  def ProcessRaw(self, data, domain):
    self.LogError('MagicProtocolParser::ProcessRaw: Should be overridden!')
    return False


class ChunkParser(Selectable):
  """A Selectable which parses the input as chunks."""

  def __init__(self, fd=None, address=None, on_port=None, ui=None):
    Selectable.__init__(self, fd, address, on_port, ui=ui)
    self.want_cbytes = 0
    self.want_bytes = 0
    self.compressed = False
    self.header = ''
    self.chunk = ''
    self.zr = zlib.decompressobj()

  def __html__(self):
    return Selectable.__html__(self)

  def Cleanup(self, close=True):
    Selectable.Cleanup(self, close=close)
    self.zr = self.chunk = self.header = None

  def ProcessData(self, data):
    if self.peeking:
      self.want_cbytes = 0
      self.want_bytes = 0
      self.header = ''
      self.chunk = ''

    if self.want_bytes == 0:
      self.header += (data or '')
      if self.header.find('\r\n') < 0:
        if self.read_eof: return self.ProcessEofRead()
        return True
      try:
        size, data = self.header.split('\r\n', 1)
        self.header = ''

        if size.endswith('R'):
          self.zr = zlib.decompressobj()
          size = size[0:-1]

        if 'Z' in size:
          csize, zsize = size.split('Z')
          self.compressed = True
          self.want_cbytes = int(csize, 16)
          self.want_bytes = int(zsize, 16)
        else:
          self.compressed = False
          self.want_bytes = int(size, 16)

      except ValueError, err:
        self.LogError('ChunkParser::ProcessData: %s' % err)
        self.Log([('bad_data', data)])
        return False

      if self.want_bytes == 0:
        return False

    process = data[:self.want_bytes]
    leftover = data[self.want_bytes:]

    self.chunk += process
    self.want_bytes -= len(process)

    result = 1
    if self.want_bytes == 0:
      if self.compressed:
        try:
          cchunk = self.zr.decompress(self.chunk)
        except zlib.error:
          cchunk = ''

        if len(cchunk) != self.want_cbytes:
          result = self.ProcessCorruptChunk(self.chunk)
        else:
          result = self.ProcessChunk(cchunk)
      else:
        result = self.ProcessChunk(self.chunk)
      self.chunk = ''
      if result and leftover:
        # FIXME: This blows the stack from time to time.  We need a loop
        #        or better yet, to just process more in a subsequent
        #        iteration of the main select() loop.
        result = self.ProcessData(leftover)

    if self.read_eof: result = self.ProcessEofRead() and result
    return result

  def ProcessCorruptChunk(self, chunk):
    self.LogError('ChunkParser::ProcessData: ProcessCorruptChunk not overridden!')
    return False

  def ProcessChunk(self, chunk):
    self.LogError('ChunkParser::ProcessData: ProcessChunk not overridden!')
    return False
