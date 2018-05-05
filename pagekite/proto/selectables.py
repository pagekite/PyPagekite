"""
Selectables are low level base classes which cooperate with our select-loop.
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
import errno
import re
import struct
import threading
import time
import zlib

from pagekite.compat import *
from pagekite.common import *
from pagekite.proto.proto import HTTP_Unavailable
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
      if (SELECTABLE_ID % 0x00800) == 0:
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
      if bind and bind[0] and re.match(r'^\d+\.\d+\.\d+\.\d+$', bind[0]):
        raise ValueError('Avoid INET6 for IPv4 hosts')
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

    # Logging
    self.alt_id = None
    self.countas = 'selectables_live'
    self.sid = self.gsid = getSelectableId(self.countas)

    if address:
      addr = address or ('x.x.x.x', 'x')
      self.log_id = 's%x/%s:%s' % (self.sid, obfuIp(addr[0]), addr[1])
    else:
      self.log_id = 's%x' % self.sid

    if common.gYamon:
      common.gYamon.vadd(self.countas, 1)
      common.gYamon.vadd('selectables', 1)

  def CountAs(self, what):
    if common.gYamon:
      common.gYamon.vadd(self.countas, -1)
      common.gYamon.vadd(what, 1)
    self.countas = what
    global SELECTABLES
    SELECTABLES[self.gsid] = '%s %s' % (self.countas, self)

  def Cleanup(self, close=True):
    self.peeked = self.zw = ''
    self.Die(discard_buffer=True)
    if close:
      if self.fd:
        if logging.DEBUG_IO:
          self.LogDebug('Closing FD: %s' % self)
        self.fd.close()
    self.fd = None
    if not self.dead:
      self.dead = True
      self.CountAs('selectables_dead')
      if close:
        self.LogTraffic(final=True)

  def __del__(self):
    try:
      if common.gYamon:
        common.gYamon.vadd(self.countas, -1)
        common.gYamon.vadd('selectables', -1)
    except AttributeError:
      pass
    try:
      global SELECTABLES
      del SELECTABLES[self.gsid]
    except (KeyError, TypeError):
      pass

  def __str__(self):
    return '%s: %s<%s%s%s>' % (self.log_id, self.__class__,
                               self.read_eof and '-' or 'r',
                               self.write_eof and '-' or 'w',
                               len(self.write_blocked))

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
            '\n') % (self.zw and ('level %d' % self.zlevel) or 'off',
                     len(self.write_blocked),
                     self.dead and '-' or (obfuIp(peer[0]), peer[1]),
                     self.dead and '-' or (obfuIp(sock[0]), sock[1]),
                     self.all_in + self.read_bytes,
                     self.all_out + self.wrote_bytes,
                     time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.localtime(self.created)),
                     self.dead and 'dead' or 'alive')

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
    if fd:
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

  def LogError(self, error, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    logging.LogError(error, values)

  def LogDebug(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    logging.LogDebug(message, values)

  def LogInfo(self, message, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    logging.LogInfo(message, values)

  def LogTrafficStatus(self, final=False):
    if self.ui:
      self.ui.Status('traffic')

  def LogTraffic(self, final=False):
    if self.wrote_bytes or self.read_bytes:
      now = time.time()
      self.all_out += self.wrote_bytes
      self.all_in += self.read_bytes

      self.LogTrafficStatus(final)

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

    global SELECTABLES
    SELECTABLES[self.gsid] = '%s %s' % (self.countas, self)

  def SayHello(self):
    pass

  def ProcessData(self, data):
    self.LogError('Selectable::ProcessData: Should be overridden!')
    return False

  def ProcessEof(self):
    global SELECTABLES
    SELECTABLES[self.gsid] = '%s %s' % (self.countas, self)
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

    if logging.DEBUG_IO:
      print '===[ ATE %d PEEKED BYTES ]===\n' % eat_bytes
    self.peeked -= eat_bytes
    self.peeking = keep_peeking
    return

  def ReadData(self, maxread=None):
    if self.read_eof:
      return False

    now = time.time()
    maxread = maxread or self.maxread
    flooded = self.Flooded(now)
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
        common.DISCONNECT_COUNT += 1
        return False
      else:
        return True
    except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError), err:
      self.LogDebug('Error reading socket (SSL): %s' % err)
      common.DISCONNECT_COUNT += 1
      return False
    except socket.error, (errno, msg):
      if errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogInfo('Error reading socket: %s (errno=%s)' % (msg, errno))
        common.DISCONNECT_COUNT += 1
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

  def Flooded(self, now=None):
    delta = ((now or time.time()) - self.created)
    if delta >= 1:
      flooded = self.read_bytes + self.all_in
      flooded -= self.max_read_speed * 0.95 * delta
      return flooded
    else:
      return 0

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

  def Send(self, data, try_flush=False, activity=False,
                       just_buffer=False, allow_blocking=False):
    self.write_speed = int((self.wrote_bytes + self.all_out)
                           / max(1, (time.time() - self.created)))

    # If we're already blocked, just buffer unless explicitly asked to flush.
    if ((just_buffer) or
        ((not try_flush) and
         (len(self.write_blocked) > 0 or compat.SEND_ALWAYS_BUFFERS))):
      self.write_blocked += str(''.join(data))
      return True

    sending = ''.join([self.write_blocked, str(''.join(data))])
    self.write_blocked = ''
    sent_bytes = 0
    if sending:
      try:
        want_send = self.write_retry or min(len(sending), SEND_MAX_BYTES)
        sent_bytes = None
        # Try to write for up to 5 seconds before giving up
        for try_wait in (0, 0, 0.1, 0.2, 0.2, 0.2, 0.3, 0.5, 0.5, 1, 1, 1, 0):
          try:
            sent_bytes = self.fd.send(sending[:want_send])
            if logging.DEBUG_IO:
              print ('==> OUT =[%s: %d/%d bytes]==(\n%s)=='
                     ) % (self, sent_bytes, want_send, sending[:min(160, sent_bytes)])
            self.wrote_bytes += sent_bytes
            self.write_retry = None
            break
          except (SSL.WantWriteError, SSL.WantReadError), err:
            if logging.DEBUG_IO:
              print '=== WRITE SSL RETRY: =[%s: %s bytes]==' % (self, want_send)
            if try_wait:
              time.sleep(try_wait)
        if sent_bytes is None:
          self.LogInfo('Error sending: Too many SSL write retries')
          self.ProcessEofWrite()
          common.DISCONNECT_COUNT += 1
          return False
      except IOError, err:
        if err.errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s' % err)
          self.ProcessEofWrite()
          common.DISCONNECT_COUNT += 1
          return False
        else:
          if logging.DEBUG_IO:
            print '=== WRITE HICCUP: =[%s: %s bytes]==' % (self, want_send)
          self.write_retry = want_send
      except socket.error, (errno, msg):
        if errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s (errno=%s)' % (msg, errno))
          self.ProcessEofWrite()
          common.DISCONNECT_COUNT += 1
          return False
        else:
          if logging.DEBUG_IO:
            print '=== WRITE HICCUP: =[%s: %s bytes]==' % (self, want_send)
          self.write_retry = want_send
      except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError), err:
        self.LogInfo('Error sending (SSL): %s' % err)
        self.ProcessEofWrite()
        common.DISCONNECT_COUNT += 1
        return False
      except AttributeError:
        # This has been seen in the wild, is most likely some sort of
        # race during shutdown. :-(
        self.LogInfo('AttributeError, self.fd=%s' % self.fd)
        self.ProcessEofWrite()
        return False

    if activity:
      self.last_activity = time.time()

    self.write_blocked = sending[sent_bytes:]

    if self.wrote_bytes >= logging.LOG_THRESHOLD:
      self.LogTraffic()

    if self.write_eof and not self.write_blocked:
      self.ProcessEofWrite()
    return True

  def SendChunked(self, data, compress=True, zhistory=None, just_buffer=False):
    rst = ''
    if self.zreset:
      self.zreset = False
      rst = 'R'

    # Stop compressing streams that just get bigger.
    if zhistory and (zhistory[0] < zhistory[1]): compress = False
    try:
      try:
        if self.lock:
          self.lock.acquire()
        sdata = ''.join(data)
        if self.zw and compress and len(sdata) > 64:
          try:
            zdata = self.zw.compress(sdata) + self.zw.flush(zlib.Z_SYNC_FLUSH)
            if zhistory:
              zhistory[0] = len(sdata)
              zhistory[1] = len(zdata)
            return self.Send(['%xZ%x%s\r\n' % (len(sdata), len(zdata), rst), zdata],
                             activity=False,
                             try_flush=(not just_buffer), just_buffer=just_buffer)
          except zlib.error:
            logging.LogError('Error compressing, resetting ZChunks.')
            self.ResetZChunks()

        return self.Send(['%x%s\r\n' % (len(sdata), rst), sdata],
                         activity=False,
                         try_flush=(not just_buffer), just_buffer=just_buffer)
      except UnicodeDecodeError:
        logging.LogError('UnicodeDecodeError in SendChunked, wtf?')
        return False
    finally:
      if self.lock:
        self.lock.release()

  def Flush(self, loops=50, wait=False, allow_blocking=False):
    while (loops != 0 and
           len(self.write_blocked) > 0 and
           self.Send([], try_flush=True, activity=False,
                         allow_blocking=allow_blocking)):
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

  def Die(self, discard_buffer=False):
    if discard_buffer:
      self.write_blocked = ''
    self.read_eof = self.write_eof = True
    return True

  def HTTP_Unavail(self, config, where, proto, host, **kwargs):
    kwargs['frame_url'] = config.error_url
    if self.fd and where in ('FE', 'fe'):
      kwargs['relay_sockname'] = self.fd.getsockname()

    # Do we have a more specific error URL for this domain? This is a
    # white-label feature, for folks not wanting to hit the PageKite.net
    # servers at all. In case of a match, we also disable mention of
    # PageKite itself in the HTML boilerplate.
    dparts = host.split(':')[0].split('.')
    while dparts:
      fu = config.error_urls.get('.'.join(dparts), None)
      if fu is not None:
        kwargs['frame_url'] = fu
        kwargs['advertise'] = False
        break
      dparts.pop(0)

    return HTTP_Unavailable(where, proto, host, **kwargs)


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
MINECRAFT_HANDSHAKE = '%c' % (0x02, )
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
    if proto == 'raw' and domain: return self.ProcessProto(data, 'raw', domain)
    return False

  def ProcessData(self, data):
    # Uncomment when adding support for new protocols:
    #
    #self.LogDebug(('DATA: >%s<'
    #               ) % ' '.join(['%2.2x' % ord(d) for d in data]))

    if data.startswith(MAGIC_PREFIX):
      return self.ProcessMagic(data)

    if self.might_be_tls:
      self.might_be_tls = False
      if not (data.startswith(TLS_CLIENTHELLO) or
              data.startswith(SSL_CLIENTHELLO)):
        self.EatPeeked()

        # FIXME: These only work if the full policy request or minecraft
        #        handshake are present in the first data packet.
        if data.startswith(FLASH_POLICY_REQ):
          return self.ProcessFlashPolicyRequest(data)

        if data.startswith(MINECRAFT_HANDSHAKE):
          user, server, port = self.GetMinecraftInfo(data)
          if user and server:
            return self.ProcessProto(data, 'minecraft', server)

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

  def GetMinecraftInfo(self, data):
    try:
      (packet, version, unlen) = struct.unpack('>bbh', data[0:4])
      unlen *= 2
      (hnlen, ) = struct.unpack('>h', data[4+unlen:6+unlen])
      hnlen *= 2
      (port, ) = struct.unpack('>i', data[6+unlen+hnlen:10+unlen+hnlen])
      uname = data[4:4+unlen].decode('utf_16_be').encode('utf-8')
      sname = data[6+unlen:6+hnlen+unlen].decode('utf_16_be').encode('utf-8')
      return uname, sname, port
    except:
      return None, None, None

  def ProcessFlashPolicyRequest(self, data):
    self.LogError('MagicProtocolParser::ProcessFlashPolicyRequest: Should be overridden!')
    return False

  def ProcessTls(self, data, domain=None):
    self.LogError('MagicProtocolParser::ProcessTls: Should be overridden!')
    return False

  def ProcessProto(self, data, proto, domain):
    self.LogError('MagicProtocolParser::ProcessProto: Should be overridden!')
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
    loops = 1500
    result = more = True
    while result and more and (loops > 0):
      loops -= 1

      if self.peeking:
        self.want_cbytes = 0
        self.want_bytes = 0
        self.header = ''
        self.chunk = ''

      if self.want_bytes == 0:
        self.header += (data or '')
        if self.header.find('\r\n') < 0:
          if self.read_eof:
            return self.ProcessEofRead()
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
      data = more = data[self.want_bytes:]

      self.chunk += process
      self.want_bytes -= len(process)

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

    if result and more:
      self.LogError('Unprocessed data: %s' % data)
      raise BugFoundError('Too much data')
    elif self.read_eof:
      return self.ProcessEofRead() and result
    else:
      return result

  def ProcessCorruptChunk(self, chunk):
    self.LogError('ChunkParser::ProcessData: ProcessCorruptChunk not overridden!')
    return False

  def ProcessChunk(self, chunk):
    self.LogError('ChunkParser::ProcessData: ProcessChunk not overridden!')
    return False
