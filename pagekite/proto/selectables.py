"""
Selectables are low level base classes which cooperate with our select-loop.
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

import errno
import os
import re
import struct
import threading
import time
import zlib

from pagekite.compat import *
from pagekite.common import *
from pagekite.proto.proto import HTTP_Unavailable
from pagekite.proto.ws_abnf import ABNF
import pagekite.logging as logging
import pagekite.compat as compat
import pagekite.common as common


def obfuIp(ip):
  quads = ('%s' % ip).replace(':', '.').split('.')
  return '~%s' % '.'.join([q for q in quads[-2:]])


SELECTABLE_LOCK = threading.RLock()  # threading.Lock() will deadlock on pypy!
SELECTABLE_ID = 0
SELECTABLES = set([])
def getSelectableId(what):
  global SELECTABLES, SELECTABLE_ID, SELECTABLE_LOCK
  with SELECTABLE_LOCK:
    count = 0
    SELECTABLE_ID += 1
    SELECTABLE_ID %= 0x20000
    while SELECTABLE_ID in SELECTABLES:
      SELECTABLE_ID += 1
      SELECTABLE_ID %= 0x20000
      count += 1
      if count > 0x20000:
        raise ValueError('Too many conns!')
    SELECTABLES.add(SELECTABLE_ID)
    return SELECTABLE_ID


class Selectable(object):
  """A wrapper around a socket, for use with select."""

  HARMLESS_ERRNOS = (errno.EINTR, errno.EAGAIN, errno.ENOMEM, errno.EBUSY,
                     errno.EDEADLK, errno.EWOULDBLOCK, errno.ENOBUFS,
                     errno.EALREADY)

  def __init__(self, fd=None, address=None, on_port=None, maxread=None,
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
    self.lock = threading.RLock()
    self.last_activity = 0
    self.dead = False
    self.ui = ui

    # Quota-related stuff
    self.quota = None
    self.q_conns = None
    self.q_days = None

    # Read-related variables
    self.maxread = maxread or common.MAX_READ_BYTES
    self.read_bytes = self.all_in = 0
    self.read_eof = False
    self.peeking = False
    self.peeked = 0
    self.retry_delays = [0.0, 0.02, 0.05]

    # Write-related variables
    self.wrote_bytes = self.all_out = 0
    self.write_blocked = ''
    self.write_speed = 102400
    self.write_eof = False

    # Flow control v2
    self.acked_kb_delta = 0

    # Compression stuff
    self.zw = None
    self.zlevel = 1
    self.zreset = False

    # This is the default, until we switch to Websockets...
    self.use_websocket = False
    self.ws_zero_mask = False

    # Logging
    self.sstate = 'new'
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

  def ExtendSSLRetryDelays(self):
    self.LogDebug('Extended SSL Write retries on %s' % self)
    self.retry_delays = [0.0, 0.02, 0.05, 0.30, 0.70, 1.5, 2.0]

  def CountAs(self, what):
    with self.lock:
      if common.gYamon:
        common.gYamon.vadd(self.countas, -1)
        common.gYamon.vadd(what, 1)
      self.countas = what

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
      self.sstate = 'dead'
      self.CountAs('selectables_dead')
      if close:
        self.LogTraffic(final=True)
    try:
      global SELECTABLES, SELECTABLE_LOCK
      with SELECTABLE_LOCK:
        SELECTABLES.remove(self.gsid)
    except KeyError:
      pass

  def __del__(self):
    # Important: This can run at random times, especially under pypy, so all
    #            locks must be re-entrant (RLock), otherwise we deadlock.
    try:
      with self.lock:
        if common.gYamon and self.countas:
          common.gYamon.vadd(self.countas, -1)
          common.gYamon.vadd('selectables', -1)
          self.countas = None
    except AttributeError:
      pass

  def __str__(self):
    return '%s: %s<%s|%s%s%s>' % (self.log_id, self.__class__, self.sstate,
                                  self.read_eof and '-' or 'r',
                                  self.write_eof and '-' or 'w',
                                  len(self.write_blocked))

  def __html__(self):
    try:
      peer = self.fd.getpeername()
    except:
      peer = ('x.x.x.x', 'x')

    try:
      sock = self.fd.getsockname()
    except:
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
                     self.sstate)

  def ResetZChunks(self):
    with self.lock:
      if self.zw:
        self.zreset = True
        self.zw = zlib.compressobj(self.zlevel)

  def EnableZChunks(self, level=1):
    with self.lock:
      self.zlevel = level
      self.zw = zlib.compressobj(level)

  def EnableWebsockets(self):
    with self.lock:
      self.use_websocket = True
      self.ws_zero_mask = (
        hasattr(self.fd, 'get_cipher_name') or hasattr(self.fd, 'getpeercert'))

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

  def Log(self, values, level=logging.LOG_LEVEL_DEFAULT):
    if self.log_id: values.append(('id', self.log_id))
    logging.Log(values, level=level)

  def LogError(self, error, params=None):
    values = params or []
    if self.log_id: values.extend([('id', self.log_id), ('s', self.sstate)])
    logging.LogError(error, values)

  def LogDebug(self, message, params=None):
    values = params or []
    if self.log_id: values.extend([('id', self.log_id), ('s', self.sstate)])
    logging.LogDebug(message, values)

  def LogWarning(self, warning, params=None):
    values = params or []
    if self.log_id: values.append(('id', self.log_id))
    logging.LogWarning(warning, values)

  def LogInfo(self, message, params=None):
    values = params or []
    if self.log_id: values.extend([('id', self.log_id), ('s', self.sstate)])
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

      log_info = [('wrote', '%d' % self.wrote_bytes),
                  ('wbps', '%d' % self.write_speed),
                  ('read', '%d' % self.read_bytes)]
      if self.acked_kb_delta:
        log_info.append(('delta', '%d' % self.acked_kb_delta))
      if final:
        log_info.append(('eof', '1'))
      self.Log(log_info)

      self.bytes_logged = now
      self.wrote_bytes = self.read_bytes = 0
    elif final:
      self.Log([('eof', '1')], level=logging.LOG_LEVEL_MACH)

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
        bytecount = eat_bytes - len(discard)
        self.sstate = 'eat(%d)' % bytecount
        discard += s(self.fd.recv(bytecount))
      except socket.error as err:
        (errno, msg) = err.args
        self.LogInfo('Error reading (%d/%d) socket: %s (errno=%s)' % (
                       eat_bytes, self.peeked, msg, errno))
        time.sleep(0.1)

    if logging.DEBUG_IO:
      print('===[ ATE %d PEEKED BYTES ]===\n' % eat_bytes)
    self.sstate = 'ate(%d)' % eat_bytes
    self.peeked -= eat_bytes
    self.peeking = keep_peeking
    return

  def ReadData(self, maxread=None):
    if self.read_eof:
      return False

    now = time.time()
    maxread = maxread or self.maxread
    try:
      if self.peeking:
        self.sstate = 'peek(%d)' % maxread
        data = s(self.fd.recv(maxread, socket.MSG_PEEK))
        self.peeked = len(data)
        if logging.DEBUG_IO:
          print('<== PEEK =[%s]==(\n%s)==' % (self, data[:320]))
      else:
        self.sstate = 'read(%d)' % maxread
        data = s(self.fd.recv(maxread))
        if logging.DEBUG_IO:
          print('<== IN =[%s]==(\n%s)==' % (self, data[:160]))
      self.sstate = 'data(%d)' % len(data)
    except (SSL.WantReadError, SSL.WantWriteError):
      self.sstate += '/SSL.WRE'
      return True
    except IOError as err:
      self.sstate += '/ioerr=%s' % (err.errno,)
      if err.errno not in self.HARMLESS_ERRNOS:
        self.LogDebug('Error reading socket: %s (%s)' % (err, err.errno))
        return False
      else:
        return True
    except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError) as err:
      self.sstate += '/SSL.Error'
      self.LogDebug('Error reading socket (SSL): %s' % err)
      return False
    except socket.error as err:
      (errno, msg) = err.args
      self.sstate += '/sockerr=%s' % (err.errno,)
      if errno in self.HARMLESS_ERRNOS:
        return True
      else:
        self.LogInfo('Error reading socket: %s (errno=%s)' % (msg, errno))
        return False

    try:
      self.last_activity = now
      if data is None or data == '':
        self.sstate += '/EOF'
        self.read_eof = True
        if logging.DEBUG_IO:
          print('<== IN =[%s]==(EOF)==' % self)
        return self.ProcessData('')
      else:
        if not self.peeking:
          self.read_bytes += len(data)
          if self.acked_kb_delta:
            self.acked_kb_delta += (len(data)/1024)
          if self.read_bytes > logging.LOG_THRESHOLD: self.LogTraffic()
        return self.ProcessData(data)
    finally:
      self.sstate = (self.dead and 'dead' or 'idle')

  def RecordProgress(self, skb):
    if skb >= 0:
      all_read = (self.all_in + self.read_bytes) // 1024
      self.acked_kb_delta = max(1, all_read - skb)

  def Send(self, data, try_flush=False, activity=False,
                       just_buffer=False, allow_blocking=False):
    global SEND_MAX_BYTES
    self.write_speed = int((self.wrote_bytes + self.all_out)
                           / max(1, (time.time() - self.created)))  # Integer division

    # If we're already blocked, just buffer unless explicitly asked to flush.
    if ((just_buffer) or
        ((not try_flush) and
         (len(self.write_blocked) > 0 or compat.SEND_ALWAYS_BUFFERS))):
      self.write_blocked += str(''.join(data))
      return True

    pending = ''.join([self.write_blocked, str(''.join(data))])
    self.write_blocked = ''
    if pending:
      try:
        sent = None
        send_bytes = min(len(pending), SEND_MAX_BYTES)
        send_buffer = b(pending[:send_bytes])
        self.sstate = 'send(%d)' % (send_bytes)
        for try_wait in self.retry_delays:
          try:
            sent = self.fd.send(send_buffer)
            if logging.DEBUG_IO:
              print(('==> OUT =[%s: %d/%d bytes]==(\n%s)=='
                     ) % (self, sent, send_bytes, repr(send_buffer[:min(320, sent)])))
            self.wrote_bytes += sent
            break
          except (SSL.WantWriteError, SSL.WantReadError) as err:
            SEND_MAX_BYTES = min(4096, SEND_MAX_BYTES)  # Maybe this will help?
            if logging.DEBUG_IO:
              print('=== WRITE SSL RETRY: =[%s: %s bytes]==' % (self, send_bytes))
            self.sstate = 'send/SSL.WRE(%d,%.1f)' % (send_bytes, try_wait)
            time.sleep(try_wait)
        if sent is None:
          self.sstate += '/retries'
          self.LogInfo(
              'Error sending: Too many SSL write retries (SEND_MAX_BYTES=%d)'
              % SEND_MAX_BYTES)
          self.ProcessEofWrite()
          return False
      except IOError as err:
        self.sstate += '/ioerr=%s' % (err.errno,)
        if err.errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s' % err)
          self.ProcessEofWrite()
          return False
        else:
          if logging.DEBUG_IO:
            print('=== WRITE HICCUP: =[%s: %s bytes]==' % (self, send_bytes))
      except socket.error as err:
        (errno, msg) = err.args
        self.sstate += '/sockerr=%s' % (errno,)
        if errno not in self.HARMLESS_ERRNOS:
          self.LogInfo('Error sending: %s (errno=%s)' % (msg, errno))
          self.ProcessEofWrite()
          return False
        else:
          if logging.DEBUG_IO:
            print('=== WRITE HICCUP: =[%s: %s bytes]==' % (self, send_bytes))
      except (SSL.Error, SSL.ZeroReturnError, SSL.SysCallError) as err:
        self.sstate += '/SSL.Error'
        self.LogInfo(
            'Error sending (SSL, SEND_MAX_BYTES=%d): %s'
            % (SEND_MAX_BYTES, err))
        SEND_MAX_BYTES = min(4096, SEND_MAX_BYTES)  # Maybe this will help?
        self.ProcessEofWrite()
        return False
      except AttributeError:
        self.sstate += '/AttrError'
        # This has been seen in the wild, is most likely some sort of
        # race during shutdown. :-(
        self.LogInfo('AttributeError, self.fd=%s' % self.fd)
        self.ProcessEofWrite()
        return False

      self.write_blocked = pending[sent:]

    if activity:
      self.last_activity = time.time()

    if self.wrote_bytes >= logging.LOG_THRESHOLD:
      self.LogTraffic()

    if self.write_eof and not self.write_blocked:
      self.ProcessEofWrite()

    self.sstate = (self.dead and 'dead' or 'idle')
    return True

  def SendChunked(self, data, compress=True, zhistory=None, just_buffer=False):
    if self.use_websocket:
      with self.lock:
        return self.Send(
          [ABNF.create_frame(
            ''.join(data), ABNF.OPCODE_BINARY, 1, self.ws_zero_mask).format()],
          activity=False, try_flush=(not just_buffer), just_buffer=just_buffer)

    rst = ''
    if self.zreset:
      self.zreset = False
      rst = 'R'

    # Stop compressing streams that just get bigger.
    if zhistory and (zhistory[0] < zhistory[1]): compress = False
    with self.lock:
      try:
        sdata = ''.join(data)
        if self.zw and compress and len(sdata) > 64:
          try:
            zdata = s(self.zw.compress(b(sdata)) + self.zw.flush(zlib.Z_SYNC_FLUSH))
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
                 and (s.acked_kb_delta < (3 * s.maxread/1024)))

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
      try:
        kwargs['relay_sockname'] = self.fd.getsockname()
      except:
        kwargs['relay_sockname'] = None

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


TLS_CLIENTHELLO = '%c' % 0o26
SSL_CLIENTHELLO = '\x80'
XML_PREAMBLE = '<?xml'
XMPP_REGEXP = re.compile("<[^>]+\sto=([^\s>]+)[^>]*>")

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
            '%s') % (self.is_tls, LineParser.__html__(self))

  def ProcessData(self, data):
    # Uncomment when adding support for new protocols:
    #
    #print(('DATA: >%s<'
    #       ) % ' '.join(['%2.2x' % ord(d) for d in data]))

    if self.might_be_tls:
      self.might_be_tls = False
      if not (data.startswith(TLS_CLIENTHELLO) or
              data.startswith(SSL_CLIENTHELLO)):
        self.EatPeeked()

        # Only works if the full request is in the first data packet.
        if data.startswith(XML_PREAMBLE):
          server = self.GetXMPPServer(data)
          if server:
            return self.ProcessProto(data, 'xmpp', server)

        return LineParser.ProcessData(self, data)

      self.is_tls = True

    if self.is_tls:
      return self.ProcessTls(data)
    else:
      self.EatPeeked()
      return LineParser.ProcessData(self, data)

  def GetMsg(self, data):
    mtype, ml24, mlen = struct.unpack('>BBH', b(data[0:4]))
    mlen += ml24 * 0x10000
    return mtype, data[4:4+mlen], data[4+mlen:]

  def GetClientHelloExtensions(self, msg):
    # Ugh, so many magic numbers! These are accumulated sizes of
    # the different fields we are ignoring in the TLS headers.
    slen = struct.unpack('>B', b(msg[34]))[0]
    cslen = struct.unpack('>H', b(msg[35+slen:37+slen]))[0]
    cmlen = struct.unpack('>B', b(msg[37+slen+cslen]))[0]
    extofs = 34+1+2+1+2+slen+cslen+cmlen
    if extofs < len(msg): return msg[extofs:]
    return None

  def GetSniNames(self, extensions):
    names = []
    while extensions:
      etype, elen = struct.unpack('>HH', b(extensions[0:4]))
      if etype == 0:
        # OK, we found an SNI extension, get the list.
        namelist = extensions[6:4+elen]
        while namelist:
          ntype, nlen = struct.unpack('>BH', b(namelist[0:3]))
          if ntype == 0: names.append(namelist[3:3+nlen].lower())
          namelist = namelist[3+nlen:]
      extensions = extensions[4+elen:]
    return names

  def GetSni(self, data):
    hello, vmajor, vminor, mlen = struct.unpack('>BBBH', b(data[0:5]))
    data = data[5:]
    sni = []
    while data:
      mtype, msg, data = self.GetMsg(data)
      if mtype == 1:
        # ClientHello!
        sni.extend(self.GetSniNames(self.GetClientHelloExtensions(msg)))
    return sni

  def GetXMPPServer(self, data):
    match = XMPP_REGEXP.search(data)
    if match and match.group(1):
      server = match.group(1)
      if server[:1] in ('"', "'"):
        server = server[1:-1]
      if '@' in server:
        server = server.split('@')[-1]
      return server
    else:
      return None

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
    self.zr = None
    self.websocket_key = None

  def ProcessData(self, *args, **kwargs):
    if self.use_websocket:
      return self.ProcessWebsocketData(*args, **kwargs)
    else:
      return self.ProcessPageKiteData(*args, **kwargs)

  def __html__(self):
    return Selectable.__html__(self)

  def Cleanup(self, close=True):
    Selectable.Cleanup(self, close=close)
    self.zr = self.chunk = self.header = None

  def PrepareWebsockets(self):
    self.websocket_key = os.urandom(16)

  def ProcessWebsocketData(self, data):
    loops = 150
    happy = more = True
    while happy and more and (loops > 0):
      loops -= 1

      if self.peeking:
        self.header = ''
        self.chunk = ''

      self.header += (data or '')
      try:
        ws_frame, data = ABNF.parse(self.header)
        more = data and (len(data) > 0)
      except ValueError as err:
        self.LogError('ChunkParser::ProcessData: %s' % err)
        self.Log([('bad_data', data)])
        return False

      if ws_frame and ws_frame.length == len(ws_frame.data):
        # We have a complete frame, process it!
        self.header = ''
        happy = self.ProcessChunk(ws_frame.data) if ws_frame.data else True
      else:
        if self.read_eof:
          return self.ProcessEofRead()
        # Frame is incomplete, but there were no errors: we're done for now.
        return True

    if happy and more:
      self.LogError('Unprocessed data: %s' % data)
      raise BugFoundError('Too much data')
    elif self.read_eof:
      return self.ProcessEofRead() and happy
    else:
      return happy

    return False  # Not reached

  def ProcessPageKiteData(self, data):
    loops = 150
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

        except ValueError as err:
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
            if not self.zr:
              self.zr = zlib.decompressobj()
            cchunk = s(self.zr.decompress(b(self.chunk)))
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
