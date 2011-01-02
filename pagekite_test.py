#!/usr/bin/python -u
#
# pagekite_test.py, Copyright 2010, The PageKites Project ehf.
#                                   http://beanstalks-project.net/
#
# Testing for the core pagekite code.
#
#############################################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#############################################################################
# DESIGN:
#
#  TestInternals:
#    Basic unittests for key parts of the code: protocol parsers, signatures,
#    things that need to stay strictly compatible.
# 
#  TestNetwork:
#    Tests network communication by creating multiple threads and making
#    them talk to each-other:
#        - FrontEnd threads (mocked DNS code)
#        - BackEnd threads (mocked DNS code)
#        - HTTPD threads
#        - SMTPD threads
#        - XMPP threads
#        - Client threads checking results
#
#  TextNetworkExternal:
#    Similar to TestNetwork, but adds the ability to use external servers
#    as well, for verifying compatibility with other implementations.
#
import os
import random
import socket
import sys
import time
import threading
import unittest
import urllib

import pagekite


class MockSocketFD(object):
  def __init__(self, recv_values=None, maxsend=1500, maxread=5000):
    self.recv_values = recv_values or []
    self.sent_values = []
    self.maxsend = maxsend
    self.maxread = maxread
    self.closed = False

  def recv(self, maxread):
    if self.recv_values:
      if maxread > self.maxread: maxread = self.maxread
      if len(self.recv_values[0]) <= maxread:
        data = self.recv_values.pop(0)
      else:
        data = self.recv_values[0][0:maxread]
        self.recv_values[0] = self.recv_values[0][maxread:]
      return data
    else:
      return None 

  def send(self, data):
    if len(data) > self.maxsend:
      self.sent_values.append(data[0:self.maxsend])
      return self.maxsend
    else:
      self.sent_values.append(data)
      return len(data)
 
  def setblocking(self, val): pass
  def setsockopt(self, a, b, c): pass
  def flush(self): pass
  def close(self): self.closed = True
  def closed(self): return self.closed


class MockUiRequestHandler(pagekite.UiRequestHandler):
  def do_GET(self):
    self.send_response(200)
    self.send_header('Content-Type', 'text/plain')
    self.end_headers()
    self.wfile.write('I am %s\n' % self.server.pkite)
    self.wfile.write('asdf random junk junk crap! ' * random.randint(0, 200))


class MockPageKite(pagekite.PageKite):
  def __init__(self):
    pagekite.PageKite.__init__(self)
    self.felldown = None

  def FallDown(self, message, help=True):
    raise Exception(message)
  
  def HelpAndExit(self):
    raise Exception('Should print help')
  
  def LookupDomainQuota(lookup):
    return -1 

  def Ping(self, host, port):
    return len(host)+port

  def GetHostIpAddr(self, host):
    if host == 'localhost': return '127.0.0.1'
    return '10.1.2.%d' % len(host)

  def GetHostDetails(self, host):
    return (host, [host], ['10.1.2.%d' % len(host), '192.168.1.%d' % len(host)])


class TestInternals(unittest.TestCase):

  def setUp(self):
    pagekite.Log = pagekite.LogValues
    self.gSecret = pagekite.globalSecret()
  
  def test_signToken(self):
    # Basic signature
    self.assertEqual(pagekite.signToken(token='1234567812',
                                              secret='Bjarni',
                                              payload='Bjarni'),
                     '1234567843b16458418175599012be884a18')

    # Make sure it varies based on all variables
    self.assertNotEqual(pagekite.signToken(token='1234567812345689',
                                                 secret='BjarniTheDude',
                                                 payload='Bjarni'),
                     '1234567843b16458418175599012be884a18')
    self.assertNotEqual(pagekite.signToken(token='234567812345689',
                                                 secret='Bjarni',
                                                 payload='Bjarni'),
                     '1234567843b16458418175599012be884a18')
    self.assertNotEqual(pagekite.signToken(token='1234567812345689',
                                                 secret='Bjarni',
                                                 payload='BjarniTheDude'),
                     '1234567843b16458418175599012be884a18')

    # Test non-standard signature lengths
    self.assertEqual(pagekite.signToken(token='1234567812',
                                              secret='Bjarni',
                                              payload='Bjarni',
                                              length=1000),
                     '1234567843b16458418175599012be884a18963f10be4670')

  def test_PageKiteRequest(self):
    request = ['CONNECT PageKite:1 HTTP/1.0\r\n'] 
    zlibreq = 'X-PageKite-Features: ZChunks\r\n'
    reqbody = '\r\n'

    # Basic request, no servers.
    req = request[:]
    req.extend([zlibreq, reqbody])
    self.assertEqual(pagekite.HTTP_PageKiteRequest('x', {}),
                     ''.join(req))

    # Basic request, no servers, zchunks disabled.
    req = request[:]
    req.append(reqbody)
    self.assertEqual(pagekite.HTTP_PageKiteRequest('x', {}, nozchunks=True),
                     ''.join(req))
    
    # Full request, single server.
    bid = 'http:a'
    token = '0123456789'
    backends = {bid: ['a', 'b', 'c', 'd']}
    backends[bid][pagekite.BE_SECRET] = 'Secret'
    data = '%s:%s:%s' % (bid, pagekite.signToken(token=self.gSecret,
                                                 payload=self.gSecret,
                                                 secret='x'), token) 
    sign = pagekite.signToken(secret='Secret', payload=data, token=token)
    req = request[:]
    req.extend([zlibreq, 'X-PageKite: %s:%s\r\n' % (data, sign), reqbody])
    self.assertEqual(pagekite.HTTP_PageKiteRequest('x', backends,
                                                        tokens={bid: token},
                                                        testtoken=token),
                     ''.join(req))
    
  def test_LogValues(self):
    # Make sure the LogValues dumbs down our messages so they are easy
    # to parse and survive a trip through syslog etc.
    words, wdict = pagekite.LogValues([('spaces', '  bar  '),
                                       ('tab', 'one\ttwo'),
                                       ('cr', 'one\rtwo'),
                                       ('lf', 'one\ntwo'),
                                       ('semi', 'one;two; three')],
                                      testtime=1000)
    self.assertEqual(wdict['ts'], '%x' % 1000)
    self.assertEqual(wdict['spaces'], 'bar')
    self.assertEqual(wdict['tab'], 'one two')
    self.assertEqual(wdict['cr'], 'one two')
    self.assertEqual(wdict['lf'], 'one two')
    self.assertEqual(wdict['semi'], 'one;two, three')
    for key, val in words: self.assertEqual(wdict[key], val)

  def test_HttpParser(self):
    Response11 = 'HTTP/1.1 200 OK'
    Request11 = 'GET / HTTP/1.1'
    Headers = ['Host: foo.com',
               'Content-Type: text/html',
               'Borked:',
               'Multi: foo',
               'Multi: bar']
    BadHeader = 'BadHeader'
    Body = 'This is the Body'

    # Parse a valid request.
    pagekite.LOG = []
    GoodRequest = [Request11]
    GoodRequest.extend(Headers)
    GoodRequest.extend(['', Body])
    goodRParse = pagekite.HttpParser(lines=GoodRequest, testbody=True)
    self.assertEquals(pagekite.LOG, [])
    self.assertEquals(goodRParse.state, goodRParse.IN_BODY)
    self.assertEquals(goodRParse.lines, GoodRequest)
    # Make sure the headers parsed properly and that we aren't case-sensitive.
    self.assertEquals(goodRParse.Header('Host')[0], 'foo.com')
    self.assertEquals(goodRParse.Header('CONTENT-TYPE')[0], 'text/html')
    self.assertEquals(goodRParse.Header('multi')[0], 'foo')
    self.assertEquals(goodRParse.Header('Multi')[1], 'bar')
    self.assertEquals(goodRParse.Header('noheader'), [])

    # Parse a valid response.
    pagekite.LOG = []
    GoodMessage = [Response11]
    GoodMessage.extend(Headers)
    GoodMessage.extend(['', Body])
    goodParse = pagekite.HttpParser(lines=GoodMessage,
                                          state=pagekite.HttpParser.IN_RESPONSE,
                                          testbody=True)
    self.assertEquals(pagekite.LOG, [])
    self.assertEquals(goodParse.state, goodParse.IN_BODY)
    self.assertEquals(goodParse.lines, GoodMessage)

    # Fail to parse a bad request.
    pagekite.LOG = []
    BadRequest = Headers[:]
    BadRequest.extend([BadHeader, '', Body])
    badParse = pagekite.HttpParser(lines=BadRequest,
                                         state=pagekite.HttpParser.IN_HEADERS,
                                         testbody=True)
    self.assertEquals(badParse.state, badParse.PARSE_FAILED)
    self.assertNotEqual(pagekite.LOG, [])
    self.assertEquals(pagekite.LOG[0]['err'][-11:-2], "BadHeader")

  def test_Selectable(self):
    packets = ['abc', '123', 'This is a long packet', 'short']

    class EchoSelectable(pagekite.Selectable):
      def __init__(self, data=None):
        pagekite.Selectable.__init__(self, fd=MockSocketFD(data, maxsend=6))
      def ProcessData(self, data):
        return self.Send(data)

    # This is a basic test of the EchoSelectable, which simply reads all
    # the available data and echos it back...
    pagekite.LOG = []
    ss = EchoSelectable(packets[:])
    while ss.ReadData() is not False: pass
    ss.Flush()
    ss.Cleanup()
    self.assertEquals(pagekite.LOG[0]['read'], '%d' % len(''.join(packets)))
    self.assertEquals(pagekite.LOG[0]['wrote'], '%d' % len(''.join(ss.fd.sent_values)))
    self.assertEquals(''.join(ss.fd.sent_values), ''.join(packets))

    # NOTE: This test does not cover the compression code and the SendChunked
    #       method, those are tested in the ChunkParser test below.

  def test_LineParser(self):
    packets = ['This is a line\n', 'This ', 'is', ' a line\nThis',
               ' is a line\n']
     
    class EchoLineParser(pagekite.LineParser):
      def __init__(self, data=None):
        pagekite.LineParser.__init__(self, fd=MockSocketFD(data))
      def ProcessLine(self, line, lines):
        return self.Send(line)

    # This is a basic test of the EchoLineParser, which simply reads all
    # the available data and echos it back...
    pagekite.LOG = []
    ss = EchoLineParser(packets[:])
    while ss.ReadData() is not False: pass
    ss.Flush()
    ss.Cleanup()
    self.assertEquals(pagekite.LOG[0]['read'], '%d' % len(''.join(packets)))
    self.assertEquals(pagekite.LOG[0]['wrote'], '%d' % len(''.join(ss.fd.sent_values)))
    self.assertEquals(''.join(ss.fd.sent_values), ''.join(packets))
    # Verify that the data was reassembled into complete lines.
    self.assertEquals(ss.fd.sent_values[0], 'This is a line\n')
    self.assertEquals(ss.fd.sent_values[1], 'This is a line\n')
    self.assertEquals(ss.fd.sent_values[2], 'This is a line\n')

  def test_ChunkParser(self):
    # Easily compressed raw data...
    unchunked = ['This would be chunk one, one, one, one, one!!1',
                 'This is chunk two, chunk two, chunk two, woot!',
                 'And finally, chunk three, three, chunk, three chunk three']

    chunker = pagekite.Selectable(fd=MockSocketFD())
    chunked = chunker.fd.sent_values

    # First, let's just test the basic chunk generation
    for chunk in unchunked: chunker.SendChunked(chunk) 
    for i in [0, 1, 2]:
      self.assertEquals(chunked[i], '%x\r\n%s' % (len(unchunked[i]), 
                                                  unchunked[i]))
    # Second, test compressed chunk generation
    chunker.EnableZChunks(9)
    for chunk in unchunked: chunker.SendChunked(chunk) 
    for i in [0, 1, 2]:
      self.assertTrue(chunked[i+3].startswith('%xZ' % len(unchunked[i])))
      self.assertTrue(len(chunked[i+3]) < len(unchunked[i]))

    # Define our EchoChunkParser...
    class EchoChunkParser(pagekite.ChunkParser):
      def __init__(self, data=None):
        pagekite.ChunkParser.__init__(self, fd=MockSocketFD(data, maxread=1))
      def ProcessChunk(self, chunk):
        return self.Send(chunk)
   
    # Finally, let's let the ChunkParser unchunk it all again.   
    pagekite.LOG = []
    ss = EchoChunkParser(chunked[:])
    while ss.ReadData() is not False: pass
    ss.Flush()
    ss.Cleanup()
    self.assertEquals(pagekite.LOG[-1]['read'], '%d' % len(''.join(chunked)))
    self.assertEquals(pagekite.LOG[-1]['wrote'], '%d' % (2*len(''.join(unchunked))))
    self.assertEquals(''.join(ss.fd.sent_values), 2 * ''.join(unchunked))

    # FIXME: Corrupt chunks aren't tested.

  def test_PageKite(self):
    bn = MockPageKite()

    def C1(arg): return bn.Configure([arg]) or True
    def C2(a1,a2): return bn.Configure([a1,a2]) or True
    def EQ(val, var): return self.assertEquals(val, var) or True

    ##[ Common options ]######################################################

    C1('--httpd=localhost:1234') and EQ(('localhost', 1234), bn.ui_sspec)
    C2('-H', 'localhost:4321') and EQ(('localhost', 4321), bn.ui_sspec)

    C1('--httppass=password') and EQ('password', bn.ui_password)
    C2('-X', 'passx') and EQ('passx', bn.ui_password)

#   C1('--pemfile=/dev/null') and EQ('/dev/null', bn.ui_pemfile)
#   C2('-P', '/dev/zero') and EQ('/dev/zero', bn.ui_pemfile)

    C1('--nozchunks') and EQ(True, bn.disable_zchunks)
    
    C1('--logfile=/dev/null') and EQ('/dev/null', bn.logfile)
    C2('-L', '/dev/zero') and EQ('/dev/zero', bn.logfile)

    C1('--daemonize') and EQ(True, bn.daemonize)
    bn.daemonize = False
    C1('-Z') and EQ(True, bn.daemonize)

    C1('--runas=root:root') and EQ(0, bn.setuid) and EQ(0, bn.setgid)
    C1('--runas=daemon') and EQ(1, bn.setuid)
    C2('-U', 'root:daemon') and EQ(0, bn.setuid) and EQ(1, bn.setgid)

    C1('--pidfile=/dev/null') and EQ('/dev/null', bn.pidfile)
    C2('-I', '/dev/zero') and EQ('/dev/zero', bn.pidfile)

    ##[ Front-end options ]###################################################

    C1('--isfrontend') and EQ(True, bn.isfrontend)
    bn.isfrontend = False
    C1('-f') and EQ(True, bn.isfrontend)

    C1('--authdomain=a.com') and EQ('a.com', bn.auth_domain)
    C2('-A', 'b.com') and EQ('b.com', bn.auth_domain)

#   C1('--register=a.com') and EQ('a.com', bn.register_with)
#   C2('-R', 'b.com') and EQ('b.com', bn.register_with)

    C1('--host=a.com') and EQ('a.com', bn.server_host)
    C2('-h', 'b.com') and EQ('b.com', bn.server_host)
   
    C1('--ports=1,2,3') and EQ([1,2,3], bn.server_ports) 
    C2('-p', '4,5') and EQ([4,5], bn.server_ports) 
    
    C1('--protos=HTTP,https') and EQ(['http', 'https'], bn.server_protos)
    
#   C1('--domain=http,https:a.com:secret')

    ##[ Back-end options ]###################################################

    C1('--all') and EQ(True, bn.require_all)
    bn.require_all = False
    C1('-a') and EQ(True, bn.require_all)

    C1('--dyndns=beanstalks.net') and EQ(bn.dyndns[0], pagekite.DYNDNS['beanstalks.net'])
    C2('-D', 'a@no-ip.com') and EQ(bn.dyndns, (pagekite.DYNDNS['no-ip.com'], {'user': 'a', 'pass': ''}))
    C1('--dyndns=a:b@c') and EQ(bn.dyndns, ('c', {'user': 'a', 'pass': 'b'}))
   
    C1('--frontends=2:a.com:80') and EQ((2, 'a.com', 80), bn.servers_auto)
    C1('--frontend=b.com:80') and EQ(['b.com:80'], bn.servers_manual)

    C1('--new') and EQ(True, bn.servers_new_only)
    bn.servers_new_only = False
    C1('-N') and EQ(True, bn.servers_new_only)

    C1('--backend=http:a.com:LOCALhost:80:x')
    EQ(bn.backends, {'http:a.com': ('http', 'a.com', 'localhost:80', 'x')})

  def test_Connections(self):
    class MockTunnel(pagekite.Selectable):
      def __init__(self, sname):
        pagekite.Selectable.__init__(self, fd=MockSocketFD([]))
        self.server_name = sname
    class MockAuthThread(pagekite.AuthThread):
      def __init__(self, conns):
        self.conns = conns
      def start(self):
        self.started = True

    conns = pagekite.Connections(MockPageKite())
    sel = MockTunnel('test.com')
    conns.Add(sel)
    conns.start(auth_thread=MockAuthThread(conns))

    self.assertEqual(conns.auth.started, True)
    self.assertEqual(conns.Sockets(), [sel.fd])
    self.assertEqual(conns.Blocked(), [])
    sel.write_blocked = ['block']
    self.assertEqual(conns.Blocked(), [sel.fd])
    self.assertEqual(conns.Connection(sel.fd), sel)

    sel.fd.close()
    conns.CleanFds()
    self.assertEqual(conns.Sockets(), [])

    sel.fd.closed = False
    conns.Tunnel('http', 'test.com', conn=sel)
    self.assertEqual(conns.TunnelServers(), ['test.com'])
    self.assertEqual(conns.Tunnel('http', 'test.com'), [sel])

    conns.Remove(sel)
    self.assertEqual(conns.Tunnel('http', 'test.com'), None)

  def test_AuthThread(self):
    at = pagekite.AuthThread(None)
    # FIXME
    pass

  def test_MagicProtocolParser(self):
    # FIXME
    pass

  def test_Tunnel(self):
    # FIXME
    pass

  def test_UserConn(self):
    # FIXME
    pass

  def test_UnknownConn(self):
    # FIXME
    pass


class KiteRunner(threading.Thread):
  def __init__(self, pagekite_object):
    threading.Thread.__init__(self)
    self.pagekite_object = pagekite_object 
  def run(self):
    self.pagekite_object.Start()

class RequestRunner(threading.Thread):
  def __init__(self, loops, urls, expect):
    threading.Thread.__init__(self)
    self.loops = loops
    self.urls = urls
    self.expect = expect
    self.errors = []

  def run(self):
    while self.loops > 0:
      try:
        url = self.urls[random.randint(0, len(self.urls)-1)]
        result = ''.join(urllib.urlopen(url).readlines())
        if self.expect not in result:
          self.errors.append('Bad result: %s' % result)
      except Exception, e:
        self.loops = 0
        self.errors.append('Error: %s' % e)
      finally:
        self.loops -= 1 
  

class ForkRequestRunner(RequestRunner):
  def start(self):
    if 0 == os.fork():
      self.run()
      os._exit(0)


class TestNetwork(unittest.TestCase):
  def setUp(self):
    pagekite.LOG = []
    self.fe = []
    self.be = []
    self.startFrontEnds(2)

  def startFrontEnds(self, count):
    n = 0
    while n < count:
      fe = MockPageKite().Configure([
        '--isfrontend', 
        '--host=localhost',
        '--ports=99%d0' % n,
        '--httpd=:99%d1' % n,
        '--domain=http,https:localhost:1234'
      ])
      KiteRunner(fe).start()
      self.fe.append(fe)
      n += 1

    for fe in self.fe:
      while not fe.looping: time.sleep(1)

  def stopPageKites(self, pks):
    for pk in pks:
      pk.looping = False
      fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      fd.connect((pk.server_host, pk.server_ports[0]))

  def LogData(self, data=None):
    return ''.join(['\n%s' % l for l in (data or pagekite.LOG) if 'debug' not in l])

  def tearDown(self):
    self.stopPageKites(self.fe)
    self.stopPageKites(self.be)

  # TESTS:
  #  - End-to-end test of web-server behind multiple FE=BE tunnel,
  #    multiple clients, large number of requests in parallel.
  #  - Test reconnection logic.
  # 

  def test_OneBackEnd(self):
    be = MockPageKite().Configure([
      '--isfrontend', 
      '--host=localhost',
      '--ports=9800',
      '--httpd=:9801',
      '--frontend=localhost:9900',
      '--frontend=localhost:9910',
      '--backend=http,https:localhost:localhost:9801:1234'
    ]) 
    be.ui_request_handler = MockUiRequestHandler

    pagekite.LOG = []
    KiteRunner(be).start()
    self.be.append(be)

    # Parse the log until we see connections are up and running...
    waiting = len(self.fe) 
    loops = 5
    parsed = []
    while waiting > 0 and loops > 0:
      loops -= 1
      while pagekite.LOG:
        line = pagekite.LOG.pop(0)
        parsed.append(line)
        if 'connect' in line: waiting -= 1
      if waiting > 0:
        time.sleep(1)
    if not loops:
      raise Exception('No connection after 5 seconds\n%s' % self.LogData(data=parsed))

    urls = ['http://LOCALhost:%d/' % pk.server_ports[0] for pk in self.fe]
    ForkRequestRunner(10, urls, 'MockPageKite').start()
    ForkRequestRunner(10, urls, 'MockPageKite').start()
    rr = RequestRunner(15, urls, 'MockPageKite') 
    rr.start()
    while rr.loops > 0: time.sleep(1)
    if rr.errors: raise Exception('Ick: %s, %s%s' % (
                                    rr.errors,
                                    self.LogData(data=parsed),
                                    self.LogData(data=pagekite.LOG)))


class TestNetworkExternal(unittest.TestCase):
  def setUp(self):
    # FIXME
    pass


if __name__ == '__main__':
  unittest.main()
