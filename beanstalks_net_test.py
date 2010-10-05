#!/usr/bin/python -u
#
# beanstalks_net_test.py, Copyright 2010, The Beanstalks Project ehf.
#                                         http://beanstalks-project.net/
#
# Testing for the core beanstalks_net code.
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
import beanstalks_net
import unittest


class MockSocketFD(object):
  def __init__(self, recv_values=None, maxsend=1500):
    self.recv_values = recv_values or []
    self.sent_values = []
    self.maxsend = maxsend
    self.closed = False

  def recv(self, maxread):
    if self.recv_values:
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


class MockBeanstalksNet(beanstalks_net.BeanstalksNet):
  def __init__(self):
    beanstalks_net.BeanstalksNet.__init__(self)
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
    return '10.1.2.%d' % len(host)

  def GetHostDetails(self, host):
    return (host, [host], ['10.1.2.%d' % len(host), '192.168.1.%d' % len(host)])


class TestInternals(unittest.TestCase):

  def setUp(self):
    beanstalks_net.Log = beanstalks_net.LogValues
    self.gSecret = beanstalks_net.globalSecret()
  
  def test_signToken(self):
    # Basic signature
    self.assertEqual(beanstalks_net.signToken(token='1234567812',
                                              secret='Bjarni',
                                              payload='Bjarni'),
                     '1234567843b16458418175599012be884a18')

    # Make sure it varies based on all variables
    self.assertNotEqual(beanstalks_net.signToken(token='1234567812345689',
                                                 secret='BjarniTheDude',
                                                 payload='Bjarni'),
                     '1234567843b16458418175599012be884a18')
    self.assertNotEqual(beanstalks_net.signToken(token='234567812345689',
                                                 secret='Bjarni',
                                                 payload='Bjarni'),
                     '1234567843b16458418175599012be884a18')
    self.assertNotEqual(beanstalks_net.signToken(token='1234567812345689',
                                                 secret='Bjarni',
                                                 payload='BjarniTheDude'),
                     '1234567843b16458418175599012be884a18')

    # Test non-standard signature lengths
    self.assertEqual(beanstalks_net.signToken(token='1234567812',
                                              secret='Bjarni',
                                              payload='Bjarni',
                                              length=1000),
                     '1234567843b16458418175599012be884a18963f10be4670')

  def test_BeanstalkRequest(self):
    request = ['POST /Beanstalk~Magic~Beans/0.2 HTTP/1.1\r\n',
               'Host: x\r\n',
               'Content-Type: application/octet-stream\r\n',
               'Transfer-Encoding: chunked\r\n'] 
    zlibreq = 'X-Beanstalk-Features: ZChunks\r\n'
    reqbody = '\r\nOK\r\n'

    # Basic request, no servers.
    req = request[:]
    req.extend([zlibreq, reqbody])
    self.assertEqual(beanstalks_net.HTTP_BeanstalkRequest('x', {}),
                     ''.join(req))

    # Basic request, no servers, zchunks disabled.
    req = request[:]
    req.append(reqbody)
    self.assertEqual(beanstalks_net.HTTP_BeanstalkRequest('x', {}, nozchunks=True),
                     ''.join(req))
    
    # Full request, single server.
    bid = 'http:a'
    token = '0123456789'
    backends = {bid: ['a', 'b', 'c', 'd']}
    backends[bid][beanstalks_net.BE_SECRET] = 'Secret'
    data = '%s:%s:%s' % (bid, beanstalks_net.signToken(token=self.gSecret,
                                                       payload=self.gSecret,
                                                       secret='x'), token) 
    sign = beanstalks_net.signToken(secret='Secret', payload=data, token=token)
    req = request[:]
    req.extend([zlibreq, 'X-Beanstalk: %s:%s\r\n' % (data, sign), reqbody])
    self.assertEqual(beanstalks_net.HTTP_BeanstalkRequest('x', backends,
                                                          tokens={bid: token},
                                                          testtoken=token),
                     ''.join(req))
    
  def test_LogValues(self):
    # Make sure the LogValues dumbs down our messages so they are easy
    # to parse and survive a trip through syslog etc.
    words, wdict = beanstalks_net.LogValues([('spaces', '  bar  '),
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
               'Multi: foo',
               'Multi: bar']
    BadHeader = 'BadHeader'
    Body = 'This is the Body'

    # Parse a valid request.
    beanstalks_net.LOG = []
    GoodRequest = [Request11]
    GoodRequest.extend(Headers)
    GoodRequest.extend(['', Body])
    goodRParse = beanstalks_net.HttpParser(lines=GoodRequest, testbody=True)
    self.assertEquals(beanstalks_net.LOG, [])
    self.assertEquals(goodRParse.state, goodRParse.IN_BODY)
    self.assertEquals(goodRParse.lines, GoodRequest)
    # Make sure the headers parsed properly and that we aren't case-sensitive.
    self.assertEquals(goodRParse.Header('Host')[0], 'foo.com')
    self.assertEquals(goodRParse.Header('CONTENT-TYPE')[0], 'text/html')
    self.assertEquals(goodRParse.Header('multi')[0], 'foo')
    self.assertEquals(goodRParse.Header('Multi')[1], 'bar')
    self.assertEquals(goodRParse.Header('noheader'), [])

    # Parse a valid response.
    beanstalks_net.LOG = []
    GoodMessage = [Response11]
    GoodMessage.extend(Headers)
    GoodMessage.extend(['', Body])
    goodParse = beanstalks_net.HttpParser(lines=GoodMessage,
                                          state=beanstalks_net.HttpParser.IN_RESPONSE,
                                          testbody=True)
    self.assertEquals(beanstalks_net.LOG, [])
    self.assertEquals(goodParse.state, goodParse.IN_BODY)
    self.assertEquals(goodParse.lines, GoodMessage)

    # Fail to parse a bad request.
    beanstalks_net.LOG = []
    BadRequest = Headers[:]
    BadRequest.extend([BadHeader, '', Body])
    badParse = beanstalks_net.HttpParser(lines=BadRequest,
                                         state=beanstalks_net.HttpParser.IN_HEADERS,
                                         testbody=True)
    self.assertEquals(badParse.state, badParse.PARSE_FAILED)
    self.assertNotEqual(beanstalks_net.LOG, [])
    self.assertEquals(beanstalks_net.LOG[0]['err'][-11:-2], "BadHeader")

  def test_Selectable(self):
    packets = ['abc', '123', 'This is a long packet', 'short']

    class EchoSelectable(beanstalks_net.Selectable):
      def __init__(self, data=None):
        beanstalks_net.Selectable.__init__(self,
                                           fd=MockSocketFD(data, maxsend=6))
      def ProcessData(self, data):
        return self.Send(data)

    # This is a basic test of the EchoSelectable, which simply reads all
    # the available data and echos it back...
    beanstalks_net.LOG = []
    ss = EchoSelectable(packets[:])
    while ss.ReadData() is not False: pass
    ss.Flush()
    ss.Cleanup()
    self.assertEquals(beanstalks_net.LOG[0]['read'], '%d' % len(''.join(packets)))
    self.assertEquals(beanstalks_net.LOG[0]['wrote'], '%d' % len(''.join(ss.fd.sent_values)))
    self.assertEquals(''.join(ss.fd.sent_values), ''.join(packets))

    # NOTE: This test does not cover the compression code and the SendChunked
    #       method, those are tested in the ChunkParser test below.

  def test_LineParser(self):
    packets = ['This is a line\n', 'This ', 'is', ' a line\nThis',
               ' is a line\n']
     
    class EchoLineParser(beanstalks_net.LineParser):
      def __init__(self, data=None):
        beanstalks_net.LineParser.__init__(self, fd=MockSocketFD(data))
      def ProcessLine(self, line, lines):
        return self.Send(line)

    # This is a basic test of the EchoLineParser, which simply reads all
    # the available data and echos it back...
    beanstalks_net.LOG = []
    ss = EchoLineParser(packets[:])
    while ss.ReadData() is not False: pass
    ss.Flush()
    ss.Cleanup()
    self.assertEquals(beanstalks_net.LOG[0]['read'], '%d' % len(''.join(packets)))
    self.assertEquals(beanstalks_net.LOG[0]['wrote'], '%d' % len(''.join(ss.fd.sent_values)))
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

    chunker = beanstalks_net.Selectable(fd=MockSocketFD())
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
    class EchoChunkParser(beanstalks_net.ChunkParser):
      def __init__(self, data=None):
        beanstalks_net.ChunkParser.__init__(self, fd=MockSocketFD(data))
      def ProcessChunk(self, chunk):
        return self.Send(chunk)
   
    # Finally, let's let the ChunkParser unchunk it all again.   
    beanstalks_net.LOG = []
    ss = EchoChunkParser(chunked[:])
    while ss.ReadData() is not False: pass
    ss.Flush()
    ss.Cleanup()
    self.assertEquals(beanstalks_net.LOG[-1]['read'], '%d' % len(''.join(chunked)))
    self.assertEquals(beanstalks_net.LOG[-1]['wrote'], '%d' % (2*len(''.join(unchunked))))
    self.assertEquals(''.join(ss.fd.sent_values), 2 * ''.join(unchunked))

    # FIXME: Corrupt chunks aren't tested.

  def test_BeanstalksNet(self):
    bn = MockBeanstalksNet()

    def C1(arg): return bn.Configure([arg]) or True
    def C2(a1,a2): return bn.Configure([a1,a2]) or True
    def EQ(val, var): return self.assertEquals(val, var) or True

    ##[ Common options ]######################################################

    C1('--httpd=localhost:1234') and EQ(('localhost', 1234), bn.ui_sspec)
    C2('-H', 'localhost:4321') and EQ(('localhost', 4321), bn.ui_sspec)

    C1('--httppass=password') and EQ('password', bn.ui_password)
    C2('-X', 'passx') and EQ('passx', bn.ui_password)

    C1('--httpopen') and EQ(True, bn.ui_open)
    bn.ui_open = False
    C1('-W') and EQ(True, bn.ui_open)

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

    C1('--dyndns=beanstalks.net') and EQ(bn.dyndns[0], beanstalks_net.DYNDNS['beanstalks.net'])
    C2('-D', 'a@no-ip.com') and EQ(bn.dyndns, (beanstalks_net.DYNDNS['no-ip.com'], {'user': 'a', 'pass': ''}))
    C1('--dyndns=a:b@c') and EQ(bn.dyndns, ('c', {'user': 'a', 'pass': 'b'}))
   
    C1('--frontends=2:a.com:80') and EQ((2, 'a.com', 80), bn.servers_auto)
    C1('--frontend=b.com:80') and EQ(['b.com:80'], bn.servers_manual)

    C1('--new') and EQ(True, bn.servers_new_only)
    bn.servers_new_only = False
    C1('-N') and EQ(True, bn.servers_new_only)

    C1('--backend=http:a.com:localhost:80:x')
    EQ(bn.backends, {'http:a.com': ('http', 'a.com', 'localhost:80', 'x')})

  def test_Connections(self):
    conns = beanstalks_net.Connections(MockBeanstalksNet())

    sel = beanstalks_net.Selectable(fd=MockSocketFD([]))
    conns.Add(sel)

    self.assertEqual(conns.Sockets(), [sel.fd])
    self.assertEqual(conns.Blocked(), [])
    self.assertEqual(conns.Connection(sel.fd), sel)

    sel.fd.close()
    conns.CleanFds()
    self.assertEqual(conns.Sockets(), [])

    
    pass

  def test_AuthThread(self):
    at = beanstalks_net.AuthThread(None)
    pass

  def test_MagicProtocolParser(self):
    pass

  def test_Tunnel(self):
    pass

  def test_UserConn(self):
    pass

  def test_UnknownConn(self):
    pass



class TestNetwork(unittest.TestCase):

  def setUp(self):
    pass


if __name__ == '__main__':
  unittest.main()
