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
    self.assertEqual(beanstalks_net.HTTP_BeanstalkRequest('x', {}, nozlib=True),
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
    packets = ['abc', '123']

    class TestSelectable(beanstalks_net.Selectable):
      def __init__(self, data=None):
        beanstalks_net.Selectable.__init__(self,
                                           fd=MockSocketFD(recv_values=data))
        self.processed = []
        self.sent = self.fd.sent_values
      def ProcessData(self, data):
        self.processed.append(data)

    beanstalks_net.LOG = []
    ss = TestSelectable(packets[:])
    ss.ReadData()
    ss.Send('hello world')
    ss.ReadData()
    self.assertEquals(beanstalks_net.LOG, [])
    self.assertEquals(ss.processed, packets)
    self.assertEquals(ss.sent, packets)
    

class TestNetwork(unittest.TestCase):

  def setUp(self):
    pass


if __name__ == '__main__':
  unittest.main()
