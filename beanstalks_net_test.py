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
#    Basic unittests of key parts of the code - protocol parsers, signatures,
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


class TestInternals(unittest.TestCase):

  def setUp(self):
    self.globalSecret = beanstalks_net.globalSecret()
  
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
    data = '%s:%s:%s' % (bid, beanstalks_net.signToken(token=self.globalSecret,
                                                       payload=self.globalSecret,
                                                       secret='x'), token) 
    sign = beanstalks_net.signToken(secret='Secret', payload=data, token=token)
    req = request[:]
    req.extend([zlibreq, 'X-Beanstalk: %s:%s\r\n' % (data, sign), reqbody])
    self.assertEqual(beanstalks_net.HTTP_BeanstalkRequest('x', backends,
                                                          tokens={bid: token},
                                                          testtoken=token),
                     ''.join(req))
    
  def test_LogValues(self):
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
    pass


if __name__ == '__main__':
  unittest.main()
