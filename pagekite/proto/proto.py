"""
PageKite protocol and HTTP protocol related code and constants.
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
import os
import random
import struct
import time

from pagekite.compat import *
from pagekite.common import *
import pagekite.logging as logging


gSecret = None
def globalSecret():
  global gSecret
  if not gSecret:
    # This always works...
    gSecret = '%8.8x%s%8.8x' % (random.randint(0, 0x7FFFFFFE),
                                time.time(),
                                random.randint(0, 0x7FFFFFFE))

    # Next, see if we can augment that with some real randomness.
    try:
      newSecret = sha1hex(open('/dev/urandom').read(64) + gSecret)
      gSecret = newSecret
      logging.LogDebug('Seeded signatures using /dev/urandom, hooray!')
    except:
      try:
        newSecret = sha1hex(os.urandom(64) + gSecret)
        gSecret = newSecret
        logging.LogDebug('Seeded signatures using os.urandom(), hooray!')
      except:
        logging.LogInfo('WARNING: Seeding signatures with time.time() and random.randint()')

  return gSecret

TOKEN_LENGTH=36
def signToken(token=None, secret=None, payload='', timestamp=None,
              length=TOKEN_LENGTH):
  """
  This will generate a random token with a signature which could only have come
  from this server.  If a token is provided, it is re-signed so the original
  can be compared with what we would have generated, for verification purposes.

  If a timestamp is provided it will be embedded in the signature to a
  resolution of 10 minutes, and the signature will begin with the letter 't'

  Note: This is only as secure as random.randint() is random.
  """
  if not secret: secret = globalSecret()
  if not token: token = sha1hex('%s%8.8x' % (globalSecret(),
                                             random.randint(0, 0x7FFFFFFD)+1))
  if timestamp:
    tok = 't' + token[1:]
    ts = '%x' % int(timestamp/600)
    return tok[0:8] + sha1hex(secret + payload + ts + tok[0:8])[0:length-8]
  else:
    return token[0:8] + sha1hex(secret + payload + token[0:8])[0:length-8]

def checkSignature(sign='', secret='', payload=''):
  """
  Check a signature for validity. When using timestamped signatures, we only
  accept signatures from the current and previous windows.
  """
  if sign[0] == 't':
    ts = int(time.time())
    for window in (0, 1):
      valid = signToken(token=sign, secret=secret, payload=payload,
                        timestamp=(ts-(window*600)))
      if sign == valid: return True
    return False
  else:
    valid = signToken(token=sign, secret=secret, payload=payload)
    return sign == valid

def PageKiteRequestHeaders(server, backends, tokens=None, testtoken=None):
  req = []
  tokens = tokens or {}
  for d in backends.keys():
    if (backends[d][BE_BHOST] and
        backends[d][BE_SECRET] and
        backends[d][BE_STATUS] not in BE_INACTIVE):

      # A stable (for replay on challenge) but unguessable salt.
      my_token = sha1hex(globalSecret() + server + backends[d][BE_SECRET]
                         )[:TOKEN_LENGTH]

      # This is the challenge (salt) from the front-end, if any.
      server_token = d in tokens and tokens[d] or ''

      # Our payload is the (proto, name) combined with both salts
      data = '%s:%s:%s' % (d, my_token, server_token)

      # Sign the payload with the shared secret (random salt).
      sign = signToken(secret=backends[d][BE_SECRET],
                       payload=data,
                       token=testtoken)

      req.append('X-PageKite: %s:%s\r\n' % (data, sign))
  return req

def HTTP_PageKiteRequest(server, backends, tokens=None, nozchunks=False,
                         tls=False, testtoken=None, replace=None):
  req = ['CONNECT PageKite:1 HTTP/1.0\r\n',
         'X-PageKite-Features: AddKites\r\n',
         'X-PageKite-Version: %s\r\n' % APPVER]

  if not nozchunks:
    req.append('X-PageKite-Features: ZChunks\r\n')
  if replace:
    req.append('X-PageKite-Replace: %s\r\n' % replace)
  if tls:
    req.append('X-PageKite-Features: TLS\r\n')

  req.extend(PageKiteRequestHeaders(server, backends,
                                    tokens=tokens, testtoken=testtoken))
  req.append('\r\n')
  return ''.join(req)

def HTTP_ResponseHeader(code, title, mimetype='text/html', first_headers=None):
  if mimetype.startswith('text/') and ';' not in mimetype:
    mimetype += ('; charset=%s' % DEFAULT_CHARSET)
  return ('HTTP/1.1 %s %s\r\n%sContent-Type: %s\r\nPragma: no-cache\r\n'
          'Expires: 0\r\nCache-Control: no-store\r\nConnection: close'
          '\r\n') % (code, title, ''.join(first_headers or []), mimetype)

def HTTP_Header(name, value):
  return '%s: %s\r\n' % (name, value)

def HTTP_StartBody():
  return '\r\n'

def HTTP_ConnectOK():
  return 'HTTP/1.0 200 Connection Established\r\n\r\n'

def HTTP_ConnectBad(code=503, status='Unavailable'):
  return 'HTTP/1.0 %s %s\r\n\r\n' % (code, status)

def HTTP_Response(code, title, body,
                  mimetype='text/html', headers=None,
                  trackable=False, overloaded=False):
  if overloaded or trackable:
    headers = headers or []

  if trackable:  # Put this first...
    headers = [HTTP_Header('X-PageKite-UUID', MAGIC_UUID)] + headers

  if overloaded:  # No, put this first!
    headers = [HTTP_Header('X-PageKite-Overloaded', 'Sorry')] + headers

  return ''.join([
    HTTP_ResponseHeader(code, title, mimetype, first_headers=headers),
    HTTP_StartBody(),
    ''.join(body)])

def HTTP_NoFeConnection(proto):
  if proto.endswith('.json'):
    (mt, content) = ('application/json', '{"pagekite-status": "down-fe"}')
  else:
    (mt, content) = ('image/gif', base64.decodestring(
      'R0lGODlhCgAKAMQCAN4hIf/+/v///+EzM+AuLvGkpORISPW+vudgYOhiYvKpqeZY'
      'WPbAwOdaWup1dfOurvW7u++Rkepycu6PjwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAACH5BAEAAAIALAAAAAAKAAoAAAUtoCAcyEA0jyhEQOs6AuPO'
      'QJHQrjEAQe+3O98PcMMBDAdjTTDBSVSQEmGhEIUAADs='))
  return HTTP_Response(200, 'OK', content, mimetype=mt,
      headers=[HTTP_Header('X-PageKite-Status', 'Down-FE'),
               HTTP_Header('Access-Control-Allow-Origin', '*')])

def HTTP_NoBeConnection(proto):
  if proto.endswith('.json'):
    (mt, content) = ('application/json', '{"pagekite-status": "down-be"}')
  else:
    (mt, content) = ('image/gif', base64.decodestring(
      'R0lGODlhCgAKAPcAAI9hE6t2Fv/GAf/NH//RMf/hd7u6uv/mj/ntq8XExMbFxc7N'
      'zc/Ozv/xwfj31+jn5+vq6v///////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAACH5BAEAABIALAAAAAAKAAoAAAhDACUIlBAgwMCDARo4MHiQ'
      '4IEGDAcGKAAAAESEBCoiiBhgQEYABzYK7OiRQIEDBgMIEDCgokmUKlcOKFkgZcGb'
      'BSUEBAA7'))
  return HTTP_Response(200, 'OK', content, mimetype=mt,
      headers=[HTTP_Header('X-PageKite-Status', 'Down-BE'),
               HTTP_Header('Access-Control-Allow-Origin', '*')])

def HTTP_GoodBeConnection(proto):
  if proto.endswith('.json'):
    (mt, content) = ('application/json', '{"pagekite-status": "ok"}')
  else:
    (mt, content) = ('image/gif', base64.decodestring(
      'R0lGODlhCgAKANUCAEKtP0StQf8AAG2/a97w3qbYpd/x3mu/aajZp/b79vT69Mnn'
      'yK7crXTDcqraqcfmxtLr0VG0T0ivRpbRlF24Wr7jveHy4Pv9+53UnPn8+cjnx4LI'
      'gNfu1v///37HfKfZpq/crmG6XgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      'AAAAAAAAAAAAAAAAACH5BAEAAAIALAAAAAAKAAoAAAZIQIGAUDgMEASh4BEANAGA'
      'xRAaaHoYAAPCCZUoOIDPAdCAQhIRgJGiAG0uE+igAMB0MhYoAFmtJEJcBgILVU8B'
      'GkpEAwMOggJBADs='))
  return HTTP_Response(200, 'OK', content, mimetype=mt,
      headers=[HTTP_Header('X-PageKite-Status', 'OK'),
               HTTP_Header('Access-Control-Allow-Origin', '*')])

def HTTP_Unavailable(where, proto, domain, comment='', frame_url=None,
                     code=503, status='Unavailable', headers=None,
                     overloaded=False, advertise=True, relay_sockname=None):
  if advertise:
    label = "PageKite"
    whatis = ''.join(['<a href="', WWWHOME, '"><i>', label, '</i></a>'])
  else:
    label = "Connection"
    whatis = "connection"

  if code == 401:
    headers = headers or []
    headers.append(HTTP_Header('WWW-Authenticate', 'Basic realm=%s' % label))

  message = ''.join(['<h1>Sorry! (', where, ')</h1>',
                     '<p>The ', proto.upper(), ' ', whatis, ' for <b>',
                     domain, '</b> is unavailable at the moment.</p>',
                     '<p>Please try again later.</p><!-- ', comment, ' -->'])
  if frame_url:
    if '?' in frame_url:
      frame_url += ('&amp;where=%s&amp;proto=%s&amp;domain=%s'
                    % (where.upper(), proto, domain))
      if relay_sockname is not None:
        frame_url += ('&amp;relay=%s' % relay_sockname[0])
    return HTTP_Response(code, status,
                         ['<html><frameset cols="*">',
                          '<frame target="_top" src="', frame_url, '" />',
                          '<noframes>', message, '</noframes>',
                          '</frameset></html>\n'],
                         headers=headers,
                         trackable=True, overloaded=overloaded)
  else:
    return HTTP_Response(code, status,
                         ['<html><body>', message, '</body></html>\n'],
                         headers=headers,
                         trackable=True, overloaded=overloaded)

def TLS_Unavailable(forbidden=False, unavailable=False):
  """Generate a TLS alert record aborting this connectin."""
  # FIXME: Should we really be ignoring forbidden and unavailable?
  # Unfortunately, Chrome/ium only honors code 49, any other code will
  # cause it to transparently retry with SSLv3. So although this is a
  # bit misleading, this is what we send...
  return struct.pack('>BBBBBBB', 0x15, 3, 3, 0, 2, 2, 49) # 49 = Access denied
