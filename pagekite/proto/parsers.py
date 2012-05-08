from pagekite.logging import *

HTTP_METHODS = ['OPTIONS', 'CONNECT', 'GET', 'HEAD', 'POST', 'PUT', 'TRACE',
                'PROPFIND', 'PROPPATCH', 'MKCOL', 'DELETE', 'COPY', 'MOVE',
                'LOCK', 'UNLOCK', 'PING']
HTTP_VERSIONS = ['HTTP/1.0', 'HTTP/1.1']


class BaseLineParser(object):
  """Base protocol parser class."""

  PROTO = 'unknown'
  PROTOS = ['unknown']
  PARSE_UNKNOWN = -2
  PARSE_FAILED = -1
  PARSE_OK = 100

  def __init__(self, lines=None, state=PARSE_UNKNOWN, proto=PROTO):
    self.state = state
    self.protocol = proto
    self.lines = []
    self.domain = None
    self.last_parser = self
    if lines is not None:
      for line in lines:
        if not self.Parse(line): break

  def ParsedOK(self):
    return (self.state == self.PARSE_OK)

  def Parse(self, line):
    self.lines.append(line)
    return False

  def ErrorReply(self, port=None):
    return ''


class MagicLineParser(BaseLineParser):
  """Parse an unknown incoming connection request, line-by-line."""

  PROTO = 'magic'

  def __init__(self, lines=None, state=BaseLineParser.PARSE_UNKNOWN,
                     parsers=[]):
    self.parsers = [p() for p in parsers]
    BaseLineParser.__init__(self, lines, state, self.PROTO)
    if self.last_parser == self:
      self.last_parser = self.parsers[-1]

  def ParsedOK(self):
    return self.last_parser.ParsedOK()

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    self.last_parser = self.parsers[-1]
    for p in self.parsers[:]:
      if not p.Parse(line):
        self.parsers.remove(p)
      elif p.ParsedOK():
        self.last_parser = p
        self.domain = p.domain
        self.protocol = p.protocol
        self.state = p.state
        self.parsers = [p]
        break

    if not self.parsers:
      LogDebug('No more parsers!')

    return (len(self.parsers) > 0)


class HttpLineParser(BaseLineParser):
  """Parse an HTTP request, line-by-line."""

  PROTO = 'http'
  PROTOS = ['http']
  IN_REQUEST = 11
  IN_HEADERS = 12
  IN_BODY = 13
  IN_RESPONSE = 14

  def __init__(self, lines=None, state=IN_REQUEST, testbody=False):
    self.method = None
    self.path = None
    self.version = None
    self.code = None
    self.message = None
    self.headers = []
    self.body_result = testbody
    BaseLineParser.__init__(self, lines, state, self.PROTO)

  def ParseResponse(self, line):
    self.version, self.code, self.message = line.split()

    if not self.version.upper() in HTTP_VERSIONS:
      LogDebug('Invalid version: %s' % self.version)
      return False

    self.state = self.IN_HEADERS
    return True

  def ParseRequest(self, line):
    self.method, self.path, self.version = line.split()

    if not self.method in HTTP_METHODS:
      LogDebug('Invalid method: %s' % self.method)
      return False

    if not self.version.upper() in HTTP_VERSIONS:
      LogDebug('Invalid version: %s' % self.version)
      return False

    self.state = self.IN_HEADERS
    return True

  def ParseHeader(self, line):
    if line in ('', '\r', '\n', '\r\n'):
      self.state = self.IN_BODY
      return True

    header, value = line.split(':', 1)
    if value and value.startswith(' '): value = value[1:]

    self.headers.append((header.lower(), value))
    return True

  def ParseBody(self, line):
    # Could be overridden by subclasses, for now we just play dumb.
    return self.body_result

  def ParsedOK(self):
    return (self.state == self.IN_BODY)

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    try:
      if (self.state == self.IN_RESPONSE):
        return self.ParseResponse(line)

      elif (self.state == self.IN_REQUEST):
        return self.ParseRequest(line)

      elif (self.state == self.IN_HEADERS):
        return self.ParseHeader(line)

      elif (self.state == self.IN_BODY):
        return self.ParseBody(line)

    except ValueError, err:
      LogDebug('Parse failed: %s, %s, %s' % (self.state, err, self.lines))

    self.state = BaseLineParser.PARSE_FAILED
    return False

  def Header(self, header):
    return [h[1].strip() for h in self.headers if h[0] == header.lower()]


class FingerLineParser(BaseLineParser):
  """Parse an incoming Finger request, line-by-line."""

  PROTO = 'finger'
  PROTOS = ['finger', 'httpfinger']
  WANT_FINGER = 71

  def __init__(self, lines=None, state=WANT_FINGER):
    BaseLineParser.__init__(self, lines, state, self.PROTO)

  def ErrorReply(self, port=None):
    if port == 79:
      return ('PageKite wants to know, what domain?\n'
              'Try: finger user+domain@domain\n')
    else:
      return ''

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    if ' ' in line: return False
    if '+' in line:
      arg0, self.domain = line.strip().split('+', 1)
    elif '@' in line:
      arg0, self.domain = line.strip().split('@', 1)

    if self.domain:
      self.state = BaseLineParser.PARSE_OK
      self.lines[-1] = '%s\n' % arg0
      return True
    else:
      self.state = BaseLineParser.PARSE_FAILED
      return False


class IrcLineParser(BaseLineParser):
  """Parse an incoming IRC connection, line-by-line."""

  PROTO = 'irc'
  PROTOS = ['irc']
  WANT_USER = 61

  def __init__(self, lines=None, state=WANT_USER):
    self.seen = []
    BaseLineParser.__init__(self, lines, state, self.PROTO)

  def ErrorReply(self):
    return ':pagekite 451 :IRC Gateway requires user@HOST or nick@HOST\n'

  def Parse(self, line):
    BaseLineParser.Parse(self, line)
    if line in ('\n', '\r\n'): return True
    if self.state == IrcLineParser.WANT_USER:
      try:
        ocmd, arg = line.strip().split(' ', 1)
        cmd = ocmd.lower()
        self.seen.append(cmd)
        args = arg.split(' ')
        if cmd == 'pass':
          pass
        elif cmd in ('user', 'nick'):
          if '@' in args[0]:
            parts = args[0].split('@')
            self.domain = parts[-1]
            arg0 = '@'.join(parts[:-1])
          elif 'nick' in self.seen and 'user' in self.seen and not self.domain:
            raise Error('No domain found')

          if self.domain:
            self.state = BaseLineParser.PARSE_OK
            self.lines[-1] = '%s %s %s\n' % (ocmd, arg0, ' '.join(args[1:]))
        else:
          self.state = BaseLineParser.PARSE_FAILED
      except Exception, err:
        LogDebug('Parse failed: %s, %s, %s' % (self.state, err, self.lines))
        self.state = BaseLineParser.PARSE_FAILED

    return (self.state != BaseLineParser.PARSE_FAILED)
