"""
This is the pagekite.py built-in HTTP server.
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
import cgi
from cgi import escape as escape_html
import os
import re
import socket
import sys
import tempfile
import threading
import time
import traceback
import urllib

import SocketServer
from CGIHTTPServer import CGIHTTPRequestHandler
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import Cookie

from pagekite.common import *
from pagekite.compat import *
import pagekite.common as common
import pagekite.logging as logging
import pagekite.proto.selectables as selectables
import sockschain as socks


##[ Conditional imports & compatibility magic! ]###############################

try:
  import datetime
  ts_to_date = datetime.datetime.fromtimestamp
except ImportError:
  ts_to_date = str

try:
  sorted([1, 2, 3])
except:
  def sorted(l):
    tmp = l[:]
    tmp.sort()
    return tmp


# Different Python 2.x versions complain about deprecation depending on
# where we pull these from.
try:
  from urlparse import parse_qs, urlparse
except ImportError, e:
  from cgi import parse_qs
  from urlparse import urlparse
try:
  import hashlib
  def sha1hex(data):
    hl = hashlib.sha1()
    hl.update(data)
    return hl.hexdigest().lower()
except ImportError:
  import sha
  def sha1hex(data):
    return sha.new(data).hexdigest().lower()


##[ PageKite HTTPD code starts here! ]#########################################


class AuthError(Exception):
  pass


def fmt_size(count):
  if count > 2*(1024*1024*1024):
    return '%dGB' % (count / (1024*1024*1024))
  if count > 2*(1024*1024):
    return '%dMB' % (count / (1024*1024))
  if count > 2*(1024):
    return '%dKB' % (count / 1024)
  return '%dB' % count


class CGIWrapper(CGIHTTPRequestHandler):
  def __init__(self, request, path_cgi):
    self.path = path_cgi
    self.cgi_info = (os.path.dirname(path_cgi),
                     os.path.basename(path_cgi))
    self.request = request
    self.server = request.server
    self.command = request.command
    self.headers = request.headers
    self.client_address = ('unknown', 0)
    self.rfile = request.rfile
    self.wfile = tempfile.TemporaryFile()

  def translate_path(self, path): return path

  def send_response(self, code, message):
    self.wfile.write('X-Response-Code: %s\r\n' % code)
    self.wfile.write('X-Response-Message: %s\r\n' % message)

  def send_error(self, code, message):
    return self.send_response(code, message)

  def Run(self):
    self.run_cgi()
    self.wfile.seek(0)
    return self.wfile


class UiRequestHandler(SimpleXMLRPCRequestHandler):

  # Make all paths/endpoints legal, we interpret them below.
  rpc_paths = ( )

  E_PB = { 'code': 400, 'msg': 'Failed', 'mimetype': 'text/html',
           'title': 'PhotoBackup Error',
           'body': '<p>PhotoBackup Error</p>' }
  E401 = { 'code': '401', 'msg': 'Forbidden', 'mimetype': 'text/html',
           'title': '401 Forbidden',
           'body': '<p>Access Denied. Sorry!</p>' }
  E403 = { 'code': '403', 'msg': 'Forbidden', 'mimetype': 'text/html',
           'title': '403 Forbidden',
           'body': '<p>Access Denied. Sorry!</p>' }
  E404 = { 'code': '404', 'msg': 'Not found', 'mimetype': 'text/html',
           'title': '404 Not found',
           'body': '<p>File or directory not found. Sorry!</p>' }
  E500 = { 'code': '500', 'msg': 'Internal Error', 'mimetype': 'text/html',
           'title': '500 Internal Error',
           'body': '<p>Something is misconfigured or broken. Sorry!</p>' }
  ROBOTSTXT = { 'code': '200', 'msg': 'OK', 'mimetype': 'text/plain',
                'body': ('User-agent: *\n'
                         'Disallow: /\n'
                         '# pagekite.py default robots.txt\n') }

  MIME_TYPES = {
    '3gp': 'video/3gpp',            'aac': 'audio/aac',
    'atom': 'application/atom+xml', 'avi': 'video/avi',
    'bmp': 'image/bmp',             'bz2': 'application/x-bzip2',
    'c': 'text/plain',              'cpp': 'text/plain',
    'css': 'text/css',
    'conf': 'text/plain',           'cfg': 'text/plain',
    'dtd': 'application/xml-dtd',   'doc': 'application/msword',
    'gif': 'image/gif',             'gz': 'application/x-gzip',
    'h': 'text/plain',              'hpp': 'text/plain',
    'htm': 'text/html',             'html': 'text/html',
    'hqx': 'application/mac-binhex40',
    'java': 'text/plain',           'jar': 'application/java-archive',
    'jpg': 'image/jpeg',            'jpeg': 'image/jpeg',
    'js': 'application/javascript',
    'json': 'application/json',     'jsonp': 'application/javascript',
    'log': 'text/plain',
    'md': 'text/plain',            'midi': 'audio/x-midi',
    'mov': 'video/quicktime',      'mpeg': 'video/mpeg',
    'mp2': 'audio/mpeg',           'mp3': 'audio/mpeg',
    'm4v': 'video/mp4',            'mp4': 'video/mp4',
    'm4a': 'audio/mp4',
    'ogg': 'audio/vorbis',
    'pdf': 'application/pdf',      'ps': 'application/postscript',
    'pl': 'text/plain',            'png': 'image/png',
    'ppt': 'application/vnd.ms-powerpoint',
    'py': 'text/plain',            'pyw': 'text/plain',
    'pk-shtml': 'text/html',       'pk-js': 'application/javascript',
    'rc': 'text/plain',            'rtf': 'application/rtf',
    'rss': 'application/rss+xml',  'sgml': 'text/sgml',
    'sh': 'text/plain',            'shtml': 'text/plain',
    'svg': 'image/svg+xml',        'swf': 'application/x-shockwave-flash',
    'tar': 'application/x-tar',    'tgz': 'application/x-tar',
    'tiff': 'image/tiff',          'txt': 'text/plain',
    'wav': 'audio/wav',
    'xml': 'application/xml',      'xls': 'application/vnd.ms-excel',
    'xrdf': 'application/xrds+xml','zip': 'application/zip',
    'DEFAULT': 'application/octet-stream'
  }
  TEMPLATE_RAW = ('%(body)s')
  TEMPLATE_JSONP = ('window.pkData = %s;')
  TEMPLATE_HTML = ('<html><head>\n'
               '<link rel="stylesheet" media="screen, screen"'
                ' href="%(method)s://pagekite.net/css/pagekite.css"'
                ' type="text/css" title="Default stylesheet" />\n'
               '<title>%(title)s - %(prog)s v%(ver)s</title>\n'
              '</head><body>\n'
               '<h1>%(title)s</h1>\n'
               '<div id=body>%(body)s</div>\n'
               '<div id=footer><hr><i>Powered by <b>pagekite.py'
                ' v%(ver)s</b> and'
                ' <a href="'+ WWWHOME +'"><i>PageKite.net</i></a>.<br>'
                'Local time is %(now)s.</i></div>\n'
              '</body></html>\n')

  def setup(self):
    self.suppress_body = False
    if self.server.enable_ssl:
      self.connection = self.request
      self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
      self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)
    else:
      SimpleXMLRPCRequestHandler.setup(self)

  def log_message(self, format, *args):
    logging.Log([('uireq', format % args)])

  def send_header(self, header, value):
    self.wfile.write('%s: %s\r\n' % (header, value))

  def end_headers(self):
    self.wfile.write('\r\n')

  def sendStdHdrs(self, header_list=[], cachectrl='private',
                                        mimetype='text/html'):
    if mimetype.startswith('text/') and ';' not in mimetype:
      mimetype += ('; charset=%s' % DEFAULT_CHARSET)
    self.send_header('Cache-Control', cachectrl)
    self.send_header('Content-Type', mimetype)
    for header in header_list:
      self.send_header(header[0], header[1])
    self.end_headers()

  def sendChunk(self, chunk):
    if self.chunked:
      if logging.DEBUG_IO: print '<== SENDING CHUNK ===\n%s\n' % chunk
      self.wfile.write('%x\r\n' % len(chunk))
      self.wfile.write(chunk)
      self.wfile.write('\r\n')
    else:
      if logging.DEBUG_IO: print '<== SENDING ===\n%s\n' % chunk
      self.wfile.write(chunk)

  def sendEof(self):
    if self.chunked and not self.suppress_body: self.wfile.write('0\r\n\r\n')

  def sendResponse(self, message, code=200, msg='OK', mimetype='text/html',
                         header_list=[], chunked=False, length=None):
    self.log_request(code, message and len(message) or '-')
    self.wfile.write('HTTP/1.1 %s %s\r\n' % (code, msg))
    if code == 401:
      self.send_header('WWW-Authenticate',
                       'Basic realm=PK%d' % (time.time()/3600))

    self.chunked = chunked
    if chunked:
      self.send_header('Transfer-Encoding', 'chunked')
    else:
      if length:
        self.send_header('Content-Length', length)
      elif not chunked:
        self.send_header('Content-Length', len(message or ''))

    self.sendStdHdrs(header_list=header_list, mimetype=mimetype)
    if message and not self.suppress_body:
      self.sendChunk(message)

  def allowUploads(self, full_path):
    uploads = self.host_config.get('uploads', False)
    return (uploads and ((uploads is True) or re.match(uploads, full_path)))

  def needPassword(self):
    if self.server.pkite.ui_password: return True
    userkeys = [k for k in self.host_config.keys() if k.startswith('password/')]
    return userkeys

  def checkUsernamePasswordAuth(self, username, password):
    userkey = 'password/%s' % username
    if userkey in self.host_config:
      if self.host_config[userkey] == password:
        return

    if (self.server.pkite.ui_password and
        password == self.server.pkite.ui_password):
      return

    if self.needPassword():
      raise AuthError("Invalid password")

  def checkRequestAuth(self, scheme, netloc, path, qs):
    if self.needPassword():
      raise AuthError("checkRequestAuth not implemented")

  def checkPostAuth(self, scheme, netloc, path, qs, posted):
    if self.needPassword():
      raise AuthError("checkPostAuth not implemented")

  def performAuthChecks(self, scheme, netloc, path, qs):
    try:
      auth = self.headers.get('authorization')
      if auth:
        (how, ab64) = auth.strip().split()
        if how.lower() == 'basic':
          (username, password) = base64.decodestring(ab64).split(':')
          self.checkUsernamePasswordAuth(username, password)
          return True

      self.checkRequestAuth(scheme, netloc, path, qs)
      return True

    except (ValueError, KeyError, AuthError), e:
      logging.LogDebug('HTTP Auth failed: %s' % e)
    else:
      logging.LogDebug('HTTP Auth failed: Unauthorized')

    self.sendResponse('<h1>Unauthorized</h1>\n', code=401, msg='Forbidden')
    return False

  def performPostAuthChecks(self, scheme, netloc, path, qs, posted):
    try:
      self.checkPostAuth(scheme, netloc, path, qs, posted)
      return True
    except AuthError:
      self.sendResponse('<h1>Unauthorized</h1>\n', code=401, msg='Forbidden')
      return False

  def do_UNSUPPORTED(self):
    self.sendResponse('Unsupported request method.\n',
                      code=503, msg='Sorry', mimetype='text/plain')

  # Misc methods we don't support (yet)
  def do_OPTIONS(self): self.do_UNSUPPORTED()
  def do_DELETE(self): self.do_UNSUPPORTED()
  def do_PUT(self): self.do_UNSUPPORTED()

  def getHostInfo(self):
    http_host = self.headers.get('HOST', self.headers.get('host', 'unknown'))
    if http_host == 'unknown' or (http_host.startswith('localhost:') and
                http_host.replace(':', '/') not in self.server.pkite.be_config):
      http_host = None
      for bid in sorted(self.server.pkite.backends.keys()):
        be = self.server.pkite.backends[bid]
        if (be[BE_BPORT] == self.server.pkite.ui_sspec[1] and
            be[BE_STATUS] not in BE_INACTIVE):
          http_host = '%s:%s' % (be[BE_DOMAIN],
                                 be[BE_PORT] or 80)
    if not http_host:
      if self.server.pkite.be_config.keys():
        http_host = sorted(self.server.pkite.be_config.keys()
                           )[0].replace('/', ':')
      else:
        http_host = 'unknown'
    self.http_host = http_host
    self.host_config = self.server.pkite.be_config.get((':' in http_host
                                                           and http_host
                                                            or http_host+':80'
                                                        ).replace(':', '/'), {})

  def do_GET(self, command='GET'):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    qs = parse_qs(query)
    self.getHostInfo()
    self.post_data = None
    self.command = command
    if not self.performAuthChecks(scheme, netloc, path, qs): return
    try:
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, None)
    except socket.error:
      pass
    except Exception, e:
      logging.Log([('err', 'GET error at %s: %s' % (path, e))])
      if logging.DEBUG_IO: print '=== ERROR\n%s\n===' % format_exc()
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')

  def do_HEAD(self):
    self.suppress_body = True
    self.do_GET(command='HEAD')

  def do_POST(self, command='POST'):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    qs = parse_qs(query)
    self.getHostInfo()
    self.command = command

    if not self.performAuthChecks(scheme, netloc, path, qs): return

    posted = None
    self.post_data = tempfile.TemporaryFile()
    self.old_rfile = self.rfile
    try:
      # First, buffer the POST data to a file...
      clength = cleft = int(self.headers.get('content-length'))
      while cleft > 0:
        rbytes = min(64*1024, cleft)
        self.post_data.write(self.rfile.read(rbytes))
        cleft -= rbytes

      # Juggle things so the buffering is invisble.
      self.post_data.seek(0)
      self.rfile = self.post_data

      ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
      if ctype.lower() == 'multipart/form-data':
        self.post_data.seek(0)
        posted = cgi.FieldStorage(
          fp=self.post_data,
          headers=self.headers,
          environ={'REQUEST_METHOD': command, 'CONTENT_TYPE': ctype})
      elif ctype.lower() == 'application/x-www-form-urlencoded':
        if clength >= 50*1024*1024:
          raise Exception(("Refusing to parse giant posted query "
                           "string (%s bytes).") % clength)
        posted = cgi.parse_qs(self.rfile.read(clength), 1)
      elif self.host_config.get('xmlrpc', False):
        # We wrap the XMLRPC request handler in _BEGIN/_END in order to
        # expose the request environment to the RPC functions.
        RCI = self.server.RCI
        return RCI._END(SimpleXMLRPCRequestHandler.do_POST(RCI._BEGIN(self)))

      self.post_data.seek(0)
    except socket.error:
      pass
    except Exception, e:
      logging.Log([('err', 'POST error at %s: %s' % (path, e))])
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')
      self.rfile = self.old_rfile
      self.post_data = None
      return

    if not self.performPostAuthChecks(scheme, netloc, path, qs, posted): return
    try:
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, posted)
    except socket.error:
      pass
    except Exception, e:
      logging.Log([('err', 'Error handling POST at %s: %s' % (path, e))])
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')

    self.rfile = self.old_rfile
    self.post_data = None

  def openCGI(self, full_path, path, shtml_vars):
    cgi_file = CGIWrapper(self, full_path).Run()
    lines = cgi_file.read(32*1024).splitlines(True)
    if '\r\n' in lines: lines = lines[0:lines.index('\r\n')+1]
    elif '\n' in lines: lines = lines[0:lines.index('\n')+1]
    else: lines.append('')

    header_list = []
    response_code = 200
    response_message = 'OK'
    response_mimetype = 'text/html'
    for line in lines[:-1]:
      key, val = line.strip().split(': ', 1)
      if key == 'X-Response-Code':
        response_code = val
      elif key == 'X-Response-Message':
        response_message = val
      elif key.lower() == 'content-type':
        response_mimetype = val
      elif key.lower() == 'location':
        response_code = 302
        header_list.append((key, val))
      else:
        header_list.append((key, val))

    self.sendResponse(None, code=response_code,
                            msg=response_message,
                            mimetype=response_mimetype,
                            chunked=True, header_list=header_list)
    cgi_file.seek(sum([len(l) for l in lines]))
    return cgi_file

  def renderIndex(self, full_path, files=None):
    files = files or [(f, os.path.join(full_path, f))
                      for f in sorted(os.listdir(full_path))]

    # Remove dot-files and PageKite metadata files
    if self.host_config.get('indexes') != WEB_INDEX_ALL:
      files = [f for f in files if not (f[0].startswith('.') or
                                        f[0].startswith('_pagekite'))]

    fhtml = ['<table>']
    if files:
      for (fn, fpath) in files:
        fmimetype = self.getMimeType(fn)
        try:
          fsize = os.path.getsize(fpath) or ''
        except OSError:
          fsize = 0
        ops = [ ]
        if os.path.isdir(fpath):
          fclass = ['dir']
          if not fn.endswith('/'): fn += '/'
          qfn = urllib.quote(fn)
        else:
          qfn = urllib.quote(fn)
          fn = os.path.basename(fn)
          fclass = ['file']
          ops.append('download')
          if (fmimetype.startswith('text/') or
              (fmimetype == 'application/octet-stream' and fsize < 512000)):
            ops.append('view')
        (unused, ext) = os.path.splitext(fn)
        if ext:
          fclass.append(ext.replace('.', 'ext_'))
        fclass.append('mime_%s' % fmimetype.replace('/', '_'))

        ophtml = ', '.join([('<a class="%s" href="%s?%s=/%s">%s</a>'
                             ) % (op, qfn, op, qfn, op)
                            for op in sorted(ops)])
        try:
          mtime = full_path and int(os.path.getmtime(fpath) or time.time())
        except OSError:
          mtime = int(time.time())
        fhtml.append(('<tr class="%s">'
                       '<td class="ops">%s</td>'
                       '<td class="size">%s</td>'
                       '<td class="mtime">%s</td>'
                       '<td class="name"><a href="%s">%s</a></td>'
                      '</tr>'
                      ) % (' '.join(fclass), ophtml, fsize,
                           str(ts_to_date(mtime)), qfn,
                           fn.replace('<', '&lt;'),
                      ))
    else:
      fhtml.append('<tr><td><i>empty</i></td></tr>')
    fhtml.append('</table>')
    return ''.join(fhtml)

  def convertPaths(self, path):
    path = urllib.unquote(path)
    if path.find('..') >= 0: raise IOError("Evil")

    paths = self.server.pkite.ui_paths
    def_paths = paths.get('*', {})
    http_host = self.http_host
    if ':' not in http_host: http_host += ':80'
    host_paths = paths.get(http_host.replace(':', '/'), {})
    path_parts = path.split('/')
    path_rest = []
    full_path = ''
    root_path = ''
    while len(path_parts) > 0 and not full_path:
      pf = '/'.join(path_parts)
      pd = pf+'/'
      m = None
      if   pf in host_paths: m = host_paths[pf]
      elif pd in host_paths: m = host_paths[pd]
      elif pf in def_paths: m = def_paths[pf]
      elif pd in def_paths: m = def_paths[pd]
      if m:
        policy = m[0]
        root_path = m[1]
        full_path = os.path.join(root_path, *path_rest)
      else:
        path_rest.insert(0, path_parts.pop())

    return host_paths, full_path

  def handleFileUpload(self, path, uploaded,
                       data=None, shtml_vars=None, subdir=None):
    host_paths, full_path = self.convertPaths(path)
    if not (full_path
            and os.path.isdir(full_path)
            and (data or self.allowUploads(full_path))):
      return False

    try:
      if not isinstance(uploaded, list):
        uploaded = [uploaded]
      for upload in uploaded:
        fn = os.path.basename(
          hasattr(upload, 'filename') and upload.filename or 'file.dat')

        name_policy = self.host_config.get('ul_filenames', 'keep')
        if name_policy not in ('keep', 'overwrite'):
          ext = ('.' in fn and fn.split('.')[-1] or 'dat')
          fn = 'upload-%x.%s' % (time.time(), ext)

        if subdir:
          full_path = os.path.join(full_path, subdir)
          if not os.path.exists(full_path):
            os.mkdir(full_path)

        target = os.path.join(full_path, fn)
        count = 1
        while os.path.exists(target) and name_policy != 'overwrite':
          if '.' in fn:
            bn, ext = fn.rsplit('.', 1)
          else:
            bn, ext = fn, ''
          target = os.path.join(full_path, bn)
          target += '_%d' % count
          if ext: target += '.%s' % ext
          count += 1

        fd = open(target, 'wb')
        fd.write(data or upload.value)
        fd.close()

      return True
    except:
      return False

  def handlePhotoBackup(self, path, posted, shtml_vars=None):
    password = self.host_config.get('photobackup', False)
    host_paths, full_path = self.convertPaths('/')

    # This allows the user to store just the SHA512 in their PageKite
    # config file. Users with exactly 128 char passwords are screwed.
    if password and (len(password) != 128):
      password = hashlib.sha512(password).hexdigest()

    userpass = ('password' in posted and posted['password'])
    if isinstance(userpass, list):
      userpass = userpass[0]
    else:
      userpass = userpass.value

    if path == '/test':
      if not password:
        shtml_vars.update(self.E401)
      elif str(userpass) != password:
        shtml_vars.update(self.E403)
      elif not full_path or not os.path.isdir(full_path):
        shtml_vars.update(self.E500)
      else:
        self.sendResponse('OK', mimetype='text/plain')
        self.sendEof()
        return True

    elif path == '/':
      filesize = ('filesize' in posted and posted['filesize'].value)
      album = ('album' in posted and posted['album'].value)
      photo = ('upfile' in posted and posted['upfile'])
      photo_data = ((photo not in (None, False)) and photo.value or '')

      if album and (
          (':' in album) or
          ('/' in album) or
          ('\\' in album) or
          (album[:1] == '.')):
        raise ValueError('Illegal album name')

      shtml_vars.update(self.E_PB)
      if not filesize:
        shtml_vars['code'] = 400
      elif photo in (None, False):
        shtml_vars['code'] = 401
      elif str(userpass) != password:
        shtml_vars.update(self.E403)
      elif len(photo_data) != int(filesize):
        shtml_vars['code'] = 411
      elif self.handleFileUpload('/', photo,
                                 data=photo_data, subdir=album,
                                 shtml_vars=shtml_vars):
        self.sendResponse('OK', mimetype='text/plain')
        self.sendEof()
        return True
      else:
        shtml_vars['code'] = 500

    else:
      shtml_vars.update(self.E404)

    return False

  def sendStaticPath(self, path, mimetype, shtml_vars=None):
    is_shtml, is_cgi, is_dir = False, False, False
    index_list = None
    try:
      host_paths, full_path = self.convertPaths(path)

      if full_path:
        is_dir = os.path.isdir(full_path)
      else:
        if not self.host_config.get('indexes', False): return False
        if self.host_config.get('hide', False): return False

        # Generate pseudo-index
        ipath = path
        if not ipath.endswith('/'): ipath += '/'
        plen = len(ipath)
        index_list = [(p[plen:], host_paths[p][1]) for p
                                                   in sorted(host_paths.keys())
                                                   if p.startswith(ipath)]
        if not index_list: return False

        full_path = ''
        mimetype = 'text/html'
        is_dir = True

      if is_dir and not path.endswith('/'):
        self.sendResponse('\n', code=302, msg='Moved', header_list=[
                            ('Location', '%s/' % path)
                          ])
        return True

      indexes = ['index.html', 'index.htm', '_pagekite.html']

      dynamic_suffixes = []
      if self.host_config.get('pk-shtml'):
        indexes[0:0] = ['index.pk-shtml']
        dynamic_suffixes = ['.pk-shtml', '.pk-js']

      cgi_suffixes = []
      cgi_config = self.host_config.get('cgi', False)
      if cgi_config:
        if cgi_config == True: cgi_config = 'cgi'
        for suffix in cgi_config.split(','):
          indexes[0:0] = ['index.%s' % suffix]
          cgi_suffixes.append('.%s' % suffix)

      for index in indexes:
        ipath = os.path.join(full_path, index)
        if os.path.exists(ipath):
          mimetype = 'text/html'
          full_path = ipath
          is_dir = False
          break

      self.chunked = False
      rf_stat = rf_size = None
      if full_path:
        if is_dir:
          mimetype = 'text/html'
          rf_size = rf = None
          rf_stat = os.stat(full_path)
        else:
          for s in dynamic_suffixes:
            if full_path.endswith(s): is_shtml = True
          for s in cgi_suffixes:
            if full_path.endswith(s): is_cgi = True
          if not is_shtml and not is_cgi: shtml_vars = None
          rf = open(full_path, "rb")
          try:
            rf_stat = os.fstat(rf.fileno())
            rf_size = rf_stat.st_size
          except:
            self.chunked = True
    except (IOError, OSError), e:
      return False

    headers = [ ]
    if rf_stat and not (is_dir or is_shtml or is_cgi):
      # ETags for static content: we trust the file-system.
      etag = sha1hex(':'.join(['%s' % s for s in [full_path, rf_stat.st_mode,
                                   rf_stat.st_ino, rf_stat.st_dev,
                                   rf_stat.st_nlink, rf_stat.st_uid,
                                   rf_stat.st_gid, rf_stat.st_size,
                                   int(rf_stat.st_mtime),
                                   int(rf_stat.st_ctime)]]))[0:24]
      if etag == self.headers.get('if-none-match', None):
        rf.close()
        self.sendResponse('', code=304, msg='Not Modified', mimetype=mimetype)
        return True
      else:
        headers.append(('ETag', etag))

      # FIXME: Support ranges for resuming aborted transfers?

    if is_cgi:
      self.chunked = True
      rf = self.openCGI(full_path, path, shtml_vars)
    else:
      self.sendResponse(None, mimetype=mimetype,
                              length=rf_size,
                              chunked=self.chunked or (shtml_vars is not None),
                              header_list=headers)

    chunk_size = (is_shtml and 1024 or 16) * 1024
    if rf:
      while not self.suppress_body:
        data = rf.read(chunk_size)
        if data == "": break
        if is_shtml and shtml_vars:
          self.sendChunk(data % shtml_vars)
        else:
          self.sendChunk(data)
      rf.close()

    elif shtml_vars and not self.suppress_body:
      shtml_vars['title'] = '//%s%s' % (shtml_vars['http_host'], path)
      if self.host_config.get('indexes') in (True, WEB_INDEX_ON,
                                                   WEB_INDEX_ALL):
        shtml_vars['body'] = self.renderIndex(full_path, files=index_list)
      else:
        shtml_vars['body'] = ('<p><i>Directory listings disabled and</i> '
                              'index.html <i>not found.</i></p>')

      if is_dir and self.allowUploads(full_path):
        shtml_vars['body'] += (
          '<p><form method="POST" enctype="multipart/form-data">'
          '<input type="submit" value="Upload File">'
          '<input type="file" name="upload"></form></p>')

      self.sendChunk(self.TEMPLATE_HTML % shtml_vars)

    self.sendEof()
    return True

  def getMimeType(self, path):
    try:
      ext = path.split('.')[-1].lower()
    except IndexError:
      ext = 'DIRECTORY'

    if ext in self.MIME_TYPES: return self.MIME_TYPES[ext]
    return self.MIME_TYPES['DEFAULT']

  def add_kite(self, path, qs):
    if path.find(self.server.secret) == -1:
      return {'mimetype': 'text/plain', 'body': 'Invalid secret'}

    pass

  def handleHttpRequest(self, scheme, netloc, path, params, query, frag,
                              qs, posted):
    data = {
      'prog': self.server.pkite.progname,
      'mimetype': self.getMimeType(path),
      'hostname': socket.gethostname() or 'Your Computer',
      'http_host': self.http_host,
      'query_string': query,
      'code': 200,
      'body': '',
      'msg': 'OK',
      'now': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
      'ver': APPVER
    }
    for key in self.headers.keys():
      data['http_'+key.lower()] = self.headers.get(key)

    if 'download' in qs:
      data['mimetype'] = 'application/octet-stream'
      # Would be nice to set Content-Disposition too.
    elif 'view' in qs:
      data['mimetype'] = 'text/plain'

    data['method'] = data.get('http_x-pagekite-proto', 'http').lower()

    if 'http_cookie' in data:
      cookies = Cookie.SimpleCookie(data['http_cookie'])
    else:
      cookies = {}

    # Do we expose the built-in console?
    console = self.host_config.get('console', False)

    # Are we implementing the PhotoBackup protocol?
    photobackup = self.host_config.get('photobackup', False)

    if path == self.host_config.get('yamon', False):
      if common.gYamon:
        data['body'] = common.gYamon.render_vars_text(qs.get('view', [None])[0])
      else:
        data['body'] = ''

    elif console and path.startswith('/_pagekite/logout/'):
      parts = path.split('/')
      location = parts[3] or ('%s://%s/' % (data['method'], data['http_host']))
      self.sendResponse('\n', code=302, msg='Moved', header_list=[
                          ('Set-Cookie', 'pkite_token=; path=/'),
                          ('Location', location)
                        ])
      return

    elif console and path.startswith('/_pagekite/login/'):
      parts = path.split('/', 4)
      token = parts[3]
      location = parts[4] or ('%s://%s/_pagekite/' % (data['method'],
                                                      data['http_host']))
      if query: location += '?' + query
      if token == self.server.secret:
        self.sendResponse('\n', code=302, msg='Moved', header_list=[
                            ('Set-Cookie', 'pkite_token=%s; path=/' % token),
                            ('Location', location)
                          ])
        return
      else:
        logging.LogDebug("Invalid token, %s != %s" % (token,
                                                       self.server.secret))
        data.update(self.E404)

    elif console and path.startswith('/_pagekite/'):
      if not ('pkite_token' in cookies and cookies['pkite_token'].value == self.server.secret):
        self.sendResponse('<h1>Forbidden</h1>\n', code=403, msg='Forbidden')
        return

      if path == '/_pagekite/':
        if not self.sendStaticPath('%s/control.pk-shtml' % console, 'text/html',
                                   shtml_vars=data):
          self.sendResponse('<h1>Not found</h1>\n', code=404, msg='Missing')
        return
      elif path.startswith('/_pagekite/quitquitquit/'):
        self.sendResponse('<h1>Kaboom</h1>\n', code=500, msg='Asplode')
        self.wfile.flush()
        os._exit(2)
      elif path.startswith('/_pagekite/add_kite/'):
        data.update(self.add_kite(path, qs))
      elif path.endswith('/pagekite.rc'):
        data.update({'mimetype': 'application/octet-stream',
                     'body': '\n'.join(self.server.pkite.GenerateConfig())})
      elif path.endswith('/pagekite.rc.txt'):
        data.update({'mimetype': 'text/plain',
                     'body': '\n'.join(self.server.pkite.GenerateConfig())})
      elif path.endswith('/pagekite.cfg'):
        data.update({'mimetype': 'application/octet-stream',
                     'body': '\r\n'.join(self.server.pkite.GenerateConfig())})
      else:
        data.update(self.E403)
    else:
      if photobackup and (posted is not None) and (path in '/', '/test'):
        if self.handlePhotoBackup(path, posted, shtml_vars=data):
          return
      elif (posted is not None) and 'upload' in posted:
        if self.handleFileUpload(path, posted['upload'], shtml_vars=data):
          if self.sendStaticPath(path, data['mimetype'], shtml_vars=data):
            return
        else:
          data.update(self.E403)
      else:
        if self.sendStaticPath(path, data['mimetype'], shtml_vars=data):
          return
        if path == '/robots.txt':
          data.update(self.ROBOTSTXT)
        else:
          data.update(self.E404)

    if data['mimetype'] in ('application/octet-stream', 'text/plain'):
      response = self.TEMPLATE_RAW % data
    elif path.endswith('.jsonp'):
      response = self.TEMPLATE_JSONP % (data, )
    else:
      response = self.TEMPLATE_HTML % data

    self.sendResponse(response, msg=data['msg'],
                                code=data['code'],
                                mimetype=data['mimetype'],
                                chunked=False)
    self.sendEof()


class RemoteControlInterface(object):
  ACL_OPEN = ''
  ACL_READ = 'r'
  ACL_WRITE = 'w'

  def __init__(self, httpd, pkite, conns):
    self.httpd = httpd
    self.pkite = pkite
    self.conns = conns
    self.modified = False

    self.lock = threading.Lock()
    self.request = None

    # For now, nobody gets ACL_WRITE
    self.auth_tokens = {httpd.secret: self.ACL_READ}

    # Channels are in-memory logs which can be tailed over XML-RPC.
    # Javascript apps can create these for implementing chat etc.
    self.channels = {'LOG': {'access': self.ACL_READ,
                             'tokens': self.auth_tokens,
                             'data': logging.LOG}}

  def _BEGIN(self, request_object):
    self.lock.acquire()
    self.request = request_object
    return request_object

  def _END(self, rv=None):
    if self.request:
      self.request = None
      self.lock.release()
    return rv

  def connections(self, auth_token):
    if (not self.request.host_config.get('console', False) or
        self.ACL_READ not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')

    return [{'sid': c.sid,
             'dead': c.dead,
             'html': c.__html__()} for c in self.conns.conns]

  def add_kite(self, auth_token, kite_domain, kite_proto):
    if (not self.request.host_config.get('console', False) or
        self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')
    pass

  def get_kites(self, auth_token):
    if (not self.request.host_config.get('console', False) or
        self.ACL_READ not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')

    kites = []
    for bid in self.pkite.backends:
      proto, domain = bid.split(':')
      fe_proto = proto.split('-')
      kite_info = {
        'id': bid,
        'domain': domain,
        'fe_proto': fe_proto[0],
        'fe_port': (len(fe_proto) > 1) and fe_proto[1] or '',
        'fe_secret': self.pkite.backends[bid][BE_SECRET],
        'be_proto': self.pkite.backends[bid][BE_PROTO],
        'backend': self.pkite.backends[bid][BE_BACKEND],
        'fe_list': [{'name': fe.server_name,
                     'tls': fe.using_tls,
                     'sid': fe.sid} for fe in self.conns.Tunnel(proto, domain)]
      }
      kites.append(kite_info)
    return kites

  def add_kite(self, auth_token,
               proto,
               fe_port, fe_domain,
               be_port, be_domain,
               shared_secret):
    if (not self.request.host_config.get('console', False) or
        self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')
    # FIXME

  def remove_kite(self, auth_token, kite_id):
    if (not self.request.host_config.get('console', False) or
        self.ACL_WRITE not in self.auth_tokens.get(auth_token, self.ACL_OPEN)):
      raise AuthError('Unauthorized')

    if kite_id in self.pkite.backends:
      del self.pkite.backends[kite_id]
      logging.Log([('reconfigured', '1'), ('removed', kite_id)])
      self.modified = True
    return self.get_kites(auth_token)

  def mk_channel(self, auth_token, channel):
    if not self.request.host_config.get('channels', False):
      raise AuthError('Unauthorized')

    chid = '%s/%s' % (self.request.http_host, channel)
    if chid in self.channels:
      raise Error('Exists')
    else:
      self.channels[chid] = {'access': self.ACL_WRITE,
                             'tokens': {auth_token: self.ACL_WRITE},
                             'data': []}
      return self.append_channel(auth_token, channel, {'created': channel})

  def get_channel(self, auth_token, channel):
    if not self.request.host_config.get('channels', False):
      raise AuthError('Unauthorized')

    chan = self.channels.get('%s/%s' % (self.request.http_host, channel),
                             self.channels.get(channel, {}))
    req = chan.get('access', self.ACL_WRITE)
    if req not in chan.get('tokens', self.auth_tokens).get(auth_token,
                                                           self.ACL_OPEN):
      raise AuthError('Unauthorized')

    return chan.get('data', [])

  def append_channel(self, auth_token, channel, values):
    data = self.get_channel(auth_token, channel)
    global LOG_LINE
    values.update({'ts': '%x' % time.time(), 'll': '%x' % LOG_LINE})
    LOG_LINE += 1
    data.append(values)
    return values

  def get_channel_after(self, auth_token, channel, last_seen, timeout):
    data = self.get_channel(auth_token, channel)
    last_seen = int(last_seen, 16)

    # line at the remote end, then we've restarted and should send everything.
    if (last_seen == 0) or (LOG_LINE < last_seen): return data
    # FIXME: LOG_LINE global for all channels?  Is that suck?

    # We are about to get sleepy, so release our environment lock.
    self._END()

    # If our internal LOG_LINE counter is less than the count of the last seen
    # Else, wait at least one second, AND wait for a new line to be added to
    # the log (or the timeout to expire).
    time.sleep(1)
    last_ll = data[-1]['ll']
    while (timeout > 0) and (data[-1]['ll'] == last_ll):
      time.sleep(1)
      timeout -= 1

    # Return everything the client hasn't already seen.
    return [ll for ll in data if int(ll['ll'], 16) > last_seen]


class UiHttpServer(SocketServer.ThreadingMixIn, SimpleXMLRPCServer):
  def __init__(self, sspec, pkite, conns,
               handler=UiRequestHandler,
               ssl_pem_filename=None):
    SimpleXMLRPCServer.__init__(self, sspec, handler)
    self.pkite = pkite
    self.conns = conns
    self.secret = pkite.ConfigSecret()

    self.server_name = sspec[0]
    self.server_port = sspec[1]

    if ssl_pem_filename:
      ctx = socks.SSL.Context(socks.SSL.TLSv1_METHOD)
      ctx.set_cipher_list('HIGH:!MEDIUM:!LOW:!aNULL:!NULL:!SHA')
      ctx.use_privatekey_file (ssl_pem_filename)
      ctx.use_certificate_chain_file(ssl_pem_filename)
      self.socket = socks.SSL_Connect(ctx, socket.socket(self.address_family,
                                                         self.socket_type),
                                      server_side=True)
      self.server_bind()
      self.server_activate()
      self.enable_ssl = True
    else:
      self.enable_ssl = False

    try:
      from pagekite import yamond
      gYamon = common.gYamon = yamond.YamonD(sspec)
      gYamon.vset('started', int(time.time()))
      gYamon.vset('version', APPVER)
      gYamon.vset('httpd_ssl_enabled', self.enable_ssl)
      gYamon.vset('errors', 0)
      gYamon.lcreate("tunnel_rtt", 100)
      gYamon.lcreate("tunnel_wrtt", 100)
      gYamon.lists['buffered_bytes'] = [1, 0, common.buffered_bytes]
      gYamon.views['selectables'] = (selectables.SELECTABLES, {
        'idle': [0, 0, self.conns.idle],
        'conns': [0, 0, self.conns.conns]
      })
    except:
      pass

    self.RCI = RemoteControlInterface(self, pkite, conns)
    self.register_introspection_functions()
    self.register_instance(self.RCI)

  def finish_request(self, request, client_address):
    try:
      SimpleXMLRPCServer.finish_request(self, request, client_address)
    except (socket.error, socks.SSL.ZeroReturnError, socks.SSL.Error):
      pass

  def shutdown_request(self, *args):
    try:
      return SimpleXMLRPCServer.shutdown_request(self, *args)
    except TypeError:
      return SimpleXMLRPCServer.close_request(self, *args)
