"""
This is a user interface class which communicates over a pipe or socket.
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
import re
import sys
import time
import threading

from pagekite.compat import *
from pagekite.common import *
from pagekite.proto.conns import Tunnel

from nullui import NullUi

class RemoteUi(NullUi):
  """Stdio based user interface for interacting with other processes."""

  DAEMON_FRIENDLY = True
  ALLOWS_INPUT = True
  WANTS_STDERR = True
  EMAIL_RE = re.compile(r'^[a-z0-9!#$%&\'\*\+\/=?^_`{|}~-]+'
                         '(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@'
                         '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*'
                         '(?:[a-zA-Z]{2,4}|museum)$')

  def __init__(self, welcome=None, wfile=sys.stderr, rfile=sys.stdin):
    NullUi.__init__(self, welcome=welcome, wfile=wfile, rfile=rfile)
    self.CLEAR = ''
    self.NORM = self.WHITE = self.GREY = self.GREEN = self.YELLOW = ''
    self.BLUE = self.RED = self.MAGENTA = self.CYAN = ''

  def StartListingBackEnds(self):
    self.wfile.write('begin_be_list\n')

  def EndListingBackEnds(self):
    self.wfile.write('end_be_list\n')

  def NotifyBE(self, bid, be, has_ssl, dpaths,
               is_builtin=False, fingerprint=None, now=None):
    domain = be[BE_DOMAIN]
    port = be[BE_PORT]
    proto = be[BE_PROTO]
    prox = (proto == 'raw') and ' (HTTP proxied)' or ''
    if proto == 'raw' and port in ('22', 22): proto = 'ssh'
    url = '%s://%s%s' % (proto, domain, port and (':%s' % port) or '')

    message = (' be_status:'
               ' status=%x; bid=%s; domain=%s; port=%s; proto=%s;'
               ' bhost=%s; bport=%s%s%s%s'
               '\n') % (be[BE_STATUS], bid, domain, port, proto,
                        be[BE_BHOST], be[BE_BPORT],
                        has_ssl and '; ssl=1' or '',
                        is_builtin and '; builtin=1' or '',
                        fingerprint and ('; fingerprint=%s' % fingerprint) or '')
    self.wfile.write(message)

    for path in dpaths:
      message = (' be_path: domain=%s; port=%s; path=%s; policy=%s; src=%s\n'
                 ) % (domain, port or 80, path,
                      dpaths[path][0], dpaths[path][1])
      self.wfile.write(message)

  def Notify(self, message, prefix=' ',
             popup=False, color=None, now=None, alignright=''):
    message = '%s' % message
    self.wfile.write('notify: %s\n' % message)

  def NotifyMOTD(self, frontend, message):
    self.wfile.write('motd: %s %s\n' % (frontend,
                                        message.replace('\n', '  ')))

  def Status(self, tag, message=None, color=None):
    self.status_tag = tag
    self.status_msg = '%s' % (message or self.status_msg)
    if message:
      self.wfile.write('status_msg: %s\n' % message)
    if tag:
      self.wfile.write('status_tag: %s\n' % tag)

  def Welcome(self, pre=None):
    self.wfile.write('welcome: %s\n' % (pre or '').replace('\n', '  '))

  def StartWizard(self, title):
    self.wfile.write('start_wizard: %s\n' % title)

  def Retry(self):
    self.tries -= 1
    if self.tries < 0:
      raise Exception('Too many tries')
    return self.tries

  def EndWizard(self, quietly=False):
    self.wfile.write('end_wizard: %s\n' % (quietly and 'quietly' or 'done'))

  def Spacer(self):
    pass

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    while self.Retry():
      self.wfile.write('begin_ask_email\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % '\n'.join(pre).replace('\n', '  '))
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', '  '))
      self.wfile.write(' expect: email\n')
      self.wfile.write('end_ask_email\n')

      answer = self.rfile.readline().strip()
      if self.EMAIL_RE.match(answer): return answer
      if back is not None and answer == 'back': return back

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_login\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % '\n'.join(pre).replace('\n', '  '))
      if email:
        self.wfile.write(' default: %s\n' % email)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', '  '))
      self.wfile.write(' expect: email\n')
      self.wfile.write(' expect: password\n')
      self.wfile.write('end_ask_login\n')

      answer_email = self.rfile.readline().strip()
      if back is not None and answer_email == 'back': return back

      answer_pass = self.rfile.readline().strip()
      if back is not None and answer_pass == 'back': return back

      if self.EMAIL_RE.match(answer_email) and answer_pass:
        return (answer_email, answer_pass)

  def AskYesNo(self, question, default=None, pre=[], yes='Yes', no='No',
               wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_yesno\n')
      if yes:
        self.wfile.write(' yes: %s\n' % yes)
      if no:
        self.wfile.write(' no: %s\n' % no)
      if pre:
        self.wfile.write(' preamble: %s\n' % '\n'.join(pre).replace('\n', '  '))
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', '  '))
      self.wfile.write(' expect: yesno\n')
      self.wfile.write('end_ask_yesno\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer in ('y', 'n'): return (answer == 'y')
      if answer == str(default).lower(): return default

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_kitename\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % '\n'.join(pre).replace('\n', '  '))
      for domain in domains:
        self.wfile.write(' domain: %s\n' % domain)
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', '  '))
      self.wfile.write(' expect: kitename\n')
      self.wfile.write('end_ask_kitename\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer:
        for d in domains:
          if answer.endswith(d) or answer.endswith(d): return answer
        return answer+domains[0]

  def AskBackends(self, kitename, protos, ports, rawports, question, pre=[],
                  default=None, wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_backends\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % '\n'.join(pre).replace('\n', '  '))
      count = 0
      if self.server_info:
        protos = self.server_info[Tunnel.S_PROTOS]
        ports = self.server_info[Tunnel.S_PORTS]
        rawports = self.server_info[Tunnel.S_RAW_PORTS]
      self.wfile.write(' kitename: %s\n' % kitename)
      self.wfile.write(' protos: %s\n' % ', '.join(protos))
      self.wfile.write(' ports: %s\n' % ', '.join(ports))
      self.wfile.write(' rawports: %s\n' % ', '.join(rawports))
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', '  '))
      self.wfile.write(' expect: backends\n')
      self.wfile.write('end_ask_backends\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      return answer

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_multiplechoice\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % '\n'.join(pre).replace('\n', '  '))
      count = 0
      for choice in choices:
        count += 1
        self.wfile.write(' choice_%d: %s\n' % (count, choice))
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', '  '))
      self.wfile.write(' expect: choice_index\n')
      self.wfile.write('end_ask_multiplechoice\n')

      answer = self.rfile.readline().strip().lower()
      try:
        ch = int(answer)
        if ch > 0 and ch <= len(choices): return ch
      except:
        pass
      if back is not None and answer == 'back': return back

  def Tell(self, lines, error=False, back=None):
    dialog = error and 'error' or 'message'
    self.wfile.write('tell_%s: %s\n' % (dialog, '  '.join(lines)))

  def Working(self, message):
    self.wfile.write('working: %s\n' % message)


class PageKiteThread(threading.Thread):
  def __init__(self, startup_args=None, debug=False):
    threading.Thread.__init__(self)
    self.pk = None
    self.pk_readlock = threading.Condition()
    self.gui_readlock = threading.Condition()
    self.debug = debug
    self.reset()

  def reset(self):
    self.pk_incoming = []
    self.pk_eof = False
    self.gui_incoming = ''
    self.gui_eof = False

  # These routines are used by the PageKite UI, to communicate with us...
  def readline(self):
    try:
      self.pk_readlock.acquire()
      while (not self.pk_incoming) and (not self.pk_eof): self.pk_readlock.wait()
      if self.pk_incoming:
        line = self.pk_incoming.pop(0)
      else:
        line = ''
      if self.debug:
        print '>>PK>> %s' % line.strip()
      return line
    finally:
      self.pk_readlock.release()

  def write(self, data):
    if self.debug:
      print '>>GUI>> %s' % data.strip()
    try:
      self.gui_readlock.acquire()
      if data:
        self.gui_incoming += data
      else:
        self.gui_eof = True
      self.gui_readlock.notify()
    finally:
      self.gui_readlock.release()

  # And these are used by the GUI, to communicate with PageKite.
  def recv(self, bytecount):
    try:
      self.gui_readlock.acquire()
      while (len(self.gui_incoming) < bytecount) and (not self.gui_eof):
        self.gui_readlock.wait()
      data = self.gui_incoming[0:bytecount]
      self.gui_incoming = self.gui_incoming[bytecount:]
      return data
    finally:
      self.gui_readlock.release()

  def send(self, data):
    if not data.endswith('\n') and data != '':
      raise ValueError('Please always send whole lines')
    if self.debug:
      print '<<PK<< %s' % data.strip()
    try:
      self.pk_readlock.acquire()
      if data:
        self.pk_incoming.append(data)
      else:
        self.pk_eof = True
      self.pk_readlock.notify()
    finally:
      self.pk_readlock.release()

  def sendall(self, data):
    return self.send(data)

  def close(self):
    self.send('')
    self.write('')

  def setup_comms(self, pkobj):
    self.pk = pkobj
    pkobj.ui_wfile = pkobj.ui.wfile = self
    pkobj.ui_rfile = pkobj.ui.rfile = self

  def run(self):
    raise Exception('Unimplemented')


class PageKiteRestarter(PageKiteThread):

  def __init__(self, startup_args=None):
    PageKiteThread.__init__(self)
    self.pk_startup_args = startup_args
    self.looping = False
    self.stopped = True

  def config_wrapper(self, pkobj):
    old_argv = sys.argv[:]

    # Remove invalid arguments that break us.
    for evil in ('--nullui', '--basicui', '--friendly'):
      if evil in sys.argv:
        sys.argv.remove(evil)

    if self.pk_startup_args:
      sys.argv[1:1] = self.pk_startup_args[:]
      self.pk_startup_args = None
    try:
      try:
        self.setup_comms(pkobj)
        return self.configure(pkobj)
      except:
        self.pk = None
        raise
    finally:
      sys.argv = old_argv[:]

  def run(self):
    self.looping = True
    while self.looping:
      last_loop = int(time.time())
      if not self.stopped:
        self.reset()
        self.startup()
        self.close()
        self.write('status_msg: Disabled\nstatus_tag: idle\n')
        self.pk = None
      if last_loop == int(time.time()):
        time.sleep(1)

  def startup(self):
    raise Exception('Unimplemented')

  def postpone(self, func, argument):
    return func(argument)

  def stop(self, then=False):
    self.stopped = True
    if self.pk:
      self.send('exit: stopping\n')
      self.postpone(self.stop, then)
    else:
      if then:
        then()

  def restart(self):
    self.stopped = False

  def toggle(self):
    if self.stopped:
      self.restart()
    else:
      self.stop()

  def quit(self):
    self.looping = False
    self.stopped = True
    if self.pk:
      self.send('exit: quitting\n')
    self.close()
    self.pk = None
    self.join()


class CommThread(threading.Thread):
  def __init__(self, pkThread):
    threading.Thread.__init__(self)
    self.pkThread = pkThread
    self.looping = False

    self.multi = None
    self.multi_args = None

    # Callbacks
    self.cb = {}

  def call_cb(self, which, args):
    return self.cb[which](args)

  def parse_line(self, line):
#   print '<< %s' % line[:-1]
    if line.startswith('begin_'):
      self.multi = line[6:].strip()
      self.multi_args = {'_raw': []}
    elif self.multi:
      if line.startswith('end_'):
        if self.multi in self.cb:
          self.call_cb(self.multi, self.multi_args)
        elif 'default' in self.multi_args:
          self.pkThread.send(self.multi_args['default']+'\n')
        self.multi = self.multi_args = None
      else:
        self.multi_args['_raw'].append(line.strip())
        try:
          variable, value = line.strip().split(': ', 1)
          self.multi_args[variable] = value
        except ValueError:
          pass
    else:
      try:
        command, args = line.strip().split(': ', 1)
        if command in self.cb:
          self.call_cb(command, args)
      except ValueError:
        pass

  def run(self):
    self.pkThread.start()
    self.looping = True
    line = ''
    while self.looping:
      line += self.pkThread.recv(1)
      if line.endswith('\n'):
        self.parse_line(line)
        line = ''

  def quit(self):
    self.pkThread.quit()
    self.looping = False
