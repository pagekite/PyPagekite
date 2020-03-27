"""
This is a basic "Null" user interface which does nothing at all.
"""
##############################################################################

from __future__ import absolute_import
from __future__ import division

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
import sys

from pagekite.compat import *
from pagekite.common import *
import pagekite.logging as logging

class NullUi(object):
  """This is a UI that always returns default values or raises errors."""

  DAEMON_FRIENDLY = True
  ALLOWS_INPUT = False
  WANTS_STDERR = False
  REJECTED_REASONS = {
    'quota': 'You are out of quota',
    'nodays': 'Your subscription has expired',
    'noquota': 'You are out of quota',
    'noconns': 'You are flying too many kites',
    'unauthorized': 'Invalid account or shared secret'
  }

  def __init__(self, welcome=None, wfile=sys.stderr, rfile=sys.stdin):
    if sys.platform[:3] in ('win', 'os2'):
      self.CLEAR = '\n\n%s\n\n' % ('=' * 79)
      self.NORM = self.WHITE = self.GREY = self.GREEN = self.YELLOW = ''
      self.BLUE = self.RED = self.MAGENTA = self.CYAN = ''
    else:
      self.CLEAR = '\033[H\033[J'
      self.NORM = '\033[0m'
      self.WHITE = '\033[1m'
      self.GREY =  '\033[0m' #'\033[30;1m'
      self.RED = '\033[31;1m'
      self.GREEN = '\033[32;1m'
      self.YELLOW = '\033[33;1m'
      self.BLUE = '\033[34;1m'
      self.MAGENTA = '\033[35;1m'
      self.CYAN = '\033[36;1m'

    self.wfile = wfile
    self.rfile = rfile
    self.welcome = welcome
    if hasattr(self.wfile, 'buffer'):
        self.wfile = self.wfile.buffer

    self.Reset()
    self.Splash()

  def write(self, data):
    self.wfile.write(b(data))
    self.wfile.flush()

  def Reset(self):
    self.in_wizard = False
    self.wizard_tell = None
    self.last_tick = 0
    self.notify_history = {}
    self.status_tag = ''
    self.status_col = self.NORM
    self.status_msg = ''
    self.tries = 200
    self.server_info = None

  def Splash(self): pass

  def Welcome(self): pass
  def StartWizard(self, title): pass
  def EndWizard(self, quietly=False): pass
  def Spacer(self): pass

  def Browse(self, url):
    import webbrowser
    self.Tell(['Opening %s in your browser...' % url])
    webbrowser.open(url)

  def DefaultOrFail(self, question, default):
    if default is not None: return default
    raise ConfigError('Unanswerable question: %s' % question)

  def AskLogin(self, question, default=None, email=None,
               wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskEmail(self, question, default=None, pre=None,
               wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskYesNo(self, question, default=None, pre=None, yes='Yes', no='No',
               wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskQuestion(self, question, pre=[], default=None, prompt=None,
                  wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def AskBackends(self, kitename, protos, ports, rawports, question, pre=[],
                  default=None, wizard_hint=False, image=None, back=None):
    return self.DefaultOrFail(question, default)

  def Working(self, message): pass

  def Tell(self, lines, error=False, back=None):
    if error:
      logging.LogError(' '.join(lines))
      raise ConfigError(' '.join(lines))
    else:
      logging.Log([('message', ' '.join(lines))])
      return True

  def Notify(self, message, prefix=' ',
             popup=False, color=None, now=None, alignright=''):
    if popup: logging.Log([('info', '%s%s%s' % (message,
                                        alignright and ' ' or '',
                                        alignright))])

  def NotifyMOTD(self, frontend, message):
    pass

  def NotifyKiteRejected(self, proto, domain, reason, crit=False):
    if reason in self.REJECTED_REASONS:
      reason = self.REJECTED_REASONS[reason]
    self.Notify('REJECTED: %s:%s (%s)' % (proto, domain, reason),
                prefix='!', color=(crit and self.RED or self.YELLOW))

  def NotifyList(self, prefix, items, color):
    items = items[:]
    while items:
      show = []
      while items and len(prefix) + len(' '.join(show)) < 65:
        show.append(items.pop(0))
      self.Notify(' - %s: %s' % (prefix, ' '.join(show)), color=color)

  def NotifyServer(self, obj, server_info):
    self.server_info = server_info
    self.Notify(
      'Connecting to front-end relay %s ...' % server_info[obj.S_NAME],
      color=self.GREY)
    self.Notify(
      ' - Relay supports %d protocols on %d public ports.'
        % (len(server_info[obj.S_PROTOS]), len(server_info[obj.S_PORTS])),
      color=self.GREY)
    if 'raw' in server_info[obj.S_PROTOS]:
      self.Notify(
        ' - Raw TCP/IP (HTTP proxied) kites are available.',
        color=self.GREY)
    self.Notify(
      ' - To enable more logging, add option: --logfile=/path/to/logfile',
      color=self.GREY)

  def NotifyQuota(self, quota, q_days, q_conns):
    q, qMB = [], float(quota) / 1024  # Float division
    if qMB < 1024:
      q.append('%.2f MB' % qMB)
    if q_days is not None and q_days < 400:
      q.append('%d days' % q_days)
    if q_conns is not None and q_conns < 10:
      q.append('%s tunnels' % q_conns)
    if not q:
      q = ['plenty of time and bandwidth']
    self.Notify('Quota: You have %s left.' % ', '.join(q),
                prefix=(int(quota) < qMB) and '!' or ' ',
                color=self.MAGENTA)

  def NotifyIPsPerSec(self, ips, secs):
    self.Notify(
      'Abuse/DDOS protection: Relaying traffic for up to %d clients per %ds.'
         % (ips, secs),
      prefix=' ',
      color=self.MAGENTA)

  def NotifyFlyingFE(self, proto, port, domain, be=None):
    self.Notify(('Flying: %s://%s%s/'
                 ) % (proto, domain, port and ':'+port or ''),
                prefix='~<>', color=self.CYAN)

  def StartListingBackEnds(self): pass
  def EndListingBackEnds(self): pass

  def NotifyBE(self, bid, be, has_ssl, dpaths,
                     is_builtin=False, fingerprint=None):
    domain, port, proto = be[BE_DOMAIN], be[BE_PORT], be[BE_PROTO]
    prox = (proto == 'raw') and ' (HTTP proxied)' or ''
    if proto == 'raw' and port in ('22', 22): proto = 'ssh'
    if has_ssl and proto == 'http':
      proto = 'https'
    url = '%s://%s%s' % (proto, domain, port and (':%s' % port) or '')

    if be[BE_STATUS] == BE_STATUS_UNKNOWN: return
    if be[BE_STATUS] & BE_STATUS_OK:
      if be[BE_STATUS] & BE_STATUS_ERR_ANY:
        status = 'Trying'
        color = self.YELLOW
        prefix = '   '
      else:
        status = 'Flying'
        color = self.CYAN
        prefix = '~<>'
    else:
      return

    if is_builtin:
      backend = 'builtin HTTPD'
    else:
      backend = '%s:%s' % (be[BE_BHOST], be[BE_BPORT])

    self.Notify(('%s %s as %s/%s'
                 ) % (status, backend, url, prox),
                prefix=prefix, color=color)

    if status == 'Flying':
      for dp in sorted(dpaths.keys()):
        self.Notify(' - %s%s' % (url, dp), color=self.BLUE)
      if fingerprint and proto.startswith('https'):
        self.Notify(' - Fingerprint=%s' % fingerprint,
                    color=self.WHITE)
        self.Notify(('   IMPORTANT: For maximum security, use a secure channel'
                     ' to inform your'),
                    color=self.YELLOW)
        self.Notify('   guests what fingerprint to expect.',
                    color=self.YELLOW)

  def Status(self, tag, message=None, color=None): pass

  def ExplainError(self, error, title, subject=None):
    if error == 'pleaselogin':
      self.Tell([title, '', 'You already have an account. Log in to continue.'
                 ], error=True)
    elif error == 'email':
      self.Tell([title, '', 'Invalid e-mail address. Please try again?'
                 ], error=True)
    elif error == 'honey':
      self.Tell([title, '', 'Hmm. Somehow, you triggered the spam-filter.'
                 ], error=True)
    elif error in ('domaintaken', 'domain', 'subdomain'):
      self.Tell([title, '',
                 'Sorry, that domain (%s) is unavailable.' % subject,
                 '',
                 'If you registered it already, perhaps you need to log on with',
                 'a different e-mail address?',
                 ''
                 ], error=True)
    elif error == 'checkfailed':
      self.Tell([title, '',
                 'That domain (%s) is not correctly set up.' % subject
                 ], error=True)
    elif error == 'network':
      self.Tell([title, '',
                 'There was a problem communicating with %s.' % subject, '',
                 'Please verify that you have a working'
                 ' Internet connection and try again!'
                 ], error=True)
    else:
      self.Tell([title, 'Error code: %s' % error, 'Try again later?'
                 ], error=True)

