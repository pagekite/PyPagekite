"""
This is the "basic" text-mode user interface class.
"""
#############################################################################
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
#############################################################################
import re
import sys
import time

from nullui import NullUi
from pagekite.common import *


HTML_BR_RE = re.compile(r'<(br|/p|/li|/tr|/h\d)>\s*')
HTML_LI_RE = re.compile(r'<li>\s*')
HTML_NBSP_RE = re.compile(r'&nbsp;')
HTML_TAGS_RE = re.compile(r'<[^>\s][^>]*>')

def clean_html(text):
  return HTML_LI_RE.sub(' * ',
          HTML_NBSP_RE.sub('_',
           HTML_BR_RE.sub('\n', text)))

def Q(text):
  return HTML_TAGS_RE.sub('', clean_html(text))


class BasicUi(NullUi):
  """Stdio based user interface."""

  DAEMON_FRIENDLY = False
  WANTS_STDERR = True
  EMAIL_RE = re.compile(r'^[a-z0-9!#$%&\'\*\+\/=?^_`{|}~-]+'
                         '(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@'
                         '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*'
                         '(?:[a-zA-Z]{2,16})$')
  def Notify(self, message, prefix=' ',
             popup=False, color=None, now=None, alignright=''):
    now = int(now or time.time())
    color = color or self.NORM

    # We suppress duplicates that are either new or still on the screen.
    keys = self.notify_history.keys()
    if len(keys) > 20:
      for key in keys:
        if self.notify_history[key] < now-300:
          del self.notify_history[key]

    message = '%s' % message
    if message not in self.notify_history:

      # Display the time now and then.
      if (not alignright and
          (now >= (self.last_tick + 60)) and
          (len(message) < 68)):
        try:
          self.last_tick = now
          d = datetime.datetime.fromtimestamp(now)
          alignright = '[%2.2d:%2.2d]' % (d.hour, d.minute)
        except:
          pass # Fails on Python 2.2

      if not now or now > 0:
        self.notify_history[message] = now
      msg = '\r%s %s%s%s%s%s\n' % ((prefix * 3)[0:3], color, message, self.NORM,
                                   ' ' * (75-len(message)-len(alignright)),
                                   alignright)
      self.wfile.write(msg)
      self.Status(self.status_tag, self.status_msg)

  def NotifyMOTD(self, frontend, motd_message):
    lc = 1
    self.Notify('  ')
    for line in Q(motd_message).splitlines():
      self.Notify((line.strip() or ' ' * (lc+2)),
                  prefix=' ++', color=self.WHITE)
      lc += 1
    self.Notify(' ' * (lc+2), alignright='[MOTD from %s]' % frontend)
    self.Notify('   ')

  def Status(self, tag, message=None, color=None):
    self.status_tag = tag
    self.status_col = color or self.status_col or self.NORM
    self.status_msg = '%s' % (message or self.status_msg)
    if not self.in_wizard:
      message = self.status_msg
      msg = ('\r << pagekite.py [%s]%s %s%s%s\r%s'
             ) % (tag, ' ' * (8-len(tag)),
                  self.status_col, message[:52],
                  ' ' * (52-len(message)), self.NORM)
      self.wfile.write(msg)
    if tag == 'exiting':
      self.wfile.write('\n')

  def Welcome(self, pre=None):
    if self.in_wizard:
      self.wfile.write('%s%s%s' % (self.CLEAR, self.WHITE, self.in_wizard))
    if self.welcome:
      self.wfile.write('%s\r%s\n' % (self.NORM, Q(self.welcome)))
      self.welcome = None
    if self.in_wizard and self.wizard_tell:
      self.wfile.write('\n%s\r' % self.NORM)
      for line in self.wizard_tell: self.wfile.write('*** %s\n' % Q(line))
      self.wizard_tell = None
    if pre:
      self.wfile.write('\n%s\r' % self.NORM)
      for line in pre: self.wfile.write('    %s\n' % Q(line))
    self.wfile.write('\n%s\r' % self.NORM)

  def StartWizard(self, title):
    self.Welcome()
    banner = '>>> %s' %  title
    banner = ('%s%s[CTRL+C = Cancel]\n') % (banner, ' ' * (62-len(banner)))
    self.in_wizard = banner
    self.tries = 200

  def Retry(self):
    self.tries -= 1
    return self.tries

  def EndWizard(self, quietly=False):
    if self.wizard_tell:
      self.Welcome()
    self.in_wizard = None
    if sys.platform in ('win32', 'os2', 'os2emx') and not quietly:
      self.wfile.write('\n<<< press ENTER to continue >>>\n')
      self.rfile.readline()

  def Spacer(self):
    self.wfile.write('\n')

  def Readline(self):
    line = self.rfile.readline()
    if line:
      return line.strip()
    else:
      raise IOError('EOF')

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    if welcome: self.Welcome(pre)
    while self.Retry():
      self.wfile.write(' => %s ' % (Q(question), ))
      answer = self.Readline()
      if default and answer == '': return default
      if self.EMAIL_RE.match(answer.lower()): return answer
      if back is not None and answer == 'back': return back
    raise Exception('Too many tries')

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)

    def_email, def_pass = default or (email, None)
    self.wfile.write('    %s\n' % (Q(question), ))

    if not email:
      email = self.AskEmail('Your e-mail:',
                            default=def_email, back=back, welcome=False)
      if email == back: return back

    import getpass
    self.wfile.write(' => ')
    return (email, getpass.getpass() or def_pass)

  def AskYesNo(self, question, default=None, pre=[], yes='yes', no='no',
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    yn = ((default is True) and '[Y/n]'
          ) or ((default is False) and '[y/N]'
                ) or ('[y/n]')
    while self.Retry():
      self.wfile.write(' => %s %s ' % (Q(question), yn))
      answer = self.Readline().lower()
      if default is not None and answer == '': answer = default and 'y' or 'n'
      if back is not None and answer.startswith('b'): return back
      if answer in ('y', 'n'): return (answer == 'y')
    raise Exception('Too many tries')

  def AskQuestion(self, question, pre=[], default=None, prompt=' =>',
                  wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    self.wfile.write('%s %s ' % (prompt, Q(question)))
    return self.Readline()

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    if len(domains) == 1:
      self.wfile.write(('\n    (Note: the ending %s will be added for you.)'
                        ) % domains[0])
    else:
      self.wfile.write('\n    Please use one of the following domains:\n')
      for domain in domains:
        self.wfile.write('\n     *%s' % domain)
      self.wfile.write('\n')
    while self.Retry():
      self.wfile.write('\n => %s ' % Q(question))
      answer = self.Readline().lower()
      if back is not None and answer == 'back':
        return back
      elif len(domains) == 1:
        answer = answer.replace(domains[0], '')
        if answer and SERVICE_SUBDOMAIN_RE.match(answer):
          return answer+domains[0]
      else:
        for domain in domains:
          if answer.endswith(domain):
            answer = answer.replace(domain, '')
            if answer and SERVICE_SUBDOMAIN_RE.match(answer):
              return answer+domain
      self.wfile.write('    (Please only use characters A-Z, 0-9, - and _.)')
    raise Exception('Too many tries')

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    for i in range(0, len(choices)):
      self.wfile.write(('  %s %d) %s\n'
                        ) % ((default==i+1) and '*' or ' ', i+1, choices[i]))
    self.wfile.write('\n')
    while self.Retry():
      d = default and (', default=%d' % default) or ''
      self.wfile.write(' => %s [1-%d%s] ' % (Q(question), len(choices), d))
      try:
        answer = self.Readline().strip()
        if back is not None and answer.startswith('b'): return back
        choice = int(answer or default)
        if choice > 0 and choice <= len(choices): return choice
      except (ValueError, IndexError):
        pass
    raise Exception('Too many tries')

  def Tell(self, lines, error=False, back=None):
    if self.in_wizard:
      self.wizard_tell = lines
    else:
      self.Welcome()
      for line in lines: self.wfile.write('    %s\n' % line)
      if error: self.wfile.write('\n')
    return True

  def Working(self, message):
    if self.in_wizard:
      pending_messages = self.wizard_tell or []
      self.wizard_tell = pending_messages + [message+' ...']
      self.Welcome()
      self.wizard_tell = pending_messages + [message+' ... done.']
    else:
      self.Tell([message])
    return True
