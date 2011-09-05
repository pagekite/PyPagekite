import re, sys, time
import pagekite
from pagekite import NullUi

class BasicUi(NullUi):
  """Stdio based user interface."""

  WANTS_STDERR = True
  EMAIL_RE = re.compile(r'^[a-z0-9!#$%&\'\*\+\/=?^_`{|}~-]+'
                         '(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@'
                         '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*'
                         '(?:[a-zA-Z]{2,4}|museum)$')

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

      self.notify_history[message] = now
      msg = '\r%s %s%s%s%s%s\n' % ((prefix * 3)[0:3], color, message, self.NORM,
                                   ' ' * (75-len(message)-len(alignright)),
                                   alignright)
      self.wfile.write(msg)
      self.Status(self.status_tag, self.status_msg)

  def Status(self, tag, message=None, color=None):
    self.status_tag = tag
    self.status_col = color or self.status_col or self.NORM
    self.status_msg = '%s' % (message or self.status_msg)
    if not self.in_wizard:
      message = self.status_msg
      msg = ('\r << pagekite.py [%s]%s %s%s%s\r%s'
             ) % (tag, ' ' * (8-len(tag)),
                  self.status_col, message, ' ' * (52-len(message)), self.NORM)
      self.wfile.write(msg)
    if tag == 'exiting':
      self.wfile.write('\n')

  def Welcome(self, pre=None):
    if self.in_wizard:
      self.wfile.write('%s%s%s' % (self.CLEAR, self.WHITE, self.in_wizard))
    if self.welcome:
      self.wfile.write('%s\r%s\n' % (self.NORM, self.welcome))
      self.welcome = None
    if self.in_wizard and self.wizard_tell:
      self.wfile.write('\n%s\r' % self.NORM)
      for line in self.wizard_tell: self.wfile.write('*** %s\n' % line)
      self.wizard_tell = None
    if pre:
      self.wfile.write('\n%s\r' % self.NORM)
      for line in pre: self.wfile.write('    %s\n' % line)
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

  def EndWizard(self):
    if self.wizard_tell: self.Welcome()
    self.in_wizard = None
    if sys.platform in ('win32', 'os2', 'os2emx'):
      self.wfile.write('\n<<< press ENTER to continue >>>\n')
      self.rfile.readline()

  def Spacer(self):
    self.wfile.write('\n')

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    if welcome: self.Welcome(pre)
    while self.Retry():
      self.wfile.write(' => %s ' % (question, ))
      answer = self.rfile.readline().strip()
      if default and answer == '': return default
      if self.EMAIL_RE.match(answer): return answer
      if back is not None and answer == 'back': return back
    raise Exception('Too many tries')

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)

    def_email, def_pass = default or (email, None)
    self.wfile.write('    %s\n' % (question, ))

    if not email:
      email = self.AskEmail('Your e-mail:',
                            default=def_email, back=back, welcome=False)
      if email == back: return back

    import getpass
    self.wfile.write(' => ')
    return (email, getpass.getpass() or def_pass)

  def AskYesNo(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None):
    self.Welcome(pre)
    yn = ((default is True) and '[Y/n]'
          ) or ((default is False) and '[y/N]'
                ) or ('[y/n]')
    while self.Retry():
      self.wfile.write(' => %s %s ' % (question, yn))
      answer = self.rfile.readline().strip().lower()
      if default is not None and answer == '': answer = default and 'y' or 'n'
      if back is not None and answer.startswith('b'): return back
      if answer in ('y', 'n'): return (answer == 'y')
    raise Exception('Too many tries')

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
      self.wfile.write('\n => %s ' % question)
      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back':
        return back
      elif len(domains) == 1:
        answer = answer.replace(domains[0], '')
        if answer and pagekite.SERVICE_SUBDOMAIN_RE.match(answer):
          return answer+domains[0]
      else:
        for domain in domains:
          if answer.endswith(domain):
            answer = answer.replace(domain, '')
            if answer and pagekite.SERVICE_SUBDOMAIN_RE.match(answer):
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
      self.wfile.write(' => %s [1-%d%s] ' % (question, len(choices), d))
      try:
        answer = self.rfile.readline().strip()
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

