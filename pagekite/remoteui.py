import re, time
from pagekite import NullUi

class RemoteUi(NullUi):
  """Stdio based user interface for interacting with other processes."""

  WANTS_STDERR = True
  EMAIL_RE = re.compile(r'^[a-z0-9!#$%&\'\*\+\/=?^_`{|}~-]+'
                         '(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@'
                         '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*'
                         '(?:[a-zA-Z]{2,4}|museum)$')

  def Notify(self, message, prefix=' ',
             popup=False, color=None, now=None, alignright=''):

    # We suppress duplicates that are either new or recent.
    keys = self.notify_history.keys()
    if len(keys) > 20:
      for key in keys:
        if self.notify_history[key] < now-300:
          del self.notify_history[key]

    message = '%s' % message
    if message not in self.notify_history:
      self.notify_history[message] = now
      self.wfile.write('notify: %s\n' % message)

  def Status(self, tag, message=None, color=None):
    self.status_tag = tag
    self.status_msg = '%s' % (message or self.status_msg)
    if message:
      self.wfile.write('status_msg: %s\n' % message)
    if tag:
      self.wfile.write('status_tag: %s\n' % tag)

  def Welcome(self, pre=None):
    self.wfile.write('welcome: %s\n' % (pre or '').replace('\n', ' '))

  def StartWizard(self, title):
    self.wfile.write('start_wizard: %s\n' % title)

  def Retry(self):
    self.tries -= 1
    if self.tries < 0:
      raise Exception('Too many tries')
    return self.tries

  def EndWizard(self):
    self.wfile.write('end_wizard\n')

  def Spacer(self):
    pass

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    while self.Retry():
      self.wfile.write('begin_ask_email\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', ' '))
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
        self.wfile.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      if email:
        self.wfile.write(' default: %s\n' % email)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', ' '))
      self.wfile.write(' expect: email\n')
      self.wfile.write(' expect: password\n')
      self.wfile.write('end_ask_login\n')

      answer_email = self.rfile.readline().strip()
      if back is not None and answer_email == 'back': return back

      answer_pass = self.rfile.readline().strip()
      if back is not None and answer_pass == 'back': return back

      if self.EMAIL_RE.match(answer_email) and answer_pass:
        return (answer_email, answer_pass)

  def AskYesNo(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_yesno\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', ' '))
      self.wfile.write(' expect: yesno\n')
      self.wfile.write('end_ask_yesno\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer in ('y', 'n'): return (answer == 'y')

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_kitename\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      for domain in domains:
        self.wfile.write(' domain: %s\n' % domain)
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', ' '))
      self.wfile.write(' expect: kitename\n')
      self.wfile.write('end_ask_kitename\n')

      answer = self.rfile.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer: return answer

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    while self.Retry():
      self.wfile.write('begin_ask_multiplechoice\n')
      if pre:
        self.wfile.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      for choice in choices:
        self.wfile.write(' choice: %s\n' % choice)
      if default:
        self.wfile.write(' default: %s\n' % default)
      self.wfile.write(' question: %s\n' % (question or '').replace('\n', ' '))
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
    self.wfile.write('tell_%s: %s\n' % (dialog, ' '.join(lines)))

