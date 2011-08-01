import re, sys, time
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
      sys.stderr.write('notify: %s\n' % message)

  def Status(self, tag, message=None, color=None):
    self.status_tag = tag
    self.status_msg = '%s' % (message or self.status_msg)
    if message:
      sys.stderr.write('status_msg: %s\n' % message)
    if tag:
      sys.stderr.write('status_tag: %s\n' % tag)

  def Welcome(self, pre=None):
    sys.stderr.write('welcome: %s\n' % (pre or '').replace('\n', ' '))

  def StartWizard(self, title):
    sys.stderr.write('start_wizard: %s\n' % title)

  def Retry(self):
    self.tries -= 1
    if self.tries < 0:
      raise Exception('Too many tries')
    return self.tries

  def EndWizard(self):
    sys.stderr.write('end_wizard\n')

  def Spacer(self):
    pass

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    while self.Retry():
      sys.stderr.write('begin_ask_email\n')
      if pre:
        sys.stderr.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      if default:
        sys.stderr.write(' default: %s\n' % default)
      sys.stderr.write(' question: %s\n' % (question or '').replace('\n', ' '))
      sys.stderr.write(' expect: email\n')
      sys.stderr.write('end_ask_email\n')

      answer = sys.stdin.readline().strip()
      if self.EMAIL_RE.match(answer): return answer
      if back is not None and answer == 'back': return back

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    while self.Retry():
      sys.stderr.write('begin_ask_login\n')
      if pre:
        sys.stderr.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      if email:
        sys.stderr.write(' default: %s\n' % email)
      sys.stderr.write(' question: %s\n' % (question or '').replace('\n', ' '))
      sys.stderr.write(' expect: email, password\n')
      sys.stderr.write('end_ask_login\n')

      answer_email = sys.stdin.readline().strip()
      if back is not None and answer_email == 'back': return back

      answer_pass = sys.stdin.readline().strip()
      if back is not None and answer_pass == 'back': return back

      if self.EMAIL_RE.match(answer_email) and answer_pass:
        return (answer_email, answer_pass)

  def AskYesNo(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None):
    while self.Retry():
      sys.stderr.write('begin_ask_yesno\n')
      if pre:
        sys.stderr.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      if default:
        sys.stderr.write(' default: %s\n' % default)
      sys.stderr.write(' question: %s\n' % (question or '').replace('\n', ' '))
      sys.stderr.write(' expect: yesno\n')
      sys.stderr.write('end_ask_yesno\n')

      answer = sys.stdin.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer in ('y', 'n'): return (answer == 'y')

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    while self.Retry():
      sys.stderr.write('begin_ask_kitename\n')
      if pre:
        sys.stderr.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      for domain in domains:
        sys.stderr.write(' domain: %s\n' % domain)
      if default:
        sys.stderr.write(' default: %s\n' % default)
      sys.stderr.write(' question: %s\n' % (question or '').replace('\n', ' '))
      sys.stderr.write(' expect: kitename\n')
      sys.stderr.write('end_ask_kitename\n')

      answer = sys.stdin.readline().strip().lower()
      if back is not None and answer == 'back': return back
      if answer: return answer

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    while self.Retry():
      sys.stderr.write('begin_ask_multiplechoice\n')
      if pre:
        sys.stderr.write(' preamble: %s\n' % ' '.join(pre).replace('\n', ' '))
      for choice in choices:
        sys.stderr.write(' choice: %s\n' % choice)
      if default:
        sys.stderr.write(' default: %s\n' % default)
      sys.stderr.write(' question: %s\n' % (question or '').replace('\n', ' '))
      sys.stderr.write(' expect: choice\n')
      sys.stderr.write('end_ask_multiplechoice\n')

      answer = sys.stdin.readline().strip().lower()
      try:
        ch = int(answer)
        if ch >= 0 and ch < len(choices): return ch
      except: 
        pass
      if back is not None and answer == 'back': return back

  def Tell(self, lines, error=False, back=None):
    dialog = error and 'error' or 'message'
    sys.stderr.write('tell_%s: %s\n' % (dialog, ' '.join(lines)))

