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
    pass

  def StartWizard(self, title):
    pass

  def Retry(self):
    self.tries -= 1
    return self.tries

  def EndWizard(self):
    pass

  def Spacer(self):
    pass

  def AskEmail(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None, welcome=True):
    raise Exception('Unsupported')

  def AskLogin(self, question, default=None, email=None, pre=None,
               wizard_hint=False, image=None, back=None):
    raise Exception('Unsupported')

  def AskYesNo(self, question, default=None, pre=[],
               wizard_hint=False, image=None, back=None):
    raise Exception('Unsupported')

  def AskKiteName(self, domains, question, pre=[], default=None,
                  wizard_hint=False, image=None, back=None):
    raise Exception('Unsupported')

  def AskMultipleChoice(self, choices, question, pre=[], default=None,
                        wizard_hint=False, image=None, back=None):
    raise Exception('Unsupported')

  def Tell(self, lines, error=False, back=None):
    pass

