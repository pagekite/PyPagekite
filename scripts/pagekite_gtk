#!/usr/bin/env python
import datetime
import gobject
import gtk
import os
import sys
import socket
import threading
import time
import webbrowser

import pagekite
from pagekite import sha1hex, globalSecret


SHARE_DIR = "~/PageKite"

URL_HOME = ('https://pagekite.net/home/')

IMG_DIR_WINDOWS = 'gui/icons-16'
IMG_DIR_DEFAULT = 'gui/icons-127'
IMG_FILE_WIZARD  = 'pk-active.png'
ICON_FILE_ACTIVE  = 'pk-active.png'
ICON_FILE_TRAFFIC = 'pk-traffic.png'
ICON_FILE_IDLE    = 'pk-idle.png'


def GetScreenShot():
  w = gtk.gdk.get_default_root_window()
  sz = w.get_size()
  pb = gtk.gdk.Pixbuf(gtk.gdk.COLORSPACE_RGB, False, 8, sz[0], sz[1])
  pb = pb.get_from_drawable(w, w.get_colormap(), 0,0,0,0, sz[0], sz[1])
  return pb


class ShareBucket:

  S_CLIPBOARD = 1
  S_PATHS = 2
  S_SCREENSHOT = 3

  T_TEXT = 1
  T_HTML = 2
  T_MARKDOWN = 3

  JSON_INDEX = """\
{"title": %(title)s,
 "content": %(content)s,
 "files": [\n\t%(files)s\n ]}\
  """

  HTML_INDEX = """\
<html><head>
 <title>%(title)s</title>
</head><body>
 <h1 class='title'>%(title)s</h1>
 <div class='content'>%(content)s</div>
 <div class='files'>\n\t%(files)s\n\t</div>
</body></html>
  """

  def __init__(self, kitename, kiteport, title=None, dirname=None, random=False):
    share_dir = os.path.expanduser(SHARE_DIR)
    kite_dir = os.path.join(share_dir, '%s_%s' % (kitename, kiteport))
    if dirname:
      self.fullpath = os.path.join(kite_dir, dirname)
    else:
      count = 0
      while True:
        count += 1
        if random:
          dirname = sha1hex('%s%s' % (random.randint(0, 0x7ffffffe),
                                      globalSecret()))[:12]
        else:
          dirname = datetime.datetime.now().strftime("%Y-%m-%d")

        if title: dirname += '.%s' % title.replace(' ', '_')
        if count > 1: dirname += '.%3.3x' % count

        self.fullpath = os.path.join(kite_dir, dirname)
        if not os.path.exists(self.fullpath): break

    self.dirname = os.path.join('.', dirname)[1:]
    self.kitename = kitename
    self.kiteport = kiteport

    self.webpath = None

    self.title = title or 'Shared with PageKite'
    self.content = (self.T_TEXT, '')

    # Create directory!
    if not os.path.exists(share_dir): os.mkdir(share_dir, 0700)
    if not os.path.exists(kite_dir): os.mkdir(kite_dir, 0700)
    os.mkdir(self.fullpath, 0700)

  def load(self):
    return self

  def fmt_title(self, ftype='html'):
    if ftype == 'json':
      # FIXME: Escape better
      return '"%s"' % self.content[1].replace('"', '\\"')
    else:
      # FIXME: Escape better
      return '%s<' % self.content[1]

  def fmt_content(self, ftype='html'):
    if ftype == 'json':
      # FIXME: Escape better
      return '"%s"' % self.content[1].replace('"', '\\"')
    else:
      # FIXME: Escape better
      return '<pre>%s</pre>' % self.content[1]

  def fmt_file(self, filename, ftype='html'):
    # FIXME: Do something friendly with file types/extensions
    if ftype == 'json':
      # FIXME: Escape better
      return '"%s"' % filename.replace('"', '\\"')
    else:
      # FIXME: Escape better
      return ('<div class="file"><a href="%s">%s</a></div>'
              ) % (filename, os.path.basename(filename))

  def save(self):
    filelist = []
    for fn in os.listdir(self.fullpath):
      if not (fn.startswith('.') or fn in ('index.pk-html', 'index.pk-json')):
        filelist.append(fn)

    SEP = {'html': '\n\t', 'json': ',\n\t'}
    for ft, tp in (('html', self.HTML_INDEX),
                   ('json', self.JSON_INDEX)):
      fd = open(os.path.join(self.fullpath, 'index.pk-%s' % ft), 'w')
      fd.write(tp % {
        'title': self.fmt_title(self.title),
        'content': self.fmt_content(ft),
        'files': SEP[ft].join([self.fmt_file(f, ft) for f in sorted(filelist)])
      })
      fd.close()

    return self

  def set_title(self, title):
    self.title = title
    return self

  def set_content(self, content, ctype=T_TEXT):
    self.content = (ctype, content)
    return self

  def add_paths(self, paths):
    for path in paths:
      os.symlink(path, os.path.join(self.fullpath, os.path.basename(path)))
    return self

  def add_screenshot(self, screenshot):
    screenshot.save(os.path.join(self.fullpath, 'screenshot.png'), 'png')
    return self

  def pk_config(self):
    return ('webpath=%s/%s:%s:default:%s'
            ) % (self.kitename, self.kiteport, self.dirname, self.fullpath)


class PageKiteThread(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.looping = False
    self.stopped = True
    self.pk = None

    self.pk_readlock = threading.Condition()
    self.pk_incoming = []
    self.pk_eof = False

    self.gui_readlock = threading.Condition()
    self.gui_incoming = ''
    self.gui_eof = False

  # These routines are used by the PageKite UI, to communicate with us...
  def readline(self):
    self.pk_readlock.acquire()
    while (not self.pk_incoming) and (not self.pk_eof): self.pk_readlock.wait()
    if self.pk_incoming:
      line = self.pk_incoming.pop(0)
    else:
      line = ''
    self.pk_readlock.release()
    #print '>>PK>> %s' % line.strip()
    return line
  def write(self, data):
    #print '>>GUI>> %s' % data.strip()
    self.gui_readlock.acquire()
    if data:
      self.gui_incoming += data
    else:
      self.gui_eof = True
    self.gui_readlock.notify()
    self.gui_readlock.release()

  # And these are used by the GUI, to communicate with PageKite.
  def recv(self, bytecount):
    self.gui_readlock.acquire()
    while (len(self.gui_incoming) < bytecount) and (not self.gui_eof):
      self.gui_readlock.wait()
    data = self.gui_incoming[0:bytecount]
    self.gui_incoming = self.gui_incoming[bytecount:]
    self.gui_readlock.release()
    return data
  def send(self, data):
    if not data.endswith('\n') and data != '':
      raise ValueError('Please always send whole lines')
    print '<<PK<< %s' % data.strip()
    self.pk_readlock.acquire()
    if data:
      self.pk_incoming.append(data)
    else:
      self.pk_eof = True
    self.pk_readlock.notify()
    self.pk_readlock.release()

  def sendall(self, data):
    return self.send(data)

  def close(self):
    self.send('')
    self.write('')

  def Configure(self, pk):
    try:
      self.pk = pk
      pk.ui_wfile = pk.ui.wfile = self
      pk.ui_rfile = pk.ui.rfile = self
      return pagekite.Configure(pk)
    except:
      self.pk = None
      raise

  def run(self):
    self.looping = True
    while self.looping:
      if not self.stopped:
        from pagekite import remoteui, httpd
        pagekite.Main(pagekite.PageKite, self.Configure,
                      uiclass=remoteui.RemoteUi,
                      http_handler=httpd.UiRequestHandler,
                      http_server=httpd.UiHttpServer)
        self.close()
        self.write('status_msg: Disabled\nstatus_tag: idle\n')
        self.pk = None
      time.sleep(1)

  def stop(self):
    self.stopped = True
    if self.pk: self.send('exit: stopping\n')

  def toggle(self):
    if self.stopped:
      self.stopped = False
    else:
      self.stop()

  def quit(self):
    self.looping = False
    self.stopped = True
    if self.pk:
      self.send('exit: quitting\n')
    self.close()
    self.pk = None


class CommThread(threading.Thread):
  def __init__(self, pkThread):
    threading.Thread.__init__(self)
    self.pkThread = pkThread
    self.looping = False

    self.multi = None
    self.multi_args = None

    # Callbacks
    self.cb = {}

  def parse_line(self, line):
    print '<< %s' % line[:-1]
    if line.startswith('begin_'):
      self.multi = line[6:].strip()
      self.multi_args = {}
    elif self.multi:
      if line.startswith('end_'):
        if self.multi in self.cb:
          gobject.idle_add(self.cb[self.multi], self.multi_args)
        elif 'default' in self.multi_args:
          self.pkThread.send(self.multi_args['default']+'\n')
        self.multi = self.multi_args = None
      else:
        try:
          variable, value = line.strip().split(': ', 1)
          self.multi_args[variable] = value
        except ValueError:
          pass
    else:
      try:
        command, args = line.strip().split(': ', 1)
        if command in self.cb:
          gobject.idle_add(self.cb[command], args)
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


class UiContainer(gtk.Window):
  pass

class UiWizard(UiContainer):
  def __init__(self):
    pass


class PageKiteWizard:
  def __init__(self, title=''):
    self.window = gtk.Dialog()
    self.window.set_size_request(500, 300)

    # Just keep window open forever and ever
    self.window.connect("delete_event", lambda w, e: True)
    self.window.connect("destroy", lambda w: False)

    # Prepare our standard widgets
    self.title = gtk.Label("PageKite")
    self.title.set_justify(gtk.JUSTIFY_CENTER)
    self.question = gtk.Label('Welcome to PageKite!')
    self.question.set_justify(gtk.JUSTIFY_LEFT)
    self.decoration = gtk.Image()
    self.decoration.set_from_file(os.path.join(IMG_DIR_DEFAULT, IMG_FILE_WIZARD))
    self.inputprefix = gtk.Label('')
    self.textinput = gtk.Entry()
    self.inputsuffix = gtk.Label('')

    # Set up our packing...
    self.right = gtk.VBox(False, spacing=15)
    self.left = gtk.VBox(False, spacing=5)
    self.hbox = gtk.HBox(False, spacing=0)
    self.input_hbox = gtk.HBox(False, spacing=0)
    self.hbox.pack_start(self.right, expand=True, fill=True, padding=10)
    self.hbox.pack_start(self.left, expand=True, fill=True, padding=10)

    self.right.pack_start(self.decoration, expand=False, fill=False)
    self.left.pack_start(self.question, expand=True, fill=True)
    self.input_hbox.pack_start(self.inputprefix, expand=False, fill=False)
    self.input_hbox.pack_start(self.textinput, expand=True, fill=True)
    self.input_hbox.pack_start(self.inputsuffix, expand=False, fill=False)
    self.left.pack_start(self.input_hbox, expand=True, fill=True)

    self.window.vbox.pack_start(self.title, expand=False,fill=False, padding=5)
    self.window.vbox.pack_start(self.hbox, expand=True, fill=True, padding=10)

    if title: self.set_title(title)

    self.buttons = []
    self.window.show_all()
    self.input_hbox.hide()

  def set_title(self, title):
    self.title.set_markup('<big> <b>%s</b> </big>' % title)

  def click_last(self, w, e):
    if self.buttons: self.buttons[-1][0](e)

  def clear_buttons(self):
    for b in self.buttons:
      self.window.action_area.remove(b)
    self.buttons = []

  def set_question(self, question):
    self.question.set_markup(question.replace('  ', '\n'))
    self.question.set_justify(gtk.JUSTIFY_LEFT)

  def set_buttons(self, buttonlist):
    self.clear_buttons()
    for label, callback in buttonlist:
      button = gtk.Button(label)
      button.connect('clicked', callback)
      button.show()
      self.window.action_area.pack_start(button)
      self.buttons.append(button)
    # FIXME: we want to make the LAST button the 'default' action.

  def close(self):
    self.clear_buttons()
    self.window.hide()
    self.window.destroy()
    self.window = self.buttons = None


class SharingDialog(gtk.Dialog):

  DEFAULT_EXPIRATION = 2
  EXPIRATION = {
    "Never expires": 0,
    "Expires in 2 days": 2*24*3600,
    "Expires in 7 days": 7*24*3600,
    "Expires in 14 days": 14*24*3600,
    "Expires in 30 days": 30*24*3600,
    "Expires in 90 days": 90*24*3600,
    "Expires in 180 days": 180*24*3600,
    "Expires in 365 days": 365*24*3600
  }

  def __init__(self, kites, stype, sdata, title=''):
    gtk.Dialog.__init__(self, title='Sharing Details',
                        buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                 gtk.STOCK_OK, gtk.RESPONSE_OK))

    preview_box = gtk.Label("FIXME: Cropper")

    kitelist = []
    for domain in kites:
      for bid in kites[domain]:
        if 'builtin' in kites[domain][bid] and bid.startswith('http/'):
          kitelist.append('%s:%s' % (domain, bid[5:]))
    if len(kitelist) > 1:
      combo = gtk.combo_box_new_text()
      kitelist.sort(key=lambda k: len(k))
      for kite in kitelist: combo.append_text(kite)
      combo.set_active(0)
      kite_chooser_box = gtk.HBox()
      kite_chooser_box.pack_start(gtk.Label("Share on:"), expand=True, fill=True, padding=10)
      kite_chooser_box.pack_start(combo, expand=True, fill=True, padding=10)
      self.kite_chooser = combo
    elif len(kitelist) == 1:
      kite_chooser_box = gtk.Label("Sharing on %s" % kitelist[0])
      self.kite_chooser = kitelist[0]
    else:
      kite_chooser_box = gtk.Label("No kites!")
      self.kite_chooser = None

    elist = (self.EXPIRATION.keys()[:])
    elist.sort(key=lambda k: self.EXPIRATION[k])
    ecombo = gtk.combo_box_new_text()
    for exp in elist: ecombo.append_text(exp)
    ecombo.set_active(self.DEFAULT_EXPIRATION)

    expiration_box = gtk.HBox()
    expiration_box.pack_start(gtk.Label("Expiration:"), expand=True, fill=True, padding=10)
    expiration_box.pack_start(ecombo, expand=True, fill=True, padding=10)
    self.expiration = ecombo

    for widget in (preview_box, kite_chooser_box, expiration_box):
      self.vbox.pack_start(widget, expand=False, fill=False, padding=10)
      widget.show_all()

  def get_kiteinfo(self):
    if str(type(self.kite_chooser)) == "<type 'gtk.ComboBox'>":
      return self.kite_chooser.get_model()[self.kite_chooser.get_active()][0]
    else:
      return self.kite_chooser

  def get_kitename(self):
    return (self.get_kiteinfo() or ':').split(':')[0]

  def get_kiteport(self):
    return int((self.get_kiteinfo() or ':').split(':')[1])


class PageKiteStatusIcon(gtk.StatusIcon):
  MENU_TEMPLATE = '''
      <ui>
       <menubar name="Menubar">
        <menu action="Menu">
         <menuitem action="ShareClipboard"/>
         <menuitem action="SharePath"/>
         <menuitem action="ShareScreenshot"/>
        <separator/>
         %(kitelist)s
         <menuitem action="AddKite"/>
        <separator/>
         <menuitem action="About"/>
         <menu action="AdvancedMenu">
          <menuitem action="ViewLog"/>
          <menuitem action="VerboseLog"/>
          <menuitem action="ConfigFile"/>
          <separator/>
          <menuitem action="EnablePageKite"/>
          <!-- menuitem action="ConnectTo"/ -->
         </menu>
         <menuitem action="Quit"/>
        </menu>
       </menubar>
      </ui>
  '''

  def __init__(self, pkComm):
    gtk.StatusIcon.__init__(self)

    self.wizard = None
    self.pkComm = pkComm
    self.pkComm.cb.update({
      'status_tag': self.set_status_tag,
      'status_msg': self.set_status_msg,
      'tell_message': self.show_info_dialog,
      'tell_error': self.show_error_dialog,
      'start_wizard': self.start_wizard,
      'end_wizard': self.end_wizard,
      'ask_yesno': self.ask_yesno,
      'ask_email': self.ask_email,
      'ask_kitename': self.ask_kitename,
      'ask_multiplechoice': self.ask_multiplechoice,
      'be_list_start': self.reset_status,
      'be_status': self.parse_status,
      'be_path': self.parse_status,
    })
    self.set_tooltip('PageKite')

    self.icon_file = ICON_FILE_IDLE
    if sys.platform in ('win32', 'os2', 'os2emx'):
      self.icon_dir = IMG_DIR_WINDOWS
    else:
      self.icon_dir = IMG_DIR_DEFAULT
    self.set_from_file(os.path.join(self.icon_dir, self.icon_file))

    self.connect('activate', self.on_activate)
    self.connect('popup-menu', self.on_popup_menu)
    #gobject.timeout_add_seconds(1, self.on_tick)

    self.kites = {}

    try:
      GetScreenShot()
      self.have_screenshots = True
    except:
      self.have_screenshots = False
    self.have_sharing = False

    self.pkComm.start()
    self.set_visible(True)

  def create_menu(self):
    self.manager = gtk.UIManager()
    ag = gtk.ActionGroup('Actions')
    ag.add_actions([
      ('Menu',  None, 'Menu'),
       ('QuotaDisplay', None, 'XX.YY GB of Quota left'),
       ('GetQuota', None, 'Get _More Quota...', None, 'Get more Quota from PageKite.net', self.on_stub),
       ('SharePath', None, 'Share _File or Folder', None, 'Make a file or folder visible to the Web', self.share_path),
       ('ShareClipboard', None, '_Paste to Web', None, 'Make the contents of the clipboard visible to the Web', self.share_clipboard),
       ('ShareScreenshot', None, 'Share _Screenshot', None, 'Put a screenshot of your desktop on the Web', self.share_screenshot),
        ('AddKite', None, 'New _Kite', None, 'Add Another PageKite', self.new_kite),
       ('About', gtk.STOCK_ABOUT, '_About', None, 'About PageKite', self.on_about),
       ('AdvancedMenu', None, 'Ad_vanced ...'),
        ('ViewLog', None, 'PageKite _Log', None, 'Display PageKite event log', self.on_stub),
        ('ConfigFile', None, '_Configuration', None, 'Edit the PageKite configuration file', self.on_stub),
        ('ConnectTo', None, 'Connect To ...', None, 'Connect to a remote PageKite'),
       ('Quit', None, '_Quit PageKite', None, 'Turn PageKite off completely', self.quit),
    ])
    ag.add_toggle_actions([
      ('EnablePageKite', None, '_Enable PageKite', None, 'Enable local PageKite', self.toggle_enable, (not self.pkComm.pkThread.stopped)),
      ('VerboseLog', None, 'Verbose Logging', None, 'Verbose logging facilitate troubleshooting.', self.on_stub, False),
    ])

    self.manager.insert_action_group(ag, 0)
    self.manager.add_ui_from_string(self.MENU_TEMPLATE % {
      'kitelist': self.kite_menu(action_group=ag),
    })
    #self.manager.get_widget('/Menubar/Menu/QuotaDisplay').set_sensitive(False)
    self.menu = self.manager.get_widget('/Menubar/Menu/About').props.parent

  def kite_menu(self, action_group=None):
    xml, actions, toggles = [], [], []
    mc = 0

    def a(elem, tit, action=None, tooltip=None, close=True,
                     cb=None, toggle=None):
      if elem == 'menu': close = False
      if not action:
        action = 'PageKiteList_%s' % mc
      xml.append('<%s action="%s"%s>' % (elem, action, close and '/' or ''))
      if toggle is not None:
        toggles.append((action,  None, tit, None, tooltip, cb, toggle))
      else:
        actions.append((action,  None, tit, None, tooltip, cb))
      return 1

    def sn(path):
      p = path[-30:]
      if p != path:
        if '/' in p:
          p = '/'.join(('...', p.split('/', 1)[1]))
        elif '\\' in p:
          p = '\\'.join(('...', p.split('\\', 1)[1]))
      return p

    def make_cb(func, data):
      def tmp(what): return func(data)
      return tmp

#   print '%s' % self.kites
    domains = sorted(self.kites.keys())
    if len(domains):
      a('menuitem', 'My Kites:', action='PageKiteList')
      for domain in domains:
        mc += a('menu', '  %s' % domain)

        www = [k for k in self.kites[domain].keys() if k.startswith('http')]
        www.sort(key=lambda x: int(self.kites[domain][x]['port'] or
                                   self.kites[domain][x]['bport'] or 0))
        for protoport in www:
          info = self.kites[domain][protoport]
          proto = protoport.split('/')[0]
          secure = (('ssl' in info or info['proto'] == 'https')
                    and 'Secure ' or '')
          url = '%s://%s%s' % (secure and 'https' or 'http', domain,
                               info['port'] and ':%s' % info['port'] or '')
          pdesc = info['port'] and ' (port %s)' % info['port'] or ''
          bdesc = 'builtin' in info and 'PageKite' or '%s:%s' % (info['bhost'], info['bport'])

          mc += a('menuitem', '%sWWW%s to %s' % (secure, pdesc, bdesc),
                  cb=make_cb(self.kite_toggle, info), toggle=True)

          if pagekite.BE_STATUS_OK & int(info['status'], 16):
            mc += a('menuitem', 'Open in Browser',
                    cb=make_cb(self.open_url, url), tooltip=url)

          if 'paths' not in info:
            mc += a('menuitem', 'Copy Link',
                    cb=make_cb(self.copy_url, url), tooltip=url)

          elif len(info['paths'].keys()):
            for path in sorted(info['paths'].keys()):
              mc += a('menu', '  ' + sn(info['paths'][path]['src']))
              if pagekite.BE_STATUS_OK & int(info['status'], 16):
                mc += a('menuitem', 'Open in Browser',
                        cb=make_cb(self.open_url, url+path), tooltip=url+path)
              mc += a('menuitem', ('Copy Link to: %s'
                                   ) % (path == '/' and 'Home page' or path),
                      cb=make_cb(self.copy_url, url+path), tooltip=url+path)
              mc += a('menuitem', 'Stop Sharing')
              xml.append('</menu>')

          xml.append('<separator/>')

        others = [k for k in self.kites[domain].keys() if k not in www]
        others.sort(key=lambda x: int(self.kites[domain][x]['port'] or
                                      self.kites[domain][x]['bport'] or 0))
        for protoport in others:
          info = self.kites[domain][protoport]
          proto = protoport.split('/')[0]
          mc += a('menuitem', '%s' % protoport, toggle=True)

        xml.append('<separator/>')
        mc += a('menuitem', 'Configure ...')
        mc += a('menuitem', 'Delete %s' % domain)
        xml.append('</menu>')
    else:
      a('menuitem', 'No Kites Yet', action='PageKiteList')

    if action_group and actions: action_group.add_actions(actions)
    if action_group and toggles: action_group.add_toggle_actions(toggles)
    return ''.join(xml)

  def on_activate(self, data):
    if self.wizard:
      self.wizard.window.hide()
      self.wizard.window.show()
    else:
      self.create_menu()
      self.show_menu(0, 0)
    return False

  def set_status_msg(self, message):
    self.set_tooltip('PageKite: %s' % message)

  def set_status_tag(self, status):
    old_if = self.icon_file
    if status == 'traffic': self.icon_file = ICON_FILE_TRAFFIC
    elif status == 'serving': self.icon_file = ICON_FILE_TRAFFIC
    # Connecting..
    elif status == 'startup': self.icon_file = ICON_FILE_IDLE
    elif status == 'connect': self.icon_file = ICON_FILE_ACTIVE
    elif status == 'dyndns': self.icon_file = ICON_FILE_IDLE
    # Inactive, boo
    elif status == 'idle': self.icon_file = ICON_FILE_IDLE
    elif status == 'down': self.icon_file = ICON_FILE_IDLE
    elif status == 'exiting': self.icon_file = ICON_FILE_IDLE
    # Ready and waiting
    elif status == 'flying': self.icon_file = ICON_FILE_ACTIVE
    elif status == 'active': self.icon_file = ICON_FILE_ACTIVE
    if self.icon_file != old_if:
      self.set_from_file(os.path.join(self.icon_dir, self.icon_file))

  def on_popup_menu(self, status, button, when):
    if self.menu.props.visible:
      self.menu.popdown()
    else:
      self.show_menu(button, when)
    return False

  def ui_full(self):
    return (not self.pkComm.pkThread.stopped and not self.wizard)

  def show_menu(self, button, when):
    w = self.manager.get_widget

    for item in ('/Menubar/Menu/PageKiteList',
                 '/Menubar/Menu/SharedItems',
                 '/Menubar/Menu/SharePath',
                 '/Menubar/Menu/ShareClipboard',
                 '/Menubar/Menu/ShareScreenshot',
                 '/Menubar/Menu/AdvancedMenu/ViewLog',
                 '/Menubar/Menu/AdvancedMenu/VerboseLog'):
      try:
        w(item).set_sensitive(self.ui_full())
      except:
        pass

    for item in ('/Menubar/Menu/PageKiteList',
                 ):
      try:
        w(item).set_sensitive(False)
      except:
        pass

    if not self.have_screenshots:
      w('/Menubar/Menu/ShareScreenshot').hide()

    if not self.have_sharing:
      w('/Menubar/Menu/ShareScreenshot').hide()
      w('/Menubar/Menu/ShareClipboard').hide()
      w('/Menubar/Menu/SharePath').hide()

    for item in (#'/Menubar/Menu/QuotaDisplay',
                 #'/Menubar/Menu/GetQuota',
                 '/Menubar/Menu/AddKite',
                 ):
      try:
        if self.pkComm.pkThread.stopped:
          w(item).hide()
        else:
          w(item).show()
      except:
        pass

    self.menu.popup(None, None, None, button, when)

  def reset_status(self, argtext):
    self.kites = {}
    self.have_sharing = False

  def parse_status(self, argtext):
    args = {}
    for arg in argtext.split('; '):
      var, val = arg.split('=', 1)
      args[var] = val

    if 'domain' in args:
      domain_info = self.kites.get(args['domain'], {})
      proto = args.get('proto', 'http')
      port = args.get('port') or '80' # FIXME: this is dumb
      bid = '%s/%s' % (proto, port)
      backend_info = domain_info.get(bid, {})
      if 'path' in args:
        path_info = backend_info.get('paths', {})
        if 'delete' in args:
          if args['path'] in path_info: del path_info[args['path']]
        else:
          path_info[args['path']] = {
            'domain': args['domain'],
            'policy': args['policy'],
            'port': port,
            'src': args['src']
          }
          backend_info['paths'] = path_info
          domain_info[bid] = backend_info
      else:
        if 'delete' in args:
          if bid in domain_info: del domain_info[bid]
        else:
          if 'builtin' in args: self.have_sharing = True
          for i in ('proto', 'port', 'status', 'bhost', 'bport',
                    'ssl', 'builtin'):
            if i in args:
              backend_info[i] = args[i]
          domain_info[bid] = backend_info
      self.kites[args['domain']] = domain_info

  def show_info_dialog(self, message, d_type=gtk.MESSAGE_INFO):
    dlg = gtk.MessageDialog(type=d_type,
                            buttons=gtk.BUTTONS_CLOSE,
                            message_format=message.replace('  ', '\n'))
    dlg.get_action_area().children()[0].connect('clicked',
                                                lambda w: dlg.destroy())
    dlg.show()

  def show_error_dialog(self, message):
    self.show_info_dialog(message, d_type=gtk.MESSAGE_ERROR)

  def wizard_prepare(self, args):
    if 'preamble' in args:
      question = args['preamble'].replace('  ', '\n')+'\n\n'+args['question']
    else:
      question = args['question']

    wizard = self.wizard
    if not wizard: wizard = PageKiteWizard(title='A question!')
    wizard.set_question(question)

    return question, wizard

  def ask_yesno(self, args):
    question, wizard = self.wizard_prepare(args)

    def respond(window, what):
      self.pkComm.pkThread.send('%s\n' % what)
      self.wizard_first = False
      if not self.wizard: wizard.close()
    wizard.set_buttons([
      ('No', lambda w: respond(w, 'n')),
      (self.wizard and 'Yes >>' or 'Yes', lambda w: respond(w, 'y')),
    ])

  def ask_question(self, args, valid_re, callback=None):
    question, wizard = self.wizard_prepare(args)
    wizard.textinput.set_text(args.get('default', ''))
    wizard.inputprefix.set_text('  ')
    wizard.inputsuffix.set_text(args.get('domain', '')+'     ')
    wizard.input_hbox.show()

    def respond(window, what):
      wizard.input_hbox.hide()
      wizard.inputprefix.set_text('')
      wizard.inputsuffix.set_text('')
      self.wizard_first = False
      if not self.wizard: wizard.close()
      if callback:
        callback(window, what)
      else:
        self.pkComm.pkThread.send('%s\n' % what)
    wizard.set_buttons([
      ((self.wizard and not self.wizard_first) and '<< Back' or 'Cancel',
                                                  lambda w: respond(w, 'back')),
      (self.wizard and 'Next >>' or 'OK',
                             lambda w: respond(w, wizard.textinput.get_text())),
    ])

  def ask_email(self, args):
    return self.ask_question(args, '.*@.*$') # FIXME

  def ask_kitename(self, args):
    return self.ask_question(args, '.*') # FIXME

  def ask_multiplechoice(self, args):
    question, wizard = self.wizard_prepare(args)

    choices = gtk.VBox(False, spacing=15)
    clist = []
    rb = None
    for ch in sorted([k for k in args if k.startswith('choice_')]):
      rb = gtk.RadioButton(rb, args[ch])
      clist.append((rb, int(ch[7:])))
      choices.pack_start(rb)
    choices.show_all()
    self.wizard.left.pack_start(choices)

    def respond(window, choice=None):
      if not choice:
        choice = args.get('default', None)
        for cw, cn in clist:
          if cw.get_active(): choice = cn
      print 'Choice is: %s' % choice
      self.pkComm.pkThread.send('%s\n' % choice)
      self.wizard_first = False
      self.wizard.left.remove(choices)
      if not self.wizard: wizard.close()
    wizard.set_buttons([
      ((self.wizard and not self.wizard_first) and '<< Back' or 'Cancel',
                                                  lambda w: respond(w, 'back')),
      (self.wizard and 'Next >>' or 'OK', lambda w: respond(w)),
    ])

  def kite_toggle(self, kite_info):
    self.show_error_dialog('Unimplemented... %s' % (kite_info, ))

  def copy_url(self, url):
    gtk.clipboard_get('CLIPBOARD').set_text(url, len=-1)

  def open_url(self, url):
    webbrowser.open(url)

  def share_clipboard_cb(self, clipboard, text, data):
    print 'CB: %s / %s / %s' % (clipboard, text, data)
    self.show_error_dialog('Unimplemented... %s [%s/%s]' % (text, clipboard, data))

  def share_clipboard(self, data):
    cb = gtk.clipboard_get(gtk.gdk.SELECTION_CLIPBOARD)
    cb.request_text(self.share_clipboard_cb)

  def get_sharebucket(self, title, dtype, data):
    self.wizard = sd = SharingDialog(self.kites, dtype, data, title=title)
    if sd.run() == gtk.RESPONSE_OK:
      kitename = sd.get_kitename()
      kiteport = sd.get_kiteport()
    else:
      kitename = kiteport = None

    self.wizard = None
    sd.destroy()
    if not kitename: return None, None, None

    return kitename, kiteport, ShareBucket(kitename, kiteport, title=title)

  def share_path(self, data):
    try:
      RESPONSE_SHARE = gtk.RESPONSE_CANCEL + gtk.RESPONSE_OK + 1000
      self.wizard = fs = gtk.FileChooserDialog('Share Files or Folders', None,
                                               gtk.FILE_CHOOSER_ACTION_OPEN,
                                         (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                          "Share!", RESPONSE_SHARE))
      fs.set_default_response(RESPONSE_SHARE)
      fs.set_select_multiple(True)
      expl = gtk.Label("Hint: You can share multiple files or folders "
                       "by holding the <CTRL> key.")
      expl.show()
      fs.set_extra_widget(expl)

      paths = (fs.run() == RESPONSE_SHARE) and fs.get_filenames()

      fs.destroy()
      expl.destroy()
      self.wizard = None

      if paths:
        kitename, kiteport, sb = self.get_sharebucket('Shared',
                                                     ShareBucket.S_PATHS, paths)
        if not sb: return

        sb.add_paths(paths).save()
        self.pkComm.pkThread.send('config: %s\n' % sb.pk_config())
        self.pkComm.pkThread.send('save: quietly\n')
        url = 'http://%s:%s%s' % (kitename, kiteport, sb.dirname)
        self.copy_url(url)
        self.open_url(url)
    except:
      self.show_error_dialog('Sharing failed: %s' % (sys.exc_info(), ))

  def share_screenshot(self, data, title='Screenshot'):
    try:
      screenshot = GetScreenShot()
      kitename, kiteport, sb = self.get_sharebucket('Screenshot',
                                           ShareBucket.S_SCREENSHOT, screenshot)
      if not sb: return

      sb.add_screenshot(screenshot).save()
      self.pkComm.pkThread.send('config: %s\n' % sb.pk_config())
      self.pkComm.pkThread.send('save: quietly\n')
      url = 'http://%s:%s%s' % (kitename, kiteport, sb.dirname)
      self.copy_url(url)
      self.open_url(url)
    except:
      self.show_error_dialog('Screenshot failed: %s' % (sys.exc_info(), ))

  def new_kite(self, data):
    self.pkComm.pkThread.send('addkite: None\n')

  def show_about(self):
    dialog = gtk.AboutDialog()
    dialog.set_name('PageKite')
    dialog.set_version(pagekite.APPVER)
    dialog.set_comments('PageKite is a tool for running personal servers, '
                        'sharing work and communicating over the WWW.')
    dialog.set_website(pagekite.WWWHOME)
    dialog.set_license(pagekite.LICENSE)
    dialog.run()
    dialog.destroy()

  def toggle_enable(self, data):
    pkt = self.pkComm.pkThread
    pkt.toggle()
    data.set_active(not pkt.stopped)
    if pkt.stopped:
      self.kites = {}

  def start_wizard(self, title):
    if self.wizard:
      self.wizard.set_title(title)
    else:
      self.wizard = PageKiteWizard(title=title)
      self.wizard_first = True

  def end_wizard(self, message):
    if self.wizard:
      self.wizard.close()
    self.wizard = None
    self.pkComm.pkThread.send('save: quietly\n')

  def on_stub(self, data):
    print 'Stub'

  def on_about(self, data):
    self.show_about()

  def quit(self, data):
    self.set_status_tag('exiting')
    self.set_status_msg('Shutting down...')
    self.pkComm.quit()
    gobject.timeout_add_seconds(1, self.quitting)

  def quitting(self):
    if self.pkComm and self.pkComm.pkThread and self.pkComm.pkThread.pk:
      return
    gtk.main_quit()


if __name__ == '__main__':
  sys.argv[1:1] = ['--friendly']
  pkt = pksi = ct = None
  try:
    pkt = PageKiteThread()
    if '--remote' in sys.argv:
      pkt.stopped = True
      sys.argv.remove('--remote')
    else:
      pkt.stopped = False

    ct = CommThread(pkt)
    pksi = PageKiteStatusIcon(ct)
    gobject.threads_init()
    gtk.main()
  except:
    print '%s' % (sys.exc_info(), )

  if pkt: pkt.quit()
  if ct: ct.quit()


##############################################################################
CERTS="""\
StartCom Ltd.
=============
-----BEGIN CERTIFICATE-----
MIIFFjCCBH+gAwIBAgIBADANBgkqhkiG9w0BAQQFADCBsDELMAkGA1UEBhMCSUwxDzANBgNVBAgT
BklzcmFlbDEOMAwGA1UEBxMFRWlsYXQxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xGjAYBgNVBAsT
EUNBIEF1dGhvcml0eSBEZXAuMSkwJwYDVQQDEyBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhv
cml0eTEhMB8GCSqGSIb3DQEJARYSYWRtaW5Ac3RhcnRjb20ub3JnMB4XDTA1MDMxNzE3Mzc0OFoX
DTM1MDMxMDE3Mzc0OFowgbAxCzAJBgNVBAYTAklMMQ8wDQYDVQQIEwZJc3JhZWwxDjAMBgNVBAcT
BUVpbGF0MRYwFAYDVQQKEw1TdGFydENvbSBMdGQuMRowGAYDVQQLExFDQSBBdXRob3JpdHkgRGVw
LjEpMCcGA1UEAxMgRnJlZSBTU0wgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxITAfBgkqhkiG9w0B
CQEWEmFkbWluQHN0YXJ0Y29tLm9yZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA7YRgACOe
yEpRKSfeOqE5tWmrCbIvNP1h3D3TsM+x18LEwrHkllbEvqoUDufMOlDIOmKdw6OsWXuO7lUaHEe+
o5c5s7XvIywI6Nivcy+5yYPo7QAPyHWlLzRMGOh2iCNJitu27Wjaw7ViKUylS7eYtAkUEKD4/mJ2
IhULpNYILzUCAwEAAaOCAjwwggI4MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgHmMB0GA1Ud
DgQWBBQcicOWzL3+MtUNjIExtpidjShkjTCB3QYDVR0jBIHVMIHSgBQcicOWzL3+MtUNjIExtpid
jShkjaGBtqSBszCBsDELMAkGA1UEBhMCSUwxDzANBgNVBAgTBklzcmFlbDEOMAwGA1UEBxMFRWls
YXQxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xGjAYBgNVBAsTEUNBIEF1dGhvcml0eSBEZXAuMSkw
JwYDVQQDEyBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJARYS
YWRtaW5Ac3RhcnRjb20ub3JnggEAMB0GA1UdEQQWMBSBEmFkbWluQHN0YXJ0Y29tLm9yZzAdBgNV
HRIEFjAUgRJhZG1pbkBzdGFydGNvbS5vcmcwEQYJYIZIAYb4QgEBBAQDAgAHMC8GCWCGSAGG+EIB
DQQiFiBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAyBglghkgBhvhCAQQEJRYjaHR0
cDovL2NlcnQuc3RhcnRjb20ub3JnL2NhLWNybC5jcmwwKAYJYIZIAYb4QgECBBsWGWh0dHA6Ly9j
ZXJ0LnN0YXJ0Y29tLm9yZy8wOQYJYIZIAYb4QgEIBCwWKmh0dHA6Ly9jZXJ0LnN0YXJ0Y29tLm9y
Zy9pbmRleC5waHA/YXBwPTExMTANBgkqhkiG9w0BAQQFAAOBgQBscSXhnjSRIe/bbL0BCFaPiNhB
OlP1ct8nV0t2hPdopP7rPwl+KLhX6h/BquL/lp9JmeaylXOWxkjHXo0Hclb4g4+fd68p00UOpO6w
NnQt8M2YI3s3S9r+UZjEHjQ8iP2ZO1CnwYszx8JSFhKVU2Ui77qLzmLbcCOxgN8aIDjnfg==
-----END CERTIFICATE-----

StartCom Certification Authority
================================
-----BEGIN CERTIFICATE-----
MIIHyTCCBbGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEWMBQGA1UEChMN
U3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmlu
ZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDYwOTE3MTk0
NjM2WhcNMzYwOTE3MTk0NjM2WjB9MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRk
LjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMg
U3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQDBiNsJvGxGfHiflXu1M5DycmLWwTYgIiRezul38kMKogZkpMyONvg45iPwbm2xPN1y
o4UcodM9tDMr0y+v/uqwQVlntsQGfQqedIXWeUyAN3rfOQVSWff0G0ZDpNKFhdLDcfN1YjS6LIp/
Ho/u7TTQEceWzVI9ujPW3U3eCztKS5/CJi/6tRYccjV3yjxd5srhJosaNnZcAdt0FCX+7bWgiA/d
eMotHweXMAEtcnn6RtYTKqi5pquDSR3l8u/d5AGOGAqPY1MWhWKpDhk6zLVmpsJrdAfkK+F2PrRt
2PZE4XNiHzvEvqBTViVsUQn3qqvKv3b9bZvzndu/PWa8DFaqr5hIlTpL36dYUNk4dalb6kMMAv+Z
6+hsTXBbKWWc3apdzK8BMewM69KN6Oqce+Zu9ydmDBpI125C4z/eIT574Q1w+2OqqGwaVLRcJXrJ
osmLFqa7LH4XXgVNWG4SHQHuEhANxjJ/GP/89PrNbpHoNkm+Gkhpi8KWTRoSsmkXwQqQ1vp5Iki/
untp+HDH+no32NgN0nZPV/+Qt+OR0t3vwmC3Zzrd/qqc8NSLf3Iizsafl7b4r4qgEKjZ+xjGtrVc
UjyJthkqcwEKDwOzEmDyei+B26Nu/yYwl/WL3YlXtq09s68rxbd2AvCl1iuahhQqcvbjM4xdCUsT
37uMdBNSSwIDAQABo4ICUjCCAk4wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAa4wHQYDVR0OBBYE
FE4L7xqkQFulF2mHMMo0aEPQQa7yMGQGA1UdHwRdMFswLKAqoCiGJmh0dHA6Ly9jZXJ0LnN0YXJ0
Y29tLm9yZy9zZnNjYS1jcmwuY3JsMCugKaAnhiVodHRwOi8vY3JsLnN0YXJ0Y29tLm9yZy9zZnNj
YS1jcmwuY3JsMIIBXQYDVR0gBIIBVDCCAVAwggFMBgsrBgEEAYG1NwEBATCCATswLwYIKwYBBQUH
AgEWI2h0dHA6Ly9jZXJ0LnN0YXJ0Y29tLm9yZy9wb2xpY3kucGRmMDUGCCsGAQUFBwIBFilodHRw
Oi8vY2VydC5zdGFydGNvbS5vcmcvaW50ZXJtZWRpYXRlLnBkZjCB0AYIKwYBBQUHAgIwgcMwJxYg
U3RhcnQgQ29tbWVyY2lhbCAoU3RhcnRDb20pIEx0ZC4wAwIBARqBl0xpbWl0ZWQgTGlhYmlsaXR5
LCByZWFkIHRoZSBzZWN0aW9uICpMZWdhbCBMaW1pdGF0aW9ucyogb2YgdGhlIFN0YXJ0Q29tIENl
cnRpZmljYXRpb24gQXV0aG9yaXR5IFBvbGljeSBhdmFpbGFibGUgYXQgaHR0cDovL2NlcnQuc3Rh
cnRjb20ub3JnL3BvbGljeS5wZGYwEQYJYIZIAYb4QgEBBAQDAgAHMDgGCWCGSAGG+EIBDQQrFilT
dGFydENvbSBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOC
AgEAFmyZ9GYMNPXQhV59CuzaEE44HF7fpiUFS5Eyweg78T3dRAlbB0mKKctmArexmvclmAk8jhvh
3TaHK0u7aNM5Zj2gJsfyOZEdUauCe37Vzlrk4gNXcGmXCPleWKYK34wGmkUWFjgKXlf2Ysd6AgXm
vB618p70qSmD+LIU424oh0TDkBreOKk8rENNZEXO3SipXPJzewT4F+irsfMuXGRuczE6Eri8sxHk
fY+BUZo7jYn0TZNmezwD7dOaHZrzZVD1oNB1ny+v8OqCQ5j4aZyJecRDjkZy42Q2Eq/3JR44iZB3
fsNrarnDy0RLrHiQi+fHLB5LEUTINFInzQpdn4XBidUaePKVEFMy3YCEZnXZtWgo+2EuvoSoOMCZ
EoalHmdkrQYuL6lwhceWD3yJZfWOQ1QOq92lgDmUYMA0yZZwLKMS9R9Ie70cfmu3nZD0Ijuu+Pwq
yvqCUqDvr0tVk+vBtfAii6w0TiYiBKGHLHVKt+V9E9e4DGTANtLJL4YSjCMJwRuCO3NJo2pXh5Tl
1njFmUNj403gdy3hZZlyaQQaRwnmDwFWJPsfvw55qVguucQJAX6Vum0ABj6y6koQOdjQK/W/7HW/
lwLFCRsI3FU34oH7N4RDYiDK51ZLZer+bMEkkyShNOsF/5oirpt9P/FlUQqmMGqz9IgcgA38coro
g14=
-----END CERTIFICATE-----
"""
