#!/usr/bin/env python
import os
import gobject
import gtk
import sys
import socket
import threading
import time

import pagekite


URL_HOME = ('https://pagekite.net/home/')

ICON_DIR_WINDOWS = 'gui/icons-16'
ICON_DIR_DEFAULT = 'gui/icons-127'
ICON_FILE_ACTIVE  = 'pk-active.png'
ICON_FILE_TRAFFIC = 'pk-traffic.png'
ICON_FILE_IDLE    = 'pk-idle.png'


class PageKiteThread(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.looping = False
    self.stopped = True

  def Configure(self, pk):
    pass

  def run(self):
    while self.looping:
      time.sleep(1)
    self.stopped = True

  def quit(self):
    self.looping = False


class PageKiteStatusIcon(gtk.StatusIcon):
  KITEITEM_TEMPLATE = '''\
        <menu action="KiteMenu_%(count)s">
         %(services)s
        <separator/>
         <menu action="KiteSettings_%(count)s">
         <menu action="KiteDelete_%(count)s">
        </menu>
  '''
  SHARING_TEMPLATE = '''
        <separator/>
         <menuitem action="SharedItems"/>%(sharedlist)s
         <menuitem action="QuickShareClipBoard"/>
         <menuitem action="QuickSharePath"/>
         <menuitem action="QuickShareScreen"/>
  '''
  MENU_TEMPLATE = '''
      <ui>
       <menubar name="Menubar">
        <menu action="Menu">
         <menuitem action="QuotaDisplay"/>
         <menuitem action="GetQuota"/>
        <separator/>
         <menuitem action="PageKiteList"/>%(kitelist)s
         <menuitem action="AddKite"/>
        %(sharing)s
        <separator/>
         <menu action="AdvancedMenu">
          <menuitem action="ViewLog"/>
          <menuitem action="VerboseLog"/>
          <menuitem action="ConfigFile"/>
          <menuitem action="ConnectTo"/>
         </menu>
         <menuitem action="About"/>
         <menuitem action="Quit"/>
        </menu>
       </menubar>
      </ui>
  '''

  def __init__(self, pkThread):
    gtk.StatusIcon.__init__(self)

    self.pkThread = pkThread
    self.set_tooltip('PageKite')

    self.icon_file = ICON_FILE_IDLE
    if os.getenv('USERPROFILE'):
      self.icon_dir = ICON_DIR_WINDOWS
    else:
      self.icon_dir = ICON_DIR_DEFAULT
    self.set_from_file(os.path.join(self.icon_dir, self.icon_file))

    self.connect('activate', self.on_activate)
    self.connect('popup-menu', self.on_popup_menu)
    gobject.timeout_add_seconds(1, self.on_tick)

    self.set_visible(True)
    self.pkThread.start()

  def create_menu(self):
    self.manager = gtk.UIManager()
    ag = gtk.ActionGroup('Actions')
    ag.add_actions([
      ('Menu',  None, 'Menu'),

      ('QuotaDisplay', None, 'XX.YY GB of Quota left'),
      ('GetQuota', None, 'Get _More Quota...', None, 'Get more Quota from PageKite.net', self.on_stub),

      ('PageKiteList', None, 'Your kites:'),
       ('AddKite', None, 'New _Kite', None, 'Add Another PageKite', self.on_stub),

      ('SharedItems', None, 'Sharing:', None, 'Items you are currently sharing', self.on_stub),
       ('QuickShareClipBoard', None, '_Paste To Web', None, None, self.on_stub),
       ('QuickSharePath', None, 'Share _From Disk', None, None, self.on_stub),
       ('QuickShareScreen', None, 'Share _Screenshot', None, None, self.on_stub),

      ('AdvancedMenu', None, '_Advanced ...'),
       ('ViewLog', None, 'PageKite _Log', None, 'Display PageKite event log', self.on_stub),
       ('ConfigFile', None, '_Configuration', None, 'Edit the PageKite configuration file', self.on_stub),
       ('ConnectTo', None, 'Connect To ...', None, 'Connect to a remote PageKite'),

      ('About', gtk.STOCK_ABOUT, 'About', None, 'About PageKite', self.on_about),
      ('Quit', None, '_Quit PageKite', None, 'Turn PageKite off completely', self.quit),
    ])
    ag.add_toggle_actions([
      ('QuickShareEnabled', None, '_Enable Sharing', None, None, self.on_stub, False),
      ('VerboseLog', None, 'Verbose Logging', None, 'Verbose logging facilitate troubleshooting.', self.on_stub, False),
    ])

    self.manager.insert_action_group(ag, 0)
    self.manager.add_ui_from_string(self.MENU_TEMPLATE % {
      'kitelist': '',
      'sharing': '',
    })
    self.manager.get_widget('/Menubar/Menu/QuotaDisplay').set_sensitive(False)
    self.menu = self.manager.get_widget('/Menubar/Menu/About').props.parent

  def on_activate(self, data):
    self.create_menu()
    self.show_menu(0, 0)
    return False

  def on_tick(self):
    old_if = self.icon_file

    if self.pkThread.stopped:
      self.icon_file = ICON_FILE_IDLE
      self.set_tooltip('PageKite (idle)')
    else:
      traffic = False
      # FIXME: Detect traffic!
      if traffic:
        self.icon_file = ICON_FILE_TRAFFIC
        self.set_tooltip('PageKite (transmitting)')
      else:
        self.icon_file = ICON_FILE_ACTIVE
        self.set_tooltip('PageKite (active)')

    if self.icon_file != old_if:
      self.set_from_file(os.path.join(self.icon_dir, self.icon_file))

    return True

  def on_popup_menu(self, status, button, when):
    if self.menu.props.visible:
      self.menu.popdown()
    else:
      self.show_menu(button, when)
    return False

  def show_menu(self, button, when):
    w = self.manager.get_widget

    for item in ('/Menubar/Menu/PageKiteList',
                 '/Menubar/Menu/AddKite',
                 '/Menubar/Menu/SharedItems',
                 '/Menubar/Menu/QuickShareClipBoard',
                 '/Menubar/Menu/QuickSharePath',
                 '/Menubar/Menu/QuickShareScreen',
                 '/Menubar/Menu/AdvancedMenu/ViewLog',
                 '/Menubar/Menu/AdvancedMenu/VerboseLog'):
      try:
        w(item).set_sensitive(not self.pkThread.stopped)
      except:
        print '!!! No item: %s' % item

    if self.pkThread.stopped:
      w('/Menubar/Menu/QuotaDisplay').hide()
      w('/Menubar/Menu/GetQuota').hide()
    else:
      w('/Menubar/Menu/QuotaDisplay').show()
      w('/Menubar/Menu/GetQuota').show()

    self.menu.popup(None, None, None, button, when)

  def on_stub(self, data):
    print 'Stub'

  def on_about(self, data):
    dialog = gtk.AboutDialog()
    dialog.set_name('PageKite')
    dialog.set_version(pagekite.APPVER)
    dialog.set_comments('PageKite is a tool for running personal servers, '
                        'sharing work and communicating over the WWW.')
    dialog.set_website(pagekite.WWWHOME)
    dialog.run()
    dialog.destroy()

  def quit(self, data):
    self.pkThread.quit()
    sys.exit(0)


if __name__ == '__main__':
  pkt = PageKiteThread()
  try:
    pksi = PageKiteStatusIcon(pkt)
    gobject.threads_init()
    gtk.main()
  except:
    print '%s' % (sys.exc_info(), )
    pass
  pkt.quit()

