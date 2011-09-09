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
    #print '<<PK<< %s' % data.strip()
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
    if self.pk: self.send('exit: quitting\n')
    self.close()


class CommThread(threading.Thread):
  def __init__(self, pkThread):
    threading.Thread.__init__(self)
    self.pkThread = pkThread
    self.looping = False

    # Callbacks
    self.cb = {}

  def run(self):
    self.pkThread.start()
    self.looping = True
    line = ''
    while self.looping:
      line += self.pkThread.recv(1)
      if line.endswith('\n'):
        command, args = line.strip().split(': ', 1)
        if command in self.cb:
          self.cb[command](args)
        line = ''

  def quit(self):
    self.pkThread.quit()
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
          <menuitem action="EnablePageKite"/>
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

  def __init__(self, pkComm):
    gtk.StatusIcon.__init__(self)

    self.pkComm = pkComm
    self.pkComm.cb['status_tag'] = self.set_status_tag
    self.pkComm.cb['status_msg'] = self.set_status_msg
    self.set_tooltip('PageKite')

    self.icon_file = ICON_FILE_IDLE
    if sys.platform in ('win32', 'os2', 'os2emx'):
      self.icon_dir = ICON_DIR_WINDOWS
    else:
      self.icon_dir = ICON_DIR_DEFAULT
    self.set_from_file(os.path.join(self.icon_dir, self.icon_file))

    self.connect('activate', self.on_activate)
    self.connect('popup-menu', self.on_popup_menu)
    #gobject.timeout_add_seconds(1, self.on_tick)

    self.pkComm.start()
    self.set_visible(True)

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
      ('EnablePageKite', None, '_Enable PageKite', None, 'Enable local PageKite', self.toggle_enable, (not self.pkComm.pkThread.stopped)),
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
        w(item).set_sensitive(not self.pkComm.pkThread.stopped)
      except:
        print '!!! No item: %s' % item


    if self.pkComm.pkThread.stopped:
      w('/Menubar/Menu/QuotaDisplay').hide()
      w('/Menubar/Menu/GetQuota').hide()
    else:
      w('/Menubar/Menu/QuotaDisplay').show()
      w('/Menubar/Menu/GetQuota').show()

    self.menu.popup(None, None, None, button, when)

  def toggle_enable(self, data):
    pkt = self.pkComm.pkThread
    pkt.toggle()
    data.set_active(not pkt.stopped)

  def on_stub(self, data):
    print 'Stub'

  def on_about(self, data):
    dialog = gtk.AboutDialog()
    dialog.set_name('PageKite')
    dialog.set_version(pagekite.APPVER)
    dialog.set_comments('PageKite is a tool for running personal servers, '
                        'sharing work and communicating over the WWW.')
    dialog.set_website(pagekite.WWWHOME)
    dialog.set_license(pagekite.LICENSE)
    dialog.run()
    dialog.destroy()

  def quit(self, data):
    self.set_status_tag('exiting')
    self.set_status_msg('Shutting down...')
    self.pkComm.quit()
    gobject.timeout_add_seconds(1, self.quitting)

  def quitting(self):
    if self.pkComm and self.pkComm.pkThread and self.pkComm.pkThread.pk:
      return
    sys.exit(0)


if __name__ == '__main__':
  sys.argv.append('--friendly')
  pkt = pksi = ct = None
  try:
    pkt = PageKiteThread()
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
