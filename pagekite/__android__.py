import sys
import pagekite as pk
import pagekite.httpd as httpd

def Configure(pkobj):
  pkobj.rcfile = "/sdcard/pagekite.cfg"
  pkobj.enable_sslzlib = True
  pk.Configure(pkobj)

if __name__ == "__main__":
  if False:
    if '--nossl' not in sys.argv:
      sys.argv.append('--nossl')

    sys.argv.append('--logfile=stdio')
    sys.argv.append('--debugio')

  if sys.stdout.isatty():
    uiclass = pk.BasicUi
  else:
    uiclass = pk.NullUi

  pk.Main(pk.PageKite, Configure,
          uiclass=uiclass,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

