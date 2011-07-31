import sys
import pagekite as pk
import pagekite.httpd as httpd

def Configure(pkobj):
  pkobj.rcfile = "/sdcard/pagekite.cfg"
  pkobj.enable_sslzlib = True
  pk.Configure(pkobj)

if __name__ == "__main__":
  if sys.stdout.isatty():
    import pagekite.basicui
    uiclass = pagekite.basicui.BasicUi
  else:
    uiclass = pk.NullUi

  pk.Main(pk.PageKite, Configure,
          uiclass=uiclass,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

