import sys
import pagekite as pk
import pagekite.httpd as httpd

if sys.stdout.isatty():
  uiclass = pk.BasicUi
else:
  uiclass = None

pk.Main(pk.PageKite, pk.Configure,
        uiclass=uiclass,
        http_handler=httpd.UiRequestHandler,
        http_server=httpd.UiHttpServer)
