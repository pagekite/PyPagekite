import sys
import pagekite as pk
import pagekite.httpd as httpd

if __name__ == "__main__":
  if len(sys.argv) == 1:
    sys.argv.extend([
      '--daemonize',
      '--logfile=/tmp/pagekite-@KITENAME@.log',
    ])
  sys.argv[1:1] = [
    '--clean',
    '--noloop',
    '--nocrashreport',
    '--defaults',
    '--backend=https/8081:@KITENAME@:localhost:2381:@SECRET@',
    '--backend=raw/22:@KITENAME@:localhost:22:@SECRET@',
    '--all'
  ]

  pk.Main(pk.PageKite, pk.Configure,
          uiclass=pk.NullUi,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

