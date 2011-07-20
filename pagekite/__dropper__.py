import sys
import pagekite as pk
import pagekite.httpd as httpd

if __name__ == "__main__":
  kn = '@KITENAME@'
  ss = '@SECRET@'
  if len(sys.argv) == 1:
    sys.argv.extend([
      '--daemonize',
      '--runas=nobody',
      '--logfile=/tmp/pagekite-%s.log' % kn,
    ])
  sys.argv[1:1] = [
    '--clean',
    '--noloop',
    '--nocrashreport',
    '--defaults',
    '--backend=raw/22:%s:localhost:22:%s' % (kn, ss),
    '--all'
  ]
  sys.argv.extend('@ARGS@'.split())

  pk.Main(pk.PageKite, pk.Configure,
          uiclass=pk.NullUi,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

