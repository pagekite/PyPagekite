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
    '--kitename=%s' % kn,
    '--kitesecret=%s' % ss,
    '--all'
  ]
  sys.argv.extend('@ARGS@'.split())

  pk.Main(pk.PageKite, pk.Configure,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

