import sys
import pagekite as pk

if sys.stdout.isatty():
  pk.Main(pk.PageKite, pk.Configure, uiclass=pk.BasicUi)
else:
  pk.Main(pk.PageKite, pk.Configure)
