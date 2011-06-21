#!/usr/bin/python
#
# This is a poor-man's executable builder, for embedding dependencies into
# our pagekite.py file until we have proper packaging.
#
import os, sys

pydata = { }
data =  { }
order = [ ]
for filename in sys.argv[1:]:
  if filename.endswith('/__init__.py'):
    bn = os.path.basename(os.path.dirname(filename))
  else:
    bn = os.path.basename(filename).replace('.py', '')

  order.append(bn)

  fd = open(filename, 'r')
  lines = [l.replace('\n', '').replace('\r', '') for l in fd.readlines()]
  fd.close() 

  if filename.endswith('.py') or filename.endswith('.pyw'):
    pydata[bn] = lines
  else:
    data[bn] = lines

print """#!/usr/bin/python
#
# NOTE: This is a compilation of multiple Python files.
#       See below for details on individual segments.
#
import sys, imp

"""

for mn in order:
  if mn in pydata:
    what = 'MODULE'
    ddict = pydata
  else:
    what = 'FILE'
    ddict = data

  print '%s' % '#' * 79
  print
  if mn != order[-1] and what == 'MODULE':
    print 'sys.modules["%s"] = imp.new_module("%s")' % (mn, mn)
    print 'exec """'
    for line in ddict[mn]:
      print '%s' % line.replace('\\', '\\\\').replace('"', '\\"')
    print '""" in sys.modules["%s"].__dict__' % mn

  elif what == 'FILE':
    print '__DATA_%s = """' % mn.replace('.', '_').upper()
    for line in ddict[mn]:
      print '%s' % line.replace('\\', '\\\\').replace('"', '\\"')
    print '"""'

  else:
    for line in ddict[mn]:
      print '%s' % line

  print

