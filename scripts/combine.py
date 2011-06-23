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
  if '"' in filename or '\\' in filename:
    raise ValueError('Cannot handle " or \\ in filenames')

  order.append(filename)
  fd = open(filename, 'r')
  lines = [l.replace('\n', '').replace('\r', '') for l in fd.readlines()]
  fd.close() 

  if filename.endswith('.py') or filename.endswith('.pyw'):
    pydata[filename] = lines
  else:
    data[filename] = lines

print """#!/usr/bin/python
#
# NOTE: This is a compilation of multiple Python files.
#       See below for details on individual segments.
#
import imp, os, sys, StringIO

__FILES = {}
__os_path_exists = os.path.exists
__builtin_open = open

def __comb_open(filename, *args, **kwargs):
  if filename in __FILES:
    return StringIO.StringIO(__FILES[filename])
  else:
    return __builtin_open(filename, *args, **kwargs)

def __comb_exists(filename, *args, **kwargs):
  if filename in __FILES:
    return True
  else:
    return __os_path_exists(filename, *args, **kwargs)

open = __comb_open
os.path.exists = __comb_exists
sys.path[0:0] = ['/__PACK__/']

"""

for mn in order:
  if mn in pydata:
    what = 'MODULE'
    ddict = pydata
  else:
    what = 'FILE'
    ddict = data

  if mn.endswith('/__init__.py'):
    bn = os.path.basename(os.path.dirname(mn))
  else:
    bn = os.path.basename(mn).replace('.py', '')

  print '%s' % '#' * 79
  print
  if mn != order[-1] and what == 'MODULE':
    print '__FILES["/__PACK__/%s"] = """\\' % mn
    for line in ddict[mn]:
      print '%s' % line.replace('\\', '\\\\').replace('"', '\\"')
    print '"""'
    print 'sys.modules["%s"] = imp.new_module("%s")' % (bn, bn)
    print 'sys.modules["%s"].open = __comb_open' % (bn, )
    print 'exec __FILES["/__PACK__/%s"] in sys.modules["%s"].__dict__' % (mn, bn)

  elif what == 'FILE':
    print '__FILES["/__PACK__/%s"] = """\\' % mn
    for line in ddict[mn]:
      print '%s' % line.replace('\\', '\\\\').replace('"', '\\"')
    print '"""'

  else:
    for line in ddict[mn]:
      print '%s' % line

  print

