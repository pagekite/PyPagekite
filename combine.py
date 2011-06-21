#!/usr/bin/python
import os, sys

data =  { }
order = [ ]
for filename in sys.argv[1:]:
  fd = open(filename, 'r')
  bn = os.path.basename(filename).replace('.py', '')
  order.append(bn)
  data[bn] = [l.replace('\n', '').replace('\r', '') for l in fd.readlines()]
  fd.close() 

print """#!/usr/bin/python'
# This is a compilation of multiple Python files. Search for the string
# 'MODULE' to examine individual parts.
"""

first = order.pop(0)
for mn in order:
  print '##[ MODULE: %s ]%s' % (mn, '#' * (65-len(mn)))
  print
  print 'class %s(object):' % mn
  for line in data[mn]:
    print ' %s' % line
  print

print '##[ MAIN: %s ]%s' % (first, '#' * (67-len(first)))
print
for line in data[first]:
  print '%s' % line

