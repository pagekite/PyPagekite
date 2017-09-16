"""
Logging.
"""
##############################################################################
LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2017, the Beanstalks Project ehf. and Bjarni Runar Einarsson

This program is free software: you can redistribute it and/or modify it under
the terms of the  GNU  Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,  but  WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see: <http://www.gnu.org/licenses/>
"""
##############################################################################
import time
import sys

import compat, common
from compat import *
from common import *

syslog = compat.syslog
org_stdout = sys.stdout

DEBUG_IO = False

LOG = []
LOG_LINE = 0
LOG_LENGTH = 300
LOG_THRESHOLD = 256 * 1024

def LogValues(values, testtime=None):
  global LOG, LOG_LINE, LOG_LAST_TIME
  now = int(testtime or time.time())
  words = [('ts', '%x' % now),
           ('t',  '%s' % ts_to_iso(now)),
           ('ll', '%x' % LOG_LINE)]
  words.extend([(kv[0], ('%s' % kv[1]).replace('\t', ' ')
                                      .replace('\r', ' ')
                                      .replace('\n', ' ')
                                      .replace('; ', ', ')
                                      .strip()) for kv in values])
  wdict = dict(words)
  LOG_LINE += 1
  LOG.append(wdict)
  while len(LOG) > LOG_LENGTH:
    LOG[0:(LOG_LENGTH/10)] = []

  return (words, wdict)

def LogSyslog(values, wdict=None, words=None):
  if values:
    words, wdict = LogValues(values)
  if 'err' in wdict:
    syslog.syslog(syslog.LOG_ERR, '; '.join(['='.join(x) for x in words]))
  elif 'debug' in wdict:
    syslog.syslog(syslog.LOG_DEBUG, '; '.join(['='.join(x) for x in words]))
  else:
    syslog.syslog(syslog.LOG_INFO, '; '.join(['='.join(x) for x in words]))

def LogToFile(values, wdict=None, words=None):
  if values:
    words, wdict = LogValues(values)
  try:
    global LogFile
    LogFile.write('; '.join(['='.join(x) for x in words]))
    LogFile.write('\n')
  except (OSError, IOError):
    # Avoid crashing if the disk fills up or something lame like that
    pass

def LogToMemory(values, wdict=None, words=None):
  if values:
    LogValues(values)

def FlushLogMemory():
  global LOG
  for l in LOG:
    Log(None, wdict=l, words=[(w, l[w]) for w in l])

def LogError(msg, parms=None):
  emsg = [('err', msg)]
  if parms: emsg.extend(parms)
  Log(emsg)

  if common.gYamon:
    common.gYamon.vadd('errors', 1, wrap=1000000)

def LogDebug(msg, parms=None):
  emsg = [('debug', msg)]
  if parms: emsg.extend(parms)
  Log(emsg)

def LogInfo(msg, parms=None):
  emsg = [('info', msg)]
  if parms: emsg.extend(parms)
  Log(emsg)

def ResetLog():
  global LogFile, Log, org_stdout
  LogFile = org_stdout
  Log = LogToMemory

ResetLog()

