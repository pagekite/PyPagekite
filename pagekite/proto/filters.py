#!/usr/bin/python -u
"""
These are filters placed at the end of a tunnel for watching or modifying
the traffic.
"""
##############################################################################
LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2012, the Beanstalks Project ehf. and Bjarni Runar Einarsson

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

class TunnelFilter:
  """Base class for watchers/filters for data going in/out of Tunnels.""" 

  def __init__(self, identifier):
    self.identifier = identifier
  
  def filter_set_sid(self, sid, info):
    pass

  def filter_data_in(self, tunnel, sid, data):
    return data

  def filter_data_out(self, tunnel, sid, data):
    return data

