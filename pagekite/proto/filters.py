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

