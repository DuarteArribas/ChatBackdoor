class ClientHandler:
  # == Methods ==
  def __init__(self):
    """Initalize handler."""
    self.CLIENT_HANDLER_METHOD = {
      1: self.authenticate
    }

  def process(self,option,args = None):
    """Process an option received by the client and call the appropriate client handler method.
    
    Parameters
    ----------
    option : int
      The chosen menu option
    args   : tuple
      The arguments sent by the client
    Return
    ----------
    dict
      The code to be treated by the client and the respective arguments
    """
    if args == None:
      return self.CLIENT_HANDLER_METHOD[option]()
    else:
      return self.CLIENT_HANDLER_METHOD[option](args)
  
  def authenticate(self,args):
    return {"code": 1, "args": "arroz"}