import secrets
from src.elipticCurves import EllipticCurves
class ClientHandler:
  # == Methods ==
  def __init__(self):
    """Initalize handler."""
    self.CLIENT_HANDLER_METHOD = {
      0: self.registerChap1
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
  
  # Implementation of the CHAP protocol for authentication
  # Server will verify the authentication of the client
  # Client will send an authentication request

  # Code 0 == success, 1 == Failure
  def registerChap1(self,args):
    ec = EllipticCurves()
    keys = ec.generateKeys()
    
    
    
    return {'code': 0,'args': keys[0]}


  def authenticateParaDepois(self):
    nonce = secrets.randbits(128)

    
    return {'code': 0,'args': nonce}
    
    

