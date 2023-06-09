from src.ellipticCurves import EllipticCurves
import pickle
class KeyExchangeHandler:
  # == Methods ==
  def __init__(self,con,cur,connectedUsernames,keyClientAndUsernames,keyClientAndUsernames2):
    """Initalize handler.
    
    Parameters
    ----------
    con                   : sqlite3.Connection
      The connection to the local database
    cur                   : sqlite3.Cursor
      The cursor to the local database
    connectedUsernames    : list
      The list of usernames of connected clients
    keyClientAndUsernames : list
      The list of clients for key exchange and respective usernames
    """
    self.KEY_HANDLER_METHOD = {
      0: self.exchangeKeys1,
      1: self.exchangeKeys2
    }
    self.con                   = con
    self.cur                   = cur
    self.connectedUsernames    = connectedUsernames
    self.keyClientAndUsernames = keyClientAndUsernames
    self.keyClientAndUsernames2 = keyClientAndUsernames2

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
      return self.KEY_HANDLER_METHOD[option]()
    else:
      return self.KEY_HANDLER_METHOD[option](args)
    
  def exchangeKeys1(self,args):
    """Exchange keys between two clients.
    
    Parameters
    ----------
    args : tuple
      args[0] : str
        The username of the client
      args[1] : str
        The username of the friend
      args[2] : int
        The X point of the client's key
      args[3] : str
        The type of the client's key (AES, HMAC, RSA)
    
    Return
    ----------
    dict
      code : int
        2 if successful
        1 if unsuccessful
      args : str
        exception message if unsuccessful
        tuple of username, key point and cipher MAC if successful
    """
    try:
      username = args[0]
      friendUsername = args[1]
      X = args[2]
      keyType = args[3]
      for host,u in self.keyClientAndUsernames:
        if u == friendUsername:
          host.send(pickle.dumps({'code': 2,'args': (username,X,keyType)}))
          return host
    except Exception:
      return {'code': 1,'args': "An unknown error occurred."}
  
  def exchangeKeys2(self,args):
    """Exchange keys between two clients.
    
    Parameters
    ----------
    args : tuple
      args[0] : str
        The username of the client
      args[1] : int
        The Y point of the client's key
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
      args : str
        exception message if unsuccessful
        tuple of Y point if successful
    """
    try:
      username = args[0]
      Y = args[1]
      for host,u in self.keyClientAndUsernames2:
        if u == username:
          host.send(pickle.dumps({'code': 0,'args': (Y,)}))
    except Exception:
      return {'code': 1,'args': "An unknown error occurred."}