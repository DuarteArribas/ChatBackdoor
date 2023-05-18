from src.ellipticCurves import EllipticCurves
import pickle
class KeyExchangeHandler:
  # == Methods ==
  def __init__(self,con,cur,connectedUsernames,keyClientAndUsernames):
    """Initalize handler.
    
    Parameters
    ----------
    con : sqlite3.Connection
      The connection to the local database
    cur : sqlite3.Cursor
      The cursor to the local database
    """
    self.CLIENT_HANDLER_METHOD = {
      0: self.exchangeKeys1,
      1: self.exchangeKeys2
    }
    self.con                   = con
    self.cur                   = cur
    self.connectedUsernames    = connectedUsernames
    self.keyClientAndUsernames = keyClientAndUsernames

  def process(self,option,currClient,args = None):
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
    print("option",option)
    print("args",args)
    if args == None:
      return self.CLIENT_HANDLER_METHOD[option](currClient)
    else:
      return self.CLIENT_HANDLER_METHOD[option](currClient,args)
    
  def exchangeKeys1(self,currClient,args):
    try:
      username = args[0]
      friendUsername = args[1]
      X = args[2]
      cipherMac = args[3]
      if friendUsername not in self.connectedUsernames:
        return {'code': 1,'args': "Friend is not online."}
      for host,u in self.keyClientAndUsernames:
        if u == friendUsername:
          host.send(pickle.dumps({'code': 2,'args': (username,X,cipherMac)}))
          return host
    except Exception as e:
      print("2",e)
  
  def exchangeKeys2(self,currClient,args):
    try:
      username = args[0]
      Y = args[1]
      for host,u in self.keyClientAndUsernames:
        if u == username:
          return {'code': 0,'args': (Y,)}
    except Exception as e:
      print("1",e)