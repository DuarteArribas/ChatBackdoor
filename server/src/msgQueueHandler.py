from queue import Queue

class MsgQueueHandler:
  # == Methods ==
  def __init__(self,msgQueue):
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
    self.MSG_QUEUE_HANDLER_METHOD = {
      0: self.addMessageToQueue
    }
    self.msgQueue           = msgQueue

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
      return self.MSG_QUEUE_HANDLER_METHOD[option]()
    else:
      return self.MSG_QUEUE_HANDLER_METHOD[option](args)
  
  def addMessageToQueue(self,args):
    username          = args[0]
    friendUsername    = args[1]
    cipherText        = args[2]
    iv                = args[3]
    hmac              = args[4]
    N                 = args[5]
    e                 = args[6]
    rsaSig            = args[7]
    self.msgQueue.append((username,friendUsername,cipherText,iv,hmac,N,e,rsaSig))
    print("One more message has arrived!")