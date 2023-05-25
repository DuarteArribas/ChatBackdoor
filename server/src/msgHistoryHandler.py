import pickle
from datetime import datetime
import time
from Crypto.Hash import SHA512
from Crypto.Hash          import SHA512
from Crypto.Cipher        import AES
from Crypto.Util.Padding  import pad
from Crypto.PublicKey     import RSA
from Crypto.PublicKey     import ElGamal
from Crypto.Hash          import HMAC, SHA512
from Crypto.Signature     import pkcs1_15
from Crypto.Util.Padding import unpad
import os
from queue import Queue

class MsgHistoryHandler:
  # == Methods ==
  def __init__(self,con,cur,connectedUsernames,ivKey,iv):
    """Initalize handler.
    
    Parameters
    ----------
    con                   : sqlite3.Connection
      The connection to the local database
    cur                   : sqlite3.Cursor
      The cursor to the local database
    connectedUsernames    : list
      The list of usernames of connected clients
    ivKey                 : str
      The key used to encrypt the messages
    iv                    : str
      The initialization vector used to encrypt the messages
    """
    self.MSG_HISTORY_HANDLER_METHOD = {
      0: self.getHistoricalMessages
    }
    self.con                   = con
    self.cur                   = cur
    self.connectedUsernames    = connectedUsernames
    self.ivKey                 = ivKey
    self.iv                    = iv
  
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
      return self.MSG_HISTORY_HANDLER_METHOD[option]()
    else:
      return self.MSG_HISTORY_HANDLER_METHOD[option](args)
  
  def getHistoricalMessages(self,args):
    """Get historical messages from the database. 
    
    Parameters
    ----------
    args : tuple
      args[0] = username of current user
      args[1] = friendUsername
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
      args : str
        confirmation of logout if successful
        exception message if unsuccessful
    """
    try:
      username       = args[0]
      friendUsername = args[1]
      maxMessages    = args[2]
      self.cur.execute("SELECT username1,message FROM messages WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?) ORDER BY ID DESC LIMIT ?;",(username,friendUsername,friendUsername,username,maxMessages))
      messages = self.cur.fetchall()
      print(f"{username} has just asked for the previous messages with {friendUsername}!")
      return {'code': 0,'args': messages}
    except Exception as e:
      return {'code': 1,'args': "An unknown error occurred."}