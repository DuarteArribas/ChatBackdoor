import pickle
import os
import select
from src.ellipticCurves import *
from src.utils.optionArgs import OptionArgs

class KeyOptionHandler:
  """
  Attributes
  ----------
  NUMBER_BYTES_TO_RECEIVE : int
    The max number of bytes to receive
  """
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384

  # == Methods ==
  def __init__(self,keySocket,clientKeysPath,username,canBazar):
    """Initialize the key option handler.
    
    Parameters
    ----------
    keySocket : socket
      The socket with the key thread
    clientKeysPath : str
      The path of the client keys
    username : str
      The username of the client
    """
    self.keySocket  = keySocket
    self.clientKeysPath = clientKeysPath
    self.username = username
    self.canBazar    = canBazar
  
  def handleClientKeyExchange(self):
    """Handle the client key exchange."""
    while True:
      try:
        readable, _, _ = select.select([self.keySocket[0]], [], [], 1)
        if readable:
          optionArgs = pickle.loads(self.keySocket[0].recv(KeyOptionHandler.NUMBER_BYTES_TO_RECEIVE))
          if optionArgs["code"] == 2:
            ec = EllipticCurves()
            keys = ec.generateKeys()
            keyPoint = ec.multiplyPointByScalar(optionArgs['args'][1],keys[1])
            key = str(keyPoint[0])
            clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{optionArgs['args'][0]}-{self.username[0]}")
            if not os.path.exists(clientKeysPath):
              os.makedirs(clientKeysPath)
            with open(os.path.join(clientKeysPath,optionArgs['args'][2]),"w") as f:
              f.write(key)
            self.keySocket[0].send(pickle.dumps(OptionArgs(1,(optionArgs['args'][0],keys[0]))))
          elif optionArgs["code"] == 4:
            clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{optionArgs['args'][0]}-{self.username[0]}",optionArgs['args'][2])
            if not os.path.exists(clientKeysPath):
              os.makedirs(clientKeysPath)
            with open(os.path.join(clientKeysPath,"y"),"w") as f:
              f.write(optionArgs['args'][1][0].decode("latin-1"))
            with open(os.path.join(clientKeysPath,"g"),"w") as f:
              f.write(optionArgs['args'][1][1].decode("latin-1"))
            with open(os.path.join(clientKeysPath,"p"),"w") as f:
              f.write(optionArgs['args'][1][2].decode("latin-1"))
            self.keySocket[0].send(pickle.dumps(OptionArgs(4,("Success"))))
        else:
          if self.canBazar[0]:
            exit(0)
      except Exception as e:
        print(e)