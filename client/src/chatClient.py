import socket
import pickle
import hashlib
from src.utils.optionArgs import *
from src.ellipticCurves   import *

class ChatClient:
  """
  Attributes
  ----------
  NUMBER_BYTES_TO_RECEIVE : int
    The max number of bytes to receive
  """
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384
  # == Methods ==
  def __init__(self,ip,port):
    """Initialize a socket connection with the server.
    Parameters
    ----------
    ip   : str
      The ip of the server
    port : int
      The port of the server
    """
    self.ip   = ip
    self.port = int(port)

  def runClient(self,option):
    """Run the client.
    
    Parameters
    ----------
    arguments : list
      The list of command-line arguments. arguments[0] is the option
      The list of command-line arguments. arguments[1:] is the args
    """
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      self.socket = s
      s.connect((self.ip,self.port))
      self._handleClientActions(option)

  def _handleClientActions(self,option):
    """Handle client actions.
    Parameters
    ----------
    option : str
      Upload | Download
    args   : list
      The upload arguments
    """
    if option == "chapRegister":
      self.chapRegister()      
      
  def chapRegister(self):
    username = input("Username: ")
    self.socket.send(pickle.dumps(OptionArgs(0,(username)))) #! se isto bugar e da ,
    X = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    ec = EllipticCurves()
    keys = ec.generateKeys()
    self.socket.send(pickle.dumps(OptionArgs(1,(keys[0]))))
    keyPoint = ec.multiplyPointByScalar(X,keys[1])
    key = str(keyPoint[0]) + str(keyPoint[1])
    with open(f"in/{username}","w") as f:
      f.write(key)