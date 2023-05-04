import socket
import pickle
from src.utils.optionArgs import *

class ChatClient:
  """Arroz.
  
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

  def runClient(self,arguments):
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
      self._handleClientActions(arguments[0],arguments[1:])

  def _handleClientActions(self,option,args):
    """Handle client actions.
    Parameters
    ----------
    option : str
      Upload | Download
    args   : list
      The upload arguments
    """
    if option == "a":
      self.socket.send(pickle.dumps(OptionArgs(1,(args))))
      response = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
      print(response)