import socket
import pickle
from src.utils.optionArgs import *
from src.ellipticCurves   import *
from Crypto.Protocol.KDF  import PBKDF2
from Crypto.Hash          import SHA512
from Crypto.Random        import get_random_bytes
from Crypto.Cipher        import AES
from base64               import b64encode
from Crypto.Util.Padding  import pad
from src.chap             import Chap

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
    if option == 1:
      self.chapRegister()
    elif option == 2:
      self.chapLogin()
      
  def chapRegister(self):
    username = input("Username: (0 to exit) ")
    if username == "0":
      return
    self.socket.send(pickle.dumps(OptionArgs(0,(username,))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    while optionArgs["code"] == 1:
      print(optionArgs["args"])
      username = input("Username: (0 to exit) ")
      if username == "0":
        return
      self.socket.send(pickle.dumps(OptionArgs(0,(username,))))
      optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    ec = EllipticCurves()
    keys = ec.generateKeys()
    keyPoint = ec.multiplyPointByScalar(optionArgs['args'],keys[1])
    key = str(keyPoint[0])
    password = input("Password: (0 to exit) ")
    if password == "0":
      return
    salt = get_random_bytes(16)
    derivedPasswordKey = PBKDF2(key,salt,16,count=1000000,hmac_hash_module=SHA512)
    iv = get_random_bytes(16)
    cipher = AES.new(derivedPasswordKey,AES.MODE_CBC,iv)
    cipherTextBytes = cipher.encrypt(pad(password.encode('utf-8'),AES.block_size))
    cipherText = b64encode(cipherTextBytes).decode('utf-8')
    self.socket.send(pickle.dumps(OptionArgs(1,(keys[0],username,salt,iv,cipherText))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    print(optionArgs["args"])
  
  def chapLogin(self):
    username = input("Username: (0 to exit) ")
    if username == "0":
      return
    self.socket.send(pickle.dumps(OptionArgs(2,(username,))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    while optionArgs["code"] == 1:
      print(optionArgs["args"])
      username = input("Username: (0 to exit) ")
      if username == "0":
        return
      self.socket.send(pickle.dumps(OptionArgs(2,(username,))))
      optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    nonce = optionArgs["args"]
    password = input("Password: (0 to exit) ")
    if password == "0":
      return
    challenge = Chap.getChapChallenge(nonce,password)
    self.socket.send(pickle.dumps(OptionArgs(3,(username,challenge))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    elif optionArgs["code"] == 0:
      print(optionArgs["args"])
      return