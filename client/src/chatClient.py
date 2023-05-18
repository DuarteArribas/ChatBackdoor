import socket
import pickle
import threading
from src.utils.optionArgs import *
from src.ellipticCurves   import *
from Crypto.Protocol.KDF  import PBKDF2
from Crypto.Hash          import SHA512
from Crypto.Random        import get_random_bytes
from Crypto.Cipher        import AES
from base64               import b64encode
from Crypto.Util.Padding  import pad
from src.chap             import Chap
from src.menu             import Menu
import os
import os.path

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
  def __init__(self,ip,port,port2,menuHandler):
    """Initialize a socket connection with the server.
    Parameters
    ----------
    ip   : str
      The ip of the server
    port : int
      The port of the server
    """
    self.ip          = ip
    self.port        = int(port)
    self.port2       = int(port2)
    self.menuHandler = menuHandler
    self.username    = None
  
  def runClient(self,option):
    """Run the client.
    
    Parameters
    ----------
    arguments : list
      The list of command-line arguments. arguments[0] is the option
      The list of command-line arguments. arguments[1:] is the args
    """
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      s.connect((self.ip,self.port))
      self.socket = s
      self._handleClientActions(option)
  
  def runKeyClient(self):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s2:
      s2.connect((self.ip,self.port2))
      self.socket2 = s2
      self._handleClientKeyExchange()

  def _handleClientActions(self,option):
    """Handle client actions.
    Parameters
    ----------
    option   : str
      Upload | Download
    currMenu : Menu.MENUS
      The current menu
    """
    if self.menuHandler.currMenu == Menu.MENUS.INITIAL:
      if option == 1:
        self.chapRegister()
      elif option == 2:
        self.chapLogin()
        print("cucu")
    elif self.menuHandler.currMenu == Menu.MENUS.MAIN:
      if option == 1:
        self.menuHandler.currMenu = Menu.MENUS.FRIEND
      elif option == 2:
        self.sendMessage()
      elif option == 3:
        pass
      elif option == 0:
        print("aaaa")
        self.logout()
    elif self.menuHandler.currMenu == Menu.MENUS.FRIEND:
      if option == 1:
        self.addFriend()
      elif option == 2:
        self.friendRequests()
      elif option == 3:
        self.showFriendsList()
      elif option == 4:
        self.removeFriend()
      elif option == 0:
        self.menuHandler.currMenu = Menu.MENUS.MAIN
  
  def _handleClientKeyExchange(self):
    try:
      while True:
        optionArgs = pickle.loads(self.socket2.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
        print(optionArgs)
        if optionArgs["code"] == 2:
          print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
          ec = EllipticCurves()
          keys = ec.generateKeys()
          keyPoint = ec.multiplyPointByScalar(optionArgs['args'][1],keys[1])
          key = str(keyPoint[0])
          if not os.path.exists(f"client/out/{self.username}Keys/{optionArgs['args'][0]}-{self.username}"):
            os.makedirs(f"client/out/{self.username}Keys/{optionArgs['args'][0]}-{self.username}")
          with open(f"client/out/{self.username}Keys/{optionArgs['args'][0]}-{self.username}/{optionArgs['args'][2]}","w") as f:
            f.write(key)
          self.socket2.send(pickle.dumps(OptionArgs(1,(optionArgs['args'][0],keys[0])))) 
    except Exception as e:
      print(e)
  
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
    #print(self.socket)
    print(self.socket2)
    self.socket.send(pickle.dumps(OptionArgs(3,(username,challenge,str(self.socket),str(self.socket2)))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
    elif optionArgs["code"] == 0:
      print(optionArgs["args"])
      self.menuHandler.currMenu = Menu.MENUS.MAIN
      self.username = username
  
  def addFriend(self):
    friend = input("Friend Username: (0 to exit) ")
    if friend == "0":
      return
    self.socket.send(pickle.dumps(OptionArgs(4,(self.username,friend))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    print(optionArgs["args"])
  
  def friendRequests(self):
    self.socket.send(pickle.dumps(OptionArgs(5,(self.username,))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    else:
      print("===== Friend Requests =====")
      for index,friendRequest in enumerate(optionArgs["args"]):
        print(f"{index+1} -> {friendRequest[0]}")
      print("===========================")
      friendsToAccept = []
      while True:
        accept = input("Please insert the friends you want to accept separated by commas (0 to exit,y to skip): ")
        if accept == "0":
          return
        if accept == "y":
            break
        friendsToAccept = accept.split(",")
        if len([friend for friend in friendsToAccept if int(friend) not in list(range(1,len(optionArgs["args"]) + 1))]) > 0:
          print("Invalid friend request")
          continue
        else:
          break
      friendsToReject = []
      if len(optionArgs["args"]) - len(friendsToAccept) != 0:
        while True:
          reject = input("Please insert the friends you want to reject separated by commas (0 to exit,y to skip): ")
          if reject == "0":
            return
          if reject == "y":
            break
          friendsToReject = reject.split(",")
          if len([friend for friend in friendsToReject if int(friend) not in list(range(1,len(optionArgs["args"]) + 1))]) > 0:
            print("Invalid friend request")
            continue
          elif len([friend for friend in friendsToReject if friend in friendsToAccept]) > 0:
            print("You have already accepted this friend request; if you wish to discard your acceptance, please input 0.")
            continue
          else:
            break
      friendsToAccept = [optionArgs["args"][int(friend) - 1][0] for friend in friendsToAccept]
      friendsToReject = [optionArgs["args"][int(friend) - 1][0] for friend in friendsToReject]
      self.socket.send(pickle.dumps(OptionArgs(6,(self.username,friendsToAccept,friendsToReject))))
      optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
      print(optionArgs["args"])
  
  def showFriendsList(self):
    self.socket.send(pickle.dumps(OptionArgs(7,(self.username,))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    else:
      print("===== Friends List =====")
      for index,friend in enumerate(optionArgs["args"]):
        print(f"{index+1}: {friend}")
      print("========================")
  
  def removeFriend(self):
    self.socket.send(pickle.dumps(OptionArgs(7,(self.username,))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    else:
      print("===== Friends List =====")
      for index,friend in enumerate(optionArgs["args"]):
        print(f"{index+1}: {friend}")
      print("========================")
    while True:
      friendToRemove = input("Please insert the friend you wish to erase (0 to exit): ")
      if friendToRemove == "0":
        return
      if int(friendToRemove) not in list(range(1,len(optionArgs["args"]) + 1)):
        print("Invalid friend")
        continue
      else:
        break
    self.socket.send(pickle.dumps(OptionArgs(8,(self.username,optionArgs["args"][int(friendToRemove) - 1][0]))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    print(optionArgs["args"])
  
  def logout(self):
    """Logs user out.
    """
    self.socket.send(pickle.dumps(OptionArgs(9,(self.username,))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
    else:
      self.menuHandler.currMenu = Menu.MENUS.INITIAL
      self.username = ""
      print(optionArgs["args"])
  
  def sendMessage(self):
    self.socket.send(pickle.dumps(OptionArgs(7,(self.username,))))
    optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    else:
      print("===== Friends List =====")
      for index,friend in enumerate(optionArgs["args"]):
        if friend.split(" ")[1] == "(online)":
          print(f"{index+1}: {friend}")
      print("========================")
    while True:
      friendToSend = input("Please insert the friend you wish to send the message to (0 to exit): ")
      if friendToSend == "0":
        return
      if int(friendToSend) not in list(range(1,len(optionArgs["args"]) + 1)):
        print("Invalid friend")
        continue
      else:
        break
    ec   = EllipticCurves()
    X,dA = ec.generateKeys()
    print("LOOOOAOAOAOA")
    friendToSend = optionArgs["args"][int(friendToSend) - 1].split(" ")[0].split(" ")[0]
    self.socket2.send(pickle.dumps(OptionArgs(0,(self.username,friendToSend,X,"cipher"))))
    print("LULA")
    optionArgs = pickle.loads(self.socket2.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    print("aopapaoa")
    print("CCUCUCUCCUUCUCUCUCUCU")
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    Y = optionArgs["args"][0]
    keyPoint = ec.multiplyPointByScalar(Y,dA)
    key = str(keyPoint[0])
    if not os.path.exists(f"client/out/{self.username}Keys/{self.username}-{friendToSend}"):
      os.makedirs(f"client/out/{self.username}Keys/{self.username}-{friendToSend}")
    with open(f"client/out/{self.username}Keys/{self.username}-{friendToSend}/cipher","w") as f:
      f.write(key)
    print("CARAMBA PA")
    
    
    
      
      
      
      
    #
    #message = input("Please insert the message you wish to send: ")
    #
    #
    #self.socket.send(pickle.dumps(OptionArgs(10,(self.username,optionArgs["args"][int(friendToSend) - 1][0],message))))
    #optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    #print(optionArgs["args"])