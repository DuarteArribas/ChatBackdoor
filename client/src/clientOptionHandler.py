import pickle
from Crypto.Protocol.KDF  import PBKDF2
from Crypto.Hash          import SHA512
from Crypto.Random        import get_random_bytes
from Crypto.Cipher        import AES
from base64               import b64encode
from Crypto.Util.Padding  import pad
from src.chap             import Chap
from src.menu import Menu
from src.chap import Chap
from src.utils.optionArgs import OptionArgs
from src.ellipticCurves import *
import os
import os.path

class ClientOptionHandler:
  """
  Attributes
  ----------
  NUMBER_BYTES_TO_RECEIVE : int
    The max number of bytes to receive
  """
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384
  
  # == Methods ==
  def __init__(self,mainSocket,keySocket,menuHandler,username,clientKeysPath):
    """Initalize handler.
    
    Parameters
    ----------
    con : sqlite3.Connection
      The connection to the local database
    cur : sqlite3.Cursor
      The cursor to the local database
    """
    self.mainSocket = mainSocket
    self.menuHandler    = menuHandler
    self.keySocket  = keySocket
    self.username       = username
    self.clientKeysPath = clientKeysPath

  def handleClientActions(self,option):
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
    elif self.menuHandler.currMenu == Menu.MENUS.MAIN:
      if option == 1:
        self.menuHandler.currMenu = Menu.MENUS.FRIEND
      elif option == 2:
        self.menuHandler.currMenu = Menu.MENUS.CHAT
      elif option == 0:
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
    elif self.menuHandler.currMenu == Menu.MENUS.CHAT:
      friendToChat = self.getFriend()
      if friendToChat == None:
        self.menuHandler.currMenu = Menu.MENUS.MAIN
      else:
        self.chat(friendToChat)
          
  def chapRegister(self):
    """Registers user using the Challenge Handshake Authentication Protocol (CHAP)."""
    username = input("Username: (0 to exit) ")
    if username == "0":
      return
    self.mainSocket[0].send(pickle.dumps(OptionArgs(0,(username,))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    while optionArgs["code"] == 1:
      print(optionArgs["args"])
      username = input("Username: (0 to exit) ")
      if username == "0":
        return
      self.mainSocket[0].send(pickle.dumps(OptionArgs(0,(username,))))
      optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
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
    self.mainSocket[0].send(pickle.dumps(OptionArgs(1,(keys[0],username,salt,iv,cipherText))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    print(optionArgs["args"])
  
  def chapLogin(self):
    """Logs user in using the Challenge Handshake Authentication Protocol (CHAP)."""
    username = input("Username: (0 to exit) ")
    if username == "0":
      return
    self.mainSocket[0].send(pickle.dumps(OptionArgs(2,(username,))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    while optionArgs["code"] == 1:
      print(optionArgs["args"])
      username = input("Username: (0 to exit) ")
      if username == "0":
        return
      self.mainSocket[0].send(pickle.dumps(OptionArgs(2,(username,))))
      optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    nonce = optionArgs["args"]
    password = input("Password: (0 to exit) ")
    if password == "0":
      return
    challenge = Chap.getChapChallenge(nonce,password)
    self.mainSocket[0].send(pickle.dumps(OptionArgs(3,(username,challenge,str(self.mainSocket[0]),str(self.keySocket[0])))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
    elif optionArgs["code"] == 0:
      print(optionArgs["args"])
      self.menuHandler.currMenu = Menu.MENUS.MAIN
      self.username[0] = username
  
  def addFriend(self):
    """Adds a friend."""
    friend = input("Friend Username: (0 to exit) ")
    if friend == "0":
      return
    self.mainSocket[0].send(pickle.dumps(OptionArgs(4,(self.username[0],friend))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    print(optionArgs["args"])
  
  def friendRequests(self):
    """Shows friend requests and allows their acceptance and/or removal."""
    self.mainSocket[0].send(pickle.dumps(OptionArgs(5,(self.username[0],))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
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
      self.mainSocket[0].send(pickle.dumps(OptionArgs(6,(self.username[0],friendsToAccept,friendsToReject))))
      optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
      print(optionArgs["args"])
  
  def showFriendsList(self):
    """Shows friends list."""
    self.mainSocket[0].send(pickle.dumps(OptionArgs(7,(self.username[0],))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    else:
      print("===== Friends List =====")
      for index,friend in enumerate(optionArgs["args"]):
        print(f"{index+1}: {friend}")
      print("========================")
  
  def removeFriend(self):
    """Removes a user from the list of friends."""
    self.mainSocket[0].send(pickle.dumps(OptionArgs(7,(self.username[0],))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
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
    self.mainSocket[0].send(pickle.dumps(OptionArgs(8,(self.username[0],optionArgs["args"][int(friendToRemove) - 1].split(" ")[0]))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    print(optionArgs["args"])
  
  def logout(self):
    """Logs user out."""
    self.mainSocket[0].send(pickle.dumps(OptionArgs(9,(self.username[0],))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
    else:
      self.menuHandler.currMenu = Menu.MENUS.INITIAL
      print(optionArgs["args"])
      
  def getFriend(self):
    """Gets the username of another user to chat with."""
    self.mainSocket[0].send(pickle.dumps(OptionArgs(10,(self.username[0],))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(self.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return None
    else:
      print("===== Friends List =====")
      for index,friend in enumerate(optionArgs["args"]):
        if friend.split(" ")[1] == "(online)":
          print(f"{index+1}: {friend}")
      print("========================")
    while True:
      friend = input("Please insert the friend you wish to chat (0 to exit): ")
      if friend == "0":
        return None
      if int(friend) not in list(range(1,len(optionArgs["args"]) + 1)):
        print("Invalid friend")
        continue
      else:
        return optionArgs["args"][int(friend) - 1].split(" ")[0].split(" ")[0]
  
  def chat(self,friendToChat):
    """Chat with another user, exchanging keys.
    
    Parameters
    ----------
    friendToChat : str
      The username of the friend to chat with
    """
    self.exchangeKeys(friendToChat,"Cipher")
  
  def exchangeKeys(self,friendToChat,keyType):
    """Exchange keys with a friend user using Diffie-Hellman on elliptic curves protocol.
    
    Parameters
    ----------
    friendToChat : str
      The username of the friend to chat with
    keyType : str
      The type of key to exchange
    """
    ec   = EllipticCurves()
    X,dA = ec.generateKeys()
    self.keySocket[0].send(pickle.dumps(OptionArgs(0,(self.username[0],friendToChat,X,keyType))))
    optionArgs = pickle.loads(self.keySocket[0].recv(self.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    Y = optionArgs["args"][0]
    keyPoint = ec.multiplyPointByScalar(Y,dA)
    key = str(keyPoint[0])
    clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username[0]}Keys/{self.username[0]}-{friendToChat}")
    if not os.path.exists(clientKeysPath):
      os.makedirs(clientKeysPath)
    with open(os.path.join(clientKeysPath,keyType),"w") as f:
      f.write(key)