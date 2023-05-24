import pickle
from Crypto.Protocol.KDF  import PBKDF2
from Crypto.Hash          import SHA512
from Crypto.Random        import get_random_bytes
from Crypto.Cipher        import AES
from base64               import b64encode
from Crypto.Util.Padding  import pad
from Crypto.PublicKey     import RSA
from Crypto.PublicKey     import ElGamal
from src.chap             import Chap
from Crypto.Hash          import HMAC, SHA512
from Crypto.Signature     import pkcs1_15
from src.menu import Menu
from src.chap import Chap
from src.utils.optionArgs import OptionArgs
from src.ellipticCurves import *
import os
import os.path
from sympy import isprime
import random
import scrypt

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
  def __init__(self,mainSocket,keySocket,msgSocket,msgHistorySocket,menuHandler,username,clientKeysPath,rsaKeySizeBits,elGamalKeySizeBits,ivKey,currChattingFriend,canBazar):
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
    self.msgSocket  = msgSocket
    self.msgHistorySocket = msgHistorySocket
    self.username       = username
    self.clientKeysPath = clientKeysPath
    self.rsaKeySizeBits = int(rsaKeySizeBits)
    self.elGamalKeySizeBits = int(elGamalKeySizeBits)
    self.ivKey = ivKey.encode("utf-8")
    self.iv = b'J\xc7\xdc\xd33#D\xf8\xcf\x86o\x97\x81\xe0f\xcb'
    self.currChattingFriend = currChattingFriend
    self.canBazar = canBazar

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
        self.menuHandler.currMenu = Menu.MENUS.REGISTER
      elif option == 2:
        self.menuHandler.currMenu = Menu.MENUS.LOGIN
      elif option == 0:
        self.canBazar[0] = True
        return
    elif self.menuHandler.currMenu == Menu.MENUS.REGISTER:
      if option == 1:
        self.chapRegister()
      elif option == 2:
        self.schnorrRegister()
      elif option == 0:
        self.menuHandler.currMenu = Menu.MENUS.INITIAL
    elif self.menuHandler.currMenu == Menu.MENUS.LOGIN:
      if option == 1:
        self.chapLogin()
      elif option == 2:
        self.schnorrLogin()
      elif option == 0:
        self.menuHandler.currMenu = Menu.MENUS.INITIAL
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
        self.currChattingFriend[0] = None
        self.menuHandler.currMenu = Menu.MENUS.MAIN
      else:
        self.currChattingFriend[0] = friendToChat
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
    self.mainSocket[0].send(pickle.dumps(OptionArgs(17,(username,))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    pepper = '\x9a6k\xdc)\x80b:@\t\xabm\x80\x93\x8e\xabf7>~\xda(\x92\xc7I\xfe\x0ew\xb3\xc7|\x05\x98s\xb4\x07\x8a\xe0\xec\xf4\x11\xfcDp\xfc\xaflGB3r#\xb6\xd3\xa9\x86l\xech\x7fh\xe5WJ=`\xd5Qh'
    password = scrypt.hash(password,optionArgs["args"] + pepper).decode("latin-1")
    challenge = Chap.getChapChallenge(nonce,password)
    self.mainSocket[0].send(pickle.dumps(OptionArgs(3,(
      username,
      challenge,
      str(self.mainSocket[0]),
      str(self.keySocket[0]),
      str(self.msgSocket[0])
    ))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
    elif optionArgs["code"] == 0:
      print(optionArgs["args"])
      self.menuHandler.currMenu = Menu.MENUS.MAIN
      self.username[0] = username
  
  def schnorrRegister(self):
    username = input("Username: (0 to exit) ")
    if username == "0":
      return
    self.mainSocket[0].send(pickle.dumps(OptionArgs(11,(username,))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    while optionArgs["code"] == 0:
      print(optionArgs["args"])
      username = input("Username: (0 to exit) ")
      if username == "0":
        return
      self.mainSocket[0].send(pickle.dumps(OptionArgs(11,(username,))))
      optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    self.mainSocket[0].send(pickle.dumps(OptionArgs(12,(username,)))) 
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    Q = optionArgs["args"][0]
    P = optionArgs["args"][1]
    B = optionArgs["args"][2]
    privateKey = random.randint(0,Q-1)
    publicKey = pow(B, -privateKey, P)
    self.mainSocket[0].send(pickle.dumps(OptionArgs(13,(username,publicKey))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    else:
      path = f"client/out/{username}Keys/AuthenticationKeys"
      if not os.path.exists(path):
        os.makedirs(path)
      with open(os.path.join(path,"schnorrPrivateKey"),"w") as f:
        f.write(str(privateKey))
      print(optionArgs["args"])
    
  def schnorrLogin(self):
    username = input("Username: (0 to exit) ")
    if username == "0":
      return
    self.mainSocket[0].send(pickle.dumps(OptionArgs(11,(username,))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    while optionArgs["code"] == 1:
      print(optionArgs["args"])
      username = input("Username: (0 to exit) ")
      if username == "0":
        return
      self.mainSocket[0].send(pickle.dumps(OptionArgs(11,(username,))))
      optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    self.mainSocket[0].send(pickle.dumps(OptionArgs(14,(username,))))
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    P,Q,B = optionArgs["args"][0],optionArgs["args"][1],optionArgs["args"][2]
    
    # 1 - Client chooses a random number r and calculates a number to send to the server 
    # r ← {0, ..., Q − 1}, x = β**r mod P
    r = random.randint(0,Q-1)
    x = int(pow(B,r,P))

    # 2 - Client (Alice) sends the number x to the server 
    self.mainSocket[0].send(pickle.dumps(OptionArgs(15,(username,x))))

    # 5 - Receives random number e from the server and calculates the response
    optionArgs = pickle.loads(self.mainSocket[0].recv(ClientOptionHandler.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    e = optionArgs["args"]
    privateKey = 0
    path = f"client/out/{username}Keys/AuthenticationKeys/SchnorrPrivateKey"
    if not os.path.exists(path):
      print(f"Could not find private key on path {path}")
    with open(path,"r") as f:
      privateKey = int(f.read())
    y = ((privateKey * e) + r) % Q

    # 6 - Sends the response to the server 
    self.mainSocket[0].send(pickle.dumps(OptionArgs(16,(username,y,str(self.mainSocket[0]),str(self.keySocket[0]),str(self.msgSocket[0])))))
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
    self.mainSocket[0].send(pickle.dumps(OptionArgs(9,(self.username[0],str(self.mainSocket[0]),str(self.keySocket[0]),str(self.msgSocket[0])))))
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
    print(f"========== Loading chat with {friendToChat} ==========")
    if not self.exchangeKeys(friendToChat,"AESCipherKeys"):
      return
    if not self.exchangeKeys(friendToChat,"AESHmacKeys"):
      return
    if not self.generatePublicKeys(friendToChat,"RSASignatureKeys","RSA"):
      return
    self.printHistoricalMessages(friendToChat,100)
    msg = input("> ")
    print("\033[A                             \033[A")
    while msg != "/0":
      cipherKey,hmacKey,params = self.getKeys(friendToChat)
      p,q,e,d,n = params
      n = int(n)
      cipherKey     = cipherKey.encode("utf-8")
      hmacKey       = hmacKey.encode("utf-8")
      print("aaaaaaaaaaaaa")
      rsaPrivateKey = RSA.construct((119294134840169509055527211331255649644606569661527638012067481954943056851150333806315957037715620297305000118628770846689969112892212245457118060574995989517080042105263427376322274266393116193517839570773505632231596681121927337473973220312512599061231322250945506260066557538238517575390621262940383913963,65537,72892162132453240003793081431254596487759129683932347592859641345891553040333172364830897044041106776409947506759374529741974962628265550289611864072595839380092878908763844906765562034782236695192158256372726552845451322975382692014652804746885831130782746696769480546157553394854115242420454633969276355353,10933766183632575817611517034730668287155799984632223454138745671121273456287670008290843302875521274970245314593222946129064538358581018615539828479146469,10910616967349110231723734078614922645337060882141748968209834225138976011179993394299810159736904468554021708289824396553412180514827996444845438176099727))
      print("bbbbbbbb")
      msgBytes      = msg.encode("utf-8")
      cipherText,iv,hmac,rsaSig = self.processMsg(
        msgBytes,
        cipherKey,
        hmacKey,
        rsaPrivateKey,
        p
      )
      self.msgSocket[0].send(pickle.dumps(OptionArgs(0,(self.username[0],friendToChat,cipherText,iv,hmac,n,e,rsaSig))))
      self.printUserInput(msg)
      msg = input("> ")
      print("\033[A                             \033[A")
    self.currChattingFriend[0] = None
  
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
      return False
    Y = optionArgs["args"][0]
    keyPoint = ec.multiplyPointByScalar(Y,dA)
    key = str(keyPoint[0])
    clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{self.username[0]}-{friendToChat}")
    if not os.path.exists(clientKeysPath):
      os.makedirs(clientKeysPath)
    with open(os.path.join(clientKeysPath,keyType),"w") as f:
      f.write(key)
    return True
  
  def generatePublicKeys(self,friendToChat,keyType,algorithm):
    """Exchange keys with a friend user using Diffie-Hellman on elliptic curves protocol.
    
    Parameters
    ----------
    friendToChat : str
      The username of the friend to chat with
    keyType : str
      The type of key to exchange
    """
    if algorithm == "RSA":
      p,q,e,d = self.generateRSAKeypair()
      N = p * q
      clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{self.username[0]}-{friendToChat}")
      if not os.path.exists(clientKeysPath):
        os.makedirs(clientKeysPath)
      with open(os.path.join(clientKeysPath,keyType),"w") as f:
        f.write(f"P={p}\nQ={q}\nE={e}\nD={d}\nN={N}")
      return True
  
  def processMsg(self,msgBytes,cipherKey,hmacKey,rsaPrivateKey,p):
    cipherKeyAndHmacKey = (
      str(len(cipherKey.decode("utf-8"))) + ":" + str(len(cipherKey.decode("utf-8")) + len(hmacKey.decode("utf-8"))) + ":" + cipherKey.decode("utf-8") + hmacKey.decode("utf-8") + str(p)
    ).encode("utf-8")
    iv                  = self.cipherMsg(cipherKeyAndHmacKey,self.ivKey,self.iv)
    cipherText          = self.cipherMsg(msgBytes,cipherKey,iv)
    hmac                = self.calculateMsgHmac(cipherText,hmacKey)
    rsaSig              = self.calculateRSADigitalSignature(cipherText,rsaPrivateKey)
    return (cipherText,iv,hmac,rsaSig)
  
  def cipherMsg(self,msg,cipherKey,iv):
    cipher = AES.new(cipherKey.ljust(16,b"\0")[:16],AES.MODE_CBC,iv.ljust(16,b"\0")[:16])
    cipherTextBytes = cipher.encrypt(pad(msg,AES.block_size))
    return cipherTextBytes

  def calculateMsgHmac(self,msg,hmacKey):
    h = HMAC.new(hmacKey,digestmod = SHA512)
    h.update(msg)
    return h.hexdigest()
  
  def calculateRSADigitalSignature(self,msg,rsaPrivateKey):
    msgHash = SHA512.new(msg)
    signer = pkcs1_15.new(rsaPrivateKey)
    return signer.sign(msgHash)
  
  def getKeys(self,friendToChat):
    with open(os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{self.username[0]}-{friendToChat}","AESCipherKeys"),"r") as f:
      cipherKey = f.read()
      with open(os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{self.username[0]}-{friendToChat}","AESHmacKeys"),"r") as f2:
        hmacKey = f2.read()
        with open(os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{self.username[0]}-{friendToChat}","RSASignatureKeys"),"r") as f3:
          lines = f3.readlines()
          p = int(lines[0].split("=")[1])
          q = int(lines[1].split("=")[1])
          e = int(lines[2].split("=")[1])
          d = int(lines[3].split("=")[1])
          n = lines[4].split("=")[1]
          return (cipherKey,hmacKey,(p,q,e,d,n))
      
  def printUserInput(self,msg):
    print(f"{{{self.username[0]}}} : {msg}")
  
  def printFriendInput(self,friendToChat,msg):
    print(f"\t\t\t{msg} : {{{friendToChat}}}")
    
  def generateRSAKeypair(self):
    p = self.generatePrimeNumber()
    q = self.generatePrimeNumber()
    phi_N = (p - 1) * (q - 1)
    e = 65537
    d = self.calculatePrivateExponent(e,phi_N)
    return p,q,e,d

  def generatePrimeNumber(self):
    while True:
      num = random.randint(10**250,10**251)
      if isprime(num):
        return num

  def calculatePrivateExponent(self,e,phi_N):
    def extendedGcd(a,b):
      if b == 0:
        return a, 1, 0
      else:
        d, x, y = extendedGcd(b, a % b)
        return d, y, x - (a // b) * y
    _, d, _ = extendedGcd(e, phi_N)
    d %= phi_N
    if d < 0:
      d += phi_N
    return d
  
  def printHistoricalMessages(self,friendToChat,maxMessages):
    self.msgHistorySocket[0].send(pickle.dumps(OptionArgs(0,(self.username[0],friendToChat,maxMessages))))
    optionArgs = pickle.loads(self.msgHistorySocket[0].recv(self.NUMBER_BYTES_TO_RECEIVE))
    if optionArgs["code"] == 1:
      print(optionArgs["args"])
      return
    else:
      if len(optionArgs["args"]) == 0:
        print("No messages to show")
        return   
      msg = optionArgs["args"]
      msg = msg.reverse()
      for msg in optionArgs["args"]:
        if msg[0] == self.username[0]:
          self.printUserInput(msg[1])
        else:
          self.printFriendInput(msg[0],msg[1])
      print("========================================")