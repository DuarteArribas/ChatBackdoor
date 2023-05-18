import socket
import pickle
import threading
from src.utils.optionArgs import *
from src.ellipticCurves   import *
from src.clientOptionHandler import *
from src.keyOptionHandler   import *
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
  # == Methods ==
  def __init__(self,ip,mainSocketPort,keySocketPort,msgSocketPort,menuHandler,clientKeysPath):
    """Initialize a socket connection with the server.
    Parameters
    ----------
    ip   : str
      The ip of the server
    port : int
      The port of the server
    """
    self.ip                  = ip
    self.mainSocketPort      = int(mainSocketPort)
    self.keySocketPort       = int(keySocketPort)
    self.msgSocketPort       = int(msgSocketPort)
    self.mainSocket = []
    self.keySocket = []
    self.menuHandler         = menuHandler
    self.username            = None
    self.clientKeysPath      = clientKeysPath
    self.clientOptionHandler = ClientOptionHandler(self.mainSocket,self.keySocket,self.menuHandler,self.username)
    self.keyOptionHandler = KeyOptionHandler(self.keySocket,self.clientKeysPath)
  
  def runClient(self):
    thread1 = threading.Thread(target = self.runMainThread)
    thread2 = threading.Thread(target = self.runKeyThread)
    #thread3 = threading.Thread(target = self.runMsgThread)
    thread1.start()
    thread2.start()
    #thread3.start()
  
  def runMainThread(self):
    """Run the client.
    
    Parameters
    ----------
    arguments : list
      The list of command-line arguments. arguments[0] is the option
      The list of command-line arguments. arguments[1:] is the args
    """
    option = -1
    while not (option == 0 and self.menuHandler.currMenu == Menu.MENUS.INITIAL):
      if self.menuHandler.currMenu == Menu.MENUS.INITIAL:
        Menu.printInitialMenu()
        option = Menu.getInitialMenuOption()
        self.handleAction(option)
      elif self.menuHandler.currMenu == Menu.MENUS.MAIN:
        Menu.printMainMenu()
        option = Menu.getMainMenuOption()
        self.handleAction(option)
        option = -1 if option == 0 else option
      elif self.menuHandler.currMenu == Menu.MENUS.FRIEND:
        Menu.printFriendMenu()
        option = Menu.getFriendMenuOption()
        self.handleAction(option)
        option = -1 if option == 0 else option
    
  def handleAction(self,option):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      s.connect((self.ip,self.mainSocketPort))
      if self.mainSocket == []:
        self.mainSocket.append(s)
      else:
        self.mainSocket[0] = s 
      self.clientOptionHandler.handleClientActions(option)
  
  def runKeyThread(self):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s2:
      s2.connect((self.ip,self.keySocketPort))
      if self.keySocket == []:
        self.keySocket.append(s2)
      else:
        self.keySocket[0] = s2 
      self.keyOptionHandler.handleClientKeyExchange()

  #def runMsgThread(self):
  #  with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s3:
  #    s3.connect((self.ip,self.msgSocketPort))
  #    self.socket3 = s3
  #    #self._handleMsgExchange()

  #def _handleMsgExchange(self):
  #  pass
  #
  #def sendMessage(self):
  #  self.socket.send(pickle.dumps(OptionArgs(7,(self.username,))))
  #  optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
  #  if optionArgs["code"] == 1:
  #    print(optionArgs["args"])
  #    return
  #  else:
  #    print("===== Friends List =====")
  #    for index,friend in enumerate(optionArgs["args"]):
  #      if friend.split(" ")[1] == "(online)":
  #        print(f"{index+1}: {friend}")
  #    print("========================")
  #  while True:
  #    friendToSend = input("Please insert the friend you wish to send the message to (0 to exit): ")
  #    if friendToSend == "0":
  #      return
  #    if int(friendToSend) not in list(range(1,len(optionArgs["args"]) + 1)):
  #      print("Invalid friend")
  #      continue
  #    else:
  #      break
  #  ec   = EllipticCurves()
  #  X,dA = ec.generateKeys()
  #  print("LOOOOAOAOAOA")
  #  friendToSend = optionArgs["args"][int(friendToSend) - 1].split(" ")[0].split(" ")[0]
  #  self.socket2.send(pickle.dumps(OptionArgs(0,(self.username,friendToSend,X,"cipher"))))
  #  print("LULA")
  #  optionArgs = pickle.loads(self.socket2.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
  #  print("aopapaoa")
  #  print("CCUCUCUCCUUCUCUCUCUCU")
  #  if optionArgs["code"] == 1:
  #    print(optionArgs["args"])
  #    return
  #  Y = optionArgs["args"][0]
  #  keyPoint = ec.multiplyPointByScalar(Y,dA)
  #  key = str(keyPoint[0])
  #  if not os.path.exists(f"client/out/{self.username}Keys/{self.username}-{friendToSend}"):
  #    os.makedirs(f"client/out/{self.username}Keys/{self.username}-{friendToSend}")
  #  with open(f"client/out/{self.username}Keys/{self.username}-{friendToSend}/cipher","w") as f:
  #    f.write(key)
  #  print("CARAMBA PA")
  #  
    
    
      
      
      
      
    #
    #message = input("Please insert the message you wish to send: ")
    #
    #
    #self.socket.send(pickle.dumps(OptionArgs(10,(self.username,optionArgs["args"][int(friendToSend) - 1][0],message))))
    #optionArgs = pickle.loads(self.socket.recv(ChatClient.NUMBER_BYTES_TO_RECEIVE))
    #print(optionArgs["args"])