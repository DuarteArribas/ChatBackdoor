import socket
import pickle
import threading
from src.utils.optionArgs import *
from src.ellipticCurves   import *
from src.clientOptionHandler import *
from src.keyOptionHandler   import *
from src.msgOptionHandler   import *
from src.menu             import Menu
import os
import os.path

class ChatClient:
  # == Methods ==
  def __init__(self,ip,mainSocketPort,keySocketPort,msgSocketPort,msgHistorySocketPort,menuHandler,clientKeysPath,rsaKeySizeBits,elGamalKeySizeBits,ivKey):
    """Initialize a socket connection with the server.
    Parameters
    ----------
    ip             : str
      The ip of the server
    mainSocketPort : int
      The port of the socket with the main thread
    keySocketPor   : int
      The port of the socket with the key thread
    msgSocketPor   : int
      The port of the socket with the message thread
    menuHandler    : MenuHandler
      The menu handler of the client
    clientKeysPath : str
      The path of the client keys
    """
    self.ip                  = ip
    self.mainSocketPort      = int(mainSocketPort)
    self.keySocketPort       = int(keySocketPort)
    self.msgSocketPort       = int(msgSocketPort)
    self.msgHistorySocketPort = int(msgHistorySocketPort)
    self.mainSocket = []
    self.keySocket = []
    self.msgSocket  = []
    self.msgHistorySocket  = []
    self.menuHandler         = menuHandler
    self.username            = [None]
    self.clientKeysPath      = clientKeysPath
    self.rsaKeySizeBits      = rsaKeySizeBits
    self.elGamalKeySizeBits  = elGamalKeySizeBits
    self.ivKey               = ivKey
    self.currChattingFriend  = [None]
    self.canBazar = [False]
    self.clientOptionHandler = ClientOptionHandler(self.mainSocket,self.keySocket,self.msgSocket,self.msgHistorySocket,self.menuHandler,self.username,self.clientKeysPath,self.rsaKeySizeBits,self.elGamalKeySizeBits,self.ivKey,self.currChattingFriend,self.canBazar)
    self.keyOptionHandler = KeyOptionHandler(self.keySocket,self.clientKeysPath,self.username,self.canBazar)
    self.msgOptionHandler = MsgOptionHandler(self.msgSocket,self.clientKeysPath,self.username,self.menuHandler,self.currChattingFriend,self.canBazar)
  
  def runClient(self):
    """Run the client, initializing its threads."""
    thread1 = threading.Thread(target = self.runMainThread)
    thread2 = threading.Thread(target = self.runKeyThread)
    thread3 = threading.Thread(target = self.runMsgThread)
    thread4 = threading.Thread(target = self.runMsgHistoryThread)
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
  
  def runMainThread(self):
    """Run the main thread of the client, which handles the menus."""
    option = -1
    while not (option == 0 and self.menuHandler.currMenu == Menu.MENUS.INITIAL):
      if self.menuHandler.currMenu == Menu.MENUS.INITIAL:
        Menu.printInitialMenu()
        option = Menu.getInitialMenuOption()
        self.handleAction(option)
      elif self.menuHandler.currMenu == Menu.MENUS.REGISTER:
        Menu.printRegisterMenu()
        option = Menu.getRegisterOption()
        self.handleAction(option)
        option = -1 if option == 0 else option
      elif self.menuHandler.currMenu == Menu.MENUS.LOGIN:
        Menu.printLoginMenu()
        option = Menu.getLoginOption()
        self.handleAction(option)
        option = -1 if option == 0 else option
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
      elif self.menuHandler.currMenu == Menu.MENUS.CHAT:
        self.handleAction(None)
        option = -1 if option == 0 else option
    
  def handleAction(self,option):
    """Handle the action chosen by the user.

    Parameters
    ----------
    option : int
      The option chosen by the user
    """
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      s.connect((self.ip,self.mainSocketPort))
      if self.mainSocket == []:
        self.mainSocket.append(s)
      else:
        self.mainSocket[0] = s 
      self.clientOptionHandler.handleClientActions(option)
  
  def runKeyThread(self):
    """Run the key thread of the client, which handles the key exchange."""
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s2:
      s2.connect((self.ip,self.keySocketPort))
      if self.keySocket == []:
        self.keySocket.append(s2)
      else:
        self.keySocket[0] = s2 
      self.keyOptionHandler.handleClientKeyExchange()

  def runMsgThread(self):
    """Run the key thread of the client, which handles the key exchange."""
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s3:
      s3.connect((self.ip,self.msgSocketPort))
      if self.msgSocket == []:
        self.msgSocket.append(s3)
      else:
        self.msgSocket[0] = s3 
      self.msgOptionHandler.handleClientMsgExchange()
  
  def runMsgHistoryThread(self):
    """Run the key thread of the client, which handles the key exchange."""
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s4:
      s4.connect((self.ip,self.msgHistorySocketPort))
      if self.msgHistorySocket == []:
        self.msgHistorySocket.append(s4)
      else:
        self.msgHistorySocket[0] = s4
      while True:
        if self.canBazar[0]:
          exit(0)