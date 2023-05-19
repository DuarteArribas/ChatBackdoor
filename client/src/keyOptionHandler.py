import pickle
import os
from src.ellipticCurves import *
from src.utils.optionArgs import OptionArgs

class KeyOptionHandler:
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384

  def __init__(self,keySocket,clientKeysPath,username):
    self.keySocket  = keySocket
    self.clientKeysPath = clientKeysPath
    self.username = username
  
  def handleClientKeyExchange(self):
    while True:
      try:
        print("cc")
        optionArgs = pickle.loads(self.keySocket[0].recv(KeyOptionHandler.NUMBER_BYTES_TO_RECEIVE))
        if optionArgs["code"] == 2:
          print("bb")
          ec = EllipticCurves()
          keys = ec.generateKeys()
          keyPoint = ec.multiplyPointByScalar(optionArgs['args'][1],keys[1])
          key = str(keyPoint[0])
          clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username[0]}Keys/{optionArgs['args'][0]}-{self.username[0]}")
          if not os.path.exists(clientKeysPath):
            os.makedirs(clientKeysPath)
          with open(os.path.join(clientKeysPath,optionArgs['args'][2]),"w") as f:
            f.write(key)
          self.keySocket[0].send(pickle.dumps(OptionArgs(1,(optionArgs['args'][0],keys[0]))))
      except Exception as e:
        print(e)