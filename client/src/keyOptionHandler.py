import pickle
import os
from src.ellipticCurves import *
from src.utils.optionArgs import OptionArgs

class KeyOptionHandler:
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384

  def __init__(self,keySocket,clientKeysPath):
    self.keySocket  = keySocket
    self.clientKeysPath = clientKeysPath
  
  def handleClientKeyExchange(self):
    while True:
      try:
        optionArgs = pickle.loads(self.keySocket[0].recv(KeyOptionHandler.NUMBER_BYTES_TO_RECEIVE))
        if optionArgs["code"] == 2:
          ec = EllipticCurves()
          keys = ec.generateKeys()
          keyPoint = ec.multiplyPointByScalar(optionArgs['args'][1],keys[1])
          key = str(keyPoint[0])
          clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username}Keys/{optionArgs['args'][0]}-{self.username}")
          if not os.path.exists(clientKeysPath):
            os.makedirs(clientKeysPath)
          with open(clientKeysPath,"w") as f:
            f.write(key)
          self.keySocket[0].send(pickle.dumps(OptionArgs(1,(optionArgs['args'][0],keys[0]))))
      except Exception as e:
        pass