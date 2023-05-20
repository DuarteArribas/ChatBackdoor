import pickle
import os
from src.ellipticCurves import *
from src.utils.optionArgs import OptionArgs
from Crypto.Hash import SHA512
from Crypto.Hash          import SHA512
from Crypto.Cipher        import AES
from Crypto.Util.Padding  import pad
from Crypto.PublicKey     import RSA
from Crypto.PublicKey     import ElGamal
from Crypto.Hash          import HMAC, SHA512
from Crypto.Signature     import pkcs1_15
from Crypto.Util.Padding import unpad

class MsgOptionHandler:
  """
  Attributes
  ----------
  NUMBER_BYTES_TO_RECEIVE : int
    The max number of bytes to receive
  """
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384

  # == Methods ==
  def __init__(self,msgSocket,clientKeysPath,username):
    """Initialize the key option handler.
    
    Parameters
    ----------
    keySocket : socket
      The socket with the key thread
    clientKeysPath : str
      The path of the client keys
    username : str
      The username of the client
    """
    self.msgSocket  = msgSocket
    self.clientKeysPath = clientKeysPath
    self.username = username
  
  def handleClientMsgExchange(self):
    """Handle the client key exchange."""
    while True:
      try:
        optionArgs = pickle.loads(self.msgSocket[0].recv(MsgOptionHandler.NUMBER_BYTES_TO_RECEIVE))
        if optionArgs["code"] == 2:
          username          = optionArgs["args"][0]
          friendUsername    = optionArgs["args"][1]
          cipherText        = optionArgs["args"][2]
          iv                = optionArgs["args"][3]
          hmac              = optionArgs["args"][4]
          N                 = optionArgs["args"][5]
          e                 = optionArgs["args"][6]
          rsaPublicKey = RSA.construct((N,e)).publickey()
          rsaSig            = optionArgs["args"][7]
          elgamalSig        = optionArgs["args"][8]
          clientKeysPath = os.path.join(self.clientKeysPath,f"{self.username[0]}Keys",f"{username}-{self.username[0]}")
          with open(os.path.join(clientKeysPath,"AESCipherKeys"),"r") as f:
            cipherKey = f.read().encode("utf-8")
            with open(os.path.join(clientKeysPath,"AESHmacKeys"),"r") as f2:
              hmacKey = f2.read().encode("utf-8")
              message = self.decipherMsg(cipherText,cipherKey,iv)
              if hmac == self.calculateMsgHmac(cipherText,hmacKey) and self.verifyRSADigitalSignature(message.encode("utf-8"),rsaSig,rsaPublicKey):
                print(f"\t\t{username}: {message} (✓)")
              else:
                print(f"\t\t{username}: {message} (✖)")
      except Exception as e:
        print(e)
  
  def decipherMsg(self,cipherText,cipherKey,iv):
    cipher = AES.new(cipherKey.ljust(16,b"\0")[:16],AES.MODE_CBC,iv.ljust(16,b"\0")[:16])
    return unpad(cipher.decrypt(cipherText),AES.block_size).decode("utf-8")

  def calculateMsgHmac(self,msg,hmacKey):
    h = HMAC.new(hmacKey,digestmod = SHA512)
    h.update(msg)
    return h.hexdigest()
  
  def verifyRSADigitalSignature(self,msg,rsaSig,rsaPublicKey):
    msgHash = SHA512.new(msg)
    verifier = pkcs1_15.new(rsaPublicKey)
    try:
      verifier.verify(msgHash,rsaSig)
      return True
    except (ValueError,TypeError):
      return False