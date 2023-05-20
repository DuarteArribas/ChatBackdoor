import pickle
from datetime import datetime
import time
from Crypto.Hash import SHA512
from Crypto.Hash          import SHA512
from Crypto.Cipher        import AES
from Crypto.Util.Padding  import pad
from Crypto.PublicKey     import RSA
from Crypto.PublicKey     import ElGamal
from Crypto.Hash          import HMAC, SHA512
from Crypto.Signature     import pkcs1_15
from Crypto.Util.Padding import unpad
import os

class MsgExchangeHandler:
  # == Methods ==
  def __init__(self,con,cur,connectedUsernames,msgClientAndUsernames,ivKey,iv):
    """Initalize handler.
    
    Parameters
    ----------
    con                   : sqlite3.Connection
      The connection to the local database
    cur                   : sqlite3.Cursor
      The cursor to the local database
    connectedUsernames    : list
      The list of usernames of connected clients
    keyClientAndUsernames : list
      The list of clients for key exchange and respective usernames
    """
    self.MSG_HANDLER_METHOD = {
      0: self.handleNewMessage
    }
    self.con                   = con
    self.cur                   = cur
    self.connectedUsernames    = connectedUsernames
    self.msgClientAndUsernames = msgClientAndUsernames
    self.ivKey                 = ivKey
    self.iv                    = iv

  def process(self,option,args = None):
    """Process an option received by the client and call the appropriate client handler method.
    
    Parameters
    ----------
    option : int
      The chosen menu option
    args   : tuple
      The arguments sent by the client
    Return
    ----------
    dict
      The code to be treated by the client and the respective arguments
    """
    print("arroz")
    if args == None:
      return self.MSG_HANDLER_METHOD[option]()
    else:
      return self.MSG_HANDLER_METHOD[option](args)
    
  def handleNewMessage(self, args):
    """Handle new message from the database. 
    
    Parameters
    ----------
    args : tuple
      args[0] = username of current user
      args[1] = friendUsername
      args[2] = message
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
      args : str
        confirmation of logout if successful
        exception message if unsuccessful
    """
    try:
      username          = args[0]
      friendUsername    = args[1]
      cipherText        = args[2]
      iv                = args[3]
      cipherAndHmacKeys = self.decipherMsg(iv,self.ivKey,self.iv).decode("utf-8")
      cipherKey         = cipherAndHmacKeys.split(":")[2][:int(cipherAndHmacKeys.split(":")[0])]
      hmacKey           = cipherAndHmacKeys.split(":")[2][int(cipherAndHmacKeys.split(":")[0]):int(cipherAndHmacKeys.split(":")[1])]
      p                 = cipherAndHmacKeys.split(":")[2][int(cipherAndHmacKeys.split(":")[1]):]
      cipherKey         = cipherKey.encode("utf-8")
      hmacKey           = hmacKey.encode("utf-8")
      hmac              = args[4]
      N                 = args[5]
      e                 = args[6]
      q                 = N / p
      d                 = self.calculateDFromParams(p,q,e)
      rsaPrivateKey     = RSA.construct((N,e,d,p,q))
      rsaSig            = args[7]
      elgamalSig        = args[8]
      message           = self.decipherMsg(cipherText,cipherKey,iv)
      print(f"{username} just sent a message to {friendUsername}: {message.decode('utf-8')}. 15 seconds to change the message contents before being sent.")
      fileHash = SHA512.new((username + friendUsername + message.decode("utf-8") + datetime.now().strftime("%d/%m/%Y %H:%M:%S")).encode("utf-8")).hexdigest()
      with open(f"server/out/{username}-{friendUsername}-{fileHash}.txt","w") as f:
        f.write(message.decode("utf-8"))
      time.sleep(15)
      newMsg = ""
      with open(f"server/out/{username}-{friendUsername}-{fileHash}.txt","r") as f:
        newMsg = f.read()
      os.remove(f"server/out/{username}-{friendUsername}-{fileHash}.txt")
      if newMsg != message.decode("utf-8"):
        print("The original message was changed.")
      else:
        print("The original message was not changed.")
      cipherText = self.cipherMsg(newMsg.encode("utf-8"),cipherKey,iv)
      hmac = self.calculateMsgHmac(cipherText,hmacKey)
      rsaSig = self.calculateRSADigitalSignature(cipherText,rsaPrivateKey)
      self.cur.execute("INSERT INTO messages (username1,username2,message) VALUES (?,?,?);",(username,friendUsername,newMsg))
      self.con.commit()
      for host,u in self.msgClientAndUsernames:
        if u == friendUsername:
          host.send(pickle.dumps({'code': 2,'args': (username,friendUsername,cipherText,iv,hmac,N,e,rsaSig,elgamalSig)}))
          return host
      return {'code': 0,'args': "Message sent."}
    except Exception as err:
      print(err)
      return {'code': 1,'args': "An unknown error occurred."}
    
  def decipherMsg(self,cipherText,cipherKey,iv):
    cipher = AES.new(cipherKey.ljust(16,b"\0")[:16],AES.MODE_CBC,iv.ljust(16,b"\0")[:16])
    return unpad(cipher.decrypt(cipherText),AES.block_size)
  
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

  def calculateDFromParams(self,p,q,e):
    phi_N = (p - 1) * (q - 1)
    def extendedGcd(a, b):
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