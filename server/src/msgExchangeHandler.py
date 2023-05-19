import pickle
from datetime import *
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

class MsgExchangeHandler:
  # == Methods ==
  def __init__(self,con,cur,connectedUsernames,msgClientAndUsernames):
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
      cipherAndHmacKeys = self.decipherMsg(iv,self.ivKey,self.iv)
      cipherKey         = cipherAndHmacKeys.split(":")[1][:int(cipherKey.split(":")[0])]
      hmacKey           = cipherAndHmacKeys.split(":")[1][int(cipherKey.split(":")[0]):]
      hmac              = args[4]
      rsaSig            = args[5]
      elgamalSig        = args[6]
      message           = self.decipherMsg(cipherText,cipherKey,iv)
      print(f"{username} just sent a message to {friendUsername}: {message}")
      print("15 seconds to change the message contents before being sent.")
      fileHash = SHA512.new((username + friendUsername + message + date.now()).encode("utf-8")).hexdigest()
      with open(f"server/out/{username}-{friendUsername}-{fileHash}.txt","w") as f:
        f.write(message)
      time.sleep(15)
      with open(f"server/out/{username}-{friendUsername}-{fileHash}.txt","w") as f:
        newMsg = f.read()
        if newMsg != message:
          print("The original message was changed.")
        else:
          print("The original message was not changed.")
        cipherText = self.cipherMsg(newMsg,cipherKey,iv)
        hmac = self.calculateMsgHmac(cipherText,hmacKey)
        #rsaSig = self.calculateRSADigitalSignature(cipherText,rsaPrivateKey)
        self.cur.execute("INSERT INTO messages (username1,username2,message) VALUES (?,?,?);",(username,friendUsername,newMsg))
        self.con.commit()
        for host,u in self.msgClientAndUsernames:
          if u == friendUsername:
            host.send(pickle.dumps({'code': 2,'args': (username,friendUsername,cipherText,iv,hmac,rsaSig,elgamalSig)}))
            return host
      return {'code': 0,'args': "Message sent."}
    except Exception as e:
      return {'code': 1,'args': "An unknown error occurred."}
  
  
  def decipherMsg(self,cipherText,cipherKey,iv):
    cipher = AES.new(cipherKey.encode("utf-8"),AES.MODE_CBC,iv.encode("utf-8"))
    return unpad(cipher.decrypt(cipherText),AES.block_size).decode("utf-8")
  
  def cipherMsg(self,msg,cipherKey,iv):
    cipher = AES.new(pad(cipherKey,AES.block_size),AES.MODE_CBC,iv)
    cipherTextBytes = cipher.encrypt(pad(msg,AES.block_size))
    return cipherTextBytes.decode('utf-8')

  def calculateMsgHmac(self,msg,hmacKey):
    h = HMAC.new(hmacKey,digestmod = SHA512)
    h.update(msg)
    return h.hexdigest()
  
  def calculateRSADigitalSignature(self,msg,rsaPrivateKey):
    msgHash = SHA512.new(msg)
    signer = pkcs1_15.new(rsaPrivateKey)
    return signer.sign(msgHash)