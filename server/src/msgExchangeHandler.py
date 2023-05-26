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
  def __init__(self,con,cur,connectedUsernames,msgClientAndUsernames,ivKey,iv,msgQueue):
    """Initalize handler.
    
    Parameters
    ----------
    con                   : sqlite3.Connection
      The connection to the local database
    cur                   : sqlite3.Cursor
      The cursor to the local database
    connectedUsernames    : list
      The list of usernames of connected clients
    msgClientAndUsernames : list
      The list of clients for message exchange and respective usernames
    ivKey                 : str
      The key used to encrypt the messages
    iv                    : str
      The initialization vector used to encrypt the messages
    msgQueue              : list
      The list of messages to be sent
    """
    self.con                   = con
    self.cur                   = cur
    self.connectedUsernames    = connectedUsernames
    self.msgClientAndUsernames = msgClientAndUsernames
    self.ivKey                 = ivKey
    self.iv                    = iv
    self.msgQueue              = msgQueue
  
  def handleNewMessage(self):
    """Handle new message from the database. 
    
    Parameters
    ----------
    args : tuple
      args[0] = username of current user
      args[1] = friendUsername
      args[2] = cipherText
      args[3] = iv
      args[4] = hmac
      args[5] = N (RSA)
      args[6] = e (RSA)
      args[7] = rsaSig
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
      if len(self.msgQueue) == 0:
        return
      args = self.msgQueue.pop(0)
      username          = args[0]
      friendUsername    = args[1]
      cipherText        = args[2]
      iv                = args[3]
      cipherAndHmacKeys = self.decipherMsg(iv,self.ivKey,self.iv).decode("utf-8")
      cipherKey         = cipherAndHmacKeys.split(":")[2][:int(cipherAndHmacKeys.split(":")[0])]
      hmacKey           = cipherAndHmacKeys.split(":")[2][int(cipherAndHmacKeys.split(":")[0]):int(cipherAndHmacKeys.split(":")[1])]
      p                 = int(cipherAndHmacKeys.split(":")[2][int(cipherAndHmacKeys.split(":")[1]):])
      cipherKey         = cipherKey.encode("utf-8")
      hmacKey           = hmacKey.encode("utf-8")
      hmac              = args[4]
      N                 = args[5]
      e                 = args[6]
      q                 = N // p
      d                 = self.calculateDFromParams(p,q,e)
      rsaPrivateKey     = RSA.construct((N,e,d,p,q))
      rsaSig            = args[7]
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
        print(f"The original message {message.decode('utf-8')} was changed to {newMsg}.")
      else:
        print(f"The original message {message.decode('utf-8')} was not changed.")
      cipherText = self.cipherMsg(newMsg.encode("utf-8"),cipherKey,iv)
      hmac = self.calculateMsgHmac(cipherText,hmacKey)
      rsaSig = self.calculateRSADigitalSignature(cipherText,rsaPrivateKey)
      self.cur.execute("INSERT INTO messages (username1,username2,message) VALUES (?,?,?);",(username,friendUsername,newMsg))
      self.con.commit()
      print(f"Message {newMsg} was inserted into the DB as a message from {username} and {friendUsername}.")
      for host,u in self.msgClientAndUsernames:
        if u == friendUsername:
          host.send(pickle.dumps({'code': 2,'args': (username,friendUsername,cipherText,iv,hmac,N,e,rsaSig)}))
    except Exception as e:
      pass
    
  def decipherMsg(self,cipherText,cipherKey,iv):
    '''Decipher a message.
    
    Parameters
    ----------
    cipherText : bytes
      The cipher text
    cipherKey : bytes
      The cipher key
    iv : bytes
      The initialization vector

    Return
    ----------
    Deciphered message : str
    '''
    cipher = AES.new(cipherKey.ljust(16,b"\0")[:16],AES.MODE_CBC,iv.ljust(16,b"\0")[:16])
    return unpad(cipher.decrypt(cipherText),AES.block_size)
  
  def cipherMsg(self,msg,cipherKey,iv):
    '''Cipher a message.
    
    Parameters
    ----------
    msg : bytes
      The message
    cipherKey : bytes
      The cipher key
    iv : bytes
      The initialization vector

    Return
    ----------
    Ciphered message : bytes
    
    '''
    cipher = AES.new(cipherKey.ljust(16,b"\0")[:16],AES.MODE_CBC,iv.ljust(16,b"\0")[:16])
    cipherTextBytes = cipher.encrypt(pad(msg,AES.block_size))
    return cipherTextBytes

  def calculateMsgHmac(self,msg,hmacKey):
    '''Calculate the HMAC of a message.
    
    Parameters
    ----------
    msg : bytes
      The message
    hmacKey : bytes
      The HMAC key

    Return
    ----------
    HMAC of the message : str
    '''
    h = HMAC.new(hmacKey,digestmod = SHA512)
    h.update(msg)
    return h.hexdigest()
  
  def calculateRSADigitalSignature(self,msg,rsaPrivateKey):
    '''Calculate the RSA digital signature of a message.
    
    Parameters
    ----------
    msg : bytes
      The message
    rsaPrivateKey : RSA.RsaKey
      The RSA private key
    
    Return
    ----------
    RSA digital signature of the message : bytes
    '''
    msgHash = SHA512.new(msg)
    signer = pkcs1_15.new(rsaPrivateKey)
    return signer.sign(msgHash)

  def calculateDFromParams(self,p,q,e):
    '''Calculate the RSA private key parameter d from the parameters p, q and e.
    
    Parameters
    ----------
    p : int
      The RSA parameter p
    q : int
      The RSA parameter q
    e : int
      The RSA parameter e

    Return
    ----------
    RSA private key parameter d : int
    '''
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
  
  def getHistoricalMessages(self,args):
    """Get historical messages from the database. 
    
    Parameters
    ----------
    args : tuple
      args[0] = username of current user
      args[1] = friendUsername
    
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
      username       = args[0]
      friendUsername = args[1]
      maxMessages    = args[2]
      self.cur.execute("SELECT username1,message FROM messages WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?) ORDER BY ID DESC LIMIT ?;",(username,friendUsername,friendUsername,username,maxMessages))
      messages = self.cur.fetchall()
      return {'code': 0,'args': messages}
    except Exception as e:
      return {'code': 1,'args': "An unknown error occurred."}