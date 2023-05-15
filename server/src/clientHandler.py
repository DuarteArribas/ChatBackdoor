import secrets
from src.ellipticCurves import EllipticCurves
from Crypto.Protocol.KDF  import PBKDF2
from Crypto.Hash          import SHA512
from Crypto.Cipher        import AES
from base64               import b64decode
from Crypto.Util.Padding  import unpad

class ClientHandler:
  # == Methods ==
  def __init__(self,con,cur):
    """Initalize handler."""
    self.CLIENT_HANDLER_METHOD = {
      0: self.registerChap1,
      1: self.registerChap2
    }
    self.con = con
    self.cur = cur

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
      return self.CLIENT_HANDLER_METHOD[option]()
    else:
      return self.CLIENT_HANDLER_METHOD[option](args)
  
  # Code 0 == success, 1 == Failure
  def registerChap1(self,args):
    """Tries to register the client through the creation of keys with elliptic curves for implementation of the CHAP protocol for authentication. Server will verify the authentication of the client. Client will send an authentication request.
    
    Parameters
    ----------
    option : int
      The chosen menu option
    args   : tuple
      The arguments sent by the client
      args[0] = username
    Return
    ----------
    dict
      With a success code (0) and the generated public key (X) or failure code (1) and the error message
    """
    try:
      username = args[0]
      self.removeTempUsers(username)
      if self.isUserAlreadyInDB(username):
        return {'code': 1,'args': "User already exists."}
      ec   = EllipticCurves()
      X,dA = ec.generateKeys()
      self.saveUserInDB(username,dA)
      return {'code': 0,'args':X}
    except Exception as e:
      return {'code': 1,'args': e}
  
  def removeTempUsers(self,username):
    """Remove temporary user from the database.
    
    Parameters
    ----------
    username : str
      The username of the temporary user to remove.
    """
    self.cur.execute("DELETE FROM users WHERE temp = 1 AND username = ?;",(username,))
    self.con.commit()
  
  def isUserAlreadyInDB(self,username):
    """Check if user already exists (if so they can't be registered).
    
    Parameters
    ----------
    username : str
      Client's username

    Return
    ----------
    List
      Contains all users with such username (since they're unique, it will be empty or with one element) 
    """
    res = self.cur.execute(f"SELECT username FROM users WHERE username LIKE ?;",(username,))
    return res.fetchall() != []
  
  def saveUserInDB(self,username,dA):
    """Save user in the database.
    
    Parameters
    ----------
    username : str
      Client's username
    dA : int
      Client's "private" key
    """
    self.cur.execute("INSERT INTO users (username,dA,temp) VALUES (?,?,?);",(username,str(dA),1))
    self.con.commit()
  
  def registerChap2(self,args):
    """Derive password and save it in the database, registering the user.
    
    Parameters
    ----------
    args : tuple
      Client's data previously used for password encryption. 
      args[0] = Public key (Y)
      args[1] = Username
      args[2] = Salt
      args[3] = Initialization vector
      args[4] = Original ciphertext (base64 encoded)

    Return
    ----------
    dict
      With a success code (0) or failure code (1) and the error message
    """
    try:
      Y                  = args[0]
      dA                 = self.getDA(args[1])
      salt,iv,ciphertext = args[2],args[3],args[4]
      derivedPasswordKey = self.deriveKeysDecryption(Y,dA,salt)
      secret             = self.decryptPassword(derivedPasswordKey,iv,ciphertext)
      self.saveUserSecret(secret,args[1])
    except Exception as e:
      return {'code': 1,'args': "An unknown error occurred."}
  
  def getDA(self,username):
    """Get user's "private" key.
    
    Parameters
    ----------
    username : str
      Client's username
 
    Return
    ----------
    dA : int
      Client's "private" key
    """
    res = self.cur.execute(f"SELECT dA FROM users WHERE username LIKE ?;",(username,))
    return res.fetchall()[0][0]

  def deriveKeysDecryption(self,Y,dA,salt):
    """Derives a key to be used for ciphertext decryption.
    
    Parameters
    ----------
    Y    : str
      The public key of the client
    dA   : int
      Client's "private" key
    salt : int
      Salt used for the key derivation function
 
    Return
    ----------
    key : str
      Key derived from key derivation function
    """
    # Start Elliptic curves Diffie-Hellman
    ec       = EllipticCurves()
    keyPoint = ec.multiplyPointByScalar(Y,int(dA))
    # Generate a key to be used to derive the key for decryption
    key      = str(keyPoint[0])
    return PBKDF2(key,salt,16,count=1000000,hmac_hash_module=SHA512)

  def decryptPassword(self, derivedPasswordKey, iv, cipherText):
    """Decrypt previously created password with AES-128-CBC.
    
    Parameters
    ----------
    derivedPasswordKey: str
      Key used for encryption
    cipherText: str
      Base64 encoded
    iv: str
      Initialization Vector
    """
    cipher = AES.new(derivedPasswordKey,AES.MODE_CBC,iv)
    ciphertext_decoded = b64decode(cipherText)
    # Unpadding the resulting plaintext obtained from the decryption, returns the secret
    return unpad(cipher.decrypt(ciphertext_decoded),AES.block_size)
  
  def saveUserSecret(self, secret, username):
    """Save user's secret in the DB.
    
    Parameters
    ----------
    secret: str
      The CHAP secret to be saved
    username: str
      The username of the user to save the secret
    """
    self.cur.execute("UPDATE users SET password = ? AND temp = ? WHERE username LIKE ?;",(secret,0,username))
    self.con.commit()
  
  def authenticateParaDepois(self):
    """ALERTA: POR FAZER. Authenticate client in the login process.
    
    Parameters
    ----------
    username : str
      Client's username
    dA : int
      Client's "private" key
 
    Return
    ----------
    dict
      With a success code (0) and the nonce
    """
    nonce = secrets.randbits(128)
    return {'code': 0,'args': nonce}
    
    

