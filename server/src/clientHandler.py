import secrets
import pickle
from src.ellipticCurves import EllipticCurves
from Crypto.Protocol.KDF  import PBKDF2
from Crypto.Hash          import SHA512
from Crypto.Cipher        import AES
from base64               import b64decode
from Crypto.Util.Padding  import unpad
from src.chap             import Chap

class ClientHandler:
  # == Methods ==
  def __init__(self,con,cur,connectedClients,client,listOfClients,hosts,hosts2,client2,listOfClients2):
    """Initalize handler.
    
    Parameters
    ----------
    con : sqlite3.Connection
      The connection to the local database
    cur : sqlite3.Cursor
      The cursor to the local database
    """
    self.CLIENT_HANDLER_METHOD = {
      0: self.registerChap1,
      1: self.registerChap2,
      2: self.loginChap1,
      3: self.loginChap2,
      4: self.addFriend,
      5: self.getFriendRequests,
      6: self.acceptRejectFriends,
      7: self.showFriendsList,
      8: self.removeFriend,
      9: self.logout,
      10: self.exchangeKeys1,
      11: self.exchangeKeys2
    }
    self.con = con
    self.cur = cur
    self.connectedClients = connectedClients
    self.client = client
    self.listOfClients = listOfClients
    self.hosts = hosts
    self.hosts2 = hosts2
    self.client2 = client2
    self.listOfClients2 = listOfClients2

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
      return {'code': 0,'args': "User registered successfully."}
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
    return unpad(cipher.decrypt(ciphertext_decoded),AES.block_size).decode("utf-8") 
  
  def saveUserSecret(self, secret, username):
    """Save user's secret in the DB.
    
    Parameters
    ----------
    secret: str
      The CHAP secret to be saved
    username: str
      The username of the user to save the secret
    """
    self.cur.execute("UPDATE users SET password = ?, temp = ? WHERE username LIKE ?;",(secret,0,username))
    self.con.commit()
  
  def loginChap1(self,args):
    """Authenticate client in the login process.
    
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
    username = args[0]
    if not self.isUserAlreadyInDB(username):
      return {'code': 1,'args': "User is not yet registered. Register instead!"}
    nonce    = str(secrets.randbits(128))
    self.saveUserNonce(username,nonce)
    return {'code': 0,'args': nonce}
  
  def saveUserNonce(self,username,nonce):
    """Save user's nonce in the database.
    
    Parameters
    ----------
    username : str
      The username of the user to save the nonce
    nonce    : int
      The nonce to be saved
    """
    self.cur.execute("UPDATE users SET chapNonce = ? WHERE username LIKE ?;",(nonce,username))
    self.con.commit()
  
  def loginChap2(self,args):
    """Authenticate client in the login process.
    
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
    try:
      username  = args[0]
      challenge = args[1]
      secret    = self.getUserSecret(username)
      nonce     = self.getUserNonce(username)
      if challenge == Chap.getChapChallenge(nonce,secret):
        self.connectedClients.append(username)
        for client in self.listOfClients:
          if client == self.client[0]:
            self.hosts.append((client,username))
        for client in self.listOfClients2:
          if client == self.client2[0]:
            self.hosts2.append((client,username))
        return {'code': 0,'args': "Authentication successful."}
      else:
        return {'code': 1,'args': "Authentication failed."}
    except Exception as e:
      print(e)

  def getUserSecret(self, username):
    """Returns user Secret
      
    Parameters
    ----------
    username : str
      Client's username
  
    Return
    ----------
    Str
      Secret stored in database
    """
    res = self.cur.execute("SELECT password FROM users WHERE username LIKE ?;",(username,))
    return res.fetchall()[0][0]

  def getUserNonce(self,username):
    """Return user Nonce.
      
    Parameters
    ----------
    username : str
      Client's username

    Return
    ----------
    str
      Nonce stored in database
    """
    res = self.cur.execute("SELECT chapNonce FROM users WHERE username LIKE ?;",(username,))
    return res.fetchall()[0][0]
  
  def addFriend(self,args):
    """Add friend to the friend's list in the database.

    Parameters
    ----------
    args : tuple
      Username from the current user and friend's username
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
      args : str
        exception message if unsuccessful
        success message if successful
    """
    try:
      username,friendUsername = args[0],args[1]
      if not self.isUserLoggedInDB(friendUsername):
        return {'code': 1,'args': "User does not exist."}
      if self.isFriendRequested(username,friendUsername):
        return {'code': 1,'args': "Friend request already sent/received."}
      if self.areFriends(username,friendUsername):
        return {'code': 1,'args': "You are already friends."}
      self.cur.execute("INSERT INTO friends (username1,username2,acceptance) VALUES (?,?,?);",(username,friendUsername,0))
      self.con.commit()
    except Exception as e:
      return {'code': 1,'args': e}
    return {'code': 0,'args': "Friend request sent."}
  
  def isUserLoggedInDB(self,username):
    """Verify if a user is already logged in in the database.

    Parameters
    ----------
    username : str
      The username of the current user
    
    Return
    ----------
    str
      If the user is logged in returns the username
    """
    res = self.cur.execute("SELECT username FROM users WHERE username LIKE ? AND temp = ?;",(username,0))
    return res.fetchall() != []
  
  def isFriendRequested(self,username,friendUsername):
    """Verify if a friend request was already sent/received.
    
    Parameters
    ----------
    username : str
      The username of the current user
    friendUsername : str
      The username of the friend to add
    
    Return
    ----------
    str
      If the user has a request sent/received returns the usernames
    """
    res = self.cur.execute("SELECT username1,username2 FROM friends WHERE username1 LIKE ? AND username2 LIKE ? AND acceptance = ?;",(username,friendUsername,0))
    return res.fetchall() != []
  
  def areFriends(self,username,friendUsername):
    """Verify if two users are already friends.
    
    Parameters
    ----------
    username : str
      The username of the current user
    friendUsername : str
      The username of the friend
    
    Return
    ----------
    str
      If the users are already friends returns the usernames
    """
    res = self.cur.execute("SELECT username1,username2 FROM friends WHERE username1 LIKE ? AND username2 LIKE ? AND acceptance = ?;",(username,friendUsername,1))
    return res.fetchall() != []
  
  def getFriendRequests(self,args):
    """Get friend requests from the database.
    
    Parameters
    ----------
    args : tuple
      Username from the current user
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
      args : str
        exception message if unsuccessful
        list of friend requests if successful
    """
    username = args[0]
    res = self.cur.execute("SELECT username1 FROM friends WHERE username2 LIKE ? AND acceptance = ?;",(username,0))
    results = res.fetchall()
    if results == []:
      return {'code': 1,'args': "You have no friend requests."}
    else:
      return {'code': 0,'args': results}
  
  def acceptRejectFriends(self,args):
    """Accept or reject friend requests from the list of friend requests.
    
    Parameters
    ----------
    args : tuple
      args[0] = username
      args[1] = list of friends to accept
      args[2] = list of friends to reject
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
      args : str
        confirmation of acceptance/rejection of friend requests if successful
        exception message if unsuccessful
    """
    try:
      username        = args[0]
      friendsToAccept = args[1]
      friendsToReject = args[2]
      for friend in friendsToAccept:
        self.cur.execute("UPDATE friends SET acceptance = ? WHERE username1 LIKE ? AND username2 LIKE ?;",(1,friend,username))
        self.con.commit()
      for friend in friendsToReject:
        self.cur.execute("DELETE FROM friends WHERE username1 LIKE ? AND username2 LIKE ?;",(friend,username))
        self.con.commit()
      if len(friendsToAccept) > 0 and len(friendsToReject) == 0:
        return {'code': 0,'args': "Friend requests accepted."}
      elif len(friendsToAccept) == 0 and len(friendsToReject) > 0:
        return {'code': 0,'args': "Friend requests rejected."}
      else:
        return {'code': 0,'args': "Friend requests accepted and rejected."}
    except Exception as e:
      return {'code': 1,'args': e}
  
  def showFriendsList(self,args):
    """Show friends list from the database.
    
    Parameters
    ----------
    args : tuple
      args[0] = username from the current user
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
      args : str
        list of friends if successful
        sad message if unsuccessful
    """
    username = args[0]
    res = self.cur.execute("SELECT username1 FROM friends WHERE username2 LIKE ? AND acceptance = ? UNION SELECT username2 FROM friends WHERE username1 LIKE ? AND acceptance = ?;",(username,1,username,1))
    results = res.fetchall()
    resultsOnline = []
    for result in results:
      if result[0] in self.connectedClients:
        resultsOnline.append(result[0] + " (online)")
      else:
        resultsOnline.append(result[0] + " (offline)")
    if results == []:
      return {'code': 1,'args': "Sorry, you've got no friends 😭"}
    else:
      return {'code': 0,'args': resultsOnline}

  def removeFriend(self,args):
    """ Remove single friend from friend requests through its username.
    
    Parameters
    ----------
    args : tuple
      args[0] = username of current user
      args[2] = list of friends to reject
    
    Return
    ----------
    dict
      code : int
        0 if successful
        1 if unsuccessful
    """
    try: 
      username = args[0]
      friendUsername = args[1]
      self.cur.execute("DELETE FROM friends WHERE username1 LIKE ? AND username2 LIKE ?;",(username,friendUsername))
      self.cur.execute("DELETE FROM friends WHERE username2 LIKE ? AND username1 LIKE ?;",(username,friendUsername))
      self.con.commit()
      return {'code': 0,'args': "Friend removed."}
    except Exception as e:
      return {'code': 1,'args': "An unknown error occurred. Friend not removed."}
  
  def logout(self,args):
    """Logout from the database. When user logs out, their name is removed from a list containing everyone who's online in the moment. 
    
    Parameters
    ----------
    args : tuple
      args[0] = username of current user
    
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
      username = args[0]
      print(self.connectedClients)
      if username in self.connectedClients:
        self.connectedClients.remove(username)
      return {'code': 0,'args': "Logged out."}
    except Exception as e:
      return {'code': 1,'args': e}
    
  def exchangeKeys1(self,args):
    try:
      username = args[0]
      friendUsername = args[1]
      X = args[2]
      cipherMac = args[3]
      if friendUsername not in self.connectedClients:
        return {'code': 1,'args': "Friend is not online."}
      for host,u in self.hosts2:
        if u == friendUsername:
          print(host)
          host.send(pickle.dumps({'code': 2,'args': (username,X,cipherMac)}))
          return host
    except Exception as e:
      print("1: ", e)
  
  def exchangeKeys2(self,args):
    try:
      username = args[0]
      Y = args[1]
      for host,u in self.hosts2:
        if u == username:
          print("ENTRAS AQUI CARALHO?")
          return {'code': 0,'args': (Y,)}
    except Exception as e:
      print("2: ",e)