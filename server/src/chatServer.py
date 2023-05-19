import threading
import socket
import pickle
from _thread                import *
from src.utils.optionArgs   import *
from src.clientHandler      import *
from src.keyExchangeHandler import *

class ChatServer:
  """
  Attributes
  ----------
  NUMBER_BYTES_TO_RECEIVE : int
    The max number of bytes to receive
  """
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384
  
  # == Methods ==
  def __init__(self,ip,mainSocketPort,keySocketPort,msgSocketPort,maxClients,con,cur,ivKey):
    """Server initialization.
    
    Parameters
    ----------
    ip             : int
      The ip of the server
    mainSocketPort : int
      The port of the socket with the main thread
    keySocketPort  : int
      The port of the socket with the key thread
    msgSocketPort  : int
      The port of the socket with the message thread
    maxClients     : int
      The maximum number of clients to handle
    con            : sqlite3.Connection
      The connection to the local database
    cur            : sqlite3.Cursor
      The cursor to the local database
    """
    self.ip                       = ip
    self.mainSocketPort           = int(mainSocketPort)
    self.keySocketPort            = int(keySocketPort)
    self.msgSocketPort            = int(msgSocketPort)
    self.maxClients               = int(maxClients)
    self.con                      = con
    self.cur                      = cur
    self.ivKey                    = ivKey
    self.listOfClients            = []
    self.listOfKeyExchangeClients = []
    self.listOfMsgExchangeClients = []
    self.connectedUsernames       = []
    self.clientAndUsernames       = []
    self.keyClientAndUsernames    = []
    self.msgClientAndUsernames    = []
    self.clientHandler            = ClientHandler(
      self.con,
      self.cur,
      self.connectedUsernames,
      self.listOfClients,
      self.listOfKeyExchangeClients,
      self.listOfMsgExchangeClients,
      self.clientAndUsernames,
      self.keyClientAndUsernames,
      self.msgClientAndUsernames,
      self.ivKey
    )
    self.keyExchangeHandler       = KeyExchangeHandler(
      self.con,
      self.cur,
      self.connectedUsernames,
      self.keyClientAndUsernames
    )

  def runServer(self):
    """Run the server."""
    thread1 = threading.Thread(target = self.runMainThread)
    thread2 = threading.Thread(target = self.runKeyThread)
    thread3 = threading.Thread(target = self.runMsgThread)
    thread1.start()
    thread2.start()
    thread3.start()
  
  def runMainThread(self):
    """Accept main connections from clients."""
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      s.bind((self.ip,self.mainSocketPort))
      s.listen(self.maxClients)
      print("The server is listening on port " + str(self.mainSocketPort) + "...")
      while True:
        client,clientAddress = s.accept()
        self.listOfClients.append(client)
        start_new_thread(self.clientThread,(client,clientAddress))
  
  def runKeyThread(self):
    """Accept key exchange connections from clients."""
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      s.bind((self.ip,self.keySocketPort))
      s.listen(self.maxClients)
      print("The server is listening on port " + str(self.keySocketPort) + "...")
      while True:
        client,clientAddress = s.accept()
        self.listOfKeyExchangeClients.append(client)
        start_new_thread(self.keyExchangeThread,(client,clientAddress))
  
  def runMsgThread(self):
    """Accept message exchange connections from clients."""
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      s.bind((self.ip,self.msgSocketPort))
      s.listen(self.maxClients)
      print("The server is listening on port " + str(self.msgSocketPort) + "...")
      while True:
        client,clientAddress = s.accept()
        self.listOfMsgExchangeClients.append(client)
        start_new_thread(self.msgExchangeThread,(client,clientAddress))

  def clientThread(self,client,clientAddress):
    """Thread to handle the clients' operations.
    Parameters
    ----------
    client : socketObject
      The client to handle
    """
    while True: 
      try:
        # Receive client data
        opt_args = pickle.loads(client.recv(ChatServer.NUMBER_BYTES_TO_RECEIVE))
        # Process client data
        response = self.clientHandler.process(opt_args.option,opt_args.args)
        # Send response to client
        client.send(pickle.dumps(response))
      except Exception: #handle client disconnection gracefully
        pass
  
  def keyExchangeThread(self,client,clientAddress):
    """Thread to handle the clients' operations.
    Parameters
    ----------
    client : socketObject
      The client to handle
    """
    while True:
      try:
        # Receive client1 data
        opt_args = pickle.loads(client.recv(ChatServer.NUMBER_BYTES_TO_RECEIVE))
        # Process client1 data
        response = self.keyExchangeHandler.process(opt_args.option,opt_args.args)
        # Receive client2 data
        opt_args = pickle.loads(response.recv(ChatServer.NUMBER_BYTES_TO_RECEIVE))
        # Process client2 data
        response = self.keyExchangeHandler.process(opt_args.option,opt_args.args)
        # Send response back to client1
        client.send(pickle.dumps(response))
      except Exception: #handle client disconnection gracefully
        pass
      
  def msgExchangeThread(self,client,clientAddress):
    """Thread to handle the clients' operations.
    Parameters
    ----------
    client : socketObject
      The client to handle
    """
    while True: 
      try:
        # Receive client data
        opt_args = pickle.loads(client.recv(ChatServer.NUMBER_BYTES_TO_RECEIVE))
        # Process client data
        response = self.msgExchangeHandler.process(opt_args.option,opt_args.args)
        # Send response to client
        client.send(pickle.dumps(response))
      except Exception: #handle client disconnection gracefully
        pass