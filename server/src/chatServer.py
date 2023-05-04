import socket
import pickle
from _thread import *
from server.src.utils.optionArgs import *

class ChatServer:
  # == Attributes ==
  NUMBER_BYTES_TO_RECEIVE = 16384
  # == Methods ==
  def __init__(self,ip,port,maxClients):
    """Server initialization.
    
    Parameters
    ----------
    ip         : int
      The ip of the server
    port       : int
      The port to open the server on
    maxClients : int
      The maximum number of clients to handle
    """
    self.ip            = ip
    self.port          = int(port)
    self.maxClients    = int(maxClients)
    self.listOfClients = []

  def runServer(self):
    """Run the server."""
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
      s.bind((self.ip,self.port))
      s.listen(self.maxClients)
      while True:
        client,clientAddress = s.accept()
        self.listOfClients.append(client)
        start_new_thread(self.clientThread,(client,clientAddress))

  def clientThread(self,client,clientAddress):
    """Thread to handle the clients' operations.
    Parameters
    ----------
    client : socketObject
      The client to handle
    """
    client.send("Welcome to ChatWithBackdoor!")
    while True: 
      try:
        # receive client data
        opt_args = pickle.loads(client.recv(ChatServer.NUMBER_BYTES_TO_RECEIVE))
        #process client data
        response = self.clientHandler.process(opt_args.option,opt_args.args)
        client.send(pickle.dumps(response))
      except Exception: #handle client disconnection gracefully
        pass