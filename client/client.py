from configparser import ConfigParser
from src.chatClient import *
from src.menu import *
import signal,sys

def main():
  # Read configuration from config file
  cfg = ConfigParser()
  cfg.read("client/config/clientconf.cfg")
  # Init menu
  menuHandler = Menu()
  # Init client
  client = ChatClient(
    cfg.get("APP","IP"),
    cfg.get("APP","MAIN_SOCKET_PORT"),
    cfg.get("APP","KEY_SOCKET_PORT"),
    cfg.get("APP","MSG_SOCKET_PORT"),
    cfg.get("APP","MSG_HISTORY_SOCKET_PORT"),
    menuHandler,
    cfg.get("APP","CLIENT_KEYS_PATH"),
    cfg.get("APP","RSA_KEY_SIZE_BITS"),
    cfg.get("APP","ELGAMAL_KEY_SIZE_BITS"),
    cfg.get("APP","IV_KEY")
  )
  # Run client
  client.runClient()
  
if __name__ == '__main__':
  main()