from configparser import ConfigParser
from server.src.chatServer import *

def main():
  # read configuration from config file
  cfg    = ConfigParser("config/serverconf.cfg")
  server = ChatServer(
    cfg.get("APP","IP"),
    cfg.get("APP","PORT"),
    cfg.get("APP","MAX_CLIENTS")
  )
  server.runServer()

if __name__ == '__main__':
  main()