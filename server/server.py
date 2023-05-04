from configparser import ConfigParser
from src.chatServer import *

def main():
  # read configuration from config file
  cfg    = ConfigParser()
  cfg.read("server/config/serverconf.cfg")
  # initialize server
  server = ChatServer(
    cfg.get("APP","IP"),
    cfg.get("APP","PORT"),
    cfg.get("APP","MAX_CLIENTS")
  )
  # run server
  server.runServer()

if __name__ == '__main__':
  main()