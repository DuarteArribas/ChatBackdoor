import sqlite3
from configparser   import ConfigParser
from src.chatServer import *

def main():
  # Read configuration from config file
  cfg    = ConfigParser()
  cfg.read("server/config/serverconf.cfg")
  # Get a connection to the local database and cursor
  con = sqlite3.connect(
    cfg.get("APP","LOCAL_DATABASE_FILE"),
    check_same_thread = False
  )
  cur = con.cursor()
  # Init server
  server = ChatServer(
    cfg.get("APP","IP"),
    cfg.get("APP","MAIN_SOCKET_PORT"),
    cfg.get("APP","KEY_SOCKET_PORT"),
    cfg.get("APP","MSG_SOCKET_PORT"),
    cfg.get("APP","MAX_CLIENTS"),
    con,
    cur
  )
  server.runServer()
  

if __name__ == '__main__':
  main()